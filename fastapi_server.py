#!/usr/bin/env python3
"""
FastAPI Webhook Gateway - Unified HTTP entry point for all webhooks
Replaces fragmented webhook handling with secure, centralized processing
"""

import os
import logging
import asyncio
import json
import hmac
import hashlib
import time
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# Import centralized configuration
from config import get_config

# Telegram bot integration
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# Configure logging early to capture all startup logs including lifespan
# OPTIMIZED: Single structured JSON log format (eliminated duplicate plain-text logging)
# This halves log volume on Railway — every message was being written twice before
import json as _json
from datetime import datetime as _dt, timezone as _tz

class _JsonLogFormatter(logging.Formatter):
    """Single structured JSON log format for production"""
    def format(self, record):
        log_data = {
            'timestamp': _dt.fromtimestamp(record.created, _tz.utc).isoformat(),
            'level': record.levelname,
            'component': record.name,
            'message': record.getMessage(),
        }
        return _json.dumps(log_data, default=str)

_handler = logging.StreamHandler()
_handler.setFormatter(_JsonLogFormatter())
logging.root.handlers = [_handler]
logging.root.setLevel(logging.INFO)

# SECURITY: Prevent bot token leakage in HTTP request logs
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Global bot application instance
bot_app: Optional[Application] = None
_bot_application_instance = None  # Additional storage for admin alert system access
_bot_ready_event: Optional[asyncio.Event] = None  # Readiness gate for webhook requests

# Webhook verification middleware
class WebhookVerifier:
    """Secure webhook verification for all providers"""
    
    
    @staticmethod
    def verify_blockbee(request_body: bytes, headers: Dict[str, str]) -> bool:
        """Verify BlockBee webhook signature - STRICT verification required"""
        config = get_config()
        api_key = config.payment.blockbee_api_key
        if not api_key:
            logger.error("❌ CRITICAL: Missing BLOCKBEE_API_KEY - cannot verify webhook")
            return False  # STRICT: Reject unsigned webhooks
            
        signature = headers.get('x-signature', '')
        if not signature:
            logger.error("❌ CRITICAL: Missing BlockBee signature header")
            return False
            
        expected = hmac.new(
            api_key.encode('utf-8'),
            request_body,
            hashlib.sha256
        ).hexdigest()
        
        is_valid = hmac.compare_digest(signature, expected)
        if not is_valid:
            logger.error("❌ CRITICAL: BlockBee signature verification failed")
            
        return is_valid
    
    @staticmethod
    def verify_timestamp(timestamp_str: str, max_age: int = 300) -> bool:
        """Verify timestamp to prevent replay attacks"""
        try:
            timestamp = int(timestamp_str)
            current_time = int(time.time())
            return abs(current_time - timestamp) <= max_age
        except (ValueError, TypeError):
            return False

async def sync_subscription_cpanel_status():
    """
    Comprehensive cPanel suspension sync job with retry mechanism.
    Finds and fixes ALL problematic subscriptions:
    1. Expired subscriptions that should be suspended but aren't
    2. Already-suspended subscriptions with failed cPanel status
    3. Retries failed suspensions with exponential backoff (max 3 attempts)
    """
    try:
        logger.info("🔄 Starting comprehensive subscription-cPanel status sync job...")
        
        from database import execute_query, execute_update
        from services.cpanel import CPanelService
        from datetime import datetime, timezone
        
        cpanel = CPanelService()
        stats = {
            'should_be_suspended': 0,
            'failed_suspensions': 0,
            'success': 0,
            'retried': 0,
            'max_attempts_reached': 0,
            'errors': 0
        }
        
        # PART 1: Find subscriptions that SHOULD be suspended but aren't
        # These are expired one_time subscriptions still marked as active/grace_period/provisioning
        now = datetime.now(timezone.utc)
        should_be_suspended = await execute_query("""
            SELECT id, cpanel_username, domain_name, status, billing_cycle,
                   next_billing_date, cpanel_suspension_attempts
            FROM hosting_subscriptions
            WHERE status IN ('active', 'grace_period', 'provisioning')
            AND next_billing_date < %s
            AND billing_cycle = 'one_time'
            AND cpanel_username IS NOT NULL
            AND deleted_at IS NULL
        """, (now,))
        
        if should_be_suspended:
            logger.warning(f"⚠️ Found {len(should_be_suspended)} subscriptions that SHOULD be suspended but aren't!")
            stats['should_be_suspended'] = len(should_be_suspended)
            
            for sub in should_be_suspended:
                await _attempt_cpanel_suspension(cpanel, sub, stats, reason="expired_not_suspended")
        
        # PART 2: Find already-suspended subscriptions with failed/pending cPanel status
        # These need retry with exponential backoff
        failed_suspensions = await execute_query("""
            SELECT id, cpanel_username, domain_name, status,
                   cpanel_suspension_status, cpanel_suspension_attempts,
                   last_cpanel_sync_attempt
            FROM hosting_subscriptions
            WHERE status = 'suspended'
            AND cpanel_username IS NOT NULL
            AND cpanel_suspension_status IN ('failed', 'pending', 'retrying')
            AND cpanel_suspension_attempts < 3
            AND deleted_at IS NULL
        """)
        
        if failed_suspensions:
            logger.info(f"🔄 Found {len(failed_suspensions)} failed suspensions to retry")
            stats['failed_suspensions'] = len(failed_suspensions)
            
            for sub in failed_suspensions:
                await _attempt_cpanel_suspension(cpanel, sub, stats, reason="retry_failed")
        
        # PART 3: Find subscriptions that have reached max retry attempts - log for manual intervention
        max_attempts_reached = await execute_query("""
            SELECT id, cpanel_username, domain_name, status,
                   cpanel_suspension_attempts, last_cpanel_sync_attempt
            FROM hosting_subscriptions
            WHERE status = 'suspended'
            AND cpanel_username IS NOT NULL
            AND cpanel_suspension_attempts >= 3
            AND cpanel_suspension_status != 'success'
            AND deleted_at IS NULL
        """)
        
        if max_attempts_reached:
            stats['max_attempts_reached'] = len(max_attempts_reached)
            logger.critical(f"🚨 MANUAL INTERVENTION REQUIRED: {len(max_attempts_reached)} subscriptions failed suspension after 3 attempts!")
            for sub in max_attempts_reached:
                logger.critical(f"🚨 Manual suspension needed: {sub['cpanel_username']} ({sub['domain_name']}) - {sub['cpanel_suspension_attempts']} attempts")
        
        # Log final summary
        logger.info(f"✅ Sync job complete: {stats['success']} successful, {stats['retried']} retried, "
                   f"{stats['max_attempts_reached']} need manual intervention, {stats['errors']} errors")
        
        if stats['should_be_suspended'] > 0:
            logger.warning(f"⚠️ {stats['should_be_suspended']} expired subscriptions were not properly suspended - fixed!")
        
    except Exception as e:
        logger.error(f"❌ Subscription-cPanel sync job failed: {e}")


async def _attempt_cpanel_suspension(cpanel, subscription: Dict, stats: Dict, reason: str):
    """
    Attempt cPanel suspension with tracking and retry logic.
    Implements exponential backoff based on attempt count.
    """
    from database import execute_update
    from datetime import datetime, timezone, timedelta
    
    sub_id = subscription['id']
    cpanel_username = subscription['cpanel_username']
    domain_name = subscription.get('domain_name', 'unknown')
    current_attempts = subscription.get('cpanel_suspension_attempts', 0)
    
    try:
        # Attempt suspension
        suspend_result = await cpanel.suspend_account(cpanel_username)
        
        if suspend_result:
            # SUCCESS: Reset attempts, mark as success, set timestamps
            suspension_timestamp = datetime.now(timezone.utc)
            deletion_scheduled = suspension_timestamp + timedelta(days=30)
            
            await execute_update("""
                UPDATE hosting_subscriptions
                SET status = 'suspended',
                    suspended_at = %s,
                    deletion_scheduled_for = %s,
                    cpanel_suspension_status = 'success',
                    cpanel_suspension_attempts = 0,
                    last_cpanel_sync_attempt = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (suspension_timestamp, deletion_scheduled, sub_id))
            
            stats['success'] += 1
            logger.info(f"✅ cPanel suspension SUCCESS: {cpanel_username} ({domain_name}) - {reason}")
            
        else:
            # FAILED: Increment attempts, mark as failed/retrying
            new_attempts = current_attempts + 1
            new_status = 'retrying' if new_attempts < 3 else 'failed'
            
            await execute_update("""
                UPDATE hosting_subscriptions
                SET cpanel_suspension_status = %s,
                    cpanel_suspension_attempts = %s,
                    last_cpanel_sync_attempt = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (new_status, new_attempts, sub_id))
            
            stats['retried'] += 1
            logger.error(f"❌ cPanel suspension FAILED: {cpanel_username} ({domain_name}) - attempt {new_attempts}/3 - {reason}")
            
            if new_attempts >= 3:
                stats['max_attempts_reached'] += 1
                logger.critical(f"🚨 Max attempts reached for {cpanel_username} ({domain_name}) - MANUAL INTERVENTION REQUIRED")
                
    except Exception as e:
        # ERROR: Increment attempts, mark as failed
        new_attempts = current_attempts + 1
        new_status = 'retrying' if new_attempts < 3 else 'failed'
        
        await execute_update("""
            UPDATE hosting_subscriptions
            SET cpanel_suspension_status = %s,
                cpanel_suspension_attempts = %s,
                last_cpanel_sync_attempt = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (new_status, new_attempts, sub_id))
        
        stats['errors'] += 1
        logger.error(f"❌ cPanel suspension ERROR: {cpanel_username} ({domain_name}): {e} - attempt {new_attempts}/3 - {reason}")

async def process_suspended_account_deletions():
    """
    Daily cleanup job to delete hosting accounts suspended for 30+ days.
    Permanently removes cPanel accounts and notifies users.
    """
    try:
        logger.info("🗑️ Starting suspended account deletion check...")
        
        from database import execute_query, execute_update
        from services.cpanel import CPanelService
        from datetime import datetime, timezone
        
        # Find accounts where deletion is scheduled and date has passed
        now = datetime.now(timezone.utc)
        accounts_to_delete = await execute_query("""
            SELECT hs.id, hs.cpanel_username, hs.domain_name, hs.user_id, u.telegram_id, 
                   hs.suspended_at, hs.deletion_scheduled_for
            FROM hosting_subscriptions hs
            JOIN users u ON hs.user_id = u.id
            WHERE hs.status = 'suspended'
            AND hs.deletion_scheduled_for IS NOT NULL
            AND hs.deletion_scheduled_for <= %s
            AND hs.deleted_at IS NULL
        """, (now,))
        
        if not accounts_to_delete:
            logger.info("✅ Deletion check: No accounts to delete")
            return
        
        logger.info(f"🔍 Deletion check: Found {len(accounts_to_delete)} accounts to delete")
        
        cpanel = CPanelService()
        deleted_count = 0
        error_count = 0
        
        for account in accounts_to_delete:
            cpanel_username = account['cpanel_username']
            domain_name = account.get('domain_name', 'unknown')
            telegram_id = account.get('telegram_id')
            subscription_id = account['id']
            
            try:
                # Delete cPanel account
                cpanel_deleted = False
                if cpanel_username:
                    try:
                        cpanel_deleted = await cpanel.delete_account(cpanel_username, keep_dns=False)
                        if cpanel_deleted:
                            logger.info(f"✅ Deletion: cPanel account deleted: {cpanel_username}")
                        else:
                            logger.error(f"❌ Deletion: Failed to delete cPanel account: {cpanel_username}")
                    except Exception as cpanel_error:
                        logger.error(f"❌ Deletion: Error deleting cPanel account {cpanel_username}: {cpanel_error}")
                
                # Mark subscription as deleted in database
                await execute_update("""
                    UPDATE hosting_subscriptions
                    SET status = 'deleted',
                        deleted_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (subscription_id,))
                
                # Send deletion notification to user
                if telegram_id:
                    try:
                        await send_account_deletion_notification(
                            telegram_id=telegram_id,
                            domain_name=domain_name,
                            suspended_at=account['suspended_at'],
                            cpanel_deleted=cpanel_deleted
                        )
                    except Exception as notif_error:
                        logger.error(f"❌ Deletion: Failed to send notification to {telegram_id}: {notif_error}")
                
                deleted_count += 1
                logger.info(f"✅ Deletion complete: {domain_name} (subscription {subscription_id})")
                
            except Exception as e:
                error_count += 1
                logger.error(f"❌ Deletion: Error processing {domain_name}: {e}")
        
        logger.info(f"✅ Deletion check complete: {deleted_count} deleted, {error_count} errors")
        
    except Exception as e:
        logger.error(f"❌ Suspended account deletion job failed: {e}")


async def send_account_deletion_notification(telegram_id: int, domain_name: str, suspended_at, cpanel_deleted: bool):
    """Send Telegram notification to user about account deletion"""
    try:
        from telegram import Bot
        from telegram.constants import ParseMode
        from config import get_config
        from datetime import datetime, timezone
        
        config = get_config()
        bot = Bot(token=config.telegram.bot_token)
        
        # Calculate how long it was suspended
        if suspended_at:
            days_suspended = (datetime.now(timezone.utc) - suspended_at).days
        else:
            days_suspended = "30+"
        
        cpanel_status = "✅ Removed" if cpanel_deleted else "⚠️ Manual cleanup may be required"
        
        message = f"""
🗑️ <b>Hosting Account Deleted</b>

Your hosting for <code>{domain_name}</code> has been permanently deleted due to non-payment.

📅 <b>Suspended:</b> {suspended_at.strftime('%B %d, %Y') if suspended_at else 'Unknown'}
📅 <b>Deleted:</b> {datetime.now(timezone.utc).strftime('%B %d, %Y')}
⏱️ <b>Duration:</b> {days_suspended} days
🖥️ <b>cPanel Status:</b> {cpanel_status}

⚠️ <b>All data has been permanently removed.</b>

💡 You can purchase new hosting anytime at /dashboard → 🏠 Hosting Services
"""
        
        await bot.send_message(
            chat_id=telegram_id,
            text=message,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"✅ Deletion notification sent to user {telegram_id} for {domain_name}")
        
    except Exception as e:
        logger.error(f"❌ Failed to send deletion notification: {e}")
        # Don't raise - notification failure shouldn't block deletion

# Global service status tracking for health checks
_service_status = {
    'bot': False,
    'webhook': False,
    'database': False,
    'scheduler': False,
    'payment_cleanup': False,
    'language_system': False,
    'message_queue': False
}

# Startup timeout wrapper for heavy initialization tasks
async def run_with_timeout(coro, timeout_seconds: float, task_name: str, default=None):
    """Run a coroutine with timeout, logging and returning default on timeout/failure"""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"⏱️ TIMEOUT: {task_name} took longer than {timeout_seconds}s - skipping")
        return default
    except Exception as e:
        logger.warning(f"⚠️ {task_name} failed: {e}")
        return default

# FastAPI lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage FastAPI lifecycle and bot integration - ALWAYS STARTS SUCCESSFULLY"""
    global bot_app, _service_status
    
    # NOTE: FAST_STARTUP mode is deprecated - background initialization now handles fast startup
    # Heavy tasks run in background after server starts accepting requests
    fast_startup = os.getenv('FAST_STARTUP', '').lower() == 'true'
    if fast_startup:
        logger.info("⚠️ FAST_STARTUP secret detected but ignored - using background initialization instead")
        logger.info("   You can safely remove the FAST_STARTUP secret")
    
    logger.info("=" * 80)
    logger.info("🚀 STARTING FASTAPI WEBHOOK GATEWAY - GRACEFUL DEGRADATION MODE")
    logger.info("=" * 80)
    
    # Reset service status
    _service_status = {
        'bot': False,
        'webhook': False,
        'database': False,
        'scheduler': False,
        'payment_cleanup': False,
        'language_system': False,
        'message_queue': False
    }
    
    # Get configuration
    config = get_config()
    
    # Validate configuration - don't crash on failure, just warn
    try:
        validation = config.validate()
        if not validation['valid']:
            logger.error("❌ Configuration validation failed:")
            for issue in validation['issues']:
                logger.error(f"  • {issue}")
            logger.warning("⚠️ Starting with invalid configuration - some features may not work")
        
        # Log warnings but don't block startup
        if validation['warnings']:
            logger.warning("⚠️ Configuration warnings:")
            for warning in validation['warnings']:
                logger.warning(f"  • {warning}")
    except Exception as config_error:
        logger.error(f"❌ Configuration validation error: {config_error}")
        logger.warning("⚠️ Continuing startup despite configuration errors")
    
    # ========================================================================
    # CRITICAL: Bot initialization with graceful degradation
    # If bot fails to start, HTTP server STILL starts successfully
    # ALL bot-related code is inside try-except to catch token/initialization errors
    # ========================================================================
    try:
        logger.info("🚀 Initializing Telegram bot application...")
        
        # Get token (THIS CAN FAIL if token is missing/invalid)
        token = config.telegram.bot_token
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN is missing or empty")
        
        # Create bot application 
        from telegram.ext import Defaults
        
        defaults = Defaults(parse_mode='HTML')
        # THIS IS WHERE IT CAN FAIL - Application.builder().token() validates the token
        bot_app = Application.builder().token(token).concurrent_updates(128).defaults(defaults).build()
        
        # Register command handlers (similar to bot.py)
        from handlers import (
            start_command, domain_command, dns_command, wallet_command,
            search_command, profile_command, hosting_command, language_command,
            handle_callback, handle_text_message,
            stop_promos_command, start_promos_command, set_timezone_command
        )
        from admin_handlers import (
            broadcast_command, cancel_command, maintenance_command,
            handle_admin_broadcast_text, handle_admin_credit_text
        )
        
        # Add command handlers
        bot_app.add_handler(CommandHandler("start", start_command))
        bot_app.add_handler(CommandHandler("search", search_command))
        bot_app.add_handler(CommandHandler("domain", domain_command))
        bot_app.add_handler(CommandHandler("domains", domain_command))  # Alias for /domain
        bot_app.add_handler(CommandHandler("dns", dns_command))
        bot_app.add_handler(CommandHandler("wallet", wallet_command))
        bot_app.add_handler(CommandHandler("profile", profile_command))
        bot_app.add_handler(CommandHandler("hosting", hosting_command))
        bot_app.add_handler(CommandHandler("language", language_command))
        
        # Admin commands
        bot_app.add_handler(CommandHandler("broadcast", broadcast_command))
        bot_app.add_handler(CommandHandler("cancel", cancel_command))
        bot_app.add_handler(CommandHandler("maintenance", maintenance_command))
        
        # Promo opt-out/opt-in and timezone commands
        bot_app.add_handler(CommandHandler("stop_promos", stop_promos_command))
        bot_app.add_handler(CommandHandler("start_promos", start_promos_command))
        bot_app.add_handler(CommandHandler("set_timezone", set_timezone_command))
        
        # Callback and message handlers
        bot_app.add_handler(CallbackQueryHandler(handle_callback))
        
        # CRITICAL: Add admin message handlers with proper priority groups (must match bot.py)
        bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_credit_text), group=-2)
        bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_broadcast_text), group=-1)
        bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message), group=0)
        
        # Add global error handler to prevent "No error handlers registered" errors
        async def global_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
            """Global error handler for unhandled exceptions in bot operations"""
            try:
                # Extract error details
                error = context.error
                error_type = type(error).__name__
                error_message = str(error)
                
                # Log structured error information
                logger.error(f"🚨 TELEGRAM ERROR: {error_type} - {error_message}")
                
                # Try to get user info if update contains it (with proper type handling)
                user_info = "Unknown"
                try:
                    if hasattr(update, 'effective_user') and getattr(update, 'effective_user', None):
                        eff_user = getattr(update, 'effective_user')
                        user_info = f"User {eff_user.id} (@{getattr(eff_user, 'username', 'no_username')})"
                    elif hasattr(update, 'message') and getattr(update, 'message', None):
                        msg = getattr(update, 'message')
                        if hasattr(msg, 'from_user') and getattr(msg, 'from_user', None):
                            from_user = getattr(msg, 'from_user')
                            user_info = f"User {from_user.id} (@{getattr(from_user, 'username', 'no_username')})"
                    elif hasattr(update, 'callback_query') and getattr(update, 'callback_query', None):
                        cb = getattr(update, 'callback_query')
                        if hasattr(cb, 'from_user') and getattr(cb, 'from_user', None):
                            from_user = getattr(cb, 'from_user')
                            user_info = f"User {from_user.id} (@{getattr(from_user, 'username', 'no_username')})"
                except Exception as user_extract_error:
                    logger.warning(f"⚠️ Could not extract user info: {user_extract_error}")
                    user_info = "Unknown"
                
                logger.info(f"📍 Error context: {user_info}")
                
                # Log to performance monitor if available
                try:
                    import performance_monitor
                    if hasattr(performance_monitor, 'log_error_event'):
                        performance_monitor.log_error_event(f"telegram_error_{error_type.lower()}", {
                            'error_type': error_type,
                            'error_message': error_message,
                            'user_context': user_info
                        })
                except (ImportError, AttributeError):
                    pass  # Performance monitor not available or function not found
                    
            except Exception as handler_error:
                # Prevent error handler from causing more errors
                logger.critical(f"💥 ERROR HANDLER FAILURE: {handler_error}")
        
        # Register the global error handler
        bot_app.add_error_handler(global_error_handler)
        logger.info("✅ Global error handler registered - unhandled exceptions will be logged properly")
        
        # Initialize and start bot with extended timeout and retry logic
        # Telegram API can be slow during deployment, especially under load
        BOT_INIT_TIMEOUT = 30  # OPTIMIZED: 30 seconds - prevents Railway restart loops on cold starts
        MAX_INIT_RETRIES = 3   # OPTIMIZED: 3 retries max (was 5) - faster failure detection
        
        for attempt in range(1, MAX_INIT_RETRIES + 1):
            try:
                logger.info(f"🚀 Initializing Telegram bot (attempt {attempt}/{MAX_INIT_RETRIES}, timeout={BOT_INIT_TIMEOUT}s)...")
                await asyncio.wait_for(bot_app.initialize(), timeout=BOT_INIT_TIMEOUT)
                logger.info("🚀 Starting Telegram bot application...")
                await asyncio.wait_for(bot_app.start(), timeout=BOT_INIT_TIMEOUT)
                logger.info("✅ Bot application initialized and started successfully")
                _service_status['bot'] = True
                break  # Success - exit retry loop
            except asyncio.TimeoutError:
                logger.warning(f"⏱️ Bot initialization timeout on attempt {attempt}/{MAX_INIT_RETRIES}")
                if attempt < MAX_INIT_RETRIES:
                    wait_time = attempt * 2  # Exponential backoff: 2s, 4s
                    logger.info(f"⏳ Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    raise asyncio.TimeoutError(f"Bot initialization failed after {MAX_INIT_RETRIES} attempts")
            except Exception as init_error:
                logger.warning(f"⚠️ Bot init error on attempt {attempt}: {init_error}")
                if attempt < MAX_INIT_RETRIES:
                    await asyncio.sleep(2)
                else:
                    raise
        
    except Exception as bot_error:
        # This NOW catches token validation errors, builder errors, and initialization errors!
        logger.error(f"❌ CRITICAL: Bot initialization failed: {bot_error}")
        logger.error(f"   Error type: {type(bot_error).__name__}")
        logger.warning("⚠️ GRACEFUL DEGRADATION: Bot service unavailable, but HTTP server will still start")
        logger.warning("⚠️ Health endpoint will report bot_ready: false")
        bot_app = None  # Set to None to indicate bot is not available
        _service_status['bot'] = False
    
    # ENVIRONMENT-AWARE MODE: Use polling in development, webhooks in production
    # BOT_MODE override: Set BOT_MODE=webhook or BOT_MODE=polling to force a specific mode
    # Only attempt if bot is available
    polling_task = None
    env_manager = None
    
    if bot_app is None:
        logger.warning("⚠️ Bot not available - skipping webhook/polling configuration")
        _service_status['webhook'] = False
    else:
        # Bot is available, get environment manager
        try:
            from utils.environment_manager import get_environment_manager
            env_manager = get_environment_manager()
            logger.info(f"🌍 Environment detected: {env_manager.current.value}")
        except Exception as env_error:
            logger.error(f"❌ Failed to get environment manager: {env_error}")
            logger.error("⚠️ Cannot determine environment - defaulting to development mode")
            # Create a fallback environment manager
            class FallbackEnvManager:
                is_development = True
                current = type('obj', (object,), {'value': 'development'})()
            env_manager = FallbackEnvManager()
    
    # Determine bot communication mode (polling vs webhook)
    # Priority: BOT_MODE override > environment detection
    bot_mode_override = os.getenv('BOT_MODE', '').lower()
    use_polling = False
    
    if bot_mode_override == 'polling':
        use_polling = True
        logger.info("🔧 BOT_MODE=polling - Forcing polling mode (override)")
    elif bot_mode_override == 'webhook':
        use_polling = False
        logger.info("🌐 BOT_MODE=webhook - Forcing webhook mode (override)")
    elif env_manager and env_manager.is_development:
        use_polling = True
        logger.info("🔧 Development environment - defaulting to polling mode")
    else:
        use_polling = False
        logger.info("🌐 Production environment - defaulting to webhook mode")
    
    if bot_app is not None and use_polling:
        # Development mode: Use polling for local testing
        logger.info("🔧 DEVELOPMENT MODE: Starting bot in polling mode...")
        try:
            # CRITICAL FIX: Delete webhook with retry and ensure it completes
            logger.info("🧹 Checking for existing webhook...")
            webhook_info = await bot_app.bot.get_webhook_info()
            if webhook_info.url:
                logger.info(f"⚠️ Found active webhook: {webhook_info.url}")
                logger.info("🧹 Deleting webhook to enable polling...")
                await bot_app.bot.delete_webhook(drop_pending_updates=True)
                # Wait a moment for Telegram to process the deletion
                await asyncio.sleep(1.5)
                # Verify deletion
                webhook_info = await bot_app.bot.get_webhook_info()
                if webhook_info.url:
                    logger.error(f"❌ Webhook still active after deletion: {webhook_info.url}")
                    logger.error("⚠️ Cannot start polling - webhook must be removed manually")
                    _service_status['webhook'] = False
                    return
                logger.info("✅ Webhook deleted successfully")
            else:
                logger.info("✅ No existing webhook found")
            
            # Start polling in a background task
            async def run_polling():
                try:
                    logger.info("🔄 Starting polling loop...")
                    if bot_app and hasattr(bot_app, 'updater') and bot_app.updater is not None:
                        await bot_app.updater.start_polling(
                            poll_interval=1.0,
                            timeout=10,
                            drop_pending_updates=False,
                            allowed_updates=Update.ALL_TYPES
                        )
                        logger.info("✅ Polling started successfully")
                    else:
                        logger.error("❌ Updater not available - cannot start polling")
                except Exception as poll_error:
                    logger.error(f"❌ Polling error: {poll_error}")
            
            polling_task = asyncio.create_task(run_polling())
            logger.info("✅ Bot running in POLLING mode - fetching updates from Telegram")
            logger.info("📱 Development mode active - messages will be received via polling")
            _service_status['webhook'] = True  # Mark as active for polling
            
        except Exception as polling_error:
            logger.error(f"❌ Failed to start polling mode: {polling_error}")
            logger.error("⚠️ Bot will not receive messages in development mode")
            _service_status['webhook'] = False
    elif bot_app is not None and not use_polling:
        # Webhook mode: Register Telegram webhook
        logger.info("🌐 WEBHOOK MODE: Registering Telegram webhook...")
        try:
            from utils.environment import get_webhook_url
            import hashlib
            
            # CRITICAL FIX: Ensure updater is stopped before setting webhook
            # This prevents "can't use getUpdates while webhook is active" errors
            if bot_app.updater and bot_app.updater.running:
                logger.info("🛑 Stopping any existing polling before webhook setup...")
                try:
                    await bot_app.updater.stop()
                    logger.info("✅ Polling stopped successfully")
                except Exception as stop_error:
                    logger.warning(f"⚠️ Failed to stop polling (may not have been running): {stop_error}")
            
            # Get environment-aware webhook URL
            webhook_url = get_webhook_url('telegram')
            logger.info(f"🌐 Using webhook URL: {webhook_url}")
            
            # Use persistent webhook secret token
            webhook_secret = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN')
            if not webhook_secret:
                # Generate a persistent secret based on bot token
                secret_source = f"{config.telegram.bot_token}_webhook_secret"
                webhook_secret = hashlib.sha256(secret_source.encode()).hexdigest()[:32]
                logger.info("🔐 Generated persistent webhook secret token")
            else:
                logger.info("🔐 Using existing webhook secret token")
            
            # Register webhook with Telegram
            # NEON FREE TIER FIX: Reduced to 10 to match database pool capacity (maxconn=10)
            # Prevents "Too many connections" errors on Neon free tier (112 max connections)
            webhook_result = await bot_app.bot.set_webhook(
                url=webhook_url,
                secret_token=webhook_secret,
                max_connections=10
            )
            
            if webhook_result:
                logger.info("✅ Telegram webhook registered successfully")
                # Verify webhook status
                webhook_info = await bot_app.bot.get_webhook_info()
                logger.info(f"📊 Webhook URL: {webhook_info.url}")
                logger.info(f"🔌 Max connections: {webhook_info.max_connections}")
                logger.info(f"📨 Pending updates: {webhook_info.pending_update_count}")
                _service_status['webhook'] = True
            else:
                logger.error("❌ Failed to register Telegram webhook")
                _service_status['webhook'] = False
                
        except Exception as webhook_error:
            logger.error(f"❌ Webhook registration failed: {webhook_error}")
            logger.warning("⚠️ Bot may not receive messages - webhook registration required")
            _service_status['webhook'] = False
    elif bot_app is not None:
        # This should never happen now due to fallback env_manager
        logger.error("⚠️ Environment manager unavailable - bot communication mode not configured")
        _service_status['webhook'] = False
    
    # CRITICAL: Link to webhook_handler message pipeline and start queue processor
    # Only if bot is available
    queue_task = None
    if bot_app is not None:
        try:
            from webhook_handler import set_bot_application, _process_message_queue
            current_loop = asyncio.get_running_loop()
            set_bot_application(bot_app, current_loop)
            
            # CRITICAL FIX: Connect admin alert system to bot application  
            try:
                from admin_alerts import set_admin_alert_bot_application
                set_admin_alert_bot_application(bot_app, current_loop)
                logger.info("✅ Admin alert system connected to bot application")
                
                # ADDITIONAL FIX: Store bot application globally for other services
                import builtins
                setattr(builtins, '_global_bot_application', bot_app)
                # Also store in fastapi_server module for direct access
                global _bot_application_instance
                _bot_application_instance = bot_app
                logger.info("✅ Bot application stored globally for service access")
            except Exception as alert_error:
                logger.error(f"❌ Failed to connect admin alert system: {alert_error}")

            # CRITICAL FIX: Connect renewal processor to bot application
            try:
                from services.renewal_processor import set_renewal_bot_application
                set_renewal_bot_application(bot_app)
                logger.info("✅ Renewal processor connected to bot application")
            except Exception as renewal_error:
                logger.error(f"❌ Failed to connect renewal processor: {renewal_error}")

            # CRITICAL FIX: Connect application watchdog to bot application  
            try:
                from application_watchdog import ApplicationWatchdog
                watchdog = ApplicationWatchdog()
                watchdog.set_bot_application(bot_app, current_loop)
                logger.info("✅ Application watchdog connected to bot application")
            except Exception as watchdog_error:
                logger.error(f"❌ Failed to connect application watchdog: {watchdog_error}")

            # CRITICAL FIX: Connect domain linking orchestrator to bot application
            try:
                from services.domain_linking_orchestrator import DomainLinkingOrchestrator
                domain_orchestrator = DomainLinkingOrchestrator()
                if hasattr(domain_orchestrator, 'set_bot_application'):
                    getattr(domain_orchestrator, 'set_bot_application')(bot_app, current_loop)
                    logger.info("✅ Domain linking orchestrator connected to bot application")
            except Exception as domain_error:
                logger.error(f"❌ Failed to connect domain linking orchestrator: {domain_error}")
            
            # Start the message queue processor as a background task
            queue_task = asyncio.create_task(_process_message_queue())
            _service_status['message_queue'] = True
            
            logger.info("✅ FastAPI webhook gateway started with all handlers registered")
            logger.info("✅ Integrated with webhook_handler message pipeline")
            logger.info("✅ Message queue processor started")
            logger.info("🌐 Bot running in webhook-only mode - listening for Telegram updates")
            logger.info("📱 Telegram webhook endpoint: /webhook/telegram")
            
            # CRITICAL: Signal that bot is ready to receive webhooks
            global _bot_ready_event
            _bot_ready_event = asyncio.Event()
            _bot_ready_event.set()
            logger.info("✅ Bot ready event set - webhook endpoint now accepting requests")
        except Exception as pipeline_error:
            logger.error(f"❌ Failed to setup message pipeline: {pipeline_error}")
            logger.warning("⚠️ Message queue will not be available")
            _service_status['message_queue'] = False
    else:
        logger.warning("⚠️ Bot not available - skipping message pipeline setup")
        _service_status['message_queue'] = False
    
    # Log the active payment provider for verification
    logger.info(f"💰 Primary payment provider: {config.payment.primary_provider.upper()}")
    
    # ========================================================================
    # DEFERRED INITIALIZATION: Run heavy tasks in background after server starts
    # This allows the HTTP server to pass health checks quickly during deployment
    # ========================================================================
    async def background_initialization():
        """Run heavy initialization tasks in background after server is ready"""
        global _service_status
        
        logger.info("🚀 Background initialization started...")
        
        # 1. Pre-warm database connection and wake up Neon serverless
        try:
            from database import get_connection_pool, execute_query, start_health_probe, init_database, get_db_executor
            
            logger.info("🔥 Pre-warming database connection pool...")
            start_time = time.time()
            
            pool = get_connection_pool()
            logger.info(f"✅ Connection pool created with {pool.minconn}-{pool.maxconn} connections")
            
            executor = get_db_executor()
            logger.info(f"✅ Database thread pool executor pre-warmed ({executor._max_workers} workers)")
            
            logger.info("🗄️ Initializing database schema and seeding essential data...")
            await init_database()
            logger.info("✅ Database initialization and seeding completed successfully")
            
            from database import seed_openprovider_accounts
            await seed_openprovider_accounts()
            logger.info("✅ OpenProvider accounts seeded")
            
            result = await execute_query("SELECT 1 as health_check")
            warm_time = (time.time() - start_time) * 1000
            logger.info(f"✅ Database fully pre-warmed in {warm_time:.1f}ms")
            
            await start_health_probe()
            logger.info("✅ Database health probe started")
            _service_status['database'] = True
            
        except Exception as e:
            logger.warning(f"⚠️ Database pre-warming failed: {e}")
            _service_status['database'] = False
        
        # 2. Pre-authenticate with OpenProvider (with timeout)
        try:
            from services.openprovider import get_openprovider_service
            logger.info("🔐 Pre-authenticating with OpenProvider...")
            op_service = get_openprovider_service()
            auth_success = await run_with_timeout(
                op_service.authenticate(),
                timeout_seconds=10.0,
                task_name="OpenProvider pre-authentication",
                default=False
            )
            if auth_success:
                logger.info("✅ OpenProvider pre-authenticated successfully")
        except Exception as preauth_error:
            logger.warning(f"⚠️ OpenProvider pre-authentication error: {preauth_error}")
        
        # 3. Initialize OpenProvider Account Manager (with timeout)
        try:
            from services.openprovider_manager import initialize_account_manager
            logger.info("🏢 Initializing OpenProvider Account Manager...")
            manager_success = await run_with_timeout(
                initialize_account_manager(),
                timeout_seconds=15.0,
                task_name="OpenProvider Account Manager initialization",
                default=False
            )
            if manager_success:
                logger.info("✅ OpenProvider Account Manager initialized")
        except Exception as manager_error:
            logger.warning(f"⚠️ OpenProvider Account Manager error: {manager_error}")
        
        # 4. Pre-fetch Cloudflare nameservers (with timeout)
        try:
            from services.cloudflare import CloudflareService
            cf_service = CloudflareService()
            cf_nameservers = await run_with_timeout(
                cf_service.get_account_nameservers(),
                timeout_seconds=5.0,
                task_name="Cloudflare nameserver pre-fetch",
                default=None
            )
            if cf_nameservers:
                logger.info(f"✅ Cloudflare nameservers pre-fetched: {cf_nameservers}")
        except Exception as cf_error:
            logger.warning(f"⚠️ Cloudflare nameserver pre-fetch failed: {cf_error}")
        
        # 5. Pre-initialize language system
        try:
            from localization import LanguageConfig
            lang_config = LanguageConfig()
            logger.info("✅ Language system pre-initialized")
            _service_status['language_system'] = True
        except Exception as e:
            logger.warning(f"⚠️ Language system pre-warming failed: {e}")
            _service_status['language_system'] = False
        
        logger.info("🎯 Background initialization complete!")
    
    # Start background initialization task (runs after server is accepting requests)
    background_init_task = asyncio.create_task(background_initialization())
    logger.info("📋 Background initialization scheduled - server ready for requests")
    
    # Initialize and log email configuration
    from utils.email_config import log_email_configuration
    log_email_configuration()
    
    # Start payment cleanup service
    cleanup_service = None
    try:
        from payment_cleanup_service import start_payment_cleanup_service
        logger.info("🧹 PAYMENT CLEANUP: Starting automated payment cleanup service...")
        cleanup_service = await start_payment_cleanup_service(cleanup_interval_minutes=30)
        logger.info("✅ PAYMENT CLEANUP: Service started successfully")
        logger.info(f"   • Cleanup interval: 30 minutes")
        logger.info(f"   • Service will handle stale/expired payment intents automatically")
        _service_status['payment_cleanup'] = True
    except Exception as cleanup_error:
        logger.error(f"❌ PAYMENT CLEANUP: Failed to start service: {cleanup_error}")
        logger.error("   • Payment cleanup will not be automated")
        logger.error("   • Manual cleanup can still be performed via database functions")
        _service_status['payment_cleanup'] = False
    
    # Initialize APScheduler for scheduled background jobs
    scheduler = None
    try:
        logger.info("📅 Initializing APScheduler for background jobs...")
        scheduler = AsyncIOScheduler()
        
        # Schedule daily cPanel suspension sync at 2 AM
        scheduler.add_job(
            sync_subscription_cpanel_status,
            'cron',
            hour=2,
            minute=0,
            id='sync_cpanel_suspension',
            name='Daily cPanel Suspension Sync',
            replace_existing=True
        )
        logger.info("✅ Scheduled: Daily cPanel suspension sync at 2:00 AM")
        
        # Schedule hosting renewal processor (daily at 3 AM)
        try:
            from services.renewal_processor import HostingRenewalProcessor
            renewal_processor = HostingRenewalProcessor()
            renewal_processor.set_bot_application(bot_app)
            
            scheduler.add_job(
                renewal_processor.process_all_renewals,
                'cron',
                hour=3,
                minute=0,
                id='hosting_renewal_processor',
                name='Daily Hosting Renewal Processing',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Daily hosting renewal processing at 3:00 AM")
        except Exception as renewal_schedule_error:
            logger.warning(f"⚠️ Failed to schedule renewal processor: {renewal_schedule_error}")
        
        # Schedule RDP renewal processor (daily at 4 AM, after hosting renewals)
        try:
            from services.renewal_processor import rdp_renewal_processor
            rdp_renewal_processor.set_bot_application(bot_app)
            
            scheduler.add_job(
                rdp_renewal_processor.process_all_rdp_renewals,
                'cron',
                hour=4,
                minute=0,
                id='rdp_renewal_processor',
                name='Daily RDP Renewal Processing',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Daily RDP renewal processing at 4:00 AM")
        except Exception as rdp_renewal_schedule_error:
            logger.warning(f"⚠️ Failed to schedule RDP renewal processor: {rdp_renewal_schedule_error}")
        
        # Schedule daily account deletion check at 5:00 AM (after renewal processing)
        scheduler.add_job(
            process_suspended_account_deletions,
            'cron',
            hour=5,
            minute=0,
            id='delete_suspended_accounts',
            name='Daily Suspended Account Deletion',
            replace_existing=True
        )
        logger.info("✅ Scheduled: Daily suspended account deletion at 5:00 AM")
        
        # NOTE: RDP servers are deleted IMMEDIATELY upon grace period expiration
        # No separate deletion job needed - handled by renewal processor
        
        # Schedule RDP status polling (every 3 minutes)
        try:
            from services.rdp_status_poller import run_rdp_status_polling
            
            scheduler.add_job(
                run_rdp_status_polling,
                'interval',
                minutes=10,
                id='rdp_status_polling',
                name='RDP Server Status Polling',
                replace_existing=True
            )
            logger.info("✅ Scheduled: RDP server status polling every 10 minutes")
        except Exception as rdp_polling_error:
            logger.warning(f"⚠️ Failed to schedule RDP status polling: {rdp_polling_error}")
        
        # Schedule exchange rate pre-warming (every 3 minutes)
        # This ensures webhook processing always has fresh cached rates and never blocks on API calls
        try:
            from services.fastforex import fastforex_service
            
            scheduler.add_job(
                fastforex_service.prewarm_rates,
                'interval',
                minutes=15,
                id='exchange_rate_prewarm',
                name='Exchange Rate Pre-warming',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Exchange rate pre-warming every 15 minutes (6 currencies)")
        except Exception as prewarm_error:
            logger.warning(f"⚠️ Failed to schedule exchange rate pre-warming: {prewarm_error}")
        
        # Schedule DNS reconciliation (daily at 1 AM - reduced from every 6 hours)
        # Keeps database in sync with Cloudflare by detecting externally deleted records
        try:
            from services.dns_reconciliation import run_dns_reconciliation
            
            scheduler.add_job(
                run_dns_reconciliation,
                'cron',
                hour=1,
                id='dns_reconciliation',
                name='DNS Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: DNS reconciliation daily at 1 AM")
        except Exception as dns_recon_error:
            logger.warning(f"⚠️ Failed to schedule DNS reconciliation: {dns_recon_error}")
        
        # Schedule Cloudflare zone reconciliation (daily at 1:30 AM - reduced from every 12 hours)
        # Detects zones deleted externally and cleans up orphaned zone IDs
        try:
            from services.zone_reconciliation import run_zone_reconciliation
            
            scheduler.add_job(
                run_zone_reconciliation,
                'cron',
                hour=1,
                minute=30,
                id='zone_reconciliation',
                name='Zone Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Zone reconciliation daily at 1:30 AM")
        except Exception as zone_recon_error:
            logger.warning(f"⚠️ Failed to schedule zone reconciliation: {zone_recon_error}")
        
        # Schedule domain registration reconciliation (daily at 6 AM)
        # Syncs domain status and expiry with OpenProvider
        try:
            from services.domain_reconciliation import run_domain_reconciliation
            
            scheduler.add_job(
                run_domain_reconciliation,
                'cron',
                hour=6,
                id='domain_reconciliation',
                name='Domain Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Domain reconciliation daily at 6 AM")
        except Exception as domain_recon_error:
            logger.warning(f"⚠️ Failed to schedule domain reconciliation: {domain_recon_error}")
        
        # Schedule cPanel account reconciliation (every 12 hours - reduced from every 4 hours)
        # Syncs hosting account status with WHM server
        try:
            from services.cpanel_reconciliation import run_cpanel_reconciliation
            
            scheduler.add_job(
                run_cpanel_reconciliation,
                'cron',
                hour='*/12',
                id='cpanel_reconciliation',
                name='cPanel Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: cPanel reconciliation every 12 hours")
        except Exception as cpanel_recon_error:
            logger.warning(f"⚠️ Failed to schedule cPanel reconciliation: {cpanel_recon_error}")
        
        # Schedule RDP server reconciliation (every 6 hours - reduced from every 2 hours)
        # Syncs server status with Vultr API
        try:
            from services.rdp_reconciliation import run_rdp_reconciliation
            
            scheduler.add_job(
                run_rdp_reconciliation,
                'cron',
                hour='*/6',
                id='rdp_reconciliation',
                name='RDP Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: RDP reconciliation every 6 hours")
        except Exception as rdp_recon_error:
            logger.warning(f"⚠️ Failed to schedule RDP reconciliation: {rdp_recon_error}")
        
        # Schedule payment reconciliation (every 4 hours - reduced from every hour)
        # Recovers payments that may have been confirmed but webhook failed
        try:
            from services.payment_reconciliation import run_payment_reconciliation
            
            scheduler.add_job(
                run_payment_reconciliation,
                'interval',
                hours=4,
                id='payment_reconciliation',
                name='Payment Reconciliation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Payment reconciliation every 4 hours")
        except Exception as payment_recon_error:
            logger.warning(f"⚠️ Failed to schedule payment reconciliation: {payment_recon_error}")
        
        # Schedule credential validation (daily at 7 AM)
        # Validates all external service credentials
        try:
            from services.credential_reconciliation import run_credential_validation
            
            scheduler.add_job(
                run_credential_validation,
                'cron',
                hour=7,
                id='credential_validation',
                name='Credential Validation',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Credential validation daily at 7 AM")
        except Exception as cred_recon_error:
            logger.warning(f"⚠️ Failed to schedule credential validation: {cred_recon_error}")
        
        # Schedule addon domain job processor (every 30 minutes - reduced from every 10 minutes)
        # Automatically retries adding external addon domains to cPanel after DNS propagation
        try:
            from services.addon_domain_job_service import run_addon_domain_job_processor
            
            scheduler.add_job(
                run_addon_domain_job_processor,
                'interval',
                minutes=30,
                id='addon_domain_job_processor',
                name='Addon Domain Job Processor',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Addon domain job processor every 30 minutes")
        except Exception as addon_job_error:
            logger.warning(f"⚠️ Failed to schedule addon domain job processor: {addon_job_error}")
        
        # EVENT-DRIVEN: Domain registration and hosting order processors
        # Replaced APScheduler polling (every 30s) with event-driven background tasks.
        # Processors now sleep until signaled by webhook_handler, with a 5-minute fallback.
        # This eliminates ~2,880 idle DB polls/day.
        # (Background tasks are started below, outside the scheduler block)
        
        # Schedule promotional broadcasts (hourly check for timezone-aware delivery)
        # Runs every hour, sends promos to users whose local time matches 10AM/3PM/8PM
        try:
            from promotional_broadcasts import run_hourly_promo_check
            
            scheduler.add_job(
                run_hourly_promo_check,
                'cron',
                minute=0,
                id='promo_hourly_timezone_check',
                name='Hourly Promo: Timezone-Aware Dispatch',
                replace_existing=True
            )
            logger.info("✅ Scheduled: Promotional broadcasts (hourly timezone-aware check)")
        except Exception as promo_error:
            logger.warning(f"⚠️ Failed to schedule promotional broadcasts: {promo_error}")
        
        # Start the scheduler
        scheduler.start()
        logger.info("✅ APScheduler started successfully - all background jobs scheduled")
        _service_status['scheduler'] = True
        
    except Exception as scheduler_error:
        logger.error(f"❌ Failed to initialize APScheduler: {scheduler_error}")
        logger.error("   • Scheduled background jobs will not run automatically")
        _service_status['scheduler'] = False
    
    # ========================================================================
    # STARTUP COMPLETE - Log comprehensive service status
    # ========================================================================
    logger.info("=" * 80)
    logger.info("✅ STARTUP COMPLETE - HTTP SERVER READY TO ACCEPT REQUESTS")
    logger.info("=" * 80)
    logger.info("📊 SERVICE STATUS SUMMARY:")
    logger.info(f"   🤖 Telegram Bot:       {'✅ Running' if _service_status['bot'] else '❌ Failed'}")
    logger.info(f"   🌐 Webhook/Polling:    {'✅ Active' if _service_status['webhook'] else '❌ Inactive'}")
    logger.info(f"   🗄️  Database:           {'✅ Connected' if _service_status['database'] else '❌ Failed'}")
    logger.info(f"   📅 Scheduler:          {'✅ Running' if _service_status['scheduler'] else '❌ Failed'}")
    logger.info(f"   🧹 Payment Cleanup:    {'✅ Running' if _service_status['payment_cleanup'] else '❌ Failed'}")
    logger.info(f"   🌍 Language System:    {'✅ Loaded' if _service_status['language_system'] else '❌ Failed'}")
    logger.info(f"   📬 Message Queue:      {'✅ Running' if _service_status['message_queue'] else '❌ Failed'}")
    logger.info("=" * 80)
    
    # Count successful services
    successful_services = sum(1 for status in _service_status.values() if status)
    total_services = len(_service_status)
    
    if successful_services == total_services:
        logger.info(f"🎉 ALL SERVICES STARTED SUCCESSFULLY ({successful_services}/{total_services})")
    elif successful_services > 0:
        logger.warning(f"⚠️ PARTIAL STARTUP: {successful_services}/{total_services} services running")
        logger.warning(f"   Failed services may impact functionality but HTTP server is operational")
    else:
        logger.error(f"❌ DEGRADED MODE: 0/{total_services} services started")
        logger.error(f"   HTTP server is running but bot and services are unavailable")
    
    logger.info("=" * 80)
    logger.info("🌐 HTTP ENDPOINTS AVAILABLE:")
    logger.info("   • GET  /          - Service info")
    logger.info("   • GET  /health    - Health check (always responds)")
    logger.info("   • POST /webhook/telegram - Telegram webhook")
    logger.info("   • POST /webhook/dynopay  - DynoPay webhook")
    logger.info("   • POST /webhook/blockbee - BlockBee webhook")
    logger.info("=" * 80)
    
    # EVENT-DRIVEN JOB PROCESSORS: Start as background tasks (not APScheduler)
    # These wake instantly on webhook signal, with 5-min fallback safety poll
    domain_processor_task = None
    hosting_processor_task = None
    try:
        from services.job_queue_signals import (
            run_event_driven_domain_processor,
            run_event_driven_hosting_processor
        )
        domain_processor_task = asyncio.create_task(run_event_driven_domain_processor())
        hosting_processor_task = asyncio.create_task(run_event_driven_hosting_processor())
        logger.info("✅ Event-driven job processors started (domain + hosting)")
    except Exception as evt_error:
        logger.error(f"❌ Failed to start event-driven job processors: {evt_error}")
    
    yield
    
    # Cleanup
    try:
        # Stop APScheduler if it exists
        if 'scheduler' in locals() and scheduler:
            try:
                logger.info("📅 Stopping APScheduler...")
                scheduler.shutdown(wait=False)
                logger.info("✅ APScheduler stopped successfully")
            except Exception as scheduler_stop_error:
                logger.error(f"❌ Error stopping APScheduler: {scheduler_stop_error}")
        
        # Stop payment cleanup service if it exists
        if 'cleanup_service' in locals() and cleanup_service:
            try:
                from payment_cleanup_service import stop_payment_cleanup_service
                logger.info("🧹 PAYMENT CLEANUP: Stopping cleanup service...")
                stop_payment_cleanup_service()
                logger.info("✅ PAYMENT CLEANUP: Service stopped successfully")
            except Exception as cleanup_stop_error:
                logger.error(f"❌ PAYMENT CLEANUP: Error stopping service: {cleanup_stop_error}")
        
        # Stop message queue processor if it exists
        if 'queue_task' in locals() and queue_task:
            queue_task.cancel()
            try:
                await queue_task
            except asyncio.CancelledError:
                pass
        
        # Stop polling task if it exists (development mode)
        if 'polling_task' in locals() and polling_task:
            try:
                logger.info("🔄 Stopping polling task...")
                if bot_app and hasattr(bot_app, 'updater') and bot_app.updater:
                    await bot_app.updater.stop()
                    logger.info("✅ Polling stopped successfully")
                polling_task.cancel()
                try:
                    await polling_task
                except asyncio.CancelledError:
                    pass
            except Exception as polling_stop_error:
                logger.error(f"❌ Error stopping polling: {polling_stop_error}")
        
        # Stop and shutdown bot application
        if bot_app:
            await bot_app.stop()
            await bot_app.shutdown()
    except Exception as e:
        logger.error(f"❌ Cleanup error: {e}")
        
    logger.info("🛑 FastAPI webhook gateway stopped")

# Enhanced API Documentation Metadata
API_DESCRIPTION = """
# HostBay API - Complete Domain & Hosting Management Platform

Welcome to HostBay's comprehensive REST API for domain registration, DNS management, and web hosting automation.

## 🚀 Quick Start

1. **Get API Key**: Create an API key through the HostBay Telegram bot
2. **Authenticate**: Include your API key in the `Authorization: Bearer YOUR_API_KEY` header
3. **Make Requests**: Start managing domains, DNS, and hosting programmatically

## 📚 API Features

- **Domains**: Register, transfer, manage domain lifecycle with WHOIS privacy protection
- **Privacy Protection**: Enable/disable WHOIS privacy with Iceland-based Privacy Guard contact
- **DNS**: Create, update, delete DNS records with Cloudflare
- **Nameservers**: Manage nameserver configurations
- **Hosting**: Provision and manage cPanel hosting accounts
- **Bundles**: Combined domain + hosting packages
- **Wallet**: Manage balance and view transactions
- **Monitoring**: Real-time status checks and health monitoring
- **Domain Linking**: Connect external domains to hosting
- **API Keys**: Manage API credentials and permissions

## 🔒 Authentication

All API endpoints require Bearer token authentication:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" https://api.hostbay.io/api/v1/domains
```
"""

# Category metadata for organized documentation
tags_metadata = [
    {
        "name": "Domains",
        "description": "Domain registration, transfer, renewal, and lifecycle management. Includes WHOIS privacy protection with Privacy Guard contact. Support for 200+ TLDs.",
        "externalDocs": {
            "description": "Domain Management Guide",
            "url": "https://developers.hostbay.io/domains",
        },
    },
    {
        "name": "DNS",
        "description": "Complete DNS record management powered by Cloudflare. Create, update, delete A, AAAA, CNAME, MX, TXT records and more.",
        "externalDocs": {
            "description": "DNS Management Guide",
            "url": "https://developers.hostbay.io/dns",
        },
    },
    {
        "name": "Nameservers",
        "description": "Manage domain nameserver configurations. Switch between Cloudflare, hosting nameservers, or custom nameservers.",
    },
    {
        "name": "Hosting",
        "description": "Provision and manage cPanel web hosting accounts. Create, delete, suspend, unsuspend hosting plans. View server location (Russia/Moscow datacenter), credentials, usage statistics, expiry dates, and manage email/database accounts.",
        "externalDocs": {
            "description": "Hosting Guide",
            "url": "https://developers.hostbay.io/hosting",
        },
    },
    {
        "name": "Bundles",
        "description": "Combined domain + hosting packages for streamlined provisioning. Single API call to register domain and create hosting.",
    },
    {
        "name": "Wallet",
        "description": "Wallet balance management and transaction history. Top up using various payment methods.",
    },
    {
        "name": "Monitoring",
        "description": "Real-time monitoring of domain status, DNS propagation, SSL certificates, hosting uptime, and system health.",
    },
    {
        "name": "Domain Linking",
        "description": "Connect external domains to HostBay hosting. Automated or manual DNS configuration workflows.",
    },
    {
        "name": "API Keys",
        "description": "Manage API credentials with fine-grained permissions and rate limits for enhanced security.",
    },
]

def get_api_servers():
    """
    Configure API server URLs for documentation.
    
    Returns list of server configurations for FastAPI/OpenAPI docs.
    Uses relative URL for current server to hide internal development URLs.
    """
    servers = [
        {
            "url": "/",
            "description": "Current Server"
        },
        {
            "url": "https://developers.hostbay.io",
            "description": "Production Server"
        }
    ]
    
    return servers

# Create FastAPI app with enhanced documentation
app = FastAPI(
    title="HostBay API",
    description=API_DESCRIPTION,
    version="1.0.0",
    terms_of_service="https://hostbay.io/terms",
    contact={
        "name": "HostBay Support",
        "url": "https://hostbay.io/support",
        "email": "support@hostbay.io",
    },
    license_info={
        "name": "Proprietary",
        "url": "https://hostbay.io/terms",
    },
    servers=get_api_servers(),
    openapi_tags=tags_metadata,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
    swagger_ui_parameters={
        "persistAuthorization": True,
        "displayRequestDuration": True,
        "filter": True,
        "tryItOutEnabled": True
    }
)

# Add CORS middleware to allow Swagger UI to make requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define security scheme for Bearer token authentication
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    """
    Generate OpenAPI schema with dynamic server URLs.
    
    Reads environment variables on each call to ensure server URLs are always current.
    This allows the development URL to update automatically if the Replit domain changes.
    """
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        servers=get_api_servers(),
    )
    
    # Ensure components key exists before adding securitySchemes
    if "components" not in openapi_schema:
        openapi_schema["components"] = {}
    
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "API_KEY",
            "description": "Enter your HostBay API key. Get your key from the Telegram bot: Main Menu → API Management → Create API Key"
        }
    }
    # Apply security globally to all endpoints
    openapi_schema["security"] = [{"BearerAuth": []}]
    return openapi_schema

app.openapi = custom_openapi

# Mount static files for logos, icons, etc.
app.mount("/static", StaticFiles(directory="static"), name="static")

# Favicon redirect for browsers that request /favicon.ico
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """Redirect favicon.ico requests to our SVG favicon"""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/static/favicon.svg")

# Health check endpoint - ALWAYS RETURNS 200
@app.get("/health", include_in_schema=False)
@app.get("/api/health", include_in_schema=False)
async def health_check():
    """
    Health check for monitoring - ALWAYS returns 200 OK
    Even if services are degraded, HTTP server is operational
    """
    global _service_status
    
    # HTTP server is always healthy if this endpoint responds
    successful_services = sum(1 for status in _service_status.values() if status)
    total_services = len(_service_status)
    
    # Determine overall health status
    if successful_services == total_services:
        overall_status = "healthy"
    elif successful_services > total_services // 2:
        overall_status = "degraded"
    else:
        overall_status = "critical"
    
    return {
        "status": overall_status,
        "http_server": "operational",
        "timestamp": int(time.time()),
        "bot_ready": bot_app is not None and _service_status.get('bot', False),
        "services": {
            "telegram_bot": "running" if _service_status.get('bot', False) else "failed",
            "webhook": "active" if _service_status.get('webhook', False) else "inactive",
            "database": "connected" if _service_status.get('database', False) else "failed",
            "scheduler": "running" if _service_status.get('scheduler', False) else "failed",
            "payment_cleanup": "running" if _service_status.get('payment_cleanup', False) else "failed",
            "language_system": "loaded" if _service_status.get('language_system', False) else "failed",
            "message_queue": "running" if _service_status.get('message_queue', False) else "failed"
        },
        "summary": {
            "successful": successful_services,
            "total": total_services,
            "percentage": round((successful_services / total_services * 100) if total_services > 0 else 0, 1)
        }
    }

# Custom branded Swagger UI for developers.hostbay.io
@app.get("/api-docs", response_class=HTMLResponse, include_in_schema=False)
async def custom_swagger_ui():
    """Custom branded Swagger UI for HostBay API"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HostBay API Documentation</title>
    <meta name="description" content="Complete API documentation for HostBay domain, DNS, and hosting management platform">
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <style>
        /* HostBay Custom Branding */
        :root {
            --hostbay-primary: #2563eb;
            --hostbay-secondary: #1e40af;
            --hostbay-success: #10b981;
            --hostbay-background: #f8fafc;
        }
        
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: var(--hostbay-background);
        }
        
        /* Custom Header */
        .topbar {
            background: linear-gradient(135deg, var(--hostbay-primary) 0%, var(--hostbay-secondary) 100%);
            padding: 20px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .topbar-wrapper {
            max-width: 1460px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .topbar-wrapper .link {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 24px;
            font-weight: 700;
            color: white;
            text-decoration: none;
        }
        
        .topbar-wrapper .link img {
            height: 40px;
            width: auto;
            object-fit: contain;
        }
        
        /* Swagger UI Customization */
        .swagger-ui .topbar { display: none; }
        
        .swagger-ui .info {
            margin: 50px 0;
        }
        
        .swagger-ui .info .title {
            font-size: 36px;
            color: var(--hostbay-primary);
        }
        
        .swagger-ui .scheme-container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .swagger-ui .opblock.opblock-get .opblock-summary-method {
            background: var(--hostbay-success);
        }
        
        .swagger-ui .opblock.opblock-post .opblock-summary-method {
            background: var(--hostbay-primary);
        }
        
        .swagger-ui .opblock.opblock-put .opblock-summary-method {
            background: #f59e0b;
        }
        
        .swagger-ui .opblock.opblock-delete .opblock-summary-method {
            background: #ef4444;
        }
        
        .swagger-ui .opblock-tag {
            border-bottom: 2px solid var(--hostbay-primary);
        }
        
        .swagger-ui .btn.authorize {
            background: var(--hostbay-primary);
            border-color: var(--hostbay-primary);
        }
        
        .swagger-ui .btn.authorize:hover {
            background: var(--hostbay-secondary);
            border-color: var(--hostbay-secondary);
        }
        
        /* Custom Footer */
        .custom-footer {
            background: white;
            border-top: 1px solid #e5e7eb;
            padding: 30px 0;
            margin-top: 50px;
            text-align: center;
            color: #6b7280;
        }
        
        .custom-footer a {
            color: var(--hostbay-primary);
            text-decoration: none;
        }
        
        .custom-footer a:hover {
            text-decoration: underline;
        }
        
        /* API Key Help Banner */
        .api-key-banner {
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            color: white;
            padding: 20px;
            margin: 20px auto;
            max-width: 1460px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .api-key-banner h3 {
            margin: 0 0 10px 0;
            font-size: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .api-key-banner p {
            margin: 8px 0;
            font-size: 15px;
            line-height: 1.6;
        }
        
        .api-key-banner strong {
            background: rgba(255,255,255,0.2);
            padding: 2px 8px;
            border-radius: 4px;
        }
        
        .api-key-steps {
            margin: 12px 0 0 0;
            padding-left: 20px;
        }
        
        .api-key-steps li {
            margin: 6px 0;
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-wrapper">
            <a href="/" class="link">
                <img src="/static/hostbay-logo.jpg" alt="HostBay Logo">
                <span>HostBay API Documentation</span>
            </a>
        </div>
    </div>
    
    <div class="api-key-banner">
        <h3>🔑 How to Test API Endpoints</h3>
        <p>To test endpoints interactively, you need to authenticate with your API key:</p>
        <ol class="api-key-steps">
            <li>Click the <strong>Authorize 🔓</strong> button at the top right</li>
            <li>Enter your API key in the "Value" field</li>
            <li>Click <strong>Authorize</strong> then <strong>Close</strong></li>
            <li>Now you can test any endpoint with the "Try it out" button!</li>
        </ol>
        <p style="margin-top: 12px;">💡 Don't have an API key? Get one from the HostBay Telegram bot: <strong>Main Menu → API Management → Create API Key</strong></p>
    </div>
    
    <div id="swagger-ui"></div>
    
    <div class="custom-footer">
        <p>
            <strong>HostBay API Documentation</strong> | 
            <a href="https://hostbay.io" target="_blank">Website</a> | 
            <a href="https://hostbay.io/support" target="_blank">Support</a> | 
            <a href="/redoc" target="_blank">ReDoc View</a>
        </p>
        <p style="margin-top: 10px; font-size: 14px;">
            © 2025 HostBay. All rights reserved.
        </p>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "BaseLayout",
                defaultModelsExpandDepth: 1,
                defaultModelExpandDepth: 3,
                displayRequestDuration: true,
                filter: true,
                tryItOutEnabled: true,
                syntaxHighlight: {
                    activate: true,
                    theme: "monokai"
                },
                persistAuthorization: true,
                displayOperationId: false,
                docExpansion: 'list'
            });
            
            window.ui = ui;
        };
    </script>
</body>
</html>
    """)

# Comprehensive Developer Portal Landing Page
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def developer_portal_home():
    """HostBay Developer Portal - Landing Page with Guides and Examples"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HostBay Developer Portal</title>
    <meta name="description" content="Complete developer documentation for HostBay API - Domain, DNS, and Hosting Management">
    <link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --primary: #2563eb;
            --secondary: #1e40af;
            --success: #10b981;
            --dark: #1e293b;
            --light: #f8fafc;
            --gray: #64748b;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: var(--dark);
            background: var(--light);
        }
        
        /* Navigation */
        nav {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 1rem 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .logo img {
            height: 40px;
            width: auto;
            object-fit: contain;
        }
        
        .logo-text {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }
        
        .nav-links a {
            color: white;
            text-decoration: none;
            font-weight: 500;
            transition: opacity 0.2s;
        }
        
        .nav-links a:hover {
            opacity: 0.8;
        }
        
        /* Hero Section */
        .hero {
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 4rem 2rem;
            text-align: center;
        }
        
        .hero h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        
        .hero p {
            font-size: 1.25rem;
            opacity: 0.9;
            max-width: 600px;
            margin: 0 auto 2rem;
        }
        
        .cta-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.75rem 2rem;
            border-radius: 0.5rem;
            text-decoration: none;
            font-weight: 600;
            transition: transform 0.2s, box-shadow 0.2s;
            display: inline-block;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        
        .btn-primary {
            background: white;
            color: var(--primary);
        }
        
        .btn-secondary {
            background: transparent;
            color: white;
            border: 2px solid white;
        }
        
        /* Container */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 3rem 2rem;
        }
        
        /* Feature Grid */
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
            margin-bottom: 4rem;
        }
        
        .feature-card {
            background: white;
            padding: 2rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .feature-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
        }
        
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        
        .feature-card h3 {
            color: var(--primary);
            margin-bottom: 0.5rem;
        }
        
        /* Code Examples */
        .code-section {
            background: white;
            padding: 2rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 3rem;
        }
        
        .code-tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            border-bottom: 2px solid var(--light);
        }
        
        .code-tab {
            padding: 0.75rem 1.5rem;
            background: transparent;
            border: none;
            cursor: pointer;
            font-weight: 600;
            color: var(--gray);
            transition: color 0.2s, border-color 0.2s;
            border-bottom: 3px solid transparent;
        }
        
        .code-tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        
        .code-content {
            display: none;
        }
        
        .code-content.active {
            display: block;
        }
        
        pre {
            background: #1e293b;
            color: #f8fafc;
            padding: 1.5rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            font-size: 0.875rem;
            line-height: 1.6;
            position: relative;
        }
        
        pre:hover .copy-btn {
            opacity: 1;
        }
        
        .copy-btn {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: var(--primary);
            color: white;
            border: none;
            padding: 0.4rem 0.8rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.75rem;
            opacity: 0;
            transition: opacity 0.2s, background 0.2s;
        }
        
        .copy-btn:hover {
            background: var(--secondary);
        }
        
        .copy-btn.copied {
            background: var(--success);
            opacity: 1;
        }
        
        code {
            font-family: 'Courier New', monospace;
        }
        
        .code-wrapper {
            position: relative;
        }
        
        /* Guides Section */
        .guides-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        
        .guide-card {
            background: white;
            padding: 1.5rem;
            border-radius: 0.75rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            border-left: 4px solid var(--primary);
        }
        
        .guide-card h3 {
            color: var(--primary);
            margin-bottom: 0.75rem;
        }
        
        .guide-card ul {
            list-style: none;
            padding-left: 0;
        }
        
        .guide-card li {
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--light);
        }
        
        .guide-card li:last-child {
            border-bottom: none;
        }
        
        .guide-card a {
            color: var(--dark);
            text-decoration: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .guide-card a:hover {
            color: var(--primary);
        }
        
        .guide-card a::after {
            content: "→";
            opacity: 0.5;
        }
        
        /* Footer */
        footer {
            background: var(--dark);
            color: white;
            padding: 3rem 2rem;
            margin-top: 4rem;
        }
        
        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 2rem;
        }
        
        .footer-section h4 {
            margin-bottom: 1rem;
        }
        
        .footer-section ul {
            list-style: none;
        }
        
        .footer-section a {
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            display: block;
            padding: 0.25rem 0;
        }
        
        .footer-section a:hover {
            color: white;
        }
        
        .footer-bottom {
            text-align: center;
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.5);
        }
        
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 2rem;
            }
            
            .nav-links {
                gap: 1rem;
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav>
        <div class="nav-container">
            <div class="logo">
                <img src="/static/hostbay-logo.jpg" alt="HostBay Logo">
                <span class="logo-text">Developer API</span>
            </div>
            <ul class="nav-links">
                <li><a href="#getting-started">Getting Started</a></li>
                <li><a href="#guides">Guides</a></li>
                <li><a href="/api-docs">API Reference</a></li>
                <li><a href="/redoc">ReDoc</a></li>
            </ul>
        </div>
    </nav>
    
    <!-- Hero -->
    <section class="hero">
        <h1>HostBay Developer Portal</h1>
        <p>Complete API for domain registration, DNS management, and web hosting automation</p>
        <div class="cta-buttons">
            <a href="#getting-started" class="btn btn-primary">Get Started</a>
            <a href="/api-docs" class="btn btn-secondary">API Reference</a>
        </div>
    </section>
    
    <!-- Features -->
    <div class="container">
        <h2 style="text-align: center; margin-bottom: 3rem; color: var(--primary);">Platform Features</h2>
        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">🌐</div>
                <h3>Domain Management</h3>
                <p>Register, transfer, and manage 200+ TLDs with HostBay</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔧</div>
                <h3>DNS Automation</h3>
                <p>Full Cloudflare DNS control with A, AAAA, CNAME, MX, TXT records</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🖥️</div>
                <h3>cPanel Hosting</h3>
                <p>Provision and manage hosting with email, databases, and SSL</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔐</div>
                <h3>Secure Auth</h3>
                <p>API keys with granular permissions and rate limiting</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">📊</div>
                <h3>Real-time Monitoring</h3>
                <p>Track domain status, DNS propagation, and SSL certificates</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">💳</div>
                <h3>Wallet Management</h3>
                <p>Easy balance management with flexible payment options</p>
            </div>
        </div>
        
        <!-- Getting Started -->
        <div id="getting-started" class="code-section">
            <h2 style="margin-bottom: 1.5rem; color: var(--primary);">Quick Start</h2>
            <p style="margin-bottom: 2rem; color: var(--gray);">Get started with HostBay API in minutes with code examples in multiple languages</p>
            
            <div class="code-tabs">
                <button class="code-tab active" onclick="showCode('curl')">cURL</button>
                <button class="code-tab" onclick="showCode('python')">Python</button>
                <button class="code-tab" onclick="showCode('javascript')">JavaScript</button>
                <button class="code-tab" onclick="showCode('php')">PHP</button>
            </div>
            
            <div id="curl" class="code-content active">
                <h3 style="margin-bottom: 1rem;">Step 1: Get Your API Key</h3>
                <p style="margin-bottom: 1rem;">Create an API key through the HostBay Telegram bot</p>
                
                <h3 style="margin: 2rem 0 1rem;">Step 2: Make Your First Request</h3>
                <pre><code># List your domains
curl -X GET "https://api.hostbay.io/api/v1/domains" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Register a new domain (using HostBay contacts - easiest method)
curl -X POST "https://api.hostbay.io/api/v1/domains/register" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain_name": "example.com",
    "period": 1,
    "use_hostbay_contacts": true
  }'</code></pre>
            </div>
            
            <div id="python" class="code-content">
                <h3 style="margin-bottom: 1rem;">Install SDK</h3>
                <pre><code>pip install requests</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Example Code</h3>
                <pre><code>import requests

# Configuration
API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# List domains
response = requests.get(f"{BASE_URL}/domains", headers=headers)
domains = response.json()
print(f"Your domains: {domains}")

# Register a domain (using HostBay contacts - easiest method)
domain_data = {
    "domain_name": "example.com",
    "period": 1,
    "use_hostbay_contacts": True
}

response = requests.post(
    f"{BASE_URL}/domains/register",
    headers=headers,
    json=domain_data
)
result = response.json()
print(f"Registration result: {result}")</code></pre>
            </div>
            
            <div id="javascript" class="code-content">
                <h3 style="margin-bottom: 1rem;">Install SDK</h3>
                <pre><code>npm install axios</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Example Code</h3>
                <pre><code>const axios = require('axios');

// Configuration
const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// List domains
async function listDomains() {
    const response = await axios.get(`${BASE_URL}/domains`, { headers });
    console.log('Your domains:', response.data);
}

// Register a domain (using HostBay contacts - easiest method)
async function registerDomain() {
    const domainData = {
        domain_name: 'example.com',
        period: 1,
        use_hostbay_contacts: true
    };
    
    const response = await axios.post(
        `${BASE_URL}/domains/register`,
        domainData,
        { headers }
    );
    console.log('Registration result:', response.data);
}

// Run examples
listDomains();
registerDomain();</code></pre>
            </div>
            
            <div id="php" class="code-content">
                <h3 style="margin-bottom: 1rem;">Example Code</h3>
                <pre><code><?php
// Configuration
$API_KEY = 'YOUR_API_KEY';
$BASE_URL = 'https://api.hostbay.io/api/v1';

$headers = [
    'Authorization: Bearer ' . $API_KEY,
    'Content-Type: application/json'
];

// List domains
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $BASE_URL . '/domains');
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
$domains = json_decode($response, true);
curl_close($ch);

echo "Your domains: ";
print_r($domains);

// Register a domain (using HostBay contacts - easiest method)
$domainData = [
    'domain_name' => 'example.com',
    'period' => 1,
    'use_hostbay_contacts' => true
];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $BASE_URL . '/domains/register');
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($domainData));
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
$result = json_decode($response, true);
curl_close($ch);

echo "Registration result: ";
print_r($result);
?></code></pre>
            </div>
        </div>
        
        <!-- Guides -->
        <div id="guides">
            <h2 style="text-align: center; margin-bottom: 3rem; color: var(--primary);">Comprehensive Guides & Tutorials</h2>
            
            <!-- Authentication Guide -->
            <div class="code-section" id="auth-basics">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🔐 Authentication Guide</h2>
                
                <h3 style="margin: 2rem 0 1rem;">Step 1: Create an API Key</h3>
                <p style="margin-bottom: 1rem;">You can create API keys through the HostBay Telegram bot:</p>
                <ol style="margin-left: 2rem; margin-bottom: 2rem;">
                    <li>Open the HostBay bot on Telegram</li>
                    <li>Navigate to <strong>Main Menu → API Management</strong></li>
                    <li>Click <strong>"Create New API Key"</strong></li>
                    <li>Set permissions (Domains, DNS, Hosting, Wallet)</li>
                    <li>Copy your API key (shown only once!)</li>
                </ol>
                
                <h3 style="margin: 2rem 0 1rem;">Step 2: Authenticate Your Requests</h3>
                <p style="margin-bottom: 1rem;">Include your API key in the <code>Authorization</code> header:</p>
                <pre><code>Authorization: Bearer YOUR_API_KEY</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Security Best Practices</h3>
                <ul style="margin-left: 2rem; margin-bottom: 2rem; line-height: 2;">
                    <li>✅ <strong>Never commit API keys to version control</strong></li>
                    <li>✅ <strong>Use environment variables</strong> for storing keys</li>
                    <li>✅ <strong>Create separate keys</strong> for different applications</li>
                    <li>✅ <strong>Rotate keys regularly</strong> (every 90 days recommended)</li>
                    <li>✅ <strong>Use minimal permissions</strong> (principle of least privilege)</li>
                    <li>✅ <strong>Monitor API usage</strong> in the Telegram bot dashboard</li>
                </ul>
                
                <h3 style="margin: 2rem 0 1rem;">Permissions Explained</h3>
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p><strong>Domains:</strong> Register, transfer, renew, and manage domain names</p>
                    <p><strong>DNS:</strong> Create, update, delete DNS records (A, AAAA, CNAME, MX, TXT)</p>
                    <p><strong>Hosting:</strong> Provision hosting, manage cPanel accounts, SSL certificates</p>
                    <p><strong>Wallet:</strong> View balance, make payments, transaction history</p>
                    <p><strong>API Keys:</strong> Manage other API keys (admin permission)</p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Rate Limiting</h3>
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>⚡ Default Limits</strong></p>
                    <ul style="margin-left: 1.5rem; line-height: 2;">
                        <li><strong>Hourly Limit:</strong> 1,000 requests per hour</li>
                        <li><strong>Daily Limit:</strong> 10,000 requests per day</li>
                        <li><strong>Burst Protection:</strong> Max 100 requests in 60 seconds</li>
                    </ul>
                    <p style="margin-top: 1rem;"><strong>Rate Limit Headers:</strong></p>
                    <ul style="margin-left: 1.5rem; line-height: 2;">
                        <li><code>X-RateLimit-Limit</code> - Maximum requests allowed</li>
                        <li><code>X-RateLimit-Remaining</code> - Requests remaining in current window</li>
                        <li><code>X-RateLimit-Reset</code> - Unix timestamp when limit resets</li>
                    </ul>
                    <p style="margin-top: 1rem; font-size: 0.9rem; opacity: 0.8;">💡 If you exceed rate limits, you'll receive HTTP 429 (Too Many Requests). Custom limits available for enterprise customers.</p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">💰 Wallet Balance & Financial Safety</h3>
                <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 1.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>⚠️ Insufficient Balance Protection</strong></p>
                    <p style="margin-bottom: 1rem;">All financial operations (domain registration, hosting, renewals) check wallet balance <strong>before</strong> processing. You'll receive a clear error if balance is insufficient:</p>
                    <pre style="background: #1e293b; color: #f8fafc; padding: 1rem; border-radius: 0.5rem; font-size: 0.85rem; margin: 1rem 0;"><code>{
  "error": {
    "code": "BAD_REQUEST",
    "message": "Insufficient wallet balance. Required: $35.58, Available: $15.00",
    "details": {
      "required": 35.58,
      "available": 15.0,
      "shortage": 20.58
    }
  },
  "timestamp": 1761937123
}</code></pre>
                    <p style="margin-top: 1rem;"><strong>Best Practices:</strong></p>
                    <ul style="margin-left: 1.5rem; line-height: 2; margin-top: 0.5rem;">
                        <li>Always check wallet balance before initiating purchases</li>
                        <li>Use <code>GET /api/v1/wallet/balance</code> to verify available funds</li>
                        <li>Monitor balance via webhook notifications for low balance alerts</li>
                        <li>Implement retry logic for 400 errors with balance checks</li>
                    </ul>
                </div>
            </div>
            
            <!-- Domain Management Guide -->
            <div class="code-section" id="domain-register">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🌐 Domain Management Tutorial</h2>
                
                <h3 style="margin: 2rem 0 1rem;">Two Registration Modes</h3>
                <p style="margin-bottom: 1rem;">HostBay API offers flexible domain registration with two approaches:</p>
                
                <div style="background: #f0f9ff; border-left: 4px solid var(--primary); padding: 1.5rem; margin-bottom: 2rem;">
                    <h4 style="color: var(--primary); margin-bottom: 1rem;">🚀 Option 1: HostBay-Managed Contacts (Simplest)</h4>
                    <p style="margin-bottom: 0.5rem;"><strong>Best for:</strong> Quick integrations, resellers, and automated systems</p>
                    <p style="margin-bottom: 0.5rem;"><strong>How it works:</strong> Set <code>use_hostbay_contacts: true</code> - HostBay handles all contact information automatically, just like our Telegram bot does.</p>
                    <p><strong>Advantage:</strong> Minimal API payload, fastest integration, no contact data management needed</p>
                    
                    <h4 style="color: var(--primary); margin: 1.5rem 0 1rem;">🔧 Option 2: User-Provided Contacts (Full Control)</h4>
                    <p style="margin-bottom: 0.5rem;"><strong>Best for:</strong> Enterprise, end-user portals, custom WHOIS data</p>
                    <p style="margin-bottom: 0.5rem;"><strong>How it works:</strong> Provide complete <code>contacts</code> object with registrant details</p>
                    <p><strong>Advantage:</strong> Full WHOIS control, custom contact information visible in domain registration</p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Registering with HostBay Contacts (Simple Mode)</h3>
                <p style="margin-bottom: 1rem;">The easiest way to register - no contact information required:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showSimpleCode('simple-curl')">cURL</button>
                    <button class="code-tab" onclick="showSimpleCode('simple-python')">Python</button>
                    <button class="code-tab" onclick="showSimpleCode('simple-js')">JavaScript</button>
                </div>
                
                <div id="simple-curl" class="code-content active">
                    <pre><code>curl -X POST "https://api.hostbay.io/api/v1/domains/register" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain_name": "example.com",
    "period": 1,
    "use_hostbay_contacts": true,
    "auto_renew": true
  }'</code></pre>
                </div>
                
                <div id="simple-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"

# Simple registration with HostBay contacts
domain_data = {
    "domain_name": "example.com",
    "period": 1,
    "use_hostbay_contacts": True,
    "auto_renew": True
}

headers = {"Authorization": f"Bearer {API_KEY}"}
response = requests.post(
    f"{BASE_URL}/domains/register",
    headers=headers,
    json=domain_data
)

result = response.json()
print(f"Domain registered: {result['data']['domain_name']}")
print(f"Final price (with 10% API discount): ${result['data']['pricing']['final_price']}")</code></pre>
                </div>
                
                <div id="simple-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';

async function registerDomain() {
    const domainData = {
        domain_name: 'example.com',
        period: 1,
        use_hostbay_contacts: true,
        auto_renew: true
    };
    
    const response = await axios.post(
        `${BASE_URL}/domains/register`,
        domainData,
        { headers: { Authorization: `Bearer ${API_KEY}` } }
    );
    
    console.log(`Domain registered: ${response.data.data.domain_name}`);
    console.log(`Price (10% API discount): $${response.data.data.pricing.final_price}`);
}

registerDomain();</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Registering with Custom Contacts (Full Control)</h3>
                <p style="margin-bottom: 1rem;">Provide your own contact information for WHOIS registration:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showDomainCode('domain-curl')">cURL</button>
                    <button class="code-tab" onclick="showDomainCode('domain-python')">Python</button>
                    <button class="code-tab" onclick="showDomainCode('domain-js')">JavaScript</button>
                </div>
                
                <div id="domain-curl" class="code-content active">
                    <pre><code>curl -X POST "https://api.hostbay.io/api/v1/domains/register" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain_name": "example.com",
    "period": 1,
    "contacts": {
      "registrant": {
        "first_name": "John",
        "last_name": "Doe",
        "email": "john@example.com",
        "phone": "+1.2025551234",
        "address": "123 Main St",
        "city": "New York",
        "state": "NY",
        "postal_code": "10001",
        "country": "US",
        "company": "Example Inc"
      }
    },
    "auto_renew": true,
    "privacy_protection": true
  }'</code></pre>
                </div>
                
                <div id="domain-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"

# Domain registration data
domain_data = {
    "domain_name": "example.com",
    "period": 1,
    "contacts": {
        "registrant": {
            "first_name": "John",
            "last_name": "Doe",
            "email": "john@example.com",
            "phone": "+1.2025551234",
            "address": "123 Main St",
            "city": "New York",
            "state": "NY",
            "postal_code": "10001",
            "country": "US",
            "company": "Example Inc"
        }
    },
    "auto_renew": True,
    "privacy_protection": True
}

headers = {"Authorization": f"Bearer {API_KEY}"}
response = requests.post(
    f"{BASE_URL}/domains/register",
    headers=headers,
    json=domain_data
)

result = response.json()
print(f"Domain registered: {result['data']['domain_name']}")
print(f"Privacy enabled: {result['data']['privacy_enabled']}")</code></pre>
                </div>
                
                <div id="domain-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';

async function registerDomain() {
    const domainData = {
        domain_name: 'example.com',
        period: 1,
        contacts: {
            registrant: {
                first_name: 'John',
                last_name: 'Doe',
                email: 'john@example.com',
                phone: '+1.2025551234',
                address: '123 Main St',
                city: 'New York',
                state: 'NY',
                postal_code: '10001',
                country: 'US',
                company: 'Example Inc'
            }
        },
        auto_renew: true,
        privacy_protection: true
    };
    
    const response = await axios.post(
        `${BASE_URL}/domains/register`,
        domainData,
        { headers: { Authorization: `Bearer ${API_KEY}` } }
    );
    
    console.log(`Domain registered: ${response.data.data.domain_name}`);
    console.log(`Privacy enabled: ${response.data.data.privacy_enabled}`);
}

registerDomain();</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Transferring a Domain</h3>
                <p style="margin-bottom: 1rem;">Transfer an existing domain to HostBay:</p>
                <pre><code>POST /api/v1/domains/transfer

{
  "domain_name": "existing-domain.com",
  "auth_code": "EPP-AUTH-CODE-HERE",
  "period": 1
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Renewing a Domain</h3>
                <p style="margin-bottom: 1rem;">Renew before expiration to maintain ownership:</p>
                <pre><code>POST /api/v1/domains/{domain_name}/renew

{
  "period": 1
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Managing Auto-Renewal</h3>
                <p style="margin-bottom: 1rem;">Enable or disable automatic renewal:</p>
                <pre><code>PATCH /api/v1/domains/{domain_name}

{
  "auto_renew": true
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">WHOIS Privacy Protection</h3>
                <p style="margin-bottom: 1rem;">HostBay offers comprehensive WHOIS privacy protection to shield your personal information from public WHOIS lookups. Privacy protection works differently based on how your domain is registered:</p>
                
                <div style="background: #f0f9ff; border-left: 4px solid var(--primary); padding: 1.5rem; margin-bottom: 2rem;">
                    <h4 style="color: var(--primary); margin-bottom: 1rem;">🔒 How Privacy Protection Works</h4>
                    
                    <p style="margin-bottom: 1rem;"><strong>HostBay-Managed Contacts:</strong></p>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li>Domains registered with <code>use_hostbay_contacts: true</code> use our shared privacy contact by default</li>
                        <li>Privacy toggle simply updates the database flag - no WHOIS changes needed</li>
                        <li>Your real contact is never exposed in WHOIS</li>
                    </ul>
                    
                    <p style="margin-bottom: 1rem;"><strong>User-Provided Contacts:</strong></p>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li>When privacy is <strong>enabled</strong>: Your real contact is stored securely in our database, and Privacy Guard contact (Iceland-based) is used in WHOIS</li>
                        <li>When privacy is <strong>disabled</strong>: Your original contact information is restored to WHOIS</li>
                    </ul>
                    
                    <div style="background: #1f2937; color: #e5e7eb; padding: 1rem; border-radius: 0.5rem; font-family: 'Courier New', monospace; font-size: 0.9rem;">
                        <p style="color: #9ca3af; margin-bottom: 0.5rem;"><strong>Privacy Guard Contact Details (WHOIS Replacement):</strong></p>
                        <p style="margin: 0.25rem 0;"><strong>Name:</strong> Domain Privacy Guard</p>
                        <p style="margin: 0.25rem 0;"><strong>Company:</strong> Whois Privacy Service</p>
                        <p style="margin: 0.25rem 0;"><strong>Email:</strong> cloakhost@tutamail.com</p>
                        <p style="margin: 0.25rem 0;"><strong>Phone:</strong> +354.4212434</p>
                        <p style="margin: 0.25rem 0;"><strong>Address:</strong> P.O. Box 123, Privacy Dept.</p>
                        <p style="margin: 0.25rem 0;"><strong>City:</strong> Reykjavik, Capital Region</p>
                        <p style="margin: 0.25rem 0;"><strong>Postal Code:</strong> 101</p>
                        <p style="margin: 0.25rem 0;"><strong>Country:</strong> Iceland (IS)</p>
                    </div>
                </div>
                
                <h4 style="margin: 2rem 0 1rem;">Enable Privacy During Registration</h4>
                <p style="margin-bottom: 1rem;">Set <code>privacy_protection: true</code> when registering a domain:</p>
                <pre><code>POST /api/v1/domains/register

{
  "domain_name": "example.com",
  "period": 1,
  "use_hostbay_contacts": false,
  "privacy_protection": true,
  "contacts": {
    "registrant": {
      "first_name": "John",
      "last_name": "Doe",
      "email": "john@example.com",
      "phone": "+1.2025551234",
      "address": "123 Main St",
      "city": "New York",
      "state": "NY",
      "postal_code": "10001",
      "country": "US"
    }
  }
}

# Result: Domain registered with Privacy Guard contact in WHOIS
# John Doe's real contact stored securely for later restoration</code></pre>
                
                <h4 style="margin: 2rem 0 1rem;">Toggle Privacy on Existing Domains</h4>
                <p style="margin-bottom: 1rem;">Enable or disable privacy protection anytime:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showPrivacyCode('privacy-curl')">cURL</button>
                    <button class="code-tab" onclick="showPrivacyCode('privacy-python')">Python</button>
                    <button class="code-tab" onclick="showPrivacyCode('privacy-js')">JavaScript</button>
                </div>
                
                <div id="privacy-curl" class="code-content active">
                    <pre><code># Enable privacy protection
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/privacy/enable" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Disable privacy protection (restore original contact)
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/privacy/disable" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Check privacy status
curl -X GET "https://api.hostbay.io/api/v1/domains/example.com" \\
  -H "Authorization: Bearer YOUR_API_KEY"
# Returns: privacy_enabled: true/false, contact_type: "hostbay_managed" or "user_provided"</code></pre>
                </div>
                
                <div id="privacy-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Enable privacy
response = requests.post(
    f"{BASE_URL}/domains/example.com/privacy/enable",
    headers=headers
)
print(response.json())
# {"success": true, "message": "Privacy protection enabled"}

# Disable privacy
response = requests.post(
    f"{BASE_URL}/domains/example.com/privacy/disable",
    headers=headers
)
print(response.json())
# {"success": true, "message": "Privacy protection disabled"}

# Check status
response = requests.get(
    f"{BASE_URL}/domains/example.com",
    headers=headers
)
domain = response.json()["data"]
print(f"Privacy enabled: {domain['privacy_enabled']}")
print(f"Contact type: {domain['contact_type']}")</code></pre>
                </div>
                
                <div id="privacy-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Enable privacy
const enableResponse = await axios.post(
    `${BASE_URL}/domains/example.com/privacy/enable`,
    {},
    { headers }
);
console.log(enableResponse.data);
// {"success": true, "message": "Privacy protection enabled"}

// Disable privacy
const disableResponse = await axios.post(
    `${BASE_URL}/domains/example.com/privacy/disable`,
    {},
    { headers }
);
console.log(disableResponse.data);
// {"success": true, "message": "Privacy protection disabled"}

// Check status
const domain = await axios.get(
    `${BASE_URL}/domains/example.com`,
    { headers }
);
console.log(`Privacy: ${domain.data.data.privacy_enabled}`);
console.log(`Contact type: ${domain.data.data.contact_type}`);</code></pre>
                </div>
                
                <div style="background: #dcfce7; border-left: 4px solid var(--success); padding: 1rem; margin: 2rem 0;">
                    <strong>✅ Privacy Protection Best Practices:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Always enable privacy for personal/individual domains</li>
                        <li>Privacy is idempotent - safe to call enable/disable multiple times</li>
                        <li>For HostBay-managed contacts, privacy toggle is instant (no WHOIS update needed)</li>
                        <li>For user contacts, privacy changes are applied to WHOIS within minutes</li>
                        <li>Original contact data is stored securely and can be restored anytime</li>
                    </ul>
                </div>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 2rem 0;">
                    <strong>💡 Pro Tips:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Always enable auto-renew to avoid losing domains</li>
                        <li>Enable privacy protection for personal domains during registration</li>
                        <li>Check domain availability before registration</li>
                        <li>Keep contact information up to date</li>
                        <li>Transfer domains at least 60 days before expiration</li>
                        <li>Use HostBay-managed contacts for fastest integration</li>
                    </ul>
                </div>
                
                <div style="background: linear-gradient(135deg, #e0f2fe 0%, #dbeafe 100%); border: 2px solid var(--primary); padding: 2rem; margin: 2rem 0; border-radius: 0.75rem;">
                    <h3 style="color: var(--primary); margin-top: 0; margin-bottom: 1rem;">🔄 Auto-Renewal Management: Best Practices</h3>
                    <p style="margin-bottom: 1.5rem;"><strong>Auto-renewal prevents service interruptions by automatically renewing hosting before expiration using your wallet balance.</strong></p>
                    
                    <div style="background: white; padding: 1rem; border-radius: 0.5rem; margin-bottom: 2rem; border: 1px solid var(--primary);">
                        <strong>📚 Quick Navigation:</strong>
                        <ul style="margin-left: 1.5rem; margin-top: 0.5rem; margin-bottom: 0;">
                            <li><a href="#hosting-provision" style="color: var(--primary);">Complete Auto-Renewal Tutorial with Multi-Language Code Examples (Python, JavaScript, cURL) →</a></li>
                            <li><strong>Below:</strong> Best practices, strategies, and quick endpoint reference</li>
                        </ul>
                    </div>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">When to Enable Auto-Renewal</h4>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li><strong>Production websites:</strong> Always enable to prevent downtime</li>
                        <li><strong>Critical services:</strong> Business-critical hosting should have auto-renewal enabled</li>
                        <li><strong>Long-term projects:</strong> Set-and-forget solution for ongoing projects</li>
                        <li><strong>Default recommendation:</strong> Enable auto-renewal for all hosting unless you plan to discontinue the service</li>
                    </ul>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">When to Disable Auto-Renewal</h4>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li><strong>Temporary projects:</strong> Short-term testing environments or demos</li>
                        <li><strong>Migration planned:</strong> When planning to move hosting to another provider</li>
                        <li><strong>Cost control:</strong> When you want manual approval for each renewal</li>
                        <li><strong>Service discontinuation:</strong> When planning to shut down the website</li>
                    </ul>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">Notification System</h4>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li><strong>3 days before expiration:</strong> Warning notification if auto-renewal is enabled</li>
                        <li><strong>Insufficient funds warning:</strong> Notified if wallet balance is too low for renewal</li>
                        <li><strong>Renewal success:</strong> Confirmation message when auto-renewal completes</li>
                        <li><strong>Renewal failure:</strong> Alert if auto-renewal fails (e.g., insufficient balance)</li>
                    </ul>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">Grace Period & Recovery</h4>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li><strong>7-day plans:</strong> 1-day grace period after expiration</li>
                        <li><strong>30-day plans:</strong> 2-day grace period after expiration</li>
                        <li><strong>During grace period:</strong> Service continues running, manual renewal available</li>
                        <li><strong>After grace period:</strong> Service suspended, requires manual intervention</li>
                        <li><strong>Recovery option:</strong> Manual renewal endpoint available at any time</li>
                    </ul>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">Wallet Balance Management</h4>
                    <ul style="margin-left: 1.5rem; margin-bottom: 1.5rem;">
                        <li><strong>Maintain buffer:</strong> Keep at least 2-3 renewal periods worth of funds</li>
                        <li><strong>Monitor balance:</strong> Use wallet endpoints to check balance programmatically</li>
                        <li><strong>Top-up alerts:</strong> Set up monitoring for low wallet balance</li>
                        <li><strong>Automatic top-up:</strong> Consider automated wallet funding for critical services</li>
                    </ul>
                    
                    <h4 style="margin: 1.5rem 0 0.75rem;">Control Endpoints & Examples</h4>
                    
                    <p style="margin-bottom: 1rem;"><strong>1. Enable auto-renewal during order creation:</strong></p>
                    <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/hosting/order
{
  "domain_name": "example.com",
  "domain_type": "new",  // "new", "existing", or "external"
  "plan": "pro_30day",
  "period": 1,
  "auto_renew": true
}</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>2. Check auto-renewal status:</strong></p>
                    <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/hosting/{subscription_id}/auto-renewal

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "auto_renew": true
  }
}</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>3. Toggle auto-renewal on/off:</strong></p>
                    <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>PUT /api/v1/hosting/{subscription_id}/auto-renewal
{
  "auto_renew": true
}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "auto_renew": true,
    "updated_at": "2025-11-01T09:00:00Z"
  },
  "message": "Auto-renewal enabled successfully"
}</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>4. Update auto-renewal during manual renewal:</strong></p>
                    <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 0;"><code>POST /api/v1/hosting/{subscription_id}/renew
{
  "period": 3,
  "auto_renew": true
}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "renewed": true,
    "period": 3,
    "amount_charged": 13.50,
    "auto_renew_updated": true
  }
}</code></pre>
                    
                    <p style="margin-top: 1.5rem;"><em>For detailed code examples in Python, JavaScript, and cURL, see the <a href="#hosting-provision" style="color: var(--primary);">Hosting Management Tutorial</a> section below.</em></p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Common Error Responses</h3>
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>Insufficient Wallet Balance (400 Bad Request)</strong></p>
                    <pre style="margin-bottom: 2rem;"><code>{
  "error": {
    "code": "BAD_REQUEST",
    "message": "Insufficient wallet balance. Required: $35.58, Available: $15.00",
    "details": {
      "required": 35.58,
      "available": 15.0
    }
  },
  "timestamp": 1761937123
}</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>Domain Not Available (400 Bad Request)</strong></p>
                    <pre style="margin-bottom: 2rem;"><code>{
  "error": {
    "code": "BAD_REQUEST",
    "message": "Domain example.com is not available for registration"
  },
  "timestamp": 1761937124
}</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>Rate Limit Exceeded (429 Too Many Requests)</strong></p>
                    <pre style="margin-bottom: 2rem;"><code>{
  "error": "Rate limit exceeded",
  "retry_after": 3600,
  "timestamp": 1761937125
}

# Response Headers:
# X-RateLimit-Limit: 1000
# X-RateLimit-Remaining: 0
# X-RateLimit-Reset: 1761940725</code></pre>
                    
                    <p style="margin-bottom: 1rem;"><strong>Unauthorized (401)</strong></p>
                    <pre><code>{
  "error": "Invalid or expired API key",
  "timestamp": 1761937126
}</code></pre>
                </div>
            </div>
            
            <!-- Domain Security & Transfers Guide -->
            <div class="code-section" id="domain-security-transfers">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🔒 Domain Security & Transfer Management</h2>
                
                <p style="margin-bottom: 2rem;">Complete guide to securing your domains and managing transfers between registrars. Learn how to lock/unlock domains, manage authorization codes, and handle incoming/outgoing transfers.</p>
                
                <h3 style="margin: 2rem 0 1rem;">Understanding Domain Security</h3>
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>Transfer Lock:</strong> Prevents unauthorized transfers by blocking EPP/auth code generation and transfer requests</p>
                    <p style="margin-bottom: 1rem;"><strong>EPP/Auth Code:</strong> Secret authorization code required to transfer domain to another registrar</p>
                    <p style="margin-bottom: 1rem;"><strong>Transfer Process:</strong> Typically takes 5-7 days; previous registrar has time to approve/reject</p>
                    <p><strong>ICANN 60-Day Lock:</strong> Domains cannot be transferred within 60 days of registration or contact changes</p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Step 1: Lock/Unlock Domain</h3>
                <p style="margin-bottom: 1rem;">Control whether your domain can be transferred:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('lock-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('lock-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('lock-js')">JavaScript</button>
                </div>
                
                <div id="lock-curl" class="code-content active">
                    <pre><code># Lock domain (prevent transfers)
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/lock" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "locked": true
#   },
#   "message": "Domain locked successfully"
# }

# Unlock domain (allow transfers)
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/unlock" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "locked": false
#   },
#   "message": "Domain unlocked successfully"
# }</code></pre>
                </div>
                
                <div id="lock-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Lock domain
response = requests.post(
    f"{BASE_URL}/domains/example.com/lock",
    headers=headers
)
print(f"Domain locked: {response.json()}")

# Unlock domain
response = requests.post(
    f"{BASE_URL}/domains/example.com/unlock",
    headers=headers
)
print(f"Domain unlocked: {response.json()}")</code></pre>
                </div>
                
                <div id="lock-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Lock domain
const lockResponse = await axios.post(
    `${BASE_URL}/domains/example.com/lock`,
    {},
    { headers }
);
console.log('Domain locked:', lockResponse.data);

// Unlock domain
const unlockResponse = await axios.post(
    `${BASE_URL}/domains/example.com/unlock`,
    {},
    { headers }
);
console.log('Domain unlocked:', unlockResponse.data);</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Step 2: Get Authorization Code (EPP Code)</h3>
                <p style="margin-bottom: 1rem;">Retrieve the secret code needed to transfer your domain away from HostBay:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('auth-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('auth-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('auth-js')">JavaScript</button>
                </div>
                
                <div id="auth-curl" class="code-content active">
                    <pre><code># Get auth code
curl -X GET "https://api.hostbay.io/api/v1/domains/example.com/auth-code" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "auth_code": "Ab7mN9pQr2tXvYz4"
#   },
#   "message": "Auth code retrieved successfully"
# }

# ⚠️ Important: Domain must be UNLOCKED to get auth code</code></pre>
                </div>
                
                <div id="auth-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Get auth code
response = requests.get(
    f"{BASE_URL}/domains/example.com/auth-code",
    headers=headers
)
data = response.json()
auth_code = data["data"]["auth_code"]
print(f"Auth code: {auth_code}")

# Use this code at the new registrar to initiate transfer</code></pre>
                </div>
                
                <div id="auth-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Get auth code
const response = await axios.get(
    `${BASE_URL}/domains/example.com/auth-code`,
    { headers }
);

const authCode = response.data.data.auth_code;
console.log(`Auth code: ${authCode}`);

// Use this code at the new registrar to initiate transfer</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Step 3: Reset Authorization Code</h3>
                <p style="margin-bottom: 1rem;">Generate a new auth code if the previous one was compromised or lost:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('reset-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('reset-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('reset-js')">JavaScript</button>
                </div>
                
                <div id="reset-curl" class="code-content active">
                    <pre><code># Reset auth code
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/auth-code/reset" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "auth_code": "Zk3pL8qTw5yXrUv2",
#     "type": "internal"
#   },
#   "message": "Auth code reset successfully"
# }</code></pre>
                </div>
                
                <div id="reset-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Reset auth code
response = requests.post(
    f"{BASE_URL}/domains/example.com/auth-code/reset",
    headers=headers
)
data = response.json()
new_auth_code = data["data"]["auth_code"]
print(f"New auth code: {new_auth_code}")</code></pre>
                </div>
                
                <div id="reset-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Reset auth code
const response = await axios.post(
    `${BASE_URL}/domains/example.com/auth-code/reset`,
    {},
    { headers }
);

const newAuthCode = response.data.data.auth_code;
console.log(`New auth code: ${newAuthCode}`);</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Incoming Transfer (Transfer TO HostBay)</h3>
                <p style="margin-bottom: 1rem;">Transfer a domain from another registrar to HostBay:</p>
                
                <div style="background: #f0f9ff; border-left: 4px solid var(--primary); padding: 1.5rem; margin-bottom: 1rem;">
                    <strong>📋 Prerequisites:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Domain must be unlocked at current registrar</li>
                        <li>Valid EPP/auth code from current registrar</li>
                        <li>Domain must be at least 60 days old</li>
                        <li>Domain not transferred in last 60 days</li>
                        <li>Valid WHOIS contact email addresses</li>
                    </ul>
                </div>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('transfer-in-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('transfer-in-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('transfer-in-js')">JavaScript</button>
                </div>
                
                <div id="transfer-in-curl" class="code-content active">
                    <pre><code># Initiate transfer to HostBay
curl -X POST "https://api.hostbay.io/api/v1/domains/transfer" \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "domain_name": "example.com",
    "auth_code": "Ab7mN9pQr2tXvYz4",
    "period": 1
  }'

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "status": "transfer_pending",
#     "openprovider_id": 12345678,
#     "period": 1,
#     "message": "Transfer initiated - typically completes in 5-7 days"
#   },
#   "message": "Domain transfer initiated successfully"
# }</code></pre>
                </div>
                
                <div id="transfer-in-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Initiate transfer
transfer_data = {
    "domain_name": "example.com",
    "auth_code": "Ab7mN9pQr2tXvYz4",
    "period": 1
}

response = requests.post(
    f"{BASE_URL}/domains/transfer",
    headers=headers,
    json=transfer_data
)
result = response.json()
print(f"Transfer status: {result['data']['status']}")
print(f"Expected completion: 5-7 days")</code></pre>
                </div>
                
                <div id="transfer-in-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Initiate transfer
const transferData = {
    domain_name: 'example.com',
    auth_code: 'Ab7mN9pQr2tXvYz4',
    period: 1
};

const response = await axios.post(
    `${BASE_URL}/domains/transfer`,
    transferData,
    { headers }
);

console.log(`Transfer status: ${response.data.data.status}`);
console.log('Expected completion: 5-7 days');</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Outgoing Transfer Management</h3>
                <p style="margin-bottom: 1rem;">Approve or reject transfer requests when someone initiates a transfer of your domain to another registrar:</p>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">Approve Outgoing Transfer</h4>
                <p style="margin-bottom: 1rem;">Speed up transfer instead of waiting 5 days for auto-approval:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('approve-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('approve-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('approve-js')">JavaScript</button>
                </div>
                
                <div id="approve-curl" class="code-content active">
                    <pre><code># Approve outgoing transfer
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/transfer/approve" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "approved": true,
#     "message": "Transfer approved successfully"
#   },
#   "message": "Outgoing transfer approved"
# }</code></pre>
                </div>
                
                <div id="approve-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Approve transfer
response = requests.post(
    f"{BASE_URL}/domains/example.com/transfer/approve",
    headers=headers
)
print(f"Transfer approved: {response.json()}")</code></pre>
                </div>
                
                <div id="approve-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Approve transfer
const response = await axios.post(
    `${BASE_URL}/domains/example.com/transfer/approve`,
    {},
    { headers }
);
console.log('Transfer approved:', response.data);</code></pre>
                </div>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">Reject Unauthorized Transfer</h4>
                <p style="margin-bottom: 1rem;">Block unauthorized transfer attempts:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('reject-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('reject-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('reject-js')">JavaScript</button>
                </div>
                
                <div id="reject-curl" class="code-content active">
                    <pre><code># Reject outgoing transfer
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/transfer/reject" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "rejected": true,
#     "message": "Transfer rejected successfully"
#   },
#   "message": "Outgoing transfer rejected"
# }</code></pre>
                </div>
                
                <div id="reject-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Reject transfer
response = requests.post(
    f"{BASE_URL}/domains/example.com/transfer/reject",
    headers=headers
)
print(f"Transfer rejected: {response.json()}")</code></pre>
                </div>
                
                <div id="reject-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Reject transfer
const response = await axios.post(
    `${BASE_URL}/domains/example.com/transfer/reject`,
    {},
    { headers }
);
console.log('Transfer rejected:', response.data);</code></pre>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Restart Failed Transfer</h3>
                <p style="margin-bottom: 1rem;">Retry a stuck or failed transfer operation:</p>
                
                <div class="code-tabs">
                    <button class="code-tab active" onclick="showTransferCode('restart-curl')">cURL</button>
                    <button class="code-tab" onclick="showTransferCode('restart-python')">Python</button>
                    <button class="code-tab" onclick="showTransferCode('restart-js')">JavaScript</button>
                </div>
                
                <div id="restart-curl" class="code-content active">
                    <pre><code># Restart failed transfer
curl -X POST "https://api.hostbay.io/api/v1/domains/example.com/transfer/restart" \\
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
# {
#   "success": true,
#   "data": {
#     "domain": "example.com",
#     "restarted": true,
#     "message": "Transfer restarted successfully"
#   },
#   "message": "Transfer operation restarted"
# }</code></pre>
                </div>
                
                <div id="restart-python" class="code-content">
                    <pre><code>import requests

API_KEY = "YOUR_API_KEY"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Restart transfer
response = requests.post(
    f"{BASE_URL}/domains/example.com/transfer/restart",
    headers=headers
)
print(f"Transfer restarted: {response.json()}")</code></pre>
                </div>
                
                <div id="restart-js" class="code-content">
                    <pre><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { Authorization: `Bearer ${API_KEY}` };

// Restart transfer
const response = await axios.post(
    `${BASE_URL}/domains/example.com/transfer/restart`,
    {},
    { headers }
);
console.log('Transfer restarted:', response.data);</code></pre>
                </div>
                
                <div style="background: #dcfce7; border-left: 4px solid var(--success); padding: 1rem; margin: 2rem 0;">
                    <strong>✅ Domain Security Best Practices:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Always lock domains</strong> when not transferring to prevent unauthorized transfers</li>
                        <li><strong>Store auth codes securely</strong> - treat them like passwords</li>
                        <li><strong>Reset auth codes</strong> if compromised or shared accidentally</li>
                        <li><strong>Monitor transfer notifications</strong> - approve/reject promptly</li>
                        <li><strong>Wait 60+ days</strong> after registration before transferring</li>
                        <li><strong>Verify contact email</strong> before initiating transfers</li>
                    </ul>
                </div>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 2rem 0;">
                    <strong>⏱️ Transfer Timeline:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Day 0:</strong> Transfer initiated at new registrar with auth code</li>
                        <li><strong>Day 0-1:</strong> Previous registrar receives transfer request</li>
                        <li><strong>Day 1-5:</strong> Approval window (you can approve early or reject)</li>
                        <li><strong>Day 5-7:</strong> Auto-approval if not manually approved/rejected</li>
                        <li><strong>Day 7+:</strong> Transfer complete, domain active at new registrar</li>
                    </ul>
                </div>
                
                <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 1rem; margin: 2rem 0;">
                    <strong>⚠️ Common Transfer Issues:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Domain locked:</strong> Unlock domain before getting auth code</li>
                        <li><strong>60-day lock:</strong> Cannot transfer within 60 days of registration or contact change</li>
                        <li><strong>Invalid auth code:</strong> Reset auth code if expired or incorrect</li>
                        <li><strong>Email confirmation:</strong> Check spam folder for transfer approval emails</li>
                        <li><strong>Expired domain:</strong> Renew before transferring to avoid issues</li>
                    </ul>
                </div>
                
                <div style="background: #e0f2fe; border-left: 4px solid #0ea5e9; padding: 1rem; margin: 2rem 0;">
                    <strong>ℹ️ Transfer Endpoint Testing Requirements:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Approve/Reject Transfer:</strong> These endpoints require an active outgoing transfer in progress. To test, initiate a transfer from HostBay to another registrar first.</li>
                        <li><strong>Restart Transfer:</strong> This endpoint requires a failed transfer operation. It cannot be tested without a previous failed transfer attempt.</li>
                        <li><strong>Lock/Unlock & Auth Codes:</strong> These endpoints work immediately and can be tested on any registered domain.</li>
                        <li>All endpoints have been verified against official OpenProvider API v1beta documentation and include proper error handling.</li>
                    </ul>
                </div>
            </div>
            
            <!-- DNS Management Guide -->
            <div class="code-section" id="dns-records">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🔧 DNS Management Tutorial</h2>
                
                <h3 style="margin: 2rem 0 1rem;">Understanding DNS Record Types</h3>
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p><strong>A Record:</strong> Points domain to IPv4 address (e.g., 192.0.2.1). Supports custom subdomains.</p>
                    <p><strong>AAAA Record:</strong> Points domain to IPv6 address</p>
                    <p><strong>CNAME Record:</strong> Alias one domain to another (e.g., www → example.com). Supports custom subdomains.</p>
                    <p><strong>MX Record:</strong> Mail server for email delivery</p>
                    <p><strong>TXT Record:</strong> Text data for verification, SPF, DKIM, DMARC. Supports custom subdomains including underscores for RFC-compliant records (e.g., _dmarc, _domainkey).</p>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Creating DNS Records</h3>
                <p style="margin-bottom: 1rem;">Add an A record to point your domain to a server:</p>
                <pre><code>POST /api/v1/dns/{domain_name}/records

{
  "type": "A",
  "name": "@",
  "content": "192.0.2.1",
  "ttl": 3600,
  "proxied": false
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Common DNS Configurations</h3>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">1. Point Domain to Web Server</h4>
                <pre><code># Root domain
{
  "type": "A",
  "name": "@",
  "content": "192.0.2.1"
}

# www subdomain
{
  "type": "CNAME",
  "name": "www",
  "content": "example.com"
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">2. Configure Email Server</h4>
                <pre><code># MX records for email
{
  "type": "MX",
  "name": "@",
  "content": "mail.example.com",
  "priority": 10
}

# SPF record for email authentication
{
  "type": "TXT",
  "name": "@",
  "content": "v=spf1 include:_spf.example.com ~all"
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">3. Setup Subdomain</h4>
                <pre><code>{
  "type": "A",
  "name": "blog",
  "content": "192.0.2.2"
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">4. Email Authentication (DKIM & DMARC)</h4>
                <p style="margin-bottom: 0.5rem; font-size: 0.95rem;">TXT records support underscores for RFC-compliant email authentication:</p>
                <pre><code># DMARC policy record
{
  "type": "TXT",
  "name": "_dmarc",
  "content": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"
}

# DKIM selector record
{
  "type": "TXT",
  "name": "default._domainkey",
  "content": "v=DKIM1; k=rsa; p=MIGfMA0GCSq..."
}

# Domain verification for services
{
  "type": "TXT",
  "name": "mail",
  "content": "google-site-verification=abc123..."
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 0.5rem;">5. Custom Subdomains for Services</h4>
                <pre><code># API subdomain
{
  "type": "A",
  "name": "api",
  "content": "192.0.2.3"
}

# CDN subdomain
{
  "type": "CNAME",
  "name": "cdn",
  "content": "cdn.example.cloudfront.net"
}

# Service verification TXT record
{
  "type": "TXT",
  "name": "api",
  "content": "service-token=xyz789"
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Cloudflare Integration</h3>
                <p style="margin-bottom: 1rem;">HostBay integrates with Cloudflare for advanced DNS management:</p>
                <ul style="margin-left: 2rem; margin-bottom: 2rem; line-height: 2;">
                    <li>✅ <strong>Automatic SSL/TLS</strong> certificates</li>
                    <li>✅ <strong>DDoS protection</strong> and firewall</li>
                    <li>✅ <strong>CDN acceleration</strong> for faster loading</li>
                    <li>✅ <strong>Analytics</strong> and traffic insights</li>
                    <li>✅ <strong>Page Rules</strong> for redirects and caching</li>
                </ul>
                
                <h3 style="margin: 2rem 0 1rem;">DNS Propagation</h3>
                <p style="margin-bottom: 1rem;">DNS changes can take time to propagate globally:</p>
                <ul style="margin-left: 2rem; margin-bottom: 2rem;">
                    <li>Local cache: 5-15 minutes</li>
                    <li>ISP cache: 1-4 hours</li>
                    <li>Global propagation: 24-48 hours (worst case)</li>
                    <li>Use lower TTL (300-600) for faster updates</li>
                </ul>
                
                <h3 style="margin: 2rem 0 1rem;">Bulk DNS Operations</h3>
                <p style="margin-bottom: 1rem;">Update multiple records at once (supports custom subdomains including underscores for TXT records):</p>
                <pre><code>POST /api/v1/dns/{domain_name}/records/bulk

{
  "records": [
    {"type": "A", "name": "@", "content": "192.0.2.1"},
    {"type": "A", "name": "www", "content": "192.0.2.1"},
    {"type": "A", "name": "api", "content": "192.0.2.3"},
    {"type": "CNAME", "name": "mail", "content": "example.com"},
    {"type": "MX", "name": "@", "content": "mail.example.com", "priority": 10},
    {"type": "TXT", "name": "@", "content": "v=spf1 include:_spf.example.com ~all"},
    {"type": "TXT", "name": "_dmarc", "content": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"}
  ]
}</code></pre>
                
                <div style="background: #dbeafe; border-left: 4px solid #3b82f6; padding: 1rem; margin: 1.5rem 0;">
                    <strong>💡 Custom Subdomain Support:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Name Field:</strong> The <code>name</code> field represents the subdomain portion only (e.g., "api" for api.example.com)</li>
                        <li><strong>A Records:</strong> Use any subdomain (e.g., api, blog, cdn) or @ for root domain</li>
                        <li><strong>CNAME Records:</strong> Point subdomains to other domains (e.g., www → example.com)</li>
                        <li><strong>TXT Records:</strong> Support underscores for email authentication (_dmarc, _domainkey) and custom subdomains</li>
                        <li><strong>Root Domain:</strong> Use @ to create records for the base domain</li>
                    </ul>
                </div>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 1.5rem 0;">
                    <strong>⚠️ DNS Best Practices:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Underscores:</strong> Underscores (_) in subdomains are only valid for TXT records per DNS standards (RFC 1123). Use them exclusively for email authentication (DKIM, DMARC, SPF) and service verification.</li>
                        <li><strong>Subdomain Format:</strong> For A and CNAME records, use lowercase alphanumeric characters and hyphens only (e.g., api-v2, not api_v2).</li>
                        <li><strong>TTL Values:</strong> Use lower TTL (300-600s) when testing, higher TTL (3600s+) for stable records to improve DNS caching.</li>
                    </ul>
                </div>
            </div>
            
            <!-- Hosting Management Guide -->
            <div class="code-section" id="hosting-provision">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">🖥️ Hosting Management Tutorial</h2>
                
                <h3 style="margin: 2rem 0 1rem;">Provisioning Web Hosting</h3>
                <p style="margin-bottom: 1rem;">Create a new hosting account with cPanel:</p>
                <pre><code>POST /api/v1/hosting/provision

{
  "domain_name": "example.com",
  "plan": "starter",
  "username": "exampleuser",
  "password": "SecurePassword123!",
  "email": "admin@example.com",
  "package_name": "Basic Hosting"
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Available Hosting Plans</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin: 2rem 0;">
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">Starter Plan</h4>
                        <ul style="line-height: 2; list-style: none; padding: 0;">
                            <li>✓ 10 GB Storage</li>
                            <li>✓ 100 GB Bandwidth</li>
                            <li>✓ 5 Email Accounts</li>
                            <li>✓ 1 Database</li>
                            <li>✓ Free SSL</li>
                        </ul>
                    </div>
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">Professional Plan</h4>
                        <ul style="line-height: 2; list-style: none; padding: 0;">
                            <li>✓ 50 GB Storage</li>
                            <li>✓ 500 GB Bandwidth</li>
                            <li>✓ 25 Email Accounts</li>
                            <li>✓ 10 Databases</li>
                            <li>✓ Free SSL</li>
                        </ul>
                    </div>
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">Business Plan</h4>
                        <ul style="line-height: 2; list-style: none; padding: 0;">
                            <li>✓ 100 GB Storage</li>
                            <li>✓ Unlimited Bandwidth</li>
                            <li>✓ Unlimited Email</li>
                            <li>✓ Unlimited Databases</li>
                            <li>✓ Free SSL</li>
                        </ul>
                    </div>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Subscription Details (Unified Endpoint)</h3>
                <p style="margin-bottom: 1rem;">Get hosting subscription details with optional credentials and usage data in a single request:</p>
                <pre><code>GET /api/v1/hosting/{subscription_id}
GET /api/v1/hosting/{subscription_id}?include=credentials
GET /api/v1/hosting/{subscription_id}?include=usage
GET /api/v1/hosting/{subscription_id}?include=credentials,usage

Response (with include=credentials,usage):
{
  "id": 123,
  "domain_name": "example.com",
  "plan": "Pro 30 Days",
  "status": "active",
  "cpanel_username": "exampleuser",
  "server_ip": "185.xxx.xxx.xxx",
  "auto_renew": true,
  "created_at": "2025-01-15T10:30:00Z",
  "expires_at": "2025-02-14T10:30:00Z",
  "is_active": true,
  "credentials": {
    "cpanel_url": "https://185.xxx.xxx.xxx:2083",
    "cpanel_username": "exampleuser",
    "ftp_host": "185.xxx.xxx.xxx",
    "ftp_port": 21
  },
  "usage": {
    "disk_used_mb": 256,
    "disk_limit_mb": 10240,
    "bandwidth_used_mb": 1024,
    "bandwidth_limit_mb": 102400,
    "fetched_at": "2025-01-15T12:00:00Z"
  }
}</code></pre>

                <div style="background: #dbeafe; border-left: 4px solid #3b82f6; padding: 1rem; margin: 1.5rem 0;">
                    <strong>💡 Include Flags:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><code>credentials</code> - cPanel/FTP login details (static data)</li>
                        <li><code>usage</code> - Disk and bandwidth statistics (fetched live from cPanel)</li>
                        <li>Combine multiple: <code>?include=credentials,usage</code></li>
                    </ul>
                </div>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 1.5rem 0;">
                    <strong>⚠️ Deprecated Endpoints:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><code>GET /hosting/{id}/credentials</code> → Use <code>?include=credentials</code></li>
                        <li><code>GET /hosting/{id}/usage</code> → Use <code>?include=usage</code></li>
                    </ul>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Email Account Management</h3>
                <p style="margin-bottom: 1rem;">Create email accounts for your domain:</p>
                <pre><code>POST /api/v1/hosting/{domain_name}/email

{
  "email": "info@example.com",
  "password": "SecureEmailPass123!",
  "quota": 1024
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">SSL Certificate Setup</h3>
                <p style="margin-bottom: 1rem;">Install free Let's Encrypt SSL certificate:</p>
                <pre><code>POST /api/v1/hosting/{domain_name}/ssl

{
  "type": "letsencrypt",
  "auto_renew": true
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Database Management</h3>
                <p style="margin-bottom: 1rem;">Create MySQL database:</p>
                <pre><code>POST /api/v1/hosting/{domain_name}/databases

{
  "database_name": "my_database",
  "database_user": "db_user",
  "database_password": "SecureDBPass123!"
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Auto-Renewal Management</h3>
                <p style="margin-bottom: 1rem;">Control automatic renewal for hosting subscriptions to prevent service interruptions:</p>
                
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>How It Works:</strong> When auto-renewal is enabled, your hosting subscription automatically renews before expiration using your wallet balance.</p>
                    <p style="margin-bottom: 1rem;"><strong>Benefits:</strong> No service interruptions, automatic payment processing, peace of mind</p>
                    <p><strong>Control:</strong> You can enable/disable auto-renewal at any time - during order creation, during renewal, or with dedicated endpoints</p>
                </div>
                
                <h4 style="margin: 1.5rem 0 1rem;">Enable Auto-Renewal During Order</h4>
                <p style="margin-bottom: 1rem;">Set auto-renewal when ordering hosting:</p>
                <pre><code>POST /api/v1/hosting/order

{
  "domain_name": "example.com",
  "domain_type": "new",  // "new", "existing", or "external"
  "plan": "pro_30day",
  "period": 1,
  "auto_renew": true
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 1rem;">Check Auto-Renewal Status</h4>
                <p style="margin-bottom: 1rem;">Check if auto-renewal is enabled for a subscription:</p>
                <pre><code>GET /api/v1/hosting/{subscription_id}/auto-renewal

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "auto_renew": true
  }
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 1rem;">Toggle Auto-Renewal</h4>
                <p style="margin-bottom: 1rem;">Enable or disable auto-renewal anytime:</p>
                <pre><code># Enable auto-renewal
PUT /api/v1/hosting/{subscription_id}/auto-renewal
{
  "auto_renew": true
}

# Disable auto-renewal
PUT /api/v1/hosting/{subscription_id}/auto-renewal
{
  "auto_renew": false
}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "auto_renew": true,
    "updated_at": "2025-11-01T09:00:00Z"
  },
  "message": "Auto-renewal enabled successfully"
}</code></pre>
                
                <h4 style="margin: 1.5rem 0 1rem;">Manual Renewal with Auto-Renewal Update</h4>
                <p style="margin-bottom: 1rem;">Renew hosting and update auto-renewal setting in one request:</p>
                <pre><code>POST /api/v1/hosting/{subscription_id}/renew

{
  "period": 3,
  "auto_renew": true
}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "renewed": true,
    "period": 3,
    "pricing": {
      "base_price_per_period": 5.00,
      "periods": 3,
      "price_before_discount": 15.00,
      "api_discount": 1.50,
      "final_price": 13.50
    },
    "amount_charged": 13.50,
    "auto_renew_updated": true
  },
  "message": "Hosting renewed successfully with 10% API discount"
}</code></pre>
                
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 2rem 0;">
                    <strong>⚠️ Important Notes:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Auto-renewal requires sufficient wallet balance before expiration</li>
                        <li>You'll receive warnings 3 days before auto-renewal attempts</li>
                        <li>If renewal fails due to insufficient funds, hosting enters grace period</li>
                        <li>Grace period: 1 day for 7-day plans, 2 days for 30-day plans</li>
                        <li>Auto-renewal defaults to <strong>enabled</strong> for new hosting orders</li>
                    </ul>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">File Management</h3>
                <p style="margin-bottom: 1rem;">Upload files via FTP or use cPanel File Manager:</p>
                <pre><code>GET /api/v1/hosting/{domain_name}/ftp

Response:
{
  "ftp_server": "ftp.example.com",
  "ftp_username": "exampleuser",
  "ftp_port": 21
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Backup and Restore</h3>
                <p style="margin-bottom: 1rem;">Create full account backup:</p>
                <pre><code>POST /api/v1/hosting/{domain_name}/backup

{
  "backup_type": "full",
  "email_notification": true
}</code></pre>
                
                <h3 style="margin: 2rem 0 1rem;">Addon Domain Management</h3>
                <p style="margin-bottom: 1rem;">Host multiple websites on a single hosting subscription using addon domains. Each addon domain gets its own document root directory.</p>
                
                <h4 style="margin: 1.5rem 0 0.75rem;">List Addon Domains</h4>
                <pre><code>GET /api/v1/hosting/{subscription_id}/addon-domains

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "primary_domain": "mysite.com",
    "addon_domains": [
      {
        "domain": "example.com",
        "subdomain": "example",
        "document_root": "/home/user/example_com",
        "status": "active"
      }
    ],
    "total_addon": 1,
    "total_all": 2
  }
}</code></pre>

                <h4 style="margin: 1.5rem 0 0.75rem;">Add Addon Domain</h4>
                <p style="margin-bottom: 1rem;">Add an existing domain or register a new one as an addon:</p>
                <pre><code>POST /api/v1/hosting/{subscription_id}/addon-domains

// Add existing/external domain
{
  "domain": "example.com",
  "document_root": "/public_html/myfolder",  // Optional custom path
  "subdomain": "example"  // Optional, defaults to domain name
}

// Register NEW domain as addon (charges wallet)
{
  "domain": "newsite.com",
  "register_new": true,
  "period": 1,
  "auto_renew_domain": true,
  "document_root": "/public_html/newsite"
}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "primary_domain": "mysite.com",
    "addon_domain": "example.com",
    "subdomain": "example",
    "document_root": "/public_html/myfolder",
    "nameserver_status": "updated" | "manual_update_required",
    "dns_nameservers": ["ns1.cloudflare.com", "ns2.cloudflare.com"]
  }
}</code></pre>

                <h4 style="margin: 1.5rem 0 0.75rem;">Delete Addon Domain</h4>
                <pre><code>DELETE /api/v1/hosting/{subscription_id}/addon-domains/{addon_domain}

Response:
{
  "success": true,
  "data": {
    "subscription_id": 123,
    "deleted_domain": "example.com",
    "deleted": true
  }
}</code></pre>

                <div style="background: #dcfce7; border-left: 4px solid #16a34a; padding: 1rem; margin: 2rem 0;">
                    <strong>✅ Addon Domain Features:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Custom Document Root:</strong> Specify any path like <code>/public_html/myfolder</code></li>
                        <li><strong>New Domain Registration:</strong> Register and add in one API call with <code>register_new: true</code></li>
                        <li><strong>External Domains:</strong> Add domains from other registrars with DNS instructions</li>
                        <li><strong>Automatic DNS:</strong> Cloudflare zone and A records configured automatically</li>
                    </ul>
                </div>
                
                <div style="background: #dbeafe; border-left: 4px solid var(--primary); padding: 1rem; margin: 2rem 0;">
                    <strong>📘 RDP Server Best Practices:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Monitor <code>power_status</code> field to track server state changes</li>
                        <li>Servers auto-start after creation and OS reinstalls - no manual intervention needed</li>
                        <li>Enable auto-renewal to prevent service interruptions (72-hour grace period)</li>
                        <li>Maintain sufficient wallet balance for automatic renewals</li>
                        <li>Change default Administrator password immediately after deployment</li>
                        <li>Use Windows Firewall to restrict RDP access to specific IP addresses</li>
                        <li>Enable Windows Update for security patches</li>
                        <li>Create regular snapshots/backups of critical data</li>
                        <li>Choose datacenter regions closest to your users for best performance</li>
                        <li>Use quarterly or yearly billing for cost savings (6-11% discount)</li>
                    </ul>
                </div>
            </div>
            
            <!-- Windows RDP Server Management Guide -->
            <div class="code-section" id="rdp-servers">
                <h2 style="color: var(--primary); margin-bottom: 1rem;">💻 Windows RDP Server Management</h2>
                
                <p style="margin-bottom: 2rem;">Deploy and manage Windows Server instances with Remote Desktop Protocol (RDP) access. Perfect for development, testing, or production workloads requiring Windows environments.</p>
                
                <h3 style="margin: 2rem 0 1rem;">Available RDP Plans</h3>
                <p style="margin-bottom: 1rem;">Get all available RDP plans with pricing information:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/rdp/plans

Response:
{
  "success": true,
  "data": {
    "plans": [
      {
        "id": 1,
        "name": "Basic RDP",
        "vcpu": 1,
        "ram_mb": 2048,
        "ram_gb": 2,
        "storage_gb": 55,
        "bandwidth_tb": 2,
        "monthly_price": 44.00,
        "quarterly_price": 124.08,
        "yearly_price": 470.88,
        "is_active": true
      },
      {
        "id": 2,
        "name": "Standard RDP",
        "vcpu": 1,
        "ram_mb": 4096,
        "ram_gb": 4,
        "storage_gb": 80,
        "bandwidth_tb": 3,
        "monthly_price": 72.00,
        "quarterly_price": 203.04,
        "yearly_price": 770.88,
        "is_active": true
      }
    ]
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Available Windows Templates</h3>
                <p style="margin-bottom": 1rem;">List all available Windows Server versions:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/rdp/templates

Response:
{
  "success": true,
  "data": {
    "templates": [
      {
        "id": 1,
        "windows_version": "2025",
        "edition": "Standard",
        "display_name": "Windows Server 2025 Standard",
        "is_active": true
      },
      {
        "id": 2,
        "windows_version": "2022",
        "edition": "Standard",
        "display_name": "Windows Server 2022 Standard",
        "is_active": true
      },
      {
        "id": 3,
        "windows_version": "2019",
        "edition": "Standard",
        "display_name": "Windows Server 2019 Standard",
        "is_active": true
      },
      {
        "id": 4,
        "windows_version": "2016",
        "edition": "Standard",
        "display_name": "Windows Server 2016 Standard",
        "is_active": true
      }
    ]
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Available Datacenter Regions</h3>
                <p style="margin-bottom: 1rem;">Get all 32 global datacenter regions:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/rdp/regions

Response:
{
  "success": true,
  "data": {
    "regions": [
      {
        "id": "ewr",
        "city": "New Jersey",
        "country": "US",
        "continent": "North America"
      },
      {
        "id": "lhr",
        "city": "London",
        "country": "GB",
        "continent": "Europe"
      },
      {
        "id": "sgp",
        "city": "Singapore",
        "country": "SG",
        "continent": "Asia"
      }
    ]
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Create New RDP Server</h3>
                <p style="margin-bottom: 1rem;">Deploy a new Windows Server with RDP access:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/rdp/servers
Authorization: Bearer YOUR_API_KEY

{
  "template_id": 1,
  "plan_id": 2,
  "region": "ewr",
  "billing_cycle": "monthly",
  "hostname": "my-windows-server"
}

Billing Cycle Options:
  "monthly"    - Full monthly price
  "quarterly"  - 6% discount (3 months prepaid)
  "yearly"     - 11% discount (12 months prepaid)

Response:
{
  "success": true,
  "data": {
    "message": "RDP server provisioning started",
    "server_id": 123,
    "hostname": "my-windows-server",
    "status": "provisioning",
    "power_status": "starting",
    "estimated_ready_time": "2-3 minutes"
  }
}</code></pre>

                <div style="background: #dcfce7; border-left: 4px solid #16a34a; padding: 1rem; margin: 2rem 0;">
                    <strong>🚀 Auto-Start Behavior:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>All new servers automatically start after provisioning completes</li>
                        <li>Servers automatically start after OS reinstall (1-2 minutes)</li>
                        <li>Smart retry logic handles temporary infrastructure delays</li>
                        <li>Check <code>power_status</code> field for current power state</li>
                    </ul>
                </div>

                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem; margin: 2rem 0;">
                    <strong>💰 Billing Cycles & Discounts:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li><strong>Monthly:</strong> Full monthly price</li>
                        <li><strong>Quarterly:</strong> 6% discount (3 months prepaid)</li>
                        <li><strong>Yearly:</strong> 11% discount (12 months prepaid)</li>
                        <li>Maximum 10 RDP servers per user</li>
                        <li>Auto-renewal enabled by default</li>
                    </ul>
                </div>

                <h3 style="margin: 2rem 0 1rem;">Power Status Values</h3>
                <p style="margin-bottom: 1rem;">The <code>power_status</code> field indicates the current power state of your server:</p>
                
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <ul style="margin-left: 1.5rem;">
                        <li><strong>starting</strong> - Server is powering on (auto-start in progress)</li>
                        <li><strong>running</strong> - Server is powered on and accessible via RDP</li>
                        <li><strong>stopped</strong> - Server is powered off (not billed for compute time)</li>
                        <li><strong>stopping</strong> - Server is shutting down</li>
                        <li><strong>restarting</strong> - Server is rebooting</li>
                        <li><strong>reinstalling</strong> - OS reinstall in progress (1-2 minutes)</li>
                    </ul>
                    <p style="margin-top: 1rem;"><strong>Note:</strong> Servers in <code>starting</code> or <code>reinstalling</code> states will automatically transition to <code>running</code> when ready. Smart retry logic ensures reliable auto-start even during temporary infrastructure delays.</p>
                </div>

                <h3 style="margin: 2rem 0 1rem;">List Your RDP Servers</h3>
                <p style="margin-bottom: 1rem;">Get all your RDP servers:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/rdp/servers
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "servers": [
      {
        "id": 123,
        "hostname": "my-windows-server",
        "public_ip": "192.0.2.10",
        "status": "active",
        "power_status": "running",
        "os": "Windows Server 2022 Standard",
        "plan": {
          "name": "Standard RDP",
          "vcpu": 1,
          "ram_mb": 4096,
          "storage_gb": 80
        },
        "region": "ewr",
        "billing": {
          "cycle": "monthly",
          "monthly_price": 72.00,
          "next_renewal": "2025-12-03T00:00:00Z",
          "auto_renew": true
        },
        "created_at": "2025-11-03T10:00:00Z",
        "activated_at": "2025-11-03T10:08:00Z"
      }
    ],
    "total": 1
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Get Server Details & Credentials</h3>
                <p style="margin-bottom: 1rem;">Retrieve full server details including RDP credentials:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>GET /api/v1/rdp/servers/123
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "id": 123,
    "hostname": "my-windows-server",
    "public_ip": "192.0.2.10",
    "status": "active",
    "power_status": "running",
    "os": "Windows Server 2022 Standard",
    "credentials": {
      "username": "Administrator",
      "password": "SecureP@ssw0rd123"
    },
    "plan": {
      "name": "Standard RDP",
      "vcpu": 1,
      "ram_mb": 4096,
      "storage_gb": 80
    },
    "region": "ewr",
    "billing": {
      "cycle": "monthly",
      "monthly_price": 72.00,
      "next_renewal": "2025-12-03T00:00:00Z",
      "auto_renew": true
    },
    "created_at": "2025-11-03T10:00:00Z",
    "activated_at": "2025-11-03T10:08:00Z"
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Server Control Actions</h3>
                
                <h4 style="margin: 1.5rem 0 1rem;">Start Server</h4>
                <p style="margin-bottom: 1rem;">Power on a stopped server:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/rdp/servers/123/start
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "message": "Server is starting",
    "server_id": 123
  }
}</code></pre>

                <h4 style="margin: 1.5rem 0 1rem;">Stop Server</h4>
                <p style="margin-bottom: 1rem;">Power off a running server:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/rdp/servers/123/stop
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "message": "Server is stopping",
    "server_id": 123
  }
}</code></pre>

                <h4 style="margin: 1.5rem 0 1rem;">Restart Server</h4>
                <p style="margin-bottom: 1rem;">Reboot a running server:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/rdp/servers/123/restart
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "message": "Server is restarting",
    "server_id": 123
  }
}</code></pre>

                <h4 style="margin: 1.5rem 0 1rem;">Reinstall OS</h4>
                <p style="margin-bottom: 1rem;">Completely wipe and reinstall Windows (generates new password):</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>POST /api/v1/rdp/servers/123/reinstall
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "message": "OS reinstall started. Server will auto-start when ready.",
    "server_id": 123,
    "power_status": "reinstalling",
    "estimated_time": "1-2 minutes"
  }
}</code></pre>

                <div style="background: #fee2e2; border-left: 4px solid #dc2626; padding: 1rem; margin: 2rem 0;">
                    <strong>⚠️ Warning - Reinstall OS:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>All data on the server will be permanently deleted</li>
                        <li>A fresh Windows installation will be deployed</li>
                        <li>New Administrator password will be generated</li>
                        <li>Server automatically starts after reinstall completes (1-2 minutes)</li>
                        <li>This action cannot be undone</li>
                    </ul>
                </div>

                <h4 style="margin: 1.5rem 0 1rem;">Delete Server</h4>
                <p style="margin-bottom": 1rem;">Permanently delete a server and stop billing:</p>
                <pre style="background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1.5rem;"><code>DELETE /api/v1/rdp/servers/123
Authorization: Bearer YOUR_API_KEY

Response:
{
  "success": true,
  "data": {
    "message": "Server my-windows-server deleted successfully",
    "server_id": 123
  }
}</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Auto-Renewal System</h3>
                <p style="margin-bottom: 1rem;">RDP servers have automatic renewal with a 72-hour grace period:</p>
                
                <div style="background: var(--light); padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 2rem;">
                    <p style="margin-bottom: 1rem;"><strong>How It Works:</strong> When auto-renewal is enabled, your RDP server automatically renews before expiration using your wallet balance.</p>
                    <p style="margin-bottom: 1rem;"><strong>Grace Period:</strong> 72 hours after renewal due date before server is suspended</p>
                    <p style="margin-bottom: 1rem;"><strong>Warnings:</strong> You'll receive notifications 3 days before renewal</p>
                    <p><strong>Suspension:</strong> If payment fails after grace period, server is stopped to prevent further charges</p>
                </div>

                <h3 style="margin: 2rem 0 1rem;">Complete Workflow Example (Python)</h3>
                <p style="margin-bottom: 1rem;">End-to-end example of deploying and managing a Windows RDP server:</p>
                <pre style="background: #1e1e1e; color: #d4d4d4; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem; overflow-x: auto;"><code>import requests
import time

# Your API key
API_KEY = "YOUR_API_KEY_HERE"
BASE_URL = "https://api.hostbay.io/api/v1"
headers = {"Authorization": f"Bearer {API_KEY}"}

# Step 1: Get available plans
response = requests.get(f"{BASE_URL}/rdp/plans", headers=headers)
plans = response.json()["data"]["plans"]
print(f"Available plans: {len(plans)}")

# Step 2: Get available templates
response = requests.get(f"{BASE_URL}/rdp/templates", headers=headers)
templates = response.json()["data"]["templates"]
print(f"Available Windows versions: {len(templates)}")

# Step 3: Get regions
response = requests.get(f"{BASE_URL}/rdp/regions", headers=headers)
regions = response.json()["data"]["regions"]
print(f"Available regions: {len(regions)}")

# Step 4: Create RDP server
create_data = {
    "template_id": 1,  # Windows Server 2025
    "plan_id": 2,      # Standard RDP
    "region": "ewr",   # New Jersey
    "billing_cycle": "monthly",
    "hostname": "my-dev-server"
}
response = requests.post(f"{BASE_URL}/rdp/servers", json=create_data, headers=headers)
result = response.json()["data"]
server_id = result["server_id"]
print(f"Server provisioning started: {server_id}")

# Step 5: Wait for provisioning (check every 30 seconds)
while True:
    response = requests.get(f"{BASE_URL}/rdp/servers/{server_id}", headers=headers)
    server = response.json()["data"]
    
    if server["status"] == "active":
        print(f"Server ready!")
        print(f"IP: {server['public_ip']}")
        print(f"Username: {server['credentials']['username']}")
        print(f"Password: {server['credentials']['password']}")
        break
    elif server["status"] == "failed":
        print("Provisioning failed")
        break
    
    print(f"Status: {server['status']} - waiting...")
    time.sleep(30)

# Step 6: Connect via RDP
print(f"Connect with: mstsc /v:{server['public_ip']}")

# Step 7: Manage server
# Restart server
requests.post(f"{BASE_URL}/rdp/servers/{server_id}/restart", headers=headers)
print("Server restarted")

# Step 8: Get all your servers
response = requests.get(f"{BASE_URL}/rdp/servers", headers=headers)
all_servers = response.json()["data"]["servers"]
print(f"You have {len(all_servers)} RDP server(s)")</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Complete Workflow Example (JavaScript/Node.js)</h3>
                <pre style="background: #1e1e1e; color: #d4d4d4; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem; overflow-x: auto;"><code>const axios = require('axios');

const API_KEY = 'YOUR_API_KEY_HERE';
const BASE_URL = 'https://api.hostbay.io/api/v1';
const headers = { 'Authorization': `Bearer ${API_KEY}` };

async function deployRDPServer() {
    try {
        // Get available plans
        const plansResponse = await axios.get(`${BASE_URL}/rdp/plans`, { headers });
        console.log(`Available plans: ${plansResponse.data.data.plans.length}`);
        
        // Create RDP server
        const createData = {
            template_id: 1,
            plan_id: 2,
            region: 'ewr',
            billing_cycle: 'monthly',
            hostname: 'my-dev-server'
        };
        
        const createResponse = await axios.post(
            `${BASE_URL}/rdp/servers`,
            createData,
            { headers }
        );
        
        const serverId = createResponse.data.data.server_id;
        console.log(`Server provisioning started: ${serverId}`);
        
        // Wait for server to be ready
        while (true) {
            const serverResponse = await axios.get(
                `${BASE_URL}/rdp/servers/${serverId}`,
                { headers }
            );
            
            const server = serverResponse.data.data;
            
            if (server.status === 'active') {
                console.log('Server ready!');
                console.log(`IP: ${server.public_ip}`);
                console.log(`Username: ${server.credentials.username}`);
                console.log(`Password: ${server.credentials.password}`);
                break;
            } else if (server.status === 'failed') {
                console.log('Provisioning failed');
                break;
            }
            
            console.log(`Status: ${server.status} - waiting...`);
            await new Promise(resolve => setTimeout(resolve, 30000));
        }
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
    }
}

deployRDPServer();</code></pre>

                <h3 style="margin: 2rem 0 1rem;">Complete Workflow Example (cURL)</h3>
                <pre style="background: #1e1e1e; color: #d4d4d4; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem; overflow-x: auto;"><code># Set your API key
API_KEY="YOUR_API_KEY_HERE"

# Get available plans
curl -X GET "https://api.hostbay.io/api/v1/rdp/plans" \\
  -H "Authorization: Bearer $API_KEY"

# Get available Windows templates
curl -X GET "https://api.hostbay.io/api/v1/rdp/templates" \\
  -H "Authorization: Bearer $API_KEY"

# Create RDP server
curl -X POST "https://api.hostbay.io/api/v1/rdp/servers" \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "template_id": 1,
    "plan_id": 2,
    "region": "ewr",
    "billing_cycle": "yearly",
    "hostname": "my-dev-server"
  }'

# Billing options: "monthly", "quarterly" (6% off), "yearly" (11% off)

# Get server details (replace 123 with your server_id)
curl -X GET "https://api.hostbay.io/api/v1/rdp/servers/123" \\
  -H "Authorization: Bearer $API_KEY"

# Restart server
curl -X POST "https://api.hostbay.io/api/v1/rdp/servers/123/restart" \\
  -H "Authorization: Bearer $API_KEY"

# Delete server
curl -X DELETE "https://api.hostbay.io/api/v1/rdp/servers/123" \\
  -H "Authorization: Bearer $API_KEY"</code></pre>

                <div style="background: #dbeafe; border-left: 4px solid var(--primary); padding: 1rem; margin: 2rem 0;">
                    <strong>📘 Best Practices:</strong>
                    <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                        <li>Enable auto-renewal to prevent service interruptions</li>
                        <li>Maintain sufficient wallet balance for automatic renewals</li>
                        <li>Change the Administrator password immediately after deployment</li>
                        <li>Enable Windows Firewall and configure security rules</li>
                        <li>Keep Windows Update enabled for security patches</li>
                        <li>Use strong RDP passwords (12+ characters, mixed case, numbers, symbols)</li>
                        <li>Consider using VPN or IP whitelist for RDP access</li>
                        <li>Take regular backups before major changes</li>
                        <li>Monitor CPU and RAM usage to ensure plan is adequate</li>
                        <li>Use quarterly or yearly billing for cost savings (6-11% discount)</li>
                    </ul>
                </div>
                
                <h3 style="margin: 2rem 0 1rem;">Connecting to Your RDP Server</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin: 2rem 0;">
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">Windows</h4>
                        <ol style="line-height: 2; padding-left: 1.5rem;">
                            <li>Press Win + R</li>
                            <li>Type: <code>mstsc</code></li>
                            <li>Enter server IP</li>
                            <li>Login with credentials</li>
                        </ol>
                    </div>
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">macOS</h4>
                        <ol style="line-height: 2; padding-left: 1.5rem;">
                            <li>Install Microsoft Remote Desktop</li>
                            <li>Click "Add PC"</li>
                            <li>Enter server IP</li>
                            <li>Login with credentials</li>
                        </ol>
                    </div>
                    <div style="background: white; border: 2px solid var(--primary); padding: 1.5rem; border-radius: 0.5rem;">
                        <h4 style="color: var(--primary); margin-bottom: 0.5rem;">Linux</h4>
                        <ol style="line-height: 2; padding-left: 1.5rem;">
                            <li>Install Remmina or FreeRDP</li>
                            <li>Create new RDP connection</li>
                            <li>Enter server IP</li>
                            <li>Login with credentials</li>
                        </ol>
                    </div>
                </div>
            </div>
            
            <!-- Quick Reference Guide Cards -->
            <h2 style="text-align: center; margin: 4rem 0 3rem; color: var(--primary);">Quick Reference Guides</h2>
            <div class="guides-grid">
                <div class="guide-card">
                    <h3>🔐 Authentication</h3>
                    <ul>
                        <li><a href="#auth-basics">API Key Basics</a></li>
                        <li><a href="#auth-basics">Permissions & Access Control</a></li>
                        <li><a href="#auth-basics">Security Best Practices</a></li>
                        <li><a href="#auth-basics">Rate Limiting</a></li>
                    </ul>
                </div>
                <div class="guide-card">
                    <h3>🌐 Domain Management</h3>
                    <ul>
                        <li><a href="#domain-register">Registering Domains</a></li>
                        <li><a href="#domain-register">Transferring Domains</a></li>
                        <li><a href="#domain-register">Renewals & Auto-Renew</a></li>
                        <li><a href="#domain-register">WHOIS Privacy</a></li>
                    </ul>
                </div>
                <div class="guide-card">
                    <h3>🔧 DNS Management</h3>
                    <ul>
                        <li><a href="#dns-records">Managing DNS Records</a></li>
                        <li><a href="#dns-records">Cloudflare Integration</a></li>
                        <li><a href="#dns-records">DNS Propagation</a></li>
                        <li><a href="#dns-records">Bulk Operations</a></li>
                    </ul>
                </div>
                <div class="guide-card">
                    <h3>🖥️ Hosting Management</h3>
                    <ul>
                        <li><a href="#hosting-provision">Provisioning Hosting</a></li>
                        <li><a href="#hosting-provision">Auto-Renewal Management</a></li>
                        <li><a href="#hosting-provision">cPanel Access</a></li>
                        <li><a href="#hosting-provision">Email Management</a></li>
                        <li><a href="#hosting-provision">SSL Certificates</a></li>
                        <li><a href="#hosting-provision">Addon Domain Management</a></li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- API Reference Section -->
        <div class="code-section" style="text-align: center;">
            <h2 style="margin-bottom: 1rem; color: var(--primary);">Complete API Reference</h2>
            <p style="margin-bottom: 2rem; color: var(--gray);">Explore all 88 endpoints with interactive testing</p>
            <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                <a href="/api-docs" class="btn btn-primary">Interactive API Docs</a>
                <a href="/redoc" class="btn btn-secondary" style="color: var(--primary); border-color: var(--primary);">ReDoc View</a>
                <a href="/openapi.json" class="btn btn-secondary" style="color: var(--primary); border-color: var(--primary);">OpenAPI Schema</a>
            </div>
        </div>
    </div>
    
    <!-- Footer -->
    <footer>
        <div class="footer-content">
            <div class="footer-section">
                <h4>Documentation</h4>
                <ul>
                    <li><a href="#getting-started">Getting Started</a></li>
                    <li><a href="/api-docs">API Reference</a></li>
                    <li><a href="#guides">Guides</a></li>
                    <li><a href="/openapi.json">OpenAPI Spec</a></li>
                </ul>
            </div>
            <div class="footer-section">
                <h4>Resources</h4>
                <ul>
                    <li><a href="https://hostbay.io">Main Website</a></li>
                    <li><a href="https://hostbay.io/support">Support</a></li>
                    <li><a href="https://hostbay.io/terms">Terms of Service</a></li>
                    <li><a href="https://hostbay.io/privacy">Privacy Policy</a></li>
                </ul>
            </div>
            <div class="footer-section">
                <h4>Contact</h4>
                <ul>
                    <li><a href="mailto:support@hostbay.io">support@hostbay.io</a></li>
                    <li><a href="https://t.me/hostbay">Telegram</a></li>
                </ul>
            </div>
        </div>
        <div class="footer-bottom">
            © 2025 HostBay. All rights reserved.
        </div>
    </footer>
    
    <script>
        // Copy to clipboard functionality
        document.addEventListener('DOMContentLoaded', function() {
            // Add copy buttons to all code blocks
            document.querySelectorAll('pre').forEach(function(pre) {
                if (!pre.querySelector('.copy-btn')) {
                    const button = document.createElement('button');
                    button.className = 'copy-btn';
                    button.textContent = 'Copy';
                    button.setAttribute('aria-label', 'Copy code to clipboard');
                    
                    button.addEventListener('click', function() {
                        const code = pre.querySelector('code');
                        const text = code ? code.textContent : pre.textContent;
                        
                        navigator.clipboard.writeText(text).then(function() {
                            button.textContent = 'Copied!';
                            button.classList.add('copied');
                            
                            setTimeout(function() {
                                button.textContent = 'Copy';
                                button.classList.remove('copied');
                            }, 2000);
                        }).catch(function(err) {
                            button.textContent = 'Failed';
                            setTimeout(function() {
                                button.textContent = 'Copy';
                            }, 2000);
                        });
                    });
                    
                    pre.appendChild(button);
                }
            });
        });
        
        function showCode(lang) {
            // Hide all code content
            document.querySelectorAll('.code-content').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active from all tabs
            document.querySelectorAll('.code-tab').forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected content and activate tab
            document.getElementById(lang).classList.add('active');
            event.target.classList.add('active');
        }
        
        function showSimpleCode(lang) {
            // Hide all simple code content
            document.querySelectorAll('#simple-curl, #simple-python, #simple-js').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active from simple code tabs
            const simpleTabs = event.target.closest('.code-tabs').querySelectorAll('.code-tab');
            simpleTabs.forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected content and activate tab
            document.getElementById(lang).classList.add('active');
            event.target.classList.add('active');
        }
        
        function showDomainCode(lang) {
            // Hide all domain code content
            document.querySelectorAll('#domain-curl, #domain-python, #domain-js').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active from domain code tabs
            const domainTabs = event.target.closest('.code-tabs').querySelectorAll('.code-tab');
            domainTabs.forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected content and activate tab
            document.getElementById(lang).classList.add('active');
            event.target.classList.add('active');
        }
        
        function showPrivacyCode(lang) {
            // Hide all privacy code content
            document.querySelectorAll('#privacy-curl, #privacy-python, #privacy-js').forEach(el => {
                el.classList.remove('active');
            });
            
            // Remove active from privacy code tabs
            const privacyTabs = event.target.closest('.code-tabs').querySelectorAll('.code-tab');
            privacyTabs.forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected content and activate tab
            document.getElementById(lang).classList.add('active');
            event.target.classList.add('active');
        }
        
        function showTransferCode(lang) {
            // Hide all transfer code content sections
            const transferSections = [
                '#lock-curl', '#lock-python', '#lock-js',
                '#auth-curl', '#auth-python', '#auth-js',
                '#reset-curl', '#reset-python', '#reset-js',
                '#transfer-in-curl', '#transfer-in-python', '#transfer-in-js',
                '#approve-curl', '#approve-python', '#approve-js',
                '#reject-curl', '#reject-python', '#reject-js',
                '#restart-curl', '#restart-python', '#restart-js'
            ];
            
            transferSections.forEach(selector => {
                const el = document.querySelector(selector);
                if (el) el.classList.remove('active');
            });
            
            // Remove active from transfer code tabs
            const transferTabs = event.target.closest('.code-tabs').querySelectorAll('.code-tab');
            transferTabs.forEach(el => {
                el.classList.remove('active');
            });
            
            // Show selected content and activate tab
            document.getElementById(lang).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
    """)

@app.get("/test-admin-alerts", include_in_schema=False)
async def test_admin_alerts():
    """Test admin alert system functionality from within application context"""
    try:
        from admin_alerts import send_critical_alert, get_admin_alert_system, AdminAlertConfig
        
        # Check admin configuration
        config = AdminAlertConfig()
        admin_user_ids = config.admin_user_ids
        
        # Test direct bot message first
        alert_system = get_admin_alert_system()
        bot_application = getattr(alert_system, '_bot_application', None)
        bot_connected = bot_application is not None
        bot_instance_available = bot_connected and hasattr(bot_application, 'bot') and bot_application.bot is not None
        
        direct_send_result = None
        if bot_instance_available:
            try:
                # Test direct message send to first admin
                test_admin_id = admin_user_ids[0] if admin_user_ids else None
                if test_admin_id and bot_application and bot_application.bot:
                    await bot_application.bot.send_message(
                        chat_id=test_admin_id,
                        text="🔧 Direct bot test message - Admin alert system diagnostic",
                        parse_mode=None
                    )
                    direct_send_result = True
                    logger.info(f"✅ Direct bot message sent successfully to {test_admin_id}")
                else:
                    direct_send_result = False
                    logger.error("❌ No admin user IDs configured")
            except Exception as direct_error:
                direct_send_result = False
                logger.error(f"❌ Direct bot message failed: {direct_error}")
        
        # Test admin alert system
        alert_success = await send_critical_alert(
            'ADMIN_SYSTEM_TEST',
            '✅ Admin alert system verification - Notifications working correctly from within application',
            'system_health',
            {
                'test_type': 'internal_endpoint_test',
                'connection_status': 'verified',
                'timestamp': '2025-09-23T06:07:30Z'
            }
        )
        
        return JSONResponse({
            "status": "success" if alert_success else "failed",
            "alert_sent": alert_success,
            "direct_bot_test": direct_send_result,
            "bot_connected": bot_connected,
            "bot_instance_available": bot_instance_available,
            "admin_user_ids": admin_user_ids,
            "admin_count": len(admin_user_ids),
            "admin_alert_system": "operational" if alert_success else "needs_attention",
            "message": "Admin alert test completed from within application context"
        })
        
    except Exception as e:
        logger.error(f"Admin alert test failed: {e}")
        return JSONResponse({
            "status": "error", 
            "error": str(e),
            "admin_alert_system": "error"
        }, status_code=500)

@app.get("/test-admin-alerts-with-username", include_in_schema=False)
async def test_admin_alerts_with_username():
    """Test admin alerts with @username display feature"""
    try:
        from admin_alerts import send_info_alert, send_warning_alert
        from database import execute_query
        
        # Get a real user from database for testing
        users = await execute_query('SELECT id, telegram_id, username, first_name FROM users LIMIT 1')
        
        if not users:
            return JSONResponse({"status": "error", "message": "No users found in database"})
        
        user = users[0]
        user_id = user['id']
        username = user.get('username', 'N/A')
        first_name = user.get('first_name', 'N/A')
        
        results = []
        
        # Test 1: Wallet deposit alert (with user_id)
        result1 = await send_info_alert(
            component='WalletDeposit',
            message='💵 TEST: Wallet deposit $25.00 via BLOCKBEE',
            category='payment_processing',
            details={
                'user_id': user_id,
                'amount_usd': 25.00,
                'provider': 'blockbee',
                'txid': 'test_tx_abc123def456',
                'order_id': 'wallet_fund_test_123'
            }
        )
        results.append({"test": "wallet_deposit", "sent": result1})
        
        # Test 2: Domain registration alert
        result2 = await send_info_alert(
            component='RegistrationOrchestrator',
            message='✅ TEST: Domain registered: testdomain.com',
            category='domain_registration',
            details={
                'user_id': user_id,
                'domain_name': 'testdomain.com',
                'order_id': 'domain_test_123',
                'payment_method': 'wallet'
            }
        )
        results.append({"test": "domain_registration", "sent": result2})
        
        # Test 3: Warning alert
        result3 = await send_warning_alert(
            component='TestSystem',
            message='⚠️ TEST: System warning with customer info',
            category='system_health',
            details={
                'user_id': user_id,
                'action': 'test_warning'
            }
        )
        results.append({"test": "warning_alert", "sent": result3})
        
        return JSONResponse({
            "status": "success",
            "test_user": {
                "user_id": user_id,
                "username": username,
                "first_name": first_name,
                "expected_display": f"@{username}" if username else first_name
            },
            "results": results,
            "message": "Check Telegram for alerts with @username display"
        })
        
    except Exception as e:
        logger.error(f"Admin alert username test failed: {e}")
        return JSONResponse({"status": "error", "error": str(e)}, status_code=500)

@app.get("/test-crypto-payment-display", include_in_schema=False)
async def test_crypto_payment_display():
    """Test crypto payment display with both USD and crypto amounts"""
    try:
        from message_utils import render_crypto_payment
        from services.dynopay import DynoPayService
        from services.blockbee import BlockBeeService
        
        test_results = {}
        
        # Test 1: DynoPay LTC payment
        dynopay = DynoPayService()
        if dynopay.is_available():
            try:
                payment_result = await dynopay.create_payment_address('LTC', 'test_order_123', 75.0, 12345)
                if payment_result:
                    message, keyboard = render_crypto_payment(
                        address=payment_result['address'],
                        crypto_name="LTC",
                        usd_amount=75.0,
                        crypto_amount=payment_result.get('crypto_amount'),
                        order_id='test_order_123',
                        expires_minutes=15
                    )
                    test_results['dynopay_ltc'] = {
                        'success': True,
                        'payment_message': message,
                        'crypto_amount': payment_result.get('crypto_amount', 'Missing'),
                        'provider': 'DynoPay'
                    }
                else:
                    test_results['dynopay_ltc'] = {'success': False, 'error': 'Payment creation failed'}
            except Exception as e:
                test_results['dynopay_ltc'] = {'success': False, 'error': str(e)}
        else:
            test_results['dynopay_ltc'] = {'success': False, 'error': 'DynoPay not available'}
        
        # Test 2: BlockBee LTC payment (backup provider)
        blockbee = BlockBeeService()
        if blockbee.is_available():
            try:
                payment_result = await blockbee.create_payment_address('LTC', 'test_order_456', 75.0, 12345)
                if payment_result:
                    message, keyboard = render_crypto_payment(
                        address=payment_result['address'],
                        crypto_name="LTC",
                        usd_amount=75.0,
                        crypto_amount=payment_result.get('crypto_amount'),
                        order_id='test_order_456',
                        expires_minutes=15
                    )
                    test_results['blockbee_ltc'] = {
                        'success': True,
                        'payment_message': message,
                        'crypto_amount': payment_result.get('crypto_amount', 'Missing'),
                        'provider': 'BlockBee'
                    }
                else:
                    test_results['blockbee_ltc'] = {'success': False, 'error': 'Payment creation failed'}
            except Exception as e:
                test_results['blockbee_ltc'] = {'success': False, 'error': str(e)}
        else:
            test_results['blockbee_ltc'] = {'success': False, 'error': 'BlockBee not available'}
        
        # Test 3: Simulate the exact payment display format
        test_crypto_amount = "0.9375 LTC"  # Example: $75 / $80 per LTC
        demo_message, demo_keyboard = render_crypto_payment(
            address="MVfWvy4rrBfBipjWdFrnnqi879YEmnMMHe",
            crypto_name="LTC",
            usd_amount=75.0,
            crypto_amount=test_crypto_amount,
            order_id='demo_order',
            expires_minutes=15
        )
        
        test_results['demonstration'] = {
            'payment_message': demo_message,
            'shows_crypto_amount': test_crypto_amount in demo_message,
            'shows_usd_amount': '$75.00' in demo_message
        }
        
        return JSONResponse({
            "status": "success",
            "crypto_display_fixed": True,
            "test_results": test_results,
            "summary": {
                "dynopay_working": test_results.get('dynopay_ltc', {}).get('success', False),
                "blockbee_working": test_results.get('blockbee_ltc', {}).get('success', False),
                "demo_display_correct": test_results['demonstration']['shows_crypto_amount'] and test_results['demonstration']['shows_usd_amount']
            }
        })
        
    except Exception as e:
        logger.error(f"Crypto payment display test failed: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e)
        }, status_code=500)

# Simple webhook test endpoint
@app.post("/webhook/test-simple", include_in_schema=False)
async def test_simple():
    """Simple webhook test without dependencies"""
    return JSONResponse({"status": "simple test ok"})

# Telegram webhook endpoint (both paths for direct and ingress-proxied access)
@app.post("/webhook/telegram", include_in_schema=False)
@app.post("/api/webhook/telegram", include_in_schema=False)
async def telegram_webhook(request: Request):
    """Handle Telegram webhook updates"""
    try:
        body = await request.body()
        
        # Use existing telegram webhook verification from webhook_handler
        from webhook_handler import verify_telegram_webhook_secret
        
        # Pass headers directly (case-insensitive) to avoid header case issues
        if not verify_telegram_webhook_secret(request.headers):
            logger.warning("❌ Invalid Telegram webhook signature") 
            raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Parse update
        update_data = json.loads(body.decode('utf-8'))
        
        # DEPLOYMENT FIX: Wait for bot to be ready before processing webhooks
        # This prevents race conditions where webhooks arrive before bot initialization
        # Also handles case where bot initialization failed completely
        if _bot_ready_event is None or not _bot_ready_event.is_set() or not bot_app:
            if not bot_app and _bot_ready_event is not None:
                # Bot init failed permanently - still return 503 so Telegram retries later
                # (after a redeploy that might fix the issue)
                logger.warning("⚠️ Bot initialization failed - returning 503 for Telegram retry")
            else:
                logger.info("⏳ Bot initializing - webhook will retry (503)")
            # Return 503 with Retry-After header - Telegram will automatically retry
            return JSONResponse(
                {"status": "initializing", "message": "Bot starting up, please retry"},
                status_code=503,
                headers={"Retry-After": "10"}  # Longer retry for failed init
            )
            
        update = Update.de_json(update_data, bot_app.bot)
        
        if not update:
            logger.error("❌ Failed to parse Telegram update")
            raise HTTPException(status_code=400, detail="Invalid update")
        # Process update through bot application
        await bot_app.process_update(update)
        
        logger.info(f"✅ Processed Telegram update: {update.update_id}")
        return JSONResponse({"status": "ok"})
        
    except HTTPException:
        # Let HTTP exceptions (like 403, 401) bubble up properly
        raise
    except json.JSONDecodeError as e:
        logger.error(f"❌ JSON decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ Telegram webhook error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

# ========================================
# WEBHOOK HEALTH MONITORING DASHBOARD API
# ========================================

@app.get("/api/webhook-health/dashboard", include_in_schema=False)
async def webhook_health_dashboard():
    """Main webhook health monitoring dashboard data"""
    try:
        from webhook_health_monitor import (
            get_webhook_health_summary, get_provider_health_status,
            get_recent_webhook_metrics, get_alert_summary
        )
        
        # Get comprehensive health overview
        health_summary = await get_webhook_health_summary()
        provider_status = await get_provider_health_status()
        recent_metrics = await get_recent_webhook_metrics(hours=24)
        alert_summary = await get_alert_summary(hours=24)
        
        return JSONResponse({
            "status": "success",
            "dashboard": {
                "health_summary": health_summary,
                "provider_status": provider_status,
                "recent_metrics": recent_metrics,
                "alert_summary": alert_summary,
                "timestamp": int(time.time())
            }
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH DASHBOARD: Error loading dashboard: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

@app.get("/api/webhook-health/providers", include_in_schema=False)
async def webhook_health_providers():
    """Provider-specific webhook health status"""
    try:
        from webhook_health_monitor import get_provider_health_status, get_provider_health_details
        
        # Get detailed provider health information
        provider_status = await get_provider_health_status()
        provider_details = {}
        
        for provider in ['dynopay', 'blockbee']:
            provider_details[provider] = await get_provider_health_details(provider)
        
        return JSONResponse({
            "status": "success",
            "providers": {
                "overview": provider_status,
                "details": provider_details
            },
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH PROVIDERS: Error loading provider data: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

@app.get("/api/webhook-health/metrics", include_in_schema=False)
async def webhook_health_metrics(hours: int = 24):
    """Raw webhook health metrics data"""
    try:
        from webhook_health_monitor import (
            get_recent_webhook_metrics, get_webhook_performance_stats,
            get_missing_confirmations_count
        )
        
        # Limit hours to prevent excessive data load
        hours = min(max(1, hours), 168)  # 1 hour to 1 week
        
        # Get metrics data
        recent_metrics = await get_recent_webhook_metrics(hours=hours)
        performance_stats = await get_webhook_performance_stats(hours=hours)
        missing_confirmations = await get_missing_confirmations_count()
        
        return JSONResponse({
            "status": "success",
            "metrics": {
                "recent_webhooks": recent_metrics,
                "performance_stats": performance_stats,
                "missing_confirmations": missing_confirmations,
                "time_range_hours": hours
            },
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH METRICS: Error loading metrics: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

@app.get("/api/webhook-health/alerts", include_in_schema=False)
async def webhook_health_alerts(hours: int = 24):
    """Recent webhook health alerts and notifications"""
    try:
        from webhook_health_monitor import get_alert_summary, get_recent_alerts
        from admin_alerts import get_admin_alert_system
        
        # Limit hours to prevent excessive data load
        hours = min(max(1, hours), 168)  # 1 hour to 1 week
        
        # Get alert data
        alert_summary = await get_alert_summary(hours=hours)
        recent_alerts = await get_recent_alerts(hours=hours)
        
        # Get admin alert stats if available
        admin_alert_stats = {}
        try:
            alert_system = get_admin_alert_system()
            admin_alert_stats = await alert_system.get_alert_stats()
        except Exception as e:
            logger.warning(f"⚠️ Could not load admin alert stats: {e}")
        
        return JSONResponse({
            "status": "success",
            "alerts": {
                "summary": alert_summary,
                "recent_alerts": recent_alerts,
                "admin_alert_stats": admin_alert_stats,
                "time_range_hours": hours
            },
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH ALERTS: Error loading alerts: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

@app.get("/api/webhook-health/config", include_in_schema=False)
async def webhook_health_config():
    """Current webhook health monitoring configuration"""
    try:
        from webhook_health_monitor import get_health_config
        
        config = await get_health_config()
        
        return JSONResponse({
            "status": "success",
            "config": config,
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH CONFIG: Error loading config: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

@app.post("/api/webhook-health/test-recovery", include_in_schema=False)
async def webhook_health_test_recovery():
    """Test webhook recovery mechanisms (admin only)"""
    try:
        from webhook_health_monitor import trigger_recovery_test
        
        # Run recovery test
        test_result = await trigger_recovery_test()
        
        return JSONResponse({
            "status": "success",
            "test_result": test_result,
            "timestamp": int(time.time())
        })
        
    except Exception as e:
        logger.error(f"❌ WEBHOOK HEALTH TEST: Error running recovery test: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "timestamp": int(time.time())
        }, status_code=500)

# BlockBee webhook endpoint - TYPE-SAFE VERSION
@app.post("/webhook/blockbee", include_in_schema=False)
@app.post("/api/webhook/blockbee", include_in_schema=False)
async def blockbee_webhook(request: Request):
    """Handle BlockBee payment webhook with type-safe processing"""
    try:
        body = await request.body()
        headers = dict(request.headers)
        query_params = dict(request.query_params)
        
        logger.info(f"🔄 TYPE-SAFE BLOCKBEE: Received webhook with query params: {list(query_params.keys())}")
        
        # Security validation (keeping existing security logic)
        from config import get_config
        config = get_config()
        if not config.payment.blockbee_api_key:
            logger.error("❌ CRITICAL: Missing BLOCKBEE_API_KEY - cannot verify webhook")
            raise HTTPException(status_code=500, detail="Configuration error")
            
        from security.webhook_security import get_security_manager, create_security_config
        
        client_ip = request.client.host if request.client else 'unknown'
        if 'x-forwarded-for' in request.headers:
            client_ip = request.headers['x-forwarded-for'].split(',')[0].strip()
        
        security_manager = get_security_manager()
        security_config = create_security_config('blockbee')
        
        validation_result = await security_manager.validate_webhook_security(
            body, headers, client_ip, security_config
        )
        
        if not validation_result['valid']:
            security_reasons = ', '.join(validation_result['reasons'])
            logger.warning(f"❌ BlockBee webhook security validation failed: {security_reasons}")
            raise HTTPException(status_code=403, detail=f"Security validation failed: {security_reasons}")
        
        logger.info(f"✅ BlockBee webhook security validated")
        
        # Parse callback data safely
        try:
            callback_data = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            # Fallback to query params if JSON parsing fails
            callback_data = query_params
        
        # =================================================================
        # TYPE-SAFE PROCESSING: Use BlockBee adapter and schema validation
        # =================================================================
        
        # Step 1: Validate with Pydantic schema and convert to DTO
        from schemas.webhook_schemas import validate_webhook_data, BlockBeeWebhookSchema
        from adapters.blockbee_adapter import BlockBeeAdapter
        from webhook_handler import PaymentWebhookHandler
        
        try:
            # Validate webhook schema
            validated_webhook = validate_webhook_data(callback_data, "blockbee")
            logger.info(f"✅ TYPE-SAFE: BlockBee schema validation passed")
            
            # Use BlockBee adapter to convert to PaymentIntentDTO
            adapter = BlockBeeAdapter()
            payment_intent = await adapter.convert_webhook_to_payment_intent(
                callback_data, 
                query_params={k: [v] for k, v in query_params.items()} if query_params else None,
                validate_schema=False  # Already validated above
            )
            
            logger.info(f"✅ TYPE-SAFE: Converted to PaymentIntentDTO - order: {payment_intent.order_id}, amount: {payment_intent.get_display_amount()}")
            
        except Exception as conversion_error:
            logger.error(f"❌ TYPE-SAFE: Failed to convert BlockBee webhook: {conversion_error}")
            # Fallback to legacy processing if type-safe conversion fails
            logger.warning("⚠️ TYPE-SAFE: Falling back to legacy processing")
            raise conversion_error
        
        # Step 2: Check idempotency using the safe transaction ID
        from database import register_webhook_callback, complete_webhook_callback
        from utils.type_converters import safe_int, safe_string
        
        txid = safe_string(payment_intent.transaction_id, field_name="transaction_id") or "unknown"
        confirmations = safe_int(callback_data.get('confirmations'), default=0, field_name="confirmations") or 0
        
        # Determine callback type
        callback_type = 'wallet_deposit'
        if payment_intent.order_id.startswith('domain_'):
            callback_type = 'domain_order'
        elif payment_intent.order_id.startswith('hosting_'):
            callback_type = 'hosting_payment'
        
        # CRITICAL FIX: For domain/hosting orders, use order-level idempotency (ignore confirmation count)
        # This prevents duplicate registration attempts when retries come with different confirmation counts
        if callback_type in ('domain_order', 'hosting_payment'):
            external_callback_id = f"blockbee_order_{payment_intent.order_id}"
            # Use confirmation_count=0 for idempotency check to ensure order-level deduplication
            confirmations = 0
            logger.info(f"🔒 Using order-level idempotency for {callback_type}: {external_callback_id}")
        else:
            external_callback_id = f"blockbee_safe_{txid}_{confirmations}_{payment_intent.order_id}"
        
        # ENHANCED LOGGING: Super visible wallet deposit notification
        if callback_type == 'wallet_deposit':
            logger.info(f"")
            logger.info(f"{'='*80}")
            logger.info(f"💵 WALLET DEPOSIT WEBHOOK RECEIVED - BlockBee")
            logger.info(f"{'='*80}")
            logger.info(f"   Order ID: {payment_intent.order_id}")
            logger.info(f"   Amount: ${payment_intent.amount_usd}")
            logger.info(f"   Status: {payment_intent.status}")
            logger.info(f"   TXID: {txid[:20]}..." if txid and len(txid) > 20 else f"   TXID: {txid}")
            logger.info(f"{'='*80}")
            logger.info(f"")
        
        # Check idempotency
        is_new_callback = await register_webhook_callback(
            order_id=payment_intent.order_id,
            confirmation_count=confirmations,
            callback_type=callback_type,
            txid=txid,
            amount_usd=payment_intent.amount_usd,  # Pass Decimal directly as expected
            provider='blockbee',
            external_id=external_callback_id
        )
        
        if not is_new_callback:
            logger.info(f"🔄 TYPE-SAFE: Duplicate BlockBee callback ignored - {external_callback_id}")
            return JSONResponse({"status": "duplicate_ignored"})
        
        # Step 3: Process payment with type-safe handler
        try:
            # CRITICAL FIX: Create clean payment data from validated PaymentIntentDTO
            # This ensures amount is pre-parsed as Decimal, preventing silent failures
            clean_payment_data = {
                'order_id': payment_intent.order_id,
                'provider': 'blockbee',
                'status': payment_intent.status,
                'amount': payment_intent.amount_usd,  # Already validated as Decimal
                'currency': payment_intent.original_currency or 'USD',
                'txid': payment_intent.transaction_id or 'unknown'
            }
            
            logger.info(f"💰 WEBHOOK PROCESSING: BlockBee callback for {callback_type} - Order: {payment_intent.order_id}, Amount: ${payment_intent.amount_usd}")
            logger.info(f"   Clean payment data created: amount={clean_payment_data['amount']}, status={clean_payment_data['status']}")
            
            payment_handler = PaymentWebhookHandler()
            result = await payment_handler.process_payment_webhook(clean_payment_data)
            
            logger.info(f"   Payment handler result: {result}")
            
            # Mark callback as completed
            success = result.get('success', False) if isinstance(result, dict) else bool(result)
            await complete_webhook_callback(payment_intent.order_id, confirmations, callback_type, success=success)
            
            if success:
                logger.info(f"✅ TYPE-SAFE BLOCKBEE: Successfully processed payment {payment_intent.order_id}")
                return JSONResponse({"status": "processed", "method": "type_safe"})
            else:
                error_msg = result.get('error', 'Unknown error') if isinstance(result, dict) else 'Payment processing failed'
                logger.error(f"❌ TYPE-SAFE BLOCKBEE: Failed to process payment {payment_intent.order_id}: {error_msg}")
                raise HTTPException(status_code=500, detail=f"Payment processing failed: {error_msg}")
            
        except Exception as processing_error:
            await complete_webhook_callback(payment_intent.order_id, confirmations, callback_type, success=False)
            logger.error(f"❌ TYPE-SAFE BLOCKBEE: Processing error: {processing_error}")
            raise
        
    except HTTPException:
        # Let HTTP exceptions (like 403, 401) bubble up properly
        raise
    except json.JSONDecodeError as e:
        logger.error(f"❌ BlockBee JSON decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ BlockBee webhook error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

# DynoPay webhook endpoint - TYPE-SAFE VERSION
@app.post("/webhook/dynopay", include_in_schema=False)
@app.post("/api/webhook/dynopay", include_in_schema=False)
async def dynopay_webhook(request: Request):
    """Handle DynoPay payment webhook with type-safe processing"""
    try:
        body = await request.body()
        query_params = dict(request.query_params)
        
        logger.info(f"🔄 TYPE-SAFE DYNOPAY: Received webhook with query params: {list(query_params.keys())}")
        
        # Parse webhook data safely
        try:
            parsed_data = json.loads(body.decode('utf-8'))
        except json.JSONDecodeError:
            parsed_data = query_params.copy()
        
        # Security validation (keeping existing security logic)
        from security.webhook_security import get_security_manager, create_security_config
        
        client_ip = request.client.host if request.client else 'unknown'
        if 'x-forwarded-for' in request.headers:
            client_ip = request.headers['x-forwarded-for'].split(',')[0].strip()
        
        security_manager = get_security_manager()
        security_config = create_security_config('dynopay')
        
        headers_dict = dict(request.headers)
        auth_token = query_params.get('auth_token', '')
        order_id = query_params.get('order_id', '')
        
        validation_result = await security_manager.validate_webhook_security(
            body, headers_dict, client_ip, security_config, provider='dynopay',
            auth_token=auth_token, order_id=order_id
        )
        
        if not validation_result['valid']:
            security_reasons = ', '.join(validation_result['reasons'])
            logger.warning(f"❌ DynoPay webhook security validation failed: {security_reasons}")
            raise HTTPException(status_code=403, detail=f"Security validation failed: {security_reasons}")
        
        logger.info(f"✅ DynoPay webhook security validated")
        
        # Parse final callback data
        callback_data = json.loads(body.decode('utf-8'))
        
        # =================================================================
        # EVENT FILTER: Only process payment.confirmed events
        # Ignore pending, underpaid, etc. — return 200 so DynoPay doesn't retry
        # =================================================================
        event = callback_data.get('event', '').lower()
        status_raw = callback_data.get('status', '').lower()
        
        # Accept: payment.confirmed event OR legacy successful/confirmed/completed status
        confirmed_events = {'payment.confirmed', 'payment.overpaid'}
        confirmed_statuses = {'successful', 'confirmed', 'completed'}
        
        is_confirmed = (event in confirmed_events) or (status_raw in confirmed_statuses)
        
        if not is_confirmed:
            logger.info(f"🔇 DynoPay webhook ignored (not confirmed): event='{event}', status='{status_raw}' — returning 200 OK")
            return JSONResponse({"status": "ignored", "reason": f"Only confirmed payments processed (got event={event}, status={status_raw})"})
        
        logger.info(f"✅ DynoPay confirmed payment event: event='{event}', status='{status_raw}'")
        
        # =================================================================
        # TYPE-SAFE PROCESSING: Use DynoPay adapter and schema validation
        # =================================================================
        
        # Step 1: Validate with Pydantic schema and convert to DTO  
        from schemas.webhook_schemas import validate_webhook_data, DynoPayWebhookSchema
        from adapters.dynopay_adapter import DynoPayAdapter
        from webhook_handler import PaymentWebhookHandler
        
        # CRITICAL FIX: Inject our order_id from query params into callback_data
        # DynoPay sends their transaction_id in the body, but OUR order_id is in query params
        if order_id:
            callback_data['order_id'] = order_id
            logger.info(f"📌 Injected order_id from query params: {order_id}")
        
        try:
            # Validate webhook schema
            validated_webhook = validate_webhook_data(callback_data, "dynopay")
            logger.info(f"✅ TYPE-SAFE: DynoPay schema validation passed")
            
            # Use DynoPay adapter to convert to PaymentIntentDTO
            adapter = DynoPayAdapter()
            payment_intent = await adapter.convert_webhook_to_payment_intent(
                callback_data, 
                validate_schema=False  # Already validated above
            )
            
            logger.info(f"✅ TYPE-SAFE: Converted to PaymentIntentDTO - order: {payment_intent.order_id}, amount: {payment_intent.get_display_amount()}")
            
        except Exception as conversion_error:
            logger.error(f"❌ TYPE-SAFE: Failed to convert DynoPay webhook: {conversion_error}")
            # This is the critical fix - instead of using unsafe float() conversions,
            # we fail fast and log the error with the problematic data
            logger.error(f"   Raw webhook data: {callback_data}")
            logger.error(f"   This prevents 'could not convert string to float: domain.com' errors")
            raise HTTPException(status_code=400, detail=f"Invalid webhook data: {conversion_error}")
        
        # Step 2: Check idempotency using the safe transaction ID
        from database import register_webhook_callback, complete_webhook_callback
        from utils.type_converters import safe_int, safe_string
        
        txid = safe_string(payment_intent.transaction_id, field_name="transaction_id") or "unknown"
        confirmations = safe_int(callback_data.get('confirmations'), default=0, field_name="confirmations") or 0
        
        # Determine callback type
        callback_type = 'wallet_deposit'
        if payment_intent.order_id.startswith('domain_'):
            callback_type = 'domain_order'
        elif payment_intent.order_id.startswith('hosting_'):
            callback_type = 'hosting_payment'
        
        # CRITICAL FIX: For domain/hosting orders, use order-level idempotency (ignore confirmation count)
        # This prevents duplicate registration attempts when retries come with different confirmation counts
        if callback_type in ('domain_order', 'hosting_payment'):
            external_callback_id = f"dynopay_order_{payment_intent.order_id}"
            # Use confirmation_count=0 for idempotency check to ensure order-level deduplication
            confirmations = 0
            logger.info(f"🔒 Using order-level idempotency for {callback_type}: {external_callback_id}")
        else:
            external_callback_id = f"dynopay_safe_{txid}_{confirmations}_{payment_intent.order_id}"
        
        # ENHANCED LOGGING: Super visible wallet deposit notification
        if callback_type == 'wallet_deposit':
            logger.info(f"")
            logger.info(f"{'='*80}")
            logger.info(f"💵 WALLET DEPOSIT WEBHOOK RECEIVED - DynoPay")
            logger.info(f"{'='*80}")
            logger.info(f"   Order ID: {payment_intent.order_id}")
            logger.info(f"   Amount: ${payment_intent.amount_usd}")
            logger.info(f"   Status: {payment_intent.status}")
            logger.info(f"   TXID: {txid[:20]}..." if txid and len(txid) > 20 else f"   TXID: {txid}")
            logger.info(f"{'='*80}")
            logger.info(f"")
        
        # Check idempotency
        is_new_callback = await register_webhook_callback(
            order_id=payment_intent.order_id,
            confirmation_count=confirmations,
            callback_type=callback_type,
            txid=txid,
            amount_usd=payment_intent.amount_usd,  # Pass Decimal directly as expected
            provider='dynopay',
            external_id=external_callback_id
        )
        
        if not is_new_callback:
            logger.info(f"🔄 TYPE-SAFE: Duplicate DynoPay callback ignored - {external_callback_id}")
            return JSONResponse({"status": "duplicate_ignored"})
        
        # Step 3: Process payment with type-safe handler
        try:
            # CRITICAL FIX: Create clean payment data from validated PaymentIntentDTO
            # This ensures amount is pre-parsed as Decimal, preventing silent failures
            clean_payment_data = {
                'order_id': payment_intent.order_id,
                'provider': 'dynopay',
                'status': payment_intent.status,
                'amount': payment_intent.amount_usd,  # Already validated as Decimal
                'currency': payment_intent.original_currency or 'USD',
                'txid': payment_intent.transaction_id or 'unknown'
            }
            
            logger.info(f"💰 WEBHOOK PROCESSING: DynoPay callback for {callback_type} - Order: {payment_intent.order_id}, Amount: ${payment_intent.amount_usd}")
            logger.info(f"   Clean payment data created: amount={clean_payment_data['amount']}, status={clean_payment_data['status']}")
            
            payment_handler = PaymentWebhookHandler()
            result = await payment_handler.process_payment_webhook(clean_payment_data)
            
            logger.info(f"   Payment handler result: {result}")
            
            # Mark callback as completed
            success = result.get('success', False) if isinstance(result, dict) else bool(result)
            await complete_webhook_callback(payment_intent.order_id, confirmations, callback_type, success=success)
            
            if success:
                logger.info(f"✅ TYPE-SAFE DYNOPAY: Successfully processed payment {payment_intent.order_id}")
                return JSONResponse({"status": "processed", "method": "type_safe"})
            else:
                error_msg = result.get('error', 'Unknown error') if isinstance(result, dict) else 'Payment processing failed'
                logger.error(f"❌ TYPE-SAFE DYNOPAY: Failed to process payment {payment_intent.order_id}: {error_msg}")
                raise HTTPException(status_code=500, detail=f"Payment processing failed: {error_msg}")
            
        except Exception as processing_error:
            await complete_webhook_callback(payment_intent.order_id, confirmations, callback_type, success=False)
            logger.error(f"❌ TYPE-SAFE DYNOPAY: Processing error: {processing_error}")
            raise
        
    except HTTPException:
        # Let HTTP exceptions (like 403, 401) bubble up properly
        raise
    except json.JSONDecodeError as e:
        logger.error(f"❌ DynoPay JSON decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ DynoPay webhook error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

# OpenProvider webhook endpoint  
@app.post("/webhooks/openprovider", include_in_schema=False)
async def openprovider_webhook(request: Request):
    """Handle OpenProvider domain status webhook"""
    try:
        body = await request.body()
        
        # Add OpenProvider webhook authentication if required
        # Note: OpenProvider may use IP whitelisting or Basic Auth
        # For now, we'll process all requests but could add verification here
        
        # Parse webhook data
        webhook_data = json.loads(body.decode('utf-8'))
        
        logger.info(f"🌐 OpenProvider webhook received: {webhook_data}")
        
        # Route to unified webhook handler for processing
        from webhook_handler import _process_payment_callback
        
        # Build callback URL path for processing  
        domain_name = webhook_data.get('domain', 'unknown')
        callback_path = f"/webhook/openprovider?domain={domain_name}"
        
        # Process through unified handler
        result = await _process_payment_callback(webhook_data, body, callback_path)
        
        logger.info(f"🌐 OpenProvider webhook processed: {result}")
        
        return JSONResponse({"status": "processed"})
        
    except HTTPException:
        # Let HTTP exceptions (like 403, 401) bubble up properly
        raise
    except json.JSONDecodeError as e:
        logger.error(f"❌ OpenProvider JSON decode error: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"❌ OpenProvider webhook error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

# Generic webhook endpoint for testing
@app.post("/webhooks/test", include_in_schema=False)
async def test_webhook(request: Request):
    """Test webhook endpoint for development"""
    body = await request.body()
    headers = dict(request.headers)
    
    logger.info(f"🧪 Test webhook received")
    logger.info(f"Headers: {headers}")
    logger.info(f"Body: {body.decode('utf-8')}")
    
    return JSONResponse({"status": "test_received", "timestamp": int(time.time())})

# REST API Root and Health endpoints
@app.get("/api/v1", include_in_schema=False)
async def api_root():
    """REST API root endpoint - lists available endpoints"""
    return {
        "name": "HostBay REST API",
        "version": "1.0.0",
        "documentation": "/api/v1/docs",
        "endpoints": {
            "domains": "/api/v1/domains",
            "dns": "/api/v1/domains/{domain_name}/dns",
            "nameservers": "/api/v1/domains/{domain_name}/nameservers",
            "hosting": "/api/v1/hosting",
            "bundles": "/api/v1/bundles",
            "wallet": "/api/v1/wallet",
            "orders": "/api/v1/orders",
            "monitoring": "/api/v1/system",
            "linking": "/api/v1/domains/{domain_name}/link",
            "api_keys": "/api/v1/keys",
            "rdp_servers": "/api/v1/rdp"
        }
    }

@app.get("/api/v1/health", include_in_schema=False)
async def api_health():
    """REST API health check endpoint"""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "api": "operational"
    }

# Mount REST API routes
try:
    from api.routes import (
        domains,
        dns,
        nameservers,
        hosting,
        bundles,
        wallet,
        monitoring,
        linking,
        api_keys,
        webhooks,
        status,
        rdp,
        test_notifications
    )
    
    app.include_router(domains.router, prefix="/api/v1", tags=["Domains"])
    app.include_router(dns.router, prefix="/api/v1", tags=["DNS"])
    app.include_router(nameservers.router, prefix="/api/v1", tags=["Nameservers"])
    app.include_router(hosting.router, prefix="/api/v1", tags=["Hosting"])
    app.include_router(bundles.router, prefix="/api/v1", tags=["Bundles"])
    app.include_router(wallet.router, prefix="/api/v1", tags=["Wallet"])
    app.include_router(monitoring.router, prefix="/api/v1", tags=["Monitoring"])
    app.include_router(linking.router, prefix="/api/v1", tags=["Domain Linking"])
    app.include_router(api_keys.router, prefix="/api/v1", tags=["API Keys"])
    app.include_router(webhooks.router, prefix="/api/v1", tags=["Webhooks"])
    app.include_router(status.router, prefix="/api/v1", tags=["Status"])
    app.include_router(rdp.router, prefix="/api/v1", tags=["RDP Servers"])
    app.include_router(test_notifications.router, prefix="/api/v1", tags=["Testing"])
    
    logger.info("✅ REST API routes mounted at /api/v1 (110+ endpoints)")
except Exception as e:
    logger.error(f"⚠️ Failed to mount REST API routes: {e}")

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "timestamp": int(time.time())}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"❌ Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "timestamp": int(time.time())}
    )

# Development server
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    # Run FastAPI server
    uvicorn.run(
        "fastapi_server:app",
        host="0.0.0.0",
        port=5000,
        reload=False,
        log_level="info"
    )