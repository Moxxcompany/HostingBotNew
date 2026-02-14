"""
Consolidated Admin Handlers for Telegram Bot
Contains ALL admin functionality: commands, callbacks, text handlers, and broadcast features
"""

import os
import logging
import time
import asyncio
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes, ApplicationHandlerStop
from database import (
    execute_query, get_or_create_user, credit_user_wallet,
    get_user_wallet_balance, execute_update
)
from pricing_utils import format_money
from brand_config import get_platform_name
from message_utils import create_error_message, format_bold, format_inline_code, escape_html
from webhook_handler import get_bot_application
from localization import t, resolve_user_language, t_html
# Import unified ID handling functions
from unified_user_id_handlers import (
    get_user_data_by_telegram_id,
    get_internal_user_id_from_telegram_id,
    validate_telegram_id,
    get_wallet_balance_by_telegram_id
)

logger = logging.getLogger(__name__)

async def safe_edit_message_text(query, text, reply_markup=None, parse_mode=None):
    """
    Safely edit message text with proper error handling for 'message not modified' errors.
    
    Args:
        query: Telegram callback query
        text: New message text
        reply_markup: Optional inline keyboard
        parse_mode: Optional parse mode (HTML, Markdown, etc.)
    """
    try:
        await query.edit_message_text(
            text=text,
            reply_markup=reply_markup,
            parse_mode=parse_mode
        )
    except Exception as e:
        # Convert exception to string safely to avoid circular references
        try:
            error_msg = str(e).lower()
        except:
            error_msg = "unknown error"
            
        if "message is not modified" in error_msg:
            # Message content is the same, this is not a real error
            logger.debug("Message not modified (content unchanged)")
            return
        elif "bad request" in error_msg and "message to edit not found" in error_msg:
            # Message was deleted or became inaccessible
            logger.warning("Message to edit not found")
            return
        else:
            # Real error, log safely and re-raise
            logger.error("Failed to edit message - see next error for details")
            raise

def clear_admin_states(context):
    """Clear all admin states when user navigates away from admin areas"""
    if not context.user_data:
        return
    
    states_cleared = []
    
    # Clear admin credit state
    if 'admin_credit_state' in context.user_data:
        del context.user_data['admin_credit_state']
        states_cleared.append('admin_credit_state')
    
    # Clear broadcast state  
    if 'awaiting_broadcast' in context.user_data:
        del context.user_data['awaiting_broadcast']
        states_cleared.append('awaiting_broadcast')
    
    if states_cleared:
        logger.info(f"🧹 AUTO_CLEANUP: Cleared admin states: {', '.join(states_cleared)}")

def is_admin_user(user_id: int) -> bool:
    """
    Check if a user ID is an admin across all admin configuration methods.
    Supports ADMIN_USER_IDS, ADMIN_USER_ID, and ADDITIONAL_ADMIN_USER_IDS.
    """
    admin_ids = []
    
    # Try the standard ADMIN_USER_IDS first (comma-separated)
    admin_ids_str = os.getenv('ADMIN_USER_IDS', '')
    if admin_ids_str:
        for admin_id in admin_ids_str.split(','):
            admin_id = admin_id.strip()
            if admin_id:
                try:
                    admin_ids.append(int(admin_id))
                except ValueError:
                    continue
    
    # Fallback to legacy format for backward compatibility
    if not admin_ids:
        # Primary admin user
        primary_admin = os.getenv('ADMIN_USER_ID')
        if primary_admin and primary_admin.isdigit():
            admin_ids.append(int(primary_admin))
        
        # Additional admin users (comma-separated)
        additional_admins = os.getenv('ADDITIONAL_ADMIN_USER_IDS', '')
        if additional_admins:
            for admin_id in additional_admins.split(','):
                admin_id = admin_id.strip()
                if admin_id:
                    try:
                        admin_ids.append(int(admin_id))
                    except ValueError:
                        continue
    
    return user_id in admin_ids

# ========== ADMIN LANGUAGE CONTEXT HELPER ==========

async def get_admin_language(user_id: int, user_lang_code: Optional[str] = None) -> str:
    """
    Resolve admin language preference for admin interface.
    Admin commands should use admin's preferred language.
    
    Args:
        user_id: Admin user's Telegram ID
        user_lang_code: Admin user's Telegram language code
        
    Returns:
        Language code for admin interface
    """
    try:
        return await resolve_user_language(user_id, user_lang_code)
    except Exception as e:
        logger.warning(f"Failed to resolve admin language for {user_id}: {e}")
        return 'en'  # Fallback to English for admin interface

async def get_user_notification_language(user_id: int) -> str:
    """
    Resolve language for notifications sent to users (not admin interface).
    User notifications should always be in the user's preferred language.
    
    Args:
        user_id: Target user's Telegram ID
        
    Returns:
        Language code for user notification
    """
    try:
        return await resolve_user_language(user_id)
    except Exception as e:
        logger.warning(f"Failed to resolve user notification language for {user_id}: {e}")
        return 'en'  # Fallback to English

# ========== ADMIN COMMAND HANDLERS ==========


async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to broadcast message to all users with batching and retry logic"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in broadcast command")
        return
    
    # SECURITY: Multi-layer admin validation using unified admin check
    if not is_admin_user(user.id):
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /broadcast command")
        
        # Get admin language for security response
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        await message.reply_text(
            t('admin.access.denied', admin_lang) + "\n\n" + 
            t('admin.access.restricted', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    # Get admin language for all responses
    admin_lang = await get_admin_language(user.id, user.language_code)
    
    # Get broadcast message from command arguments
    if not context.args:
        await message.reply_text(
            t('admin.commands.broadcast.usage', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    broadcast_message = " ".join(context.args)
    
    if len(broadcast_message.strip()) == 0:
        await message.reply_text(
            t('admin.commands.broadcast.empty_message', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        # Send broadcast using shared helper
        result = await send_broadcast(broadcast_message, update, context, admin_lang)
        
        if not result['success']:
            await message.reply_text(result['message'])
        
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in broadcast_command by admin {user.id}: {e}")
        await message.reply_text(
            t('admin.commands.broadcast.failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def send_broadcast(broadcast_message: str, update: Update, context: ContextTypes.DEFAULT_TYPE, admin_lang: str = 'en'):
    """
    Shared broadcast helper function with batching and retry logic.
    Used by both /broadcast command and button interface.
    """
    user = update.effective_user
    message = update.effective_message or (update.callback_query.message if update.callback_query else None)
    
    try:
        # Get all admin IDs to exclude from broadcast
        admin_ids = []
        admin_ids_str = os.getenv('ADMIN_USER_IDS', '')
        if admin_ids_str:
            for admin_id in admin_ids_str.split(','):
                admin_id = admin_id.strip()
                if admin_id:
                    try:
                        admin_ids.append(int(admin_id))
                    except ValueError:
                        continue
        
        # Fallback to legacy admin ID formats
        if not admin_ids:
            admin_id_str = os.getenv('ADMIN_USER_ID', '')
            if admin_id_str:
                try:
                    admin_ids.append(int(admin_id_str))
                except ValueError:
                    pass
        
        # Additional admin IDs
        additional_ids_str = os.getenv('ADDITIONAL_ADMIN_USER_IDS', '')
        if additional_ids_str:
            for admin_id in additional_ids_str.split(','):
                admin_id = admin_id.strip()
                if admin_id:
                    try:
                        admin_ids.append(int(admin_id))
                    except ValueError:
                        continue
        
        # Get all users who have accepted terms, excluding admins
        if admin_ids:
            # Exclude admin users from broadcast recipients
            placeholders = ','.join(['%s'] * len(admin_ids))
            query = f"SELECT telegram_id, first_name FROM users WHERE terms_accepted = true AND telegram_id NOT IN ({placeholders}) ORDER BY id"
            users = await execute_query(query, tuple(admin_ids))
            logger.info(f"📢 BROADCAST: Excluding {len(admin_ids)} admin user(s) from broadcast recipients")
        else:
            # No admins to exclude (shouldn't happen, but safe fallback)
            users = await execute_query(
                "SELECT telegram_id, first_name FROM users WHERE terms_accepted = true ORDER BY id",
                ()
            )
        
        if not users:
            return {
                'success': False,
                'message': t('admin.commands.broadcast.no_recipients', admin_lang)
            }
        
        total_users = len(users)
        
        # Show initial status
        message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
        
        if not message:
            return {'success': False, 'message': 'No message available for broadcast status'}
            
        status_message = None
        # Type-safe message reply for broadcast status - properly handle MaybeInaccessibleMessage
        # Only use messages that are actual Message objects, not MaybeInaccessibleMessage
        from telegram import Message
        if message and isinstance(message, Message):
            status_message = await message.reply_text(
                t('admin.broadcast.title', admin_lang) + "\n\n" +
                f"<b>Message:</b> {message_preview}\n" +
                f"<b>Recipients:</b> {total_users} users\n" +
                f"<b>Status:</b> " + t('admin.broadcast.status_starting', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
        # Broadcast with batching and retry logic
        batch_size = 30  # Telegram rate limit friendly
        total_sent = 0
        total_failed = 0
        
        for i in range(0, total_users, batch_size):
            batch = users[i:i + batch_size]
            batch_sent = 0
            batch_failed = 0
            
            for target_user in batch:
                target_telegram_id = target_user['telegram_id']
                target_name = target_user.get('first_name', 'User')
                
                # Retry logic for each user
                max_retries = 3
                sent = False
                
                for attempt in range(max_retries):
                    try:
                        app = get_bot_application()
                        if app:
                            # Get user's language for broadcast notification
                            user_lang = await get_user_notification_language(target_telegram_id)
                            broadcast_header = t('admin.broadcast.broadcast_message_header', user_lang)
                            
                            await app.bot.send_message(
                                chat_id=target_telegram_id,
                                text=f"{broadcast_header}\n\n{escape_html(broadcast_message)}",
                                parse_mode=ParseMode.HTML
                            )
                            batch_sent += 1
                            sent = True
                            break
                    except Exception as send_error:
                        if attempt == max_retries - 1:  # Last attempt failed
                            logger.warning(f"Failed to send broadcast to {target_name} ({target_telegram_id}): {send_error}")
                            batch_failed += 1
                        else:
                            await asyncio.sleep(0.5)  # Brief pause before retry
                
                if sent:
                    logger.debug(f"📢 Broadcast sent to {target_name} ({target_telegram_id})")
            
            total_sent += batch_sent
            total_failed += batch_failed
            
            # Update progress
            progress = ((i + len(batch)) / total_users) * 100
            message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
            
            if status_message:
                await status_message.edit_text(
                    t('admin.broadcast.progress', admin_lang,
                      message_preview=message_preview,
                      sent=total_sent + total_failed,
                      total=total_users,
                      percentage=f"{progress:.1f}",
                      failed=total_failed),
                    parse_mode=ParseMode.HTML
                )
            
            # Rate limiting delay between batches
            if i + batch_size < total_users:
                await asyncio.sleep(1)  # 1 second delay between batches
        
        # Final results
        success_rate = (total_sent / total_users) * 100 if total_users > 0 else 0
        message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
        
        final_message = t('admin.broadcast.complete', admin_lang,
                         message_preview=message_preview,
                         total=total_users,
                         sent=total_sent,
                         failed=total_failed,
                         success_rate=f"{success_rate:.1f}")
        
        if status_message:
            await status_message.edit_text(final_message, parse_mode=ParseMode.HTML)
        
        if user:
            logger.info(f"📢 ADMIN BROADCAST: {user.username or user.first_name} sent to {total_sent}/{total_users} users")
        
        return {
            'success': True,
            'total_users': total_users,
            'total_sent': total_sent,
            'total_failed': total_failed,
            'success_rate': success_rate
        }
        
    except Exception as e:
        logger.error(f"❌ Broadcast error: {e}")
        return {
            'success': False,
            'message': t('admin.commands.broadcast.failed', admin_lang) + f"\n\nError: {str(e)[:100]}"
        }

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command to exit broadcast mode"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in cancel command")
        return
    
    try:
        # Get admin language
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        # Clear any admin states
        states_cleared = []
        
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
            states_cleared.append(t('admin.status.broadcast_mode', admin_lang))
        
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
            states_cleared.append(t('admin.status.credit_wallet_mode', admin_lang))
        
        if states_cleared:
            await message.reply_text(
                t('admin.cancel.success', admin_lang, operations=', '.join(states_cleared)),
                parse_mode=ParseMode.HTML
            )
            logger.info(f"ADMIN: User {user.id} cancelled {', '.join(states_cleared)}")
        else:
            await message.reply_text(
                t('admin.cancel.no_operations', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
    except Exception as e:
        logger.error(f"Error in cancel_command: {e}")
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.cancel.error', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def maintenance_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to manage system maintenance mode"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in maintenance command")
        return
    
    if not is_admin_user(user.id):
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /maintenance command")
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.access.denied', admin_lang) + "\n\n" + 
            t('admin.access.restricted', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        from services.maintenance_manager import MaintenanceManager
        
        admin_lang = await get_admin_language(user.id, user.language_code)
        status = await MaintenanceManager.get_maintenance_status()
        
        if status['is_active']:
            time_remaining = status.get('time_remaining_seconds', 0)
            if time_remaining and time_remaining > 0:
                minutes = time_remaining // 60
                seconds = time_remaining % 60
                time_text = f"⏳ <b>Time remaining:</b> {minutes} min {seconds} sec"
            else:
                time_text = "✅ Maintenance should be completing soon!"
            
            response_text = (
                "🔧 <b>Maintenance Mode Status</b>\n\n"
                f"<b>Status:</b> Active ✅\n"
                f"{time_text}\n\n"
                "Click below to disable maintenance mode."
            )
            
            keyboard = [
                [InlineKeyboardButton("❌ Disable Maintenance", callback_data="maintenance:disable")],
                [InlineKeyboardButton("🔄 Refresh Status", callback_data="maintenance:status")]
            ]
        else:
            response_text = (
                "🔧 <b>Maintenance Mode Status</b>\n\n"
                "<b>Status:</b> Inactive ❌\n\n"
                "Select duration to enable maintenance mode:"
            )
            
            keyboard = [
                [InlineKeyboardButton("⏱ 15 minutes", callback_data="maintenance:enable:15")],
                [InlineKeyboardButton("⏱ 30 minutes", callback_data="maintenance:enable:30")],
                [InlineKeyboardButton("⏱ 1 hour", callback_data="maintenance:enable:60")],
                [InlineKeyboardButton("⏱ 2 hours", callback_data="maintenance:enable:120")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(
            response_text,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"🔧 ADMIN: User {user.id} accessed maintenance command")
        
    except Exception as e:
        logger.error(f"❌ Error in maintenance_command: {e}")
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            "❌ <b>Error</b>\n\nFailed to access maintenance mode.",
            parse_mode=ParseMode.HTML
        )

# ========== ADMIN CALLBACK HANDLERS ==========

async def handle_admin_broadcast(query, context):
    """Handle admin broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_admin_broadcast")
        return
    
    # Security check using unified admin validation
    if not is_admin_user(user.id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to access broadcast interface")
        return
    
    try:
        await query.answer()
        
        # Set broadcast mode flag
        context.user_data['awaiting_broadcast'] = True
        
        # Get admin language and show broadcast interface
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        message = t('admin.broadcast.ready', admin_lang,
                   bold_text="Admin Broadcast Ready",
                   bold_text_ready="Broadcast mode activated!",
                   bold_text_steps="Next Steps:",
                   bold_text_type="Type your broadcast message",
                   bold_text_specs="Specs:",
                   bold_text_status="Status:")

        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.cancel_broadcast', admin_lang), callback_data="cancel_broadcast")],
            [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message_text(
            query=query,
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"📢 ADMIN: User {user.id} accessed broadcast interface")
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.errors.broadcast_interface_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def handle_cancel_broadcast(query, context):
    """Handle cancel broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_cancel_broadcast")
        return
    
    # Security check using unified admin authentication
    if not is_admin_user(user.id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to cancel broadcast")
        return
    
    try:
        await query.answer()
        
        # Get admin language and clear broadcast flag
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        if 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        # Show cancellation message
        message = t('admin.broadcast.cancelled', admin_lang, bold_text="Broadcast Cancelled")

        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message_text(
            query=query,
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast mode")
        
    except Exception as e:
        logger.error(f"Error in handle_cancel_broadcast: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.errors.broadcast_cancel_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def handle_maintenance_enable(query, context, duration_minutes: int):
    """Handle enabling maintenance mode with specified duration"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_maintenance_enable")
        return
    
    if not is_admin_user(user.id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to enable maintenance")
        return
    
    try:
        from services.maintenance_manager import MaintenanceManager
        
        await query.answer()
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        internal_user_id = await get_internal_user_id_from_telegram_id(user.id)
        if not internal_user_id:
            await safe_edit_message_text(
                query=query,
                text="❌ <b>Error</b>\n\nUser not found in database.",
                parse_mode=ParseMode.HTML
            )
            return
        
        success = await MaintenanceManager.enable_maintenance(internal_user_id, duration_minutes)
        
        if success:
            hours = duration_minutes // 60
            minutes = duration_minutes % 60
            duration_text = f"{hours}h {minutes}min" if hours > 0 else f"{minutes} min"
            
            response_text = (
                "🔧 <b>Maintenance Mode Enabled</b>\n\n"
                f"<b>Duration:</b> {duration_text}\n\n"
                "All non-admin users will now see maintenance message.\n"
                "You can disable it anytime using the button below."
            )
            
            keyboard = [
                [InlineKeyboardButton("❌ Disable Maintenance", callback_data="maintenance:disable")],
                [InlineKeyboardButton("🔄 Refresh Status", callback_data="maintenance:status")]
            ]
        else:
            response_text = "❌ <b>Error</b>\n\nFailed to enable maintenance mode."
            keyboard = [[InlineKeyboardButton("🔄 Try Again", callback_data="maintenance:status")]]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message_text(
            query=query,
            text=response_text,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"🔧 ADMIN: User {user.id} enabled maintenance for {duration_minutes} minutes")
        
    except Exception as e:
        logger.error(f"❌ Error in handle_maintenance_enable: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await safe_edit_message_text(
            query=query,
            text="❌ <b>Error</b>\n\nFailed to enable maintenance mode.",
            parse_mode=ParseMode.HTML
        )

async def handle_maintenance_disable(query, context):
    """Handle disabling maintenance mode"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_maintenance_disable")
        return
    
    if not is_admin_user(user.id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to disable maintenance")
        return
    
    try:
        from services.maintenance_manager import MaintenanceManager
        
        await query.answer()
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        success = await MaintenanceManager.disable_maintenance()
        
        if success:
            response_text = (
                "✅ <b>Maintenance Mode Disabled</b>\n\n"
                "The system is now accessible to all users."
            )
            
            keyboard = [
                [InlineKeyboardButton("⏱ Enable Maintenance", callback_data="maintenance:status")]
            ]
        else:
            response_text = "❌ <b>Error</b>\n\nFailed to disable maintenance mode."
            keyboard = [[InlineKeyboardButton("🔄 Try Again", callback_data="maintenance:status")]]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message_text(
            query=query,
            text=response_text,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"🔧 ADMIN: User {user.id} disabled maintenance mode")
        
    except Exception as e:
        logger.error(f"❌ Error in handle_maintenance_disable: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await safe_edit_message_text(
            query=query,
            text="❌ <b>Error</b>\n\nFailed to disable maintenance mode.",
            parse_mode=ParseMode.HTML
        )

async def handle_maintenance_status(query, context):
    """Handle refreshing maintenance status"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_maintenance_status")
        return
    
    if not is_admin_user(user.id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await safe_edit_message_text(
            query=query,
            text=t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to check maintenance status")
        return
    
    try:
        from services.maintenance_manager import MaintenanceManager
        
        await query.answer()
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        status = await MaintenanceManager.get_maintenance_status()
        
        if status['is_active']:
            time_remaining = status.get('time_remaining_seconds', 0)
            if time_remaining and time_remaining > 0:
                minutes = time_remaining // 60
                seconds = time_remaining % 60
                time_text = f"⏳ <b>Time remaining:</b> {minutes} min {seconds} sec"
            else:
                time_text = "✅ Maintenance should be completing soon!"
            
            response_text = (
                "🔧 <b>Maintenance Mode Status</b>\n\n"
                f"<b>Status:</b> Active ✅\n"
                f"{time_text}\n\n"
                "Click below to disable maintenance mode."
            )
            
            keyboard = [
                [InlineKeyboardButton("❌ Disable Maintenance", callback_data="maintenance:disable")],
                [InlineKeyboardButton("🔄 Refresh Status", callback_data="maintenance:status")]
            ]
        else:
            response_text = (
                "🔧 <b>Maintenance Mode Status</b>\n\n"
                "<b>Status:</b> Inactive ❌\n\n"
                "Select duration to enable maintenance mode:"
            )
            
            keyboard = [
                [InlineKeyboardButton("⏱ 15 minutes", callback_data="maintenance:enable:15")],
                [InlineKeyboardButton("⏱ 30 minutes", callback_data="maintenance:enable:30")],
                [InlineKeyboardButton("⏱ 1 hour", callback_data="maintenance:enable:60")],
                [InlineKeyboardButton("⏱ 2 hours", callback_data="maintenance:enable:120")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message_text(
            query=query,
            text=response_text,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"🔧 ADMIN: User {user.id} refreshed maintenance status")
        
    except Exception as e:
        logger.error(f"❌ Error in handle_maintenance_status: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await safe_edit_message_text(
            query=query,
            text="❌ <b>Error</b>\n\nFailed to get maintenance status.",
            parse_mode=ParseMode.HTML
        )

# ========== ADMIN TEXT MESSAGE HANDLERS ==========

async def handle_admin_broadcast_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    High-priority text handler for admin broadcast messages.
    Only processes messages when admin is in broadcast mode.
    """
    # GROUP GUARD: Silently ignore messages from groups
    chat = update.effective_chat
    if chat and chat.type in ('group', 'supergroup'):
        return False
    
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message or not message.text:
        return False  # Let other handlers process this
    
    # Check if user is admin FIRST (before logging to avoid spam)
    if not is_admin_user(user.id):
        return False  # Not admin - let other handlers process
    
    # Only log for actual admin users
    logger.info(f"🔍 ADMIN BROADCAST HANDLER: Called for admin user {user.id}")
    
    logger.info(f"🔍 ADMIN BROADCAST HANDLER: Admin confirmed - checking states")
    logger.info(f"🔍 ADMIN BROADCAST HANDLER: context.user_data = {context.user_data}")
    
    # Check if awaiting broadcast
    if not context.user_data or not context.user_data.get('awaiting_broadcast'):
        logger.info(f"🔍 ADMIN BROADCAST HANDLER: Not in broadcast mode - awaiting_broadcast = {context.user_data.get('awaiting_broadcast') if context.user_data else 'None'}")
        return False  # Not in broadcast mode - let other handlers process
    
    try:
        broadcast_message = message.text.strip()
        
        if len(broadcast_message) == 0:
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.commands.broadcast.empty_message', admin_lang),
                parse_mode=ParseMode.HTML
            )
            return True
        
        # Clear broadcast flag immediately
        del context.user_data['awaiting_broadcast']
        
        # CRITICAL: Set timestamp to prevent domain search on broadcast text
        # This prevents admin broadcast messages from triggering domain searches
        import time
        context.user_data['last_broadcast_time'] = time.time()
        
        # Get admin language and send broadcast using shared helper
        admin_lang = await get_admin_language(user.id, user.language_code)
        result = await send_broadcast(broadcast_message, update, context, admin_lang)
        
        logger.info(f"📢 ADMIN TEXT: User {user.id} sent broadcast via text input: '{broadcast_message[:50]}{'...' if len(broadcast_message) > 50 else ''}'")
        return True  # Message handled
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast_text: {e}")
        # Clear broadcast flag on error
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.errors.broadcast_text_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return True  # Message handled

async def handle_admin_credit_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    High-priority text handler for admin credit wallet workflow.
    Only processes messages when admin is in credit mode.
    """
    # GROUP GUARD: Silently ignore messages from groups
    chat = update.effective_chat
    if chat and chat.type in ('group', 'supergroup'):
        return False
    
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message or not message.text:
        return False  # Let other handlers process this
    
    # Check if user is admin FIRST (before logging to avoid spam)
    if not is_admin_user(user.id):
        return False  # Not admin - let other handlers process
    
    # Only log for actual admin users
    logger.info(f"🔍 CREDIT HANDLER: Called for admin user {user.id}")
    
    logger.info(f"🔍 CREDIT HANDLER: Admin confirmed - checking credit state")
    
    # Check admin credit state with proper null safety
    if not context.user_data:
        logger.info(f"🔍 CREDIT HANDLER: No user_data context")
        return False  # Not in credit mode - let other handlers process
        
    credit_state = context.user_data.get('admin_credit_state')
    logger.info(f"🔍 CREDIT HANDLER: Credit state: {credit_state}")
    
    if not credit_state:
        logger.info(f"🔍 CREDIT HANDLER: No credit state - user_data keys: {list(context.user_data.keys())}")
        return False  # Not in credit mode - let other handlers process
    
    try:
        step = credit_state.get('step')
        if not message or not message.text:
            logger.info(f"🔍 CREDIT HANDLER: No message text")
            return False
            
        user_input = message.text.strip()
        logger.info(f"🔍 CREDIT HANDLER: Processing step '{step}' with input: '{user_input[:20]}...'")
        
        if step == 'awaiting_user_search':
            # Handle user search input
            logger.info(f"🔍 CREDIT HANDLER: Starting user search")
            await handle_admin_credit_user_search_text(update, context, user_input)
            logger.info(f"🔍 CREDIT HANDLER: User search completed successfully")
            raise ApplicationHandlerStop  # Stop other handlers from processing this message
        elif step == 'awaiting_amount':
            # Handle amount input
            target_telegram_id = credit_state.get('target_telegram_id')
            if target_telegram_id:
                logger.info(f"🔍 CREDIT HANDLER: Starting amount processing")
                await handle_admin_credit_amount_text(update, context, target_telegram_id, user_input)
                logger.info(f"🔍 CREDIT HANDLER: Amount processing completed successfully")
            raise ApplicationHandlerStop  # Stop other handlers from processing this message
        
        return False  # Unknown state - let other handlers process
        
    except ApplicationHandlerStop:
        # Allow control-flow exceptions to propagate
        raise
    except asyncio.CancelledError:
        # Allow asyncio cancellation to propagate  
        raise
    except Exception as e:
        logger.exception("Error in handle_admin_credit_text (%s): %s", e.__class__.__name__, str(e))
        # Clear credit state on error with null safety
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
        
        if user and message:
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.errors.processing_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )
        return True  # Handler processed the error

async def handle_admin_credit_user_search_text(update: Update, context: ContextTypes.DEFAULT_TYPE, user_input: str):
    """Handle admin search for user to credit via text input"""
    # Initialize variables at function scope to prevent unbound issues
    message = update.effective_message
    effective_user = update.effective_user
    
    try:
        message = update.effective_message
        
        # Parse user input - could be user ID or @username
        target_user = None
        
        if user_input.startswith('@'):
            # Username search
            username = user_input[1:]  # Remove @
            users = await execute_query(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            if users:
                target_user = users[0]
        else:
            # Try numeric User ID search (more robust than isdigit())
            try:
                telegram_id = int(user_input.strip())
                users = await execute_query(
                    "SELECT * FROM users WHERE telegram_id = %s",
                    (telegram_id,)
                )
                if users:
                    target_user = users[0]
            except ValueError:
                # Not a valid number, will fall through to "user not found"
                pass
        
        if not target_user:
            # No user found
            effective_user = update.effective_user
            if effective_user and message:
                admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
                await message.reply_text(
                t('admin.credit.user_not_found_detailed', admin_lang, user_input=user_input),
                parse_mode=ParseMode.HTML
            )
            return
        
        # User found - show user details and ask for amount
        effective_user = update.effective_user
        if not effective_user:
            return
        admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
        
        current_balance = float(target_user['wallet_balance'] or 0)
        balance_display = format_money(current_balance, 'USD', include_currency=True)
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        # Type-safe message reply for user found confirmation
        if message and hasattr(message, 'reply_text'):
            await message.reply_text(
                t('admin.credit.user_found', admin_lang,
                  display_name=escape_html(display_name),
                  username=escape_html(username_display),
                  user_id=target_user['telegram_id'],
                  current_balance=balance_display),
                parse_mode=ParseMode.HTML
            )
        
        # Update state for next step
        if not context.user_data:
            context.user_data = {}
        context.user_data['admin_credit_state'] = {
            'step': 'awaiting_amount',
            'target_telegram_id': target_user['telegram_id']
        }
        
    except Exception as e:
        logger.error(f"Error handling admin user search text: {e}")
        # Type-safe error handling with null checks - variables initialized at function scope
        if effective_user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
            await message.reply_text(
                t('admin.errors.search_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def handle_admin_credit_amount_text(update: Update, context: ContextTypes.DEFAULT_TYPE, target_telegram_id: int, amount_str: str):
    """Handle admin entering credit amount via text input"""
    # Initialize variables at function scope to prevent unbound issues
    message = update.effective_message
    effective_user = update.effective_user
    
    try:
        
        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount > 10000:  # Safety limit
                raise ValueError("Amount too large (max $10,000)")
        except ValueError as e:
            # Type-safe error handling for invalid amount
            effective_user = update.effective_user
            if effective_user and message and hasattr(message, 'reply_text'):
                admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
                await message.reply_text(
                    t('admin.credit.invalid_amount_detailed', admin_lang, amount=amount_str),
                    parse_mode=ParseMode.HTML
                )
            return
        
        # Clear credit state
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
        
        # Execute credit directly (since this is text input, we skip confirmation)
        await execute_admin_credit_direct(update, context, target_telegram_id, amount)
        
    except Exception as e:
        logger.error(f"Error handling admin credit amount text: {e}")
        # Type-safe error handling for amount processing - variables initialized at function scope
        if effective_user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
            await message.reply_text(
                t('admin.errors.amount_processing_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def execute_admin_credit_direct(update: Update, context: ContextTypes.DEFAULT_TYPE, target_telegram_id: int, amount: float):
    """Execute admin credit transaction directly (used by text input flow)"""
    # Initialize variables at function scope to prevent unbound issues
    user = update.effective_user
    message = update.effective_message
    
    try:
        
        # Get admin language and show processing message
        if not user:
            return
        admin_lang = await get_admin_language(user.id, user.language_code)
        if not message:
            return
        processing_message = await message.reply_text(
            t('admin.credit.processing', admin_lang),
            parse_mode=ParseMode.HTML
        )
        
        # Get target user details
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_telegram_id,)
        )
        
        if not users:
            await processing_message.edit_text(
                t('admin.commands.credit_wallet.user_not_found', admin_lang, user_id=target_telegram_id),
                parse_mode=ParseMode.HTML
            )
            return
        
        target_user = users[0]
        user_internal_id = target_user['id']
        
        # Execute the credit
        description = f"Admin credit by {user.username or user.first_name} (ID: {user.id})"
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_internal_id,
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            # Get updated balance
            new_balance = await get_user_wallet_balance(target_telegram_id)
            
            display_name = target_user.get('first_name', 'Unknown')
            if target_user.get('last_name'):
                display_name += f" {target_user['last_name']}"
            
            username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
            
            transaction_id = int(time.time())
            await processing_message.edit_text(
                t('admin.credit.transaction_successful', admin_lang,
                  display_name=escape_html(display_name),
                  username_display=escape_html(username_display),
                  amount=format_money(amount, 'USD', include_currency=True),
                  new_balance=format_money(new_balance, 'USD', include_currency=True),
                  transaction_id=transaction_id,
                  admin_name=escape_html(user.username or user.first_name)),
                parse_mode=ParseMode.HTML
            )
            
            # Send notification to the user who received the credit
            try:
                app = get_bot_application()
                if app:
                    user_lang = await get_user_notification_language(target_telegram_id)
                    user_notification = t('admin.notifications.user_credit', user_lang,
                                        amount=format_money(amount, 'USD', include_currency=True),
                                        new_balance=format_money(new_balance, 'USD', include_currency=True))
                    
                    await app.bot.send_message(
                        chat_id=target_telegram_id,
                        text=user_notification,
                        parse_mode=ParseMode.HTML
                    )
                    logger.info(f"✅ Notification sent to user {target_telegram_id} about ${amount} credit")
                else:
                    logger.warning(f"⚠️ Could not send notification - bot application not available")
                    
            except Exception as notification_error:
                logger.error(f"❌ Failed to send credit notification to user {target_telegram_id}: {notification_error}")
                # Don't fail the credit transaction if notification fails
            
            logger.info(f"💳 ADMIN: User {user.id} credited ${amount} to user {target_telegram_id}")
            
        else:
            await processing_message.edit_text(
                t('admin.credit.transaction_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
    except Exception as e:
        logger.error(f"Error executing admin credit direct: {e}")
        # Type-safe error handling for credit execution - variables initialized at function scope
        if user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.errors.execution_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def handle_admin_credit_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin credit wallet command with easy UX"""
    query = getattr(update, 'callback_query', None)
    
    if query:
        # Coming from callback button - set state and show search interface
        # Type-safe user_data access
        if context.user_data is None:
            context.user_data = {}
        context.user_data['admin_credit_state'] = {
            'step': 'awaiting_user_search'
        }
        await show_admin_credit_search(query, context)
    else:
        # Coming from direct command - type-safe message access
        logger.info("Admin credit wallet handler called")
        if update.message and hasattr(update.message, 'reply_text'):
            await update.message.reply_text("Admin credit wallet functionality not yet implemented")

async def show_admin_credit_search(query, context=None):
    """Show interface for admin to search for user to credit"""
    try:
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message_text(
            query=query,
            text=t('admin.credit.search_prompt', admin_lang),
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    except Exception as e:
        logger.error(f"Error showing admin credit search: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        try:
            # Use fallback error message if translation fails
            error_text = t('admin.errors.broadcast_interface_failed', admin_lang)
        except Exception:
            error_text = "❌ Error loading interface. Please try again."
        
        await safe_edit_message_text(
            query=query,
            text=error_text,
            parse_mode=ParseMode.HTML
        )

async def handle_admin_credit_user_search(query, user_input: str):
    """Handle admin search for user to credit"""
    try:
        # Parse user input - could be user ID or @username
        target_user = None
        
        if user_input.startswith('@'):
            # Username search
            username = user_input[1:]  # Remove @
            users = await execute_query(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            if users:
                target_user = users[0]
        else:
            # Try numeric User ID search (more robust than isdigit())
            try:
                telegram_id = int(user_input.strip())
                users = await execute_query(
                    "SELECT * FROM users WHERE telegram_id = %s",
                    (telegram_id,)
                )
                if users:
                    target_user = users[0]
            except ValueError:
                # Not a valid number, will fall through to "user not found"
                pass
        
        if not target_user:
            # No user found
            message = f"""
❌ <b>User Not Found</b>

Could not find user: {user_input}

Please check:
• User ID is correct (e.g., 1234567890)
• Username is correct (e.g., @johndoe)
• User has used the bot before

Try again with a different identifier:
"""
            
            # Get admin language for localized buttons - type-safe user access
            admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code) if query.from_user else 'en'
            
            keyboard = [
                [InlineKeyboardButton(t('buttons.try_again', admin_lang), callback_data="admin_credit_wallet")],
                [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message_text(
            query=query,
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            return
        
        # User found - show user details and ask for amount
        current_balance = float(target_user['wallet_balance'] or 0)
        logger.info(f"🔍 ADMIN_CREDIT DEBUG: wallet_balance raw = {target_user.get('wallet_balance')}, current_balance = {current_balance}")
        balance_display = format_money(current_balance, 'USD', include_currency=True)
        logger.info(f"🔍 ADMIN_CREDIT DEBUG: balance_display = '{balance_display}'")
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        message = f"""
✅ <b>User Found</b>\n\n<b>Name:</b> {escape_html(display_name)}\n<b>Username:</b> {escape_html(username_display)}\n<b>User ID:</b> <code>{target_user['telegram_id']}</code>\n<b>Current Balance:</b> {balance_display}\n\nEnter the <b>amount in USD</b> to credit to this user's wallet:

Examples: 25.00, 100, 50.50
"""
        
        # Get admin language for localized buttons - type-safe user access
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code) if query.from_user else 'en'
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message_text(
            query=query,
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        # Store user info for next step (we'll need a better state management approach)
        # For now, we'll store it in a way that can be retrieved
        
    except Exception as e:
        logger.error(f"Error handling admin user search: {e}")
        await safe_edit_message_text(
            query=query,
            text="❌ Error searching for user. Please try again.")

async def handle_admin_credit_amount(query, target_telegram_id: int, amount_str: str):
    """Handle admin entering credit amount"""
    try:
        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount > 10000:  # Safety limit
                raise ValueError("Amount too large (max $10,000)")
        except ValueError as e:
            message = f"""
❌ <b>Invalid Amount</b>

{amount_str} is not a valid amount.

Please enter a valid amount in USD:
• Must be a positive number
• Maximum $10,000.00
• Examples: 25.00, 100, 50.50
"""
            
            keyboard = [
                [InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message_text(
            query=query,
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            return
        
        # Get user details for confirmation
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_telegram_id,)
        )
        
        if not users:
            await safe_edit_message_text(
            query=query,
            text="❌ Error: User not found. Please start over.")
            return
        
        target_user = users[0]
        current_balance = float(target_user['wallet_balance'] or 0)
        new_balance = current_balance + amount
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        message = f"""
⚠️ <b>Confirm Credit Transaction</b>\n\n<b>User:</b> {escape_html(display_name)} ({escape_html(username_display)})\n<b>User ID:</b> <code>{target_telegram_id}</code>\n\n<b>Current Balance:</b> {format_money(current_balance, 'USD', include_currency=True)}\n<b>Credit Amount:</b> {format_money(amount, 'USD', include_currency=True)}\n<b>New Balance:</b> {format_money(new_balance, 'USD', include_currency=True)}\n\n⚠️ <b>This action cannot be undone!</b>

Are you sure you want to credit this amount?
"""
        
        # Get admin language for localized buttons
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.confirm_credit', admin_lang), callback_data=f"admin_execute_credit:{target_telegram_id}:{amount}")],
            [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message_text(
            query=query,
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    except Exception as e:
        logger.error(f"Error handling admin credit amount: {e}")
        await safe_edit_message_text(
            query=query,
            text="❌ Error processing credit amount. Please try again.")

async def execute_admin_credit(query, target_telegram_id: int, amount: float):
    """Execute the admin credit transaction"""
    try:
        admin_user = query.from_user
        
        # Show processing message
        await safe_edit_message_text(
            query=query,
            text="⏳ Processing credit transaction...")
        
        # Get target user details
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_telegram_id,)
        )
        
        if not users:
            await safe_edit_message_text(
            query=query,
            text="❌ Error: User not found.")
            return
        
        target_user = users[0]
        user_internal_id = target_user['id']
        
        # Execute the credit
        description = f"Admin credit by {admin_user.username or admin_user.first_name} (ID: {admin_user.id})"
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_internal_id,
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{admin_user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            # Get updated balance
            new_balance = await get_user_wallet_balance(target_telegram_id)
            
            display_name = target_user.get('first_name', 'Unknown')
            if target_user.get('last_name'):
                display_name += f" {target_user['last_name']}"
            
            username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
            
            message = f"""
✅ <b>Credit Transaction Successful</b>

<b>User:</b> {escape_html(display_name)} ({escape_html(username_display)})
<b>Amount Credited:</b> {format_money(amount, 'USD', include_currency=True)}
<b>New Balance:</b> {format_money(new_balance, 'USD', include_currency=True)}

Transaction completed successfully! 
The user's wallet has been credited.

<b>Transaction ID:</b> <code>{int(time.time())}</code>
<b>Admin:</b> {escape_html(admin_user.username or admin_user.first_name)}
"""
            
            # Get admin language for localized buttons
            admin_lang = await get_admin_language(admin_user.id, admin_user.language_code)
            
            keyboard = [
                [InlineKeyboardButton(t('admin.buttons.credit_another_user', admin_lang), callback_data="admin_credit_wallet")],
                [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message_text(
            query=query,
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            
            # Send notification to the user who received the credit
            try:
                app = get_bot_application()
                if app:
                    user_notification = f"""
🎉 <b>Wallet Credit: {format_money(amount, 'USD', include_currency=True)}</b>

New Balance: {format_money(new_balance, 'USD', include_currency=True)}
"""
                    
                    await app.bot.send_message(
                        chat_id=target_telegram_id,
                        text=user_notification,
                        parse_mode=ParseMode.HTML
                    )
                    logger.info(f"✅ Notification sent to user {target_telegram_id} about ${amount} credit")
                else:
                    logger.warning(f"⚠️ Could not send notification - bot application not available")
                    
            except Exception as notification_error:
                logger.error(f"❌ Failed to send credit notification to user {target_telegram_id}: {notification_error}")
                # Don't fail the credit transaction if notification fails
            
            logger.info(f"💳 ADMIN: User {admin_user.id} credited ${amount} to user {target_telegram_id}")
            
        else:
            await safe_edit_message_text(
            query=query,
            text="❌ <b>Credit Failed</b>\n\nTransaction could not be completed. Please try again or contact support."
            )
        
    except Exception as e:
        logger.error(f"Error executing admin credit: {e}")
        await safe_edit_message_text(
            query=query,
            text="❌ Error processing credit transaction. Please try again.")

