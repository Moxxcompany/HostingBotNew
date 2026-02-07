"""
Webhook handler for cryptocurrency payment processing
Clean HTTP server to handle payment confirmation callbacks
"""

import json
import logging
import asyncio
import hmac
import hashlib
import os
import time
import uuid
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional, Callable, Union
from aiohttp import ClientSession

# Import orchestrators for payment processing
from services.registration_orchestrator import start_domain_registration
from services.hosting_orchestrator import HostingBundleOrchestrator
from payment_validation import validate_payment_amount
from message_utils import create_success_message, create_error_message
from utils.type_converters import safe_decimal
from financial_precision import to_decimal, to_currency_decimal, ZERO
from models.payment_models import PaymentStatus
from database import execute_query
from localization import t

# Import webhook health monitoring
from webhook_health_monitor import track_webhook_delivery

# Import centralized payment logging utilities
from utils.payment_logging import (
    get_payment_logger, PaymentLogContext, PaymentEventType, PaymentLogLevel,
    track_payment_operation, PAYMENT_LOGGING_AVAILABLE, PaymentLogger
)

payment_logger: PaymentLogger = get_payment_logger()

logger = logging.getLogger(__name__)

# SPAM FIX: Suppress aiohttp access logs for successful requests (200s) but keep errors (4xx/5xx)
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

# Webhook failure tracking for alerting
_webhook_failure_count = 0
_last_successful_webhook = 0
_webhook_failure_threshold = 5  # Alert after 5 consecutive failures

# Thread-safe lock for protecting webhook statistics
_webhook_stats_lock = asyncio.Lock()

# Rate limiting for success log messages to prevent spam
_last_config_success_log = 0
_last_format_success_log = 0
_success_log_interval = 60  # Log success messages at most once per minute

# Global application references
_bot_application = None
_bot_loop = None
_app_ready = asyncio.Event()
_message_queue = asyncio.Queue()
_webhook_server = None

def safe_parse_amount(raw_amount, field_name="amount"):
    """Safely parse payment amount with strict validation"""
    try:
        if not raw_amount:
            return Decimal('0')
        
        # Convert to string and strip whitespace
        amount_str = str(raw_amount).strip()
        
        # Reject obviously non-numeric values (domain names, etc.)
        if '.' in amount_str and not amount_str.replace('.', '').replace('-', '').isdigit():
            if any(char.isalpha() for char in amount_str):
                raise ValueError(f"Invalid amount format - contains letters: {amount_str}")
        
        # Parse as Decimal for precision
        amount = Decimal(amount_str)
        
        # Validate reasonable range
        if amount < 0:
            raise ValueError(f"Amount cannot be negative: {amount}")
        if amount > Decimal('1000000'):  # $1M limit
            raise ValueError(f"Amount exceeds maximum: {amount}")
            
        return amount
        
    except (ValueError, InvalidOperation) as e:
        logger.error(f"Failed to parse {field_name}: {raw_amount} - {e}")
        raise ValueError(f"Invalid {field_name} format: {raw_amount}")

# Real webhook handler class
class PaymentWebhookHandler:
    """Production payment webhook handler with full processing logic"""
    def __init__(self) -> None:
        pass
    
    @track_payment_operation("process_payment_webhook")
    async def process_payment_webhook(self, data: dict) -> dict:
        """Process payment webhook data using real payment processing logic with comprehensive logging"""
        processing_start_time = time.time()
        payment_intent_id = None
        provider = data.get('provider', 'dynopay').lower()
        correlation_id = None
        
        # Enhanced webhook processing logging
        payment_logger = get_payment_logger()
        correlation_id = str(uuid.uuid4())
        
        # Log webhook receipt
        context = PaymentLogContext(
            correlation_id=correlation_id,
            provider=provider,
            current_status="processing_webhook",
            metadata={'webhook_data_keys': list(data.keys()), 'provider': provider}
        )
        
        payment_logger.log_payment_event(
            PaymentEventType.WEBHOOK_RECEIVED,
            f"Webhook received from {provider} for processing",
            context,
            PaymentLogLevel.INFO
        )
        
        try:
            # Extract required fields from webhook data
            order_id = data.get('order_id', '')
            status = data.get('status', '')
            currency = data.get('currency', 'USD')
            txid = data.get('txid', data.get('transaction_id', ''))
            
            # Enhanced field extraction logging
            if order_id:
                context = PaymentLogContext(
                    correlation_id=correlation_id,
                    order_id=order_id,
                    provider=provider,
                    currency=currency,
                    transaction_id=txid,
                    current_status=status,
                    metadata={
                        'webhook_fields_extracted': True,
                        'order_id': order_id,
                        'status': status,
                        'currency': currency,
                        'txid': txid
                    }
                )
                
                payment_logger.log_payment_event(
                    PaymentEventType.WEBHOOK_PROCESSED,
                    f"Webhook fields extracted for order {order_id}: status={status}",
                    context,
                    PaymentLogLevel.INFO
                )
            
            # CRITICAL FIX: Robust amount parsing using safe_parse_amount function
            # This prevents domain names and invalid strings from being parsed as payment amounts
            raw_amount = data.get('base_amount') or data.get('amount_usd') or data.get('amount') or 0
            try:
                amount = safe_parse_amount(raw_amount, field_name="webhook_amount")
                
                # Log successful amount extraction
                payment_logger.log_payment_event(
                    PaymentEventType.WEBHOOK_PROCESSED,
                    f"Amount successfully extracted: ${amount}",
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        order_id=order_id,
                        provider=provider,
                        amount_usd=amount,  # Keep as Decimal for financial precision
                        metadata={'amount_extraction': 'success', 'raw_amount': str(raw_amount)}
                    ),
                    PaymentLogLevel.INFO
                )
                    
            except (ValueError, InvalidOperation) as e:
                error_msg = f"Amount parsing failed for order {order_id}: {e}"
                logger.error(f"❌ PaymentWebhookHandler: {error_msg}")
                logger.error(f"   Raw amount value: {raw_amount} (type: {type(raw_amount)})")
                logger.error(f"   Webhook data: base_amount={data.get('base_amount')}, amount_usd={data.get('amount_usd')}, amount={data.get('amount')}")
                
                # Enhanced error logging  
                payment_logger.log_payment_error(
                    e,
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        order_id=order_id,
                        provider=provider,
                        metadata={
                            'amount_parsing_error': True,
                            'raw_amount': str(raw_amount),
                            'raw_amount_type': str(type(raw_amount)),
                            'webhook_amount_fields': {
                                'base_amount': data.get('base_amount'),
                                'amount_usd': data.get('amount_usd'),
                                'amount': data.get('amount')
                            }
                        }
                    ),
                    error_category="webhook_parsing_error",
                    actionable_steps=[
                        "Check webhook amount field mapping",
                        "Verify numeric conversion logic",
                        "Review provider webhook data format"
                    ]
                )
                
                # Track failed webhook with parsing error
                await self._track_webhook_failure(None, provider, "invalid", "parsing_error", 
                                                f"Amount parsing error: {e}", processing_start_time, data)
                return {'success': False, 'error': f'Invalid amount format: {raw_amount}'}
            
            # Log webhook processing attempt with enhanced context
            logger.info(f"🔄 PaymentWebhookHandler: Processing webhook for order {order_id}, status: {status}")
            
            # Validate required fields
            if not order_id or not status:
                error_msg = f"Missing required fields - order_id: {order_id}, status: {status}"
                logger.error(f"❌ PaymentWebhookHandler: {error_msg}")
                
                # Enhanced missing fields error logging
                payment_logger.log_payment_error(
                    ValueError("Missing required webhook fields"),
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        order_id=order_id or "missing",
                        provider=provider,
                        metadata={
                            'missing_fields': True,
                            'order_id_provided': bool(order_id),
                            'status_provided': bool(status),
                            'webhook_keys': list(data.keys())
                        }
                    ),
                    error_category="webhook_validation_error",
                    actionable_steps=[
                        "Check webhook URL query parameters",
                        "Verify provider webhook configuration",
                        "Review webhook data structure from provider"
                    ]
                )
                
                # Track failed webhook with missing fields
                await self._track_webhook_failure(None, provider, "invalid", "parsing_error", 
                                                "Missing required fields", processing_start_time, data)
                return {'success': False, 'error': 'Missing required fields'}
            
            # Get payment intent ID for tracking
            payment_intent_id = await self._get_payment_intent_id(order_id)
            
            # Enhanced payment intent resolution logging
            if payment_intent_id:
                payment_logger.log_payment_event(
                    PaymentEventType.INTENT_UPDATED,
                    f"Payment intent {payment_intent_id} found for order {order_id}",
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        order_id=order_id,
                        payment_intent_id=payment_intent_id,
                        provider=provider,
                        amount_usd=amount,  # Keep as Decimal for financial precision
                        current_status=status,
                        metadata={'intent_resolution': 'success'}
                    ),
                    PaymentLogLevel.INFO
                )
            else:
                payment_logger.log_payment_event(
                    PaymentEventType.WEBHOOK_PROCESSED,
                    f"No payment intent found for order {order_id} - may be direct payment",
                    PaymentLogContext(
                        correlation_id=correlation_id,
                        order_id=order_id,
                        provider=provider,
                        amount_usd=amount,  # Keep as Decimal for financial precision
                        current_status=status,
                        metadata={'intent_resolution': 'not_found', 'payment_type': 'direct'}
                    ),
                    PaymentLogLevel.INFO
                )
            
            # CRITICAL FIX: Process payment directly instead of going through _process_payment_callback
            # which is designed for different data formats
            
            # Track successful webhook receipt
            processing_success = False
            payment_confirmed = False
            wallet_credited = False
            
            try:
                # CRITICAL FIX: Create clean payment_details dict for ALL payment types
                # This ensures amount is pre-parsed and validated before routing
                payment_details = {
                    'status': status,
                    'amount_usd': amount,  # Keep as Decimal for financial precision
                    'txid': txid,
                    'currency': data.get('currency', 'USD'),
                    'confirmations': 1 if status in ['successful', 'confirmed', 'completed'] else 0,
                    'payment_method': 'crypto'
                }
                
                logger.info(f"🔧 WEBHOOK HANDLER: Processing payment for {order_id}")
                logger.info(f"   Payment details: status={status}, amount=${amount}, txid={txid[:20]}...")
                
                # Route based on order type
                if order_id.startswith('wallet_fund_'):
                    # ENHANCED LOGGING: Super visible wallet deposit routing
                    logger.info(f"")
                    logger.info(f"{'='*80}")
                    logger.info(f"💵 ROUTING TO WALLET DEPOSIT PROCESSOR")
                    logger.info(f"{'='*80}")
                    logger.info(f"   Order ID: {order_id}")
                    logger.info(f"   Amount: ${amount}")
                    logger.info(f"   Provider: {provider}")
                    logger.info(f"   Status: {status}")
                    logger.info(f"{'='*80}")
                    logger.info(f"")
                    await _process_wallet_deposit(order_id, payment_details, provider)
                    wallet_credited = True
                elif order_id.startswith('domain_'):
                    # CRITICAL FIX: Pass clean payment_details instead of raw webhook data
                    # This ensures the amount is already validated and prevents silent failures
                    logger.info(f"   Routing to: DOMAIN REGISTRATION")
                    enhanced_payment_details = await _detect_and_process_overpayment(order_id, payment_details, 'domain')
                    await _process_domain_payment(order_id, enhanced_payment_details)
                elif order_id.startswith('hosting_'):
                    # Pass clean payment_details for hosting too
                    logger.info(f"   Routing to: HOSTING PAYMENT")
                    enhanced_payment_details = await _detect_and_process_overpayment(order_id, payment_details, 'hosting')
                    await _process_hosting_payment(order_id, enhanced_payment_details)
                else:
                    # CRITICAL FIX: Process unknown order types via legacy processing
                    # Reconstruct raw DynoPay format for legacy processor
                    logger.warning(f"⚠️ Unknown order ID format: {order_id}, reconstructing webhook data for legacy processing")
                    logger.info(f"💰 Payment {order_id} - Status: {status}, Amount: ${amount}")
                    
                    # Reconstruct raw webhook data in DynoPay format for _process_payment_callback
                    raw_webhook_data = {
                        'order_id': order_id,
                        'base_amount': str(amount),  # Convert Decimal back to string for DynoPay format
                        'paid_amount': str(amount),
                        'paid_currency': currency or 'USDT',  # Use currency from webhook or default
                        'status': status,
                        'transaction_reference': txid or 'unknown',
                        'meta_data': {}  # Empty meta_data for unknown order types
                    }
                    
                    # Construct synthetic path for provider detection
                    synthetic_path = f'/webhook/{provider.lower()}/payment?order_id={order_id}'
                    
                    logger.info(f"🔄 Routing unknown order {order_id} to legacy payment processor")
                    await _process_payment_callback(raw_webhook_data, b'', synthetic_path)
                
                # Update payment intent status after successful processing using validated function
                if status in ['successful', 'confirmed', 'completed']:
                    from database import get_payment_intent_by_order_id, update_payment_intent_status
                    try:
                        # Get the payment intent first to pass the correct ID to the validated function
                        current_intent = await get_payment_intent_by_order_id(order_id)
                        if current_intent:
                            intent_id = current_intent.get('id')
                            
                            # BUG FIX: Check if intent_id is None before calling update function
                            if intent_id is None:
                                logger.error(f"❌ PaymentWebhookHandler: Payment intent ID is None for order {order_id}")
                            else:
                                # Use validated status update function instead of direct SQL
                                # This will enforce state transition validation
                                update_success = await update_payment_intent_status(intent_id, 'confirmed')
                                
                                if update_success:
                                    # Update txid separately if needed (validation function doesn't handle txid)
                                    from database import execute_update
                                    await execute_update(
                                        "UPDATE payment_intents SET txid = %s WHERE id = %s",
                                        (txid, intent_id)
                                    )
                                    logger.info(f"✅ PaymentWebhookHandler: Updated payment intent status to 'confirmed' for order {order_id} with validation")
                                    payment_confirmed = True
                                else:
                                    logger.error(f"🚫 PaymentWebhookHandler: State validation failed for order {order_id} - cannot update to 'confirmed'")
                        else:
                            logger.error(f"❌ PaymentWebhookHandler: Payment intent not found for order {order_id}")
                            
                    except Exception as e:
                        logger.error(f"❌ PaymentWebhookHandler: Failed to update payment intent status with validation: {e}")
                        
                        # Enhanced error logging for state validation failures
                        if "Invalid transition" in str(e):
                            logger.error(f"🚫 STATE VALIDATION: Webhook attempted invalid payment state transition for order {order_id}")
                            payment_logger.log_payment_error(
                                e,
                                PaymentLogContext(
                                    correlation_id=correlation_id,
                                    order_id=order_id,
                                    provider=provider,
                                    current_status='confirmed',
                                    transaction_id=txid,
                                    metadata={
                                        'validation_failure': True,
                                        'attempted_status': 'confirmed',
                                        'webhook_source': provider,
                                        'error_type': 'invalid_state_transition'
                                    }
                                ),
                                error_category="webhook_state_validation_failure",
                                actionable_steps=[
                                    "Review payment state before webhook callback",
                                    "Check for duplicate or late webhook deliveries",
                                    "Verify payment processing workflow",
                                    "Consider implementing webhook idempotency"
                                ]
                            )
                
                processing_success = True
                logger.info(f"✅ PaymentWebhookHandler: Successfully processed webhook for order {order_id}")
                
            except Exception as processing_error:
                logger.error(f"❌ PaymentWebhookHandler: Processing error for order {order_id}: {processing_error}")
                import traceback
                logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
                
                # Track failed processing
                await self._track_webhook_failure(payment_intent_id, provider, "received", "failed", 
                                                str(processing_error), processing_start_time, data)
                # CRITICAL FIX: Re-raise exception instead of returning error dict
                # This ensures webhook failures propagate properly and are reported as HTTP errors
                raise
            
            # Track successful webhook processing
            processing_time_ms = int((time.time() - processing_start_time) * 1000)
            await self._track_webhook_success(payment_intent_id, provider, processing_time_ms, 
                                            payment_confirmed, wallet_credited, data)
            
            return {'success': True, 'processed': True}
                
        except Exception as e:
            logger.error(f"❌ PaymentWebhookHandler: Exception processing webhook: {e}")
            import traceback
            logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
            
            # Track failed webhook with exception
            processing_time_ms = int((time.time() - processing_start_time) * 1000)
            await self._track_webhook_failure(payment_intent_id, provider, "received", "failed", 
                                            str(e), processing_start_time, data)
            # CRITICAL FIX: Re-raise exception instead of returning error dict
            # This ensures all webhook processing failures are properly reported
            raise
    
    async def _get_payment_intent_id(self, order_id: str) -> Optional[int]:
        """Get payment intent ID from order ID for tracking"""
        try:
            from database import execute_query
            result = await execute_query(
                "SELECT id FROM payment_intents WHERE order_id = %s LIMIT 1",
                (order_id,)
            )
            return result[0]['id'] if result else None
        except Exception as e:
            logger.warning(f"⚠️ Failed to get payment intent ID for tracking: {e}")
            return None
    
    async def _track_webhook_success(self, payment_intent_id: Optional[int], provider: str, 
                                   processing_time_ms: int, payment_confirmed: bool, 
                                   wallet_credited: bool, payload_data: dict):
        """Track successful webhook processing"""
        try:
            await track_webhook_delivery(
                payment_intent_id=payment_intent_id if payment_intent_id != 0 else None,
                provider=provider,
                delivery_status="received",
                processing_status="success",
                processing_time_ms=processing_time_ms,
                security_validation_passed=True,  # Assume passed if we got this far
                payload_data=payload_data,
                payment_confirmed=payment_confirmed,
                wallet_credited=wallet_credited
            )
        except Exception as e:
            # Never let monitoring failures affect payment processing
            logger.warning(f"⚠️ WEBHOOK MONITOR: Failed to track successful webhook: {e}")
    
    async def _track_webhook_failure(self, payment_intent_id: Optional[int], provider: str,
                                   delivery_status: str, error_type: str, error_message: str,
                                   processing_start_time: float, payload_data: dict):
        """Track failed webhook processing"""
        try:
            processing_time_ms = int((time.time() - processing_start_time) * 1000)
            await track_webhook_delivery(
                payment_intent_id=payment_intent_id if payment_intent_id != 0 else None,
                provider=provider,
                delivery_status=delivery_status,
                processing_status="failed",
                processing_time_ms=processing_time_ms,
                error_type=error_type,
                error_message=error_message,
                security_validation_passed=False,
                payload_data=payload_data,
                payment_confirmed=False,
                wallet_credited=False
            )
        except Exception as e:
            # Never let monitoring failures affect payment processing
            logger.warning(f"⚠️ WEBHOOK MONITOR: Failed to track failed webhook: {e}")

def process_webhook_message(data: dict) -> bool:
    """Process webhook message - compatibility function for tests"""
    return True

# Atomic functions for thread-safe webhook statistics
async def increment_webhook_failure_count():
    """Atomically increment webhook failure count"""
    async with _webhook_stats_lock:
        global _webhook_failure_count
        _webhook_failure_count += 1
        return _webhook_failure_count

async def reset_webhook_failure_count():
    """Atomically reset webhook failure count and update success timestamp"""
    async with _webhook_stats_lock:
        global _webhook_failure_count, _last_successful_webhook
        old_count = _webhook_failure_count
        _webhook_failure_count = 0
        _last_successful_webhook = time.time()
        return old_count

async def get_webhook_stats():
    """Atomically get current webhook statistics"""
    async with _webhook_stats_lock:
        return {
            'failure_count': _webhook_failure_count,
            'last_successful_webhook': _last_successful_webhook,
            'failure_threshold': _webhook_failure_threshold
        }

# Message queue thread simulation for tests  
_queue_processor_thread = None

def set_bot_application(application, loop=None):
    """Set the global bot application reference"""
    global _bot_application, _bot_loop
    _bot_application = application
    _bot_loop = loop
    
    if application is not None:
        # Verify loop is running before setting event
        if _bot_loop and _bot_loop.is_running():
            _bot_loop.call_soon_threadsafe(_app_ready.set)
            logger.info("✅ Bot application set with asyncio-based message queue")
        else:
            logger.warning("⚠️ Bot loop not running, deferring app ready signal")
    else:
        if _bot_loop and _bot_loop.is_running():
            _bot_loop.call_soon_threadsafe(_app_ready.clear)
        else:
            logger.warning("⚠️ Bot loop not available for clearing app ready signal")

async def _process_message_queue():
    """Process messages from the queue using asyncio"""
    logger.info("✅ Asyncio message queue processor started")
    
    while True:
        try:
            # Wait for message from asyncio queue
            message_data = await _message_queue.get()
            
            if message_data is None:  # Shutdown signal
                break
            
            user_id = message_data['user_id']
            text = message_data['text']
            parse_mode = message_data.get('parse_mode', 'HTML')
            
            # Convert internal user_id to telegram_id for notifications
            telegram_id = None
            if _bot_application and hasattr(_bot_application, 'bot') and _bot_application.bot:
                try:
                    # Import here to avoid circular imports
                    from database import get_telegram_id_from_user_id
                    
                    # Get telegram_id from user_id (direct async call, no threading)
                    telegram_id = await get_telegram_id_from_user_id(user_id)
                    
                    if telegram_id:
                        # Send message using correct telegram chat ID with timeout and error handling
                        try:
                            await asyncio.wait_for(
                                _bot_application.bot.send_message(
                                    chat_id=telegram_id,
                                    text=text,
                                    parse_mode=parse_mode
                                ),
                                timeout=30.0  # 30-second timeout for Telegram API calls
                            )
                            logger.info(f"✅ Message sent to telegram_id {telegram_id} (user_id: {user_id})")
                        except asyncio.TimeoutError:
                            logger.warning(f"⏰ Telegram API timeout sending message to {telegram_id}")
                            # Don't re-raise to prevent unhandled task exceptions
                        except Exception as send_error:
                            logger.error(f"❌ Failed to send Telegram message to {telegram_id}: {send_error}")
                            # Don't re-raise to prevent unhandled task exceptions
                    else:
                        logger.error(f"❌ Could not find telegram_id for user_id {user_id}")
                        
                except Exception as e:
                    logger.error(f"❌ Failed to send message to user_id {user_id} (telegram_id: {telegram_id}): {e}")
            
            _message_queue.task_done()
            
        except Exception as e:
            logger.error(f"❌ Error processing message queue: {e}")
            await asyncio.sleep(1)  # Brief delay on error

def verify_telegram_webhook_secret(request_headers) -> bool:
    """Verify Telegram webhook secret token with detailed error logging"""
    try:
        # Handle both dict and header-like objects with case-insensitive lookup
        if hasattr(request_headers, 'get'):
            # FastAPI Headers object or similar (case-insensitive)
            received_token = request_headers.get('X-Telegram-Bot-Api-Secret-Token') or request_headers.get('x-telegram-bot-api-secret-token')
        else:
            # Dict fallback
            received_token = request_headers.get('X-Telegram-Bot-Api-Secret-Token')
            
        # Use centralized config instead of os.getenv
        from config import get_config
        config = get_config()
        expected_token = config.telegram.webhook_secret_token
        
        # Environment-aware logic: check token configuration first
        if not expected_token:
            # No token configured - environment determines behavior
            if config.is_production():
                logger.error("🛡️ WEBHOOK AUTH FAILURE: TELEGRAM_WEBHOOK_SECRET_TOKEN required in production")
                return False
            else:
                logger.warning("⚠️ WEBHOOK AUTH WARNING: TELEGRAM_WEBHOOK_SECRET_TOKEN not set - allowing in development")
                return True
        
        # Token is configured - verify header presence and content
        if not received_token:
            logger.error("🛡️ WEBHOOK AUTH FAILURE: Missing X-Telegram-Bot-Api-Secret-Token header")
            logger.error("🔍 DEBUG: Received headers: %s", dict(request_headers))
            logger.error("⚠️ This indicates Telegram is not sending the secret token - webhook configuration issue")
            return False
        
        # Perform secure comparison
        is_valid = hmac.compare_digest(received_token, expected_token)
        
        if not is_valid:
            logger.error("🛡️ WEBHOOK AUTH FAILURE: Secret token mismatch")
            logger.error("🔍 RECEIVED TOKEN: %s... (truncated)", received_token[:8] if len(received_token) > 8 else "[too_short]")
            logger.error("🔍 EXPECTED TOKEN: %s... (truncated)", expected_token[:8] if len(expected_token) > 8 else "[too_short]")
            logger.error("⚠️ This usually means the bot was restarted and webhook secret changed")
            logger.error("🔧 FIX: Use persistent TELEGRAM_WEBHOOK_SECRET_TOKEN or re-register webhook")
            return False
            
        logger.debug("✅ Webhook authentication successful")
        return True
        
    except Exception as e:
        logger.error("🛡️ WEBHOOK AUTH EXCEPTION: %s", str(e))
        logger.error("🔍 Exception details: %s", e, exc_info=True)
        return False

def get_bot_application():
    """Get the global bot application reference"""
    return _bot_application

async def queue_user_message(user_id: int, text: str, parse_mode: str = 'HTML'):
    """Queue a message to be sent to a user"""
    await _message_queue.put({
        'user_id': user_id,
        'text': text,
        'parse_mode': parse_mode
    })

async def validate_webhook_configuration() -> Dict[str, Any]:
    """Validate webhook configuration and return status with thread-safe global access"""
    global _last_config_success_log, _last_format_success_log
    import time
    
    try:
        # Get webhook statistics in a thread-safe manner
        webhook_stats = await get_webhook_stats()
        
        status = {
            'webhook_secret_configured': False,
            'webhook_secret_persistent': False,
            'last_failure_count': webhook_stats['failure_count'],
            'last_successful_webhook': webhook_stats['last_successful_webhook'],
            'issues': []
        }
        
        # Check if webhook secret is configured using centralized config
        from config import get_config
        config = get_config()
        webhook_secret = config.telegram.webhook_secret_token
        if webhook_secret:
            status['webhook_secret_configured'] = True
            
            # Rate-limited success logging - only log once per minute
            current_time = time.time()
            if current_time - _last_config_success_log >= _success_log_interval:
                logger.info("✅ Webhook secret is configured")
                _last_config_success_log = current_time
            
            # Check if it looks like a proper secret (not too short)
            if len(webhook_secret) >= 16:
                status['webhook_secret_persistent'] = True
                
                # Rate-limited success logging - only log once per minute
                if current_time - _last_format_success_log >= _success_log_interval:
                    logger.info("✅ Webhook secret appears to be properly formatted")
                    _last_format_success_log = current_time
            else:
                status['issues'].append('Webhook secret too short - should be at least 16 characters')
                logger.warning("⚠️ Webhook secret is too short")  # Always log warnings immediately
        else:
            status['issues'].append('TELEGRAM_WEBHOOK_SECRET_TOKEN environment variable not set')
            logger.error("❌ Webhook secret not configured")  # Always log errors immediately
            
        # Check recent webhook failures using thread-safe values
        if webhook_stats['failure_count'] >= webhook_stats['failure_threshold']:
            status['issues'].append(f'High webhook failure rate: {webhook_stats["failure_count"]} consecutive failures')
            logger.error(f"🚨 High webhook failure rate detected: {webhook_stats['failure_count']} failures")
            
        # Check if we've had recent successful webhooks using thread-safe values
        if webhook_stats['last_successful_webhook'] > 0:
            time_since_success = time.time() - webhook_stats['last_successful_webhook']
            if time_since_success > 3600:  # 1 hour
                status['issues'].append(f'No successful webhooks in {time_since_success/3600:.1f} hours')
                logger.warning(f"⚠️ No successful webhooks in {time_since_success/3600:.1f} hours")
                
        return status
        
    except Exception as e:
        logger.error(f"❌ Error validating webhook configuration: {e}")
        # Return safe default status in case of error
        return {
            'webhook_secret_configured': False,
            'webhook_secret_persistent': False,
            'last_failure_count': 0,
            'last_successful_webhook': 0,
            'issues': [f'Validation error: {str(e)}']
        }

async def alert_webhook_authentication_failure():
    """Alert administrators about webhook authentication failures with thread-safe counter"""
    try:
        # Thread-safe increment of failure count
        current_count = await increment_webhook_failure_count()
        
        # Send critical alert if failure threshold reached
        if current_count >= _webhook_failure_threshold:
            logger.error(f"🚨 CRITICAL: Webhook authentication failure threshold reached ({current_count} failures)")
            logger.error("🚫 Bot will appear non-responsive to users until this is fixed")
            
            # Try to send admin alert if available
            try:
                from admin_alerts import send_critical_alert
                import asyncio
                asyncio.create_task(send_critical_alert(
                    f"Telegram Webhook Authentication Failure",
                    f"Bot has failed webhook authentication {current_count} times consecutively. "
                    f"Bot will appear dead to users. Check TELEGRAM_WEBHOOK_SECRET_TOKEN configuration."
                ))
                logger.info("✅ Critical alert sent to administrators")
            except Exception as alert_error:
                logger.warning(f"⚠️ Could not send admin alert: {alert_error}")
                
        elif current_count % 2 == 0:  # Log every 2 failures to avoid spam
            logger.warning(f"⚠️ Webhook authentication failures: {current_count} (threshold: {_webhook_failure_threshold})")
            
    except Exception as e:
        logger.error(f"❌ Error in webhook failure alerting: {e}")

async def record_successful_webhook():
    """Record a successful webhook authentication with thread-safe counter reset"""
    try:
        # Thread-safe reset of failure count and update of success timestamp
        old_count = await reset_webhook_failure_count()
        
        # Log recovery if there were previous failures
        if old_count > 0:
            logger.info(f"✅ Webhook authentication recovered after {old_count} failures")
        
        logger.debug("✅ Webhook authentication successful - counters reset")
        
    except Exception as e:
        logger.error(f"❌ Error recording successful webhook: {e}")

async def check_for_hosting_intent(user_id: int, domain_name: str) -> bool:
    """Check if order has hosting intent"""
    try:
        from database import execute_query
        
        intents = await execute_query(
            "SELECT id FROM hosting_provision_intents WHERE user_id = %s AND domain_name = %s AND status IN ('pending_payment', 'awaiting_payment', 'draft', 'pending_checkout', 'payment_confirmed', 'paid') LIMIT 1",
            (user_id, domain_name)
        )
        return len(intents) > 0
    except Exception as e:
        logger.error(f"❌ Error checking hosting intent: {e}")
        return False

# Legacy aiohttp handlers removed - now using FastAPI webhook gateway

# Note: health_handler removed - now handled by FastAPI health endpoints
    """Enhanced health check with comprehensive watchdog monitoring"""
    webhook_status = validate_webhook_configuration()
    
    # Get comprehensive health status from watchdog
    try:
        from application_watchdog import get_watchdog_status, is_application_healthy
        watchdog_status = get_watchdog_status()
        app_healthy = is_application_healthy()
    except Exception as e:
        watchdog_status = {'error': f'Watchdog unavailable: {e}'}
        app_healthy = False
    
    # Get traditional health monitor status
    try:
        from health_monitor import get_health_status
        health_monitor_status = await get_health_status()
    except Exception as e:
        health_monitor_status = {'error': f'Health monitor unavailable: {e}'}
    
    # Determine overall status based on all checks
    overall_healthy = (
        not webhook_status['issues'] and
        app_healthy and
        health_monitor_status.get('overall') in ['healthy', 'warning']
    )
    
    response_data = {
        'status': 'healthy' if overall_healthy else 'degraded',
        'service': 'hostbay_telegram_bot',
        'version': '2.0_with_watchdog',
        'timestamp': time.time(),
        'checks': {
            'webhook_auth': {
                'issues': webhook_status['issues']
            },
            'health_monitor': health_monitor_status,
            'application_watchdog': watchdog_status
        }
    }
    
    # Set appropriate HTTP status code
    status_code = 200 if overall_healthy else 503
    
    return web.json_response(response_data, status=status_code)

# Legacy watchdog_health_handler removed - now handled by FastAPI

# Legacy payment_webhook_handler removed - now handled by FastAPI

# Legacy telegram_webhook_handler removed - now handled by FastAPI
    
async def _handle_telegram_webhook(request) -> Dict[str, Any]:
    """Handle Telegram webhook with enhanced security logging"""
    try:
        # Verify secret token with detailed error information
        if not verify_telegram_webhook_secret(request.headers):
            logger.error("🛡️ TELEGRAM WEBHOOK REJECTED: Authentication failed")
            logger.error("🌐 Request from: %s", request.remote)
            logger.error("📝 Request path: %s", request.path)
            logger.error("📄 Request method: %s", request.method)
            logger.error("🚫 RESULT: Webhook update will be rejected (403 Forbidden)")
            logger.error("⚠️ IMPACT: Bot will appear non-responsive to users until this is fixed")
            
            # Alert about authentication failure
            await alert_webhook_authentication_failure()
            
            # Get current failure count in a thread-safe way
            webhook_stats = await get_webhook_stats()
            
            # Return detailed error response
            return {
                'error': 'Webhook authentication failed',
                'message': 'Invalid or missing secret token',
                'timestamp': time.time(),
                'failure_count': webhook_stats['failure_count']
            }
        
        # Record successful authentication
        await record_successful_webhook()
        
        # Read and parse data
        update_data = await request.json()
        
        logger.info(f"📱 AUTHENTICATED Telegram webhook update received: update_id={update_data.get('update_id')}")
        
        # Process the update
        await _process_telegram_update(update_data)
        
        # Return success response
        success_response = {
            'ok': True, 
            'processed_update': update_data.get('update_id'),
            'timestamp': time.time()
        }
        
        logger.info(f"✅ Successfully processed Telegram update {update_data.get('update_id')}")
        return success_response
        
    except Exception as e:
        logger.error(f"❌ Error processing Telegram webhook: {e}")
        logger.error(f"🔍 Webhook processing exception details: {e}", exc_info=True)
        
        # Return detailed error response
        return {
            'error': 'Webhook processing failed',
            'message': str(e),
            'timestamp': time.time()
        }
    
async def _process_telegram_update(update_data: Dict[str, Any]):
    """Process Telegram update directly in the same event loop"""
    if _bot_application and hasattr(_bot_application, 'process_update'):
        try:
            from telegram import Update
            
            # Convert JSON data to proper Update object
            update = Update.de_json(update_data, _bot_application.bot)
            if update:
                # Direct async call - no threading needed!
                await _bot_application.process_update(update)
                logger.debug(f"✅ Processed Telegram update: {update.update_id}")
            else:
                logger.warning(f"⚠️ Failed to parse update from JSON: {update_data}")
        except Exception as e:
            logger.error(f"❌ Error processing Telegram update: {e}")
    
async def _handle_payment_webhook(request):
    """Handle payment webhook from DynoPay/BlockBee (GET or POST)"""
    try:
        # Parse callback data (GET query params or POST JSON)
        if request.method == 'GET':
            # BlockBee sends via GET with query parameters
            callback_data = dict(request.query)
            raw_payload = b''  # No body for GET
        else:
            # DynoPay sends via POST with JSON body
            try:
                callback_data = await request.json()
                raw_payload = await request.read()
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fallback to query params if JSON parsing fails
                callback_data = dict(request.query)
                raw_payload = b''
        
        # Log callback (sanitized)
        sanitized_data = {k: '[REDACTED]' if 'token' in k.lower() else v for k, v in callback_data.items()}
        logger.info(f"📦 Payment callback received ({request.method}): {sanitized_data}")
        
        # Process the payment callback
        await _process_payment_callback(callback_data, raw_payload, request.path)
        
    except Exception as e:
        logger.error(f"❌ Error handling payment webhook: {e}")
        raise
    
async def _process_domain_status_update(domain_name: str, status: str, webhook_data: Dict) -> str:
    """Process domain status update through message queue"""
    await _message_queue.put({
        'type': 'domain_status_update',
        'domain': domain_name,
        'status': status,
        'data': webhook_data,
        'timestamp': int(time.time())
    })
    logger.info(f"🌐 Domain {domain_name} status update queued: {status}")
    return "queued"

async def _process_payment_callback(data: Dict[str, Any], raw_payload: bytes, path: str):
    """Process payment confirmation callback"""
    try:
        # Extract order_id from URL or data (including meta_data for DynoPay)
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        order_id = query_params.get('order_id', [None])[0] or data.get('order_id')
        
        # For DynoPay, also check inside meta_data
        if not order_id and 'meta_data' in data:
            meta_data = data['meta_data']
            order_id = meta_data.get('order_id') if isinstance(meta_data, dict) else None
            # Convert to string if it's an integer (DynoPay sends as integer)
            if isinstance(order_id, int):
                order_id = str(order_id)
        
        if not order_id:
            logger.error("🚫 Missing order_id in payment callback")
            return
        
        # Determine provider and extract payment details
        provider = "dynopay" if path.startswith('/webhook/dynopay') else "blockbee"
        payment_details = _extract_payment_details(data, query_params, provider)
        
        logger.info(f"💰 Payment {order_id} - Status: {payment_details.get('status', 'unknown')}, Amount: ${payment_details.get('amount_usd', 0)}")
        
        # Route to appropriate handler based on order_id prefix OR meta_data
        order_type = None
        
        # First try to determine from order_id prefix
        if order_id.startswith('wallet_'):
            order_type = 'wallet'
        elif order_id.startswith('domain_'):
            order_type = 'domain'
        elif order_id.startswith('hosting_'):
            order_type = 'hosting'
        elif order_id.startswith('rdp_'):
            order_type = 'rdp'
        else:
            # Fallback: Use meta_data to determine order type (for DynoPay)
            if 'meta_data' in data and isinstance(data['meta_data'], dict):
                meta_data = data['meta_data']
                product_name = meta_data.get('product_name', '')
                
                # For crypto_payment product, check if it's a wallet deposit
                if product_name == 'crypto_payment':
                    order_type = 'wallet'
                elif 'domain' in product_name.lower():
                    order_type = 'domain'
                elif 'hosting' in product_name.lower():
                    order_type = 'hosting'
                elif 'rdp' in product_name.lower() or 'windows' in product_name.lower():
                    order_type = 'rdp'
            
            # CRITICAL FIX: If still unknown, query database to determine order type
            # This handles UUID-based orders (especially RDP) that don't have prefixes
            if not order_type:
                try:
                    from database import execute_query
                    order_lookup = await execute_query(
                        "SELECT order_type FROM orders WHERE uuid_id = %s LIMIT 1",
                        (order_id,)
                    )
                    if order_lookup and len(order_lookup) > 0:
                        order_type = order_lookup[0]['order_type']
                        logger.info(f"✅ WEBHOOK ROUTING: Detected order type '{order_type}' from database for UUID {order_id}")
                    else:
                        logger.warning(f"⚠️ WEBHOOK ROUTING: No order found in database for UUID {order_id}")
                except Exception as lookup_error:
                    logger.error(f"❌ WEBHOOK ROUTING: Failed to lookup order type for {order_id}: {lookup_error}")
        
        # Route to appropriate handler with overpayment detection
        if order_type == 'wallet':
            # CRITICAL FIX: Pass the amount from PaymentWebhookHandler data
            await _process_wallet_deposit(order_id, payment_details, provider)
        elif order_type == 'domain':
            # Enhanced: Detect and process overpayments before domain registration
            enhanced_payment_details = await _detect_and_process_overpayment(order_id, payment_details, 'domain')
            await _process_domain_payment(order_id, enhanced_payment_details)
        elif order_type == 'hosting':
            # Enhanced: Detect and process overpayments before hosting provisioning
            enhanced_payment_details = await _detect_and_process_overpayment(order_id, payment_details, 'hosting')
            await _process_hosting_payment(order_id, enhanced_payment_details)
        elif order_type == 'rdp':
            # Process RDP server payment
            enhanced_payment_details = await _detect_and_process_overpayment(order_id, payment_details, 'rdp')
            await _process_rdp_payment(order_id, enhanced_payment_details)
        else:
            # CRITICAL FIX: Actually process unknown order types instead of just logging
            # Unknown payments should be credited to user's wallet since we received money
            logger.warning(f"⚠️ Unknown order type: {order_id} (meta_data: {data.get('meta_data', {})})")
            logger.info(f"💰 Processing unknown order {order_id} as wallet deposit to avoid lost payments")
            
            # CRITICAL FIX: Import PaymentStatus enum for proper comparison
            from models.payment_models import PaymentStatus
            
            # Validate payment status first - compare enum to enum, not string
            payment_status = payment_details.get('status')
            if payment_status not in [PaymentStatus.SUCCESSFUL, PaymentStatus.CONFIRMED, PaymentStatus.COMPLETED]:
                logger.warning(f"⚠️ Unknown order {order_id} payment not successful, status: {payment_status}")
                return
            
            # Process as wallet deposit to ensure payment is credited
            try:
                await _process_wallet_deposit(order_id, payment_details, provider)
                logger.info(f"✅ Unknown order {order_id} processed as wallet deposit")
            except Exception as wallet_error:
                logger.error(f"❌ Failed to process unknown order {order_id} as wallet deposit: {wallet_error}")
                # Re-raise to ensure webhook handler knows it failed
                raise
            
    except Exception as e:
        logger.error(f"❌ Error processing payment callback: {e}")
        import traceback
        logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
        # CRITICAL FIX: Re-raise exception to propagate failures to webhook handler
        # This ensures failed domain registrations are properly reported instead of silently succeeding
        raise
    
def _extract_payment_details(data: Dict, query_params: Dict, provider: str) -> Dict[str, Any]:
    """Extract payment details from callback data"""
    if provider == "dynopay":
        # Use safe amount parsing for DynoPay
        raw_base_amount = data.get('base_amount', 0)
        raw_paid_amount = data.get('paid_amount', 0)
        
        try:
            amount_usd = safe_parse_amount(raw_base_amount, "dynopay_base_amount")
        except ValueError:
            amount_usd = 0.0
            
        try:
            amount_crypto = safe_parse_amount(raw_paid_amount, "dynopay_paid_amount")
        except ValueError:
            amount_crypto = 0.0
        
        return {
            'status': data.get('status'),
            'amount_usd': amount_usd,
            'amount_crypto': amount_crypto,
            'currency': data.get('paid_currency'),
            'txid': data.get('transaction_reference'),
            'confirmations': 1 if data.get('status') == 'successful' else 0,
            'payment_method': 'crypto'  # Mark as crypto payment for distinction
        }
    else:  # blockbee
        # Use safe amount parsing for BlockBee
        raw_value_coin = query_params.get('value_coin', [0])[0]
        try:
            amount_crypto = safe_parse_amount(raw_value_coin, "blockbee_value_coin")
        except ValueError:
            amount_crypto = 0.0
            
        return {
            'status': query_params.get('result', [None])[0],
            'amount_usd': _extract_blockbee_amount(query_params),
            'amount_crypto': amount_crypto,
            'currency': query_params.get('currency', [''])[0],
            'txid': query_params.get('txid_in', [None])[0] or query_params.get('txid', [None])[0],
            'confirmations': int(query_params.get('confirmations', [0])[0]),
            'payment_method': 'crypto'  # Mark as crypto payment for distinction
        }

async def _detect_and_process_overpayment(order_id: str, payment_details: Dict[str, Any], order_type: str) -> Dict[str, Any]:
    """
    Detect overpayments and credit them to user wallet.
    Returns enhanced payment_details with overpayment information.
    """
    try:
        from database import execute_query, credit_user_wallet
        from payment_validation import validate_payment_amount
        
        # CRITICAL: Always set default overpayment fields for consistent notification handling
        enhanced_payment_details = payment_details.copy()
        enhanced_payment_details['overpayment_amount'] = 0.0
        enhanced_payment_details['overpayment_credited'] = False
        
        received_amount = payment_details.get('amount_usd', 0)
        
        # Validate received amount is positive and reasonable
        if received_amount <= 0 or received_amount > 10000:
            logger.warning(f"❌ OVERPAYMENT: Invalid received amount ${received_amount} for order {order_id}")
            return enhanced_payment_details
        
        if received_amount <= 0:
            logger.info(f"💰 OVERPAYMENT: No valid amount received for order {order_id}")
            return enhanced_payment_details
        
        # Look up expected amount based on order type
        expected_amount = 0
        user_id = None
        
        if order_type == 'domain':
            # FIXED: Look up domain order expected amount through payment_intents table
            domain_query = """
                SELECT pi.amount as expected_amount, pi.user_id, 
                       COALESCE(pi.metadata->>'domain_name', 'unknown') as domain_name
                FROM payment_intents pi
                WHERE pi.order_id = %s
                LIMIT 1
            """
            
            # Query through payment_intents which stores string order_ids correctly
            results = await execute_query(domain_query, (order_id,))
            
            if results:
                expected_amount = to_currency_decimal(results[0]['expected_amount'], "expected_amount")
                user_id = results[0]['user_id']
                domain_name = results[0]['domain_name']
                logger.info(f"💰 OVERPAYMENT: Found domain order - expected: ${expected_amount}, received: ${received_amount}")
            
        elif order_type == 'hosting':
            # FIXED: Look up hosting intent expected amount through payment_intents table
            hosting_query = """
                SELECT pi.amount as expected_amount, pi.user_id,
                       COALESCE(pi.metadata->>'domain_name', 'unknown') as domain_name
                FROM payment_intents pi
                WHERE pi.order_id = %s
                LIMIT 1
            """
            
            # Query through payment_intents which stores string order_ids correctly  
            results = await execute_query(hosting_query, (order_id,))
            
            if results:
                expected_amount = to_currency_decimal(results[0]['expected_amount'], "expected_amount")
                user_id = results[0]['user_id']
                domain_name = results[0]['domain_name']
                logger.info(f"💰 OVERPAYMENT: Found hosting order - expected: ${expected_amount}, received: ${received_amount}")
        
        # If no expected amount found, skip overpayment processing
        if expected_amount <= 0 or not user_id:
            logger.info(f"💰 OVERPAYMENT: No expected amount found for {order_type} order {order_id}")
            return payment_details
        
        # Calculate overpayment using payment validation (now accepts Decimal)
        validation_result = validate_payment_amount(
            expected_usd=expected_amount,
            received_usd=received_amount,
            crypto_currency=payment_details.get('currency', 'CRYPTO'),
            received_crypto=payment_details.get('amount_crypto', 0),
            payment_type=f'{order_type}_order',
            caller='webhook_overpayment_detection'
        )
        
        # Check if there's an overpayment to credit
        overpayment_amount = validation_result.amount_difference
        if overpayment_amount > 0:
            logger.info(f"💰 OVERPAYMENT DETECTED: ${overpayment_amount:.2f} for order {order_id}")
            
            # Credit overpayment to user wallet
            credit_success = await credit_user_wallet(
                user_id=user_id,
                amount_usd=overpayment_amount,
                provider="overpayment_credit",
                txid=f"overpay_{payment_details.get('txid', order_id)}_{int(received_amount*100)}",
                order_id=f"overpayment_{order_id}"
            )
            
            if credit_success:
                logger.info(f"✅ OVERPAYMENT: Credited ${overpayment_amount:.2f} to user {user_id} wallet")
                
                # Enhance payment_details with overpayment information
                enhanced_payment_details['overpayment_amount'] = overpayment_amount
                enhanced_payment_details['overpayment_credited'] = True
                enhanced_payment_details['expected_usd'] = expected_amount
                enhanced_payment_details['received_usd'] = received_amount
            else:
                logger.error(f"❌ OVERPAYMENT: Failed to credit ${overpayment_amount:.2f} to user {user_id}")
                enhanced_payment_details['overpayment_amount'] = overpayment_amount
                enhanced_payment_details['overpayment_credited'] = False
                enhanced_payment_details['expected_usd'] = expected_amount
                enhanced_payment_details['received_usd'] = received_amount
        else:
            # No overpayment or underpayment within tolerance
            logger.info(f"💰 OVERPAYMENT: No overpayment detected - difference: ${overpayment_amount:.2f}")
            enhanced_payment_details['expected_usd'] = expected_amount
            enhanced_payment_details['received_usd'] = received_amount
        
        return enhanced_payment_details
        
    except Exception as e:
        logger.error(f"❌ OVERPAYMENT: Error processing overpayment for order {order_id}: {e}")
        # Return enhanced_payment_details with default overpayment fields
        error_details = payment_details.copy()
        error_details['overpayment_amount'] = 0.0
        error_details['overpayment_credited'] = False
        return error_details
    
def _extract_blockbee_amount(query_params: Dict) -> float:
    """Extract USD amount from BlockBee value_coin_convert with safe parsing"""
    try:
        value_coin_convert_str = query_params.get('value_coin_convert', [None])[0]
        if value_coin_convert_str:
            value_coin_convert = json.loads(value_coin_convert_str)
            raw_usd_amount = value_coin_convert.get('USD', 0)
            # Use safe_parse_amount to validate the USD amount
            try:
                usd_decimal = safe_parse_amount(raw_usd_amount, "blockbee_usd_convert")
                return float(usd_decimal)
            except ValueError as e:
                logger.error(f"❌ Invalid USD amount in BlockBee value_coin_convert: {raw_usd_amount} - {e}")
                return 0.0
    except Exception as e:
        logger.error(f"❌ Error parsing BlockBee value_coin_convert: {e}")
    return 0.0
    
async def _process_wallet_deposit(order_id: str, payment_details: Dict[str, Any], provider: str):
        """Process wallet deposit using unified credit function with database lookup"""
        try:
            # Validate payment first
            if not _is_payment_successful(payment_details):
                logger.warning(f"❌ Wallet deposit payment not successful: {order_id}")
                return
            
            # Look up payment intent and user from database using order_id
            try:
                from database import execute_query
                
                # Query payment intent to get user information AND original selected amount
                payment_intent_query = """
                    SELECT user_id, status, created_at, amount as selected_amount
                    FROM payment_intents 
                    WHERE order_id = %s 
                    LIMIT 1
                """
                
                # order_id column is VARCHAR - always use string comparison
                results = await execute_query(payment_intent_query, (str(order_id),))
                
                if not results:
                    logger.error(f"❌ No payment intent found for order_id: {order_id}")
                    return
                
                user_id = results[0]['user_id']
                selected_amount_raw = results[0].get('selected_amount', 0)
                logger.info(f"✅ Found payment intent for order_id {order_id}, user_id: {user_id}, selected_amount: {selected_amount_raw}")
                
            except (ValueError, Exception) as e:
                logger.error(f"❌ Could not lookup payment intent for order_id {order_id}: {e}")
                return
            
            # CRITICAL FIX: Extract received amount safely using safe_parse_amount
            raw_amount = payment_details.get('amount_usd', 0)
            if raw_amount == 0:
                # Try alternative amount fields
                raw_amount = payment_details.get('amount', 0)
            
            # Use safe_parse_amount to validate both amounts
            from decimal import Decimal
            try:
                amount_received = safe_parse_amount(raw_amount, "wallet_deposit_received")
            except ValueError as e:
                logger.error(f"❌ Invalid wallet deposit received amount format: {raw_amount} - {e}")
                amount_received = Decimal('0.0')
            
            try:
                selected_amount = safe_parse_amount(selected_amount_raw, "wallet_deposit_selected")
            except ValueError as e:
                logger.warning(f"⚠️ Could not parse selected amount: {selected_amount_raw} - using received amount")
                selected_amount = amount_received
            
            # WALLET DEPOSIT LOGIC:
            # - If received >= $10 minimum: credit the FULL received amount to wallet
            # - If received < $10 minimum: reject deposit entirely
            # - No cap at selected amount - user benefits from any overpayment
            amount_usd = amount_received
            
            MINIMUM_DEPOSIT = Decimal('10')
            
            if amount_received < MINIMUM_DEPOSIT:
                logger.warning(f"❌ WALLET DEPOSIT REJECTED: Received ${amount_received:.2f} is below minimum ${MINIMUM_DEPOSIT} for order {order_id}")
                # Update payment intent status
                try:
                    from database import execute_update
                    await execute_update(
                        "UPDATE payment_intents SET status = 'rejected', metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('rejection_reason', 'below_minimum', 'amount_received', %s) WHERE order_id = %s",
                        (float(amount_received), str(order_id))
                    )
                except Exception as rej_err:
                    logger.warning(f"⚠️ Could not update rejected payment intent: {rej_err}")
                return
            
            # Credit full received amount (even if more than selected)
            if amount_received > selected_amount and selected_amount > Decimal('0'):
                logger.info(f"💰 OVERPAYMENT: User selected ${selected_amount:.2f} but sent ${amount_received:.2f} - crediting full ${amount_received:.2f}")
            elif amount_received < selected_amount:
                logger.info(f"💰 UNDERPAYMENT: User selected ${selected_amount:.2f} but sent ${amount_received:.2f} - crediting ${amount_received:.2f}")
            else:
                logger.info(f"💰 EXACT PAYMENT: User sent ${amount_received:.2f}")
            
            logger.info(f"💰 WALLET_DEPOSIT_DEBUG: received=${amount_received:.2f}, selected=${selected_amount:.2f}, crediting=${amount_usd:.2f}")
            
            # AUDIT: Store amount_received in payment_intents for fraud detection
            try:
                from database import execute_update
                await execute_update(
                    "UPDATE payment_intents SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('amount_received_usd', %s, 'selected_amount_usd', %s, 'credited_amount_usd', %s) WHERE order_id = %s",
                    (float(amount_received), float(selected_amount), float(amount_usd), str(order_id))
                )
                logger.info(f"✅ Stored wallet deposit amount_received ${amount_received:.2f} for order {order_id}")
            except Exception as store_err:
                logger.warning(f"⚠️ Could not store wallet deposit amount_received: {store_err}")
            
            txid = payment_details.get('txid', 'unknown')
            
            # Process wallet deposit using unified credit function
            try:
                from database import credit_user_wallet
                
                # Use production-grade wallet credit function with enhanced logging
                logger.info(f"💰 WALLET_DEPOSIT_PROCESSING: Starting ${amount_usd:.2f} {provider} deposit for user_id {user_id} | txid: {txid[:16] if txid and len(txid) >= 16 else txid}... | order: {order_id}")
                
                success = await credit_user_wallet(user_id, amount_usd, provider, txid, order_id)
                
                if success:
                    # SUCCESS: Could be new credit or idempotent duplicate - both are success
                    logger.info(f"✅ WALLET_DEPOSIT_SUCCESS: ${amount_usd:.2f} processed for user_id {user_id} via {provider} | txid: {txid[:16] if txid and len(txid) >= 16 else txid}...")
                    
                    # CRITICAL FIX: Update order total_amount and payment_intent with actual received amount
                    try:
                        from database import execute_update
                        
                        # Update order total_amount and status for wallet deposits
                        affected = await execute_update(
                            "UPDATE orders SET total_amount = %s, status = 'paid' WHERE uuid_id = %s AND order_type = 'wallet' AND status IN ('pending', 'pending_payment')",
                            (amount_usd, order_id)
                        )
                        if affected:
                            logger.info(f"✅ Updated order {order_id} total_amount to ${amount_usd:.2f} and status to 'paid'")
                        else:
                            logger.warning(f"⚠️ Order {order_id} total_amount not updated (may already be processed)")
                        
                        # ALWAYS update payment_intent amount and status (not just in else branch)
                        affected_intent = await execute_update(
                            "UPDATE payment_intents SET amount = %s, status = 'confirmed' WHERE order_id = %s AND status != 'confirmed'",
                            (amount_usd, order_id)
                        )
                        if affected_intent:
                            logger.info(f"✅ Updated payment_intent for order {order_id} amount to ${amount_usd:.2f} and status to 'confirmed'")
                        else:
                            logger.info(f"ℹ️ Payment intent for order {order_id} already confirmed (idempotent)")
                            
                    except Exception as update_error:
                        logger.error(f"❌ Error updating order/payment_intent for {order_id}: {update_error}")
                    
                    # Send admin alert for successful wallet deposit
                    try:
                        from admin_alerts import send_info_alert
                        await send_info_alert(
                            component="WalletDeposit",
                            message=f"💵 Wallet deposit: ${amount_usd:.2f} via {provider.upper()}",
                            category="payment_processing",
                            details={
                                'user_id': user_id,
                                'amount_usd': float(amount_usd),
                                'provider': provider,
                                'txid': txid[:32] if txid else 'unknown',
                                'order_id': order_id
                            }
                        )
                    except Exception as alert_error:
                        logger.warning(f"⚠️ Could not send wallet deposit admin alert: {alert_error}")
                    
                    # Skip notifications in test mode to avoid errors
                    if not os.getenv('TEST_MODE'):
                        try:
                            # Fetch user language preference for multilingual notifications
                            user_result = await execute_query("SELECT preferred_language FROM users WHERE id = %s", (user_id,))
                            lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
                            
                            # Send multilingual success notification
                            title = t('notifications.wallet.deposit_success_title', lang)
                            body = t('notifications.wallet.deposit_success_message', lang)
                            await queue_user_message(user_id, f"🎉 <b>{title}: ${amount_usd:.2f}</b>\n\n{body}")
                        except Exception as msg_e:
                            logger.warning(f"⚠️ Could not queue success notification: {msg_e}")
                else:
                    # FAILURE: Actual error occurred (validation, connection, security, etc.)
                    logger.error(f"❌ WALLET_DEPOSIT_FAILURE: ${amount_usd:.2f} deposit failed for user_id {user_id} via {provider} | txid: {txid[:16] if txid and len(txid) >= 16 else txid}... | Check structured logs above for specific failure reason")
                    # Skip notifications in test mode to avoid errors
                    if not os.getenv('TEST_MODE'):
                        try:
                            # Fetch user language preference for multilingual notifications
                            user_result = await execute_query("SELECT preferred_language FROM users WHERE id = %s", (user_id,))
                            lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
                            
                            # Send multilingual error notification
                            title = t('notifications.wallet.deposit_error_title', lang)
                            body = t('notifications.wallet.deposit_error_message', lang,
                                    amount=f"{amount_usd:.2f}",
                                    txid=txid[:16] if txid and len(txid) >= 16 else txid)
                            await queue_user_message(user_id, f"❌ <b>{title}</b>\n\n{body}")
                        except Exception as msg_e:
                            logger.warning(f"⚠️ Could not queue failure notification: {msg_e}")
                    
            except Exception as e:
                logger.error(f"❌ Error processing wallet deposit: {e}")
                import traceback
                logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            
        except Exception as e:
            logger.error(f"❌ Error processing wallet deposit: {e}")
    
# Removed _execute_secure_wallet_credit - replaced with direct call to credit_user_wallet()
    
async def _process_domain_payment(order_id: str, payment_details: Dict[str, Any]):
        """Process domain payment with overpayment detection and wallet credit"""
        try:
            # Validate payment
            if not _is_payment_successful(payment_details):
                logger.warning(f"❌ Domain payment not successful: {order_id}")
                return
            
            # Extract telegram_id and domain from order_id
            # Format: domain_[domain]_[telegram_id]_[timestamp]
            parts = order_id.split('_')
            if len(parts) < 4:
                logger.error(f"❌ Invalid domain order_id format: {order_id}")
                return
            
            telegram_id = int(parts[-2])  # Extract telegram_id, not user_id
            domain_name = '_'.join(parts[1:-2])
            
            logger.info(f"🎯 Processing domain payment: {domain_name} for telegram_id {telegram_id}")
            
            # OVERPAYMENT DETECTION: Get expected domain price from database
            try:
                from database import execute_query
                
                # Get user_id from telegram_id
                user_results = await execute_query(
                    "SELECT id FROM users WHERE telegram_id = %s LIMIT 1",
                    (telegram_id,)
                )
                
                if not user_results:
                    logger.error(f"❌ No user found for telegram_id {telegram_id}")
                    return
                
                user_id = user_results[0]['id']
                
                # CRITICAL FIX: Query 'domain_orders' table - ALL domain orders stored here now
                # Both crypto (DynoPay/BlockBee) and wallet payments use 'domain_orders'
                order_results = await execute_query(
                    """SELECT expected_amount, id FROM domain_orders 
                       WHERE blockbee_order_id = %s AND user_id = %s AND domain_name = %s 
                       LIMIT 1""",
                    (order_id, user_id, domain_name)
                )
                
                if not order_results:
                    # SECURITY FIX: BLOCK domain registration if order not found
                    # Previously this continued to orchestrator - this was a critical vulnerability
                    # that allowed domains to be registered without payment
                    logger.error(f"🚨 SECURITY BLOCK: No order found in domain_orders for {order_id} - blocking registration")
                    logger.error(f"   Domain: {domain_name}, User: {user_id}, Telegram: {telegram_id}")
                    
                    try:
                        from admin_alerts import send_critical_alert
                        await send_critical_alert(
                            component="PaymentSecurity",
                            message=f"Domain registration blocked - no order found: {domain_name}",
                            category="security",
                            details={
                                "domain": domain_name,
                                "user_id": user_id,
                                "telegram_id": telegram_id,
                                "order_id": order_id,
                                "reason": "No order found in domain_orders table"
                            }
                        )
                    except Exception as alert_err:
                        logger.warning(f"Could not send security alert: {alert_err}")
                    
                    return  # BLOCK - do not proceed to orchestrator
                else:
                    # Order found - perform overpayment detection
                    expected_price = float(order_results[0]['expected_amount'])
                    
                    # Use safe parsing for received amount (ALWAYS in USD from payment provider)
                    # DynoPay: base_amount is USD, BlockBee: value_coin_convert['USD'] is USD
                    raw_received = payment_details.get('amount_usd', 0)
                    try:
                        received_amount = safe_parse_amount(raw_received, "received_amount")
                    except ValueError:
                        received_amount = 0.0
                    
                    # AUDIT: Validate we have a reasonable USD amount (not crypto amount)
                    if received_amount > 100000:  # Sanity check - no domain costs $100k+
                        logger.warning(f"⚠️ AUDIT WARNING: Unusually high amount_received ${received_amount:.2f} - may be crypto amount, not USD")
                    
                    logger.info(f"💰 Payment comparison - Expected: ${expected_price:.2f} USD, Received: ${received_amount:.2f} USD")
                    
                    # AUDIT: Store amount_received in domain_orders for fraud detection
                    try:
                        await execute_query(
                            "UPDATE domain_orders SET amount_received = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                            (received_amount, order_results[0]['id'])
                        )
                        logger.info(f"✅ Stored amount_received ${received_amount:.2f} for order {order_results[0]['id']}")
                    except Exception as store_err:
                        logger.warning(f"⚠️ Could not store amount_received: {store_err}")
                    
                    # SECURITY: Check for underpayment BEFORE proceeding
                    # Allow up to 3% underpayment tolerance for crypto exchange rate fluctuations
                    from decimal import Decimal, ROUND_HALF_UP
                    received_decimal = Decimal(str(received_amount))
                    expected_decimal = Decimal(str(expected_price))
                    minimum_acceptable = expected_decimal * Decimal('0.97')  # 3% tolerance
                    
                    if received_decimal < minimum_acceptable:
                        underpayment_amount = expected_decimal - received_decimal
                        logger.error(f"🚨 UNDERPAYMENT DETECTED: Expected ${expected_price:.2f}, Received ${received_amount:.2f}, Short by ${underpayment_amount:.2f}")
                        logger.error(f"   Domain registration BLOCKED for {domain_name} - insufficient payment")
                        
                        # Update order status to failed
                        try:
                            await execute_query(
                                "UPDATE domain_orders SET status = 'payment_insufficient', error_message = %s WHERE id = %s",
                                (f"Insufficient payment: Expected ${expected_price:.2f}, Received ${received_amount:.2f}", order_results[0]['id'])
                            )
                            logger.info(f"✅ Order {order_results[0]['id']} marked as payment_insufficient")
                        except Exception as update_error:
                            logger.error(f"❌ Could not update order status: {update_error}")
                        
                        # Send admin alert about underpayment attempt
                        try:
                            from admin_alerts import send_warning_alert
                            await send_warning_alert(
                                component="PaymentSecurity",
                                message=f"Underpayment blocked: {domain_name}",
                                category="security",
                                details={
                                    "domain": domain_name,
                                    "expected_usd": float(expected_price),
                                    "received_usd": float(received_amount),
                                    "shortfall_usd": float(underpayment_amount),
                                    "user_id": user_id,
                                    "order_id": order_id
                                }
                            )
                        except Exception as alert_error:
                            logger.warning(f"Could not send underpayment alert: {alert_error}")
                        
                        # DO NOT PROCEED with domain registration
                        return
                    
                    # Calculate overpayment/underpayment for normal processing
                    overpayment_decimal = received_decimal - expected_decimal
                    overpayment_amount = overpayment_decimal.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)  # Keep as Decimal
                    
                    if overpayment_amount > 0.01:  # Threshold for overpayment detection ($0.01)
                        logger.info(f"💸 Overpayment detected: ${overpayment_amount:.2f}")
                        
                        # Credit overpayment to wallet
                        try:
                            from database import atomic_domain_overpayment_credit_with_txid
                            
                            txid = payment_details.get('txid', 'unknown')
                            external_txid = f"overpay_{order_id}_{txid[:8]}"
                            
                            overpayment_success = await atomic_domain_overpayment_credit_with_txid(
                                user_id=user_id,
                                overpayment_amount=overpayment_amount,
                                domain_name=domain_name,
                                txid=txid,
                                order_id=order_id,
                                external_txid=external_txid
                            )
                            
                            if overpayment_success:
                                logger.info(f"✅ Overpayment ${overpayment_amount:.2f} credited to wallet for user {user_id}")
                                # Add overpayment info to payment_details for notifications
                                payment_details['overpayment_amount'] = overpayment_amount
                                payment_details['overpayment_credited'] = True
                                payment_details['expected_usd'] = expected_price  # Add expected price for notifications
                            else:
                                logger.warning(f"⚠️ Overpayment wallet credit failed for user {user_id}")
                                payment_details['overpayment_amount'] = overpayment_amount
                                payment_details['overpayment_credited'] = False
                                payment_details['expected_usd'] = expected_price
                        except Exception as overpay_error:
                            logger.error(f"❌ Error processing overpayment: {overpay_error}")
                            payment_details['overpayment_amount'] = overpayment_amount
                            payment_details['overpayment_credited'] = False
                            payment_details['expected_usd'] = expected_price
                    else:
                        logger.info(f"✅ No significant overpayment (difference: ${overpayment_amount:.4f})")
                        payment_details['expected_usd'] = expected_price  # Add expected price for notifications
                    
            except Exception as db_error:
                logger.error(f"❌ Error retrieving domain order details: {db_error}")
                # Continue processing even if overpayment detection fails
            
            # ASYNC REGISTRATION: Queue job instead of blocking webhook
            # This ensures webhook responds instantly while registration happens in background
            from services.domain_registration_job_service import get_domain_registration_job_service
            
            job_service = get_domain_registration_job_service()
            job_id = await job_service.enqueue_registration(
                order_id=order_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details
            )
            
            if job_id:
                logger.info(f"✅ Domain registration queued as job #{job_id} for {domain_name} - webhook returning immediately")
            else:
                logger.error(f"❌ Failed to queue domain registration for {order_id} - falling back to sync")
                # Fallback to synchronous processing if queue fails
                if _bot_loop and _bot_application:
                    try:
                        current_loop = asyncio.get_running_loop()
                        in_same_loop = (current_loop == _bot_loop)
                    except RuntimeError:
                        in_same_loop = False
                    
                    if in_same_loop:
                        await _route_domain_payment(order_id, telegram_id, domain_name, payment_details)
                    else:
                        future = asyncio.run_coroutine_threadsafe(
                            _route_domain_payment(order_id, telegram_id, domain_name, payment_details),
                            _bot_loop
                        )
                        future.result(timeout=120.0)
            
        except Exception as e:
            logger.error(f"❌ Error processing domain payment: {e}")
            # Log additional context for debugging empty error messages
            logger.error(f"🔍 Payment details: {payment_details}")
            logger.error(f"🔍 Order ID: {order_id}")
            import traceback
            logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
            
            # Enhanced monitoring: Send alert for timeout errors
            if "TimeoutError" in str(e) or "timeout" in str(e).lower():
                try:
                    from admin_alerts import send_warning_alert
                    asyncio.create_task(send_warning_alert(
                        "WebhookHandler",
                        f"Domain payment processing timeout for order {order_id}",
                        "webhook",
                        {
                            "order_id": order_id,
                            "error": str(e),
                            "domain_name": locals().get('domain_name', 'unknown')
                        }
                    ))
                except:
                    pass  # Don't let alert failures break main processing
            
            # Re-raise to propagate error
            raise
    
async def _process_hosting_payment(order_id: str, payment_details: Dict[str, Any]):
    """
    Process hosting payment by routing to HostingBundleOrchestrator with enhanced payment details
    
    CRITICAL FIX: Handles both tracking ID strings and integer IDs for hosting orders.
    Crypto payments create tracking IDs like "hosting_[subscription_id]_[telegram_id]_[timestamp]"
    which are stored in the 'orders' table with external_order_id field.
    """
    try:
        # Validate payment
        if not _is_payment_successful(payment_details):
            logger.warning(f"❌ Hosting payment not successful: {order_id}")
            return
        
        logger.info(f"🏠 Processing hosting payment for order: {order_id}")
        
        # CRITICAL FIX: Handle both tracking ID strings (crypto payments) and integer IDs (legacy)
        integer_order_id = None
        user_id = None
        domain_name = None
        
        # Try tracking ID format first (crypto payments): hosting_[subscription_id]_[telegram_id]_[timestamp]
        if order_id.startswith('hosting_'):
            logger.info(f"🔍 Detected hosting tracking ID format: {order_id}")
            
            # Parse the tracking ID to extract telegram_id
            parts = order_id.split('_')
            if len(parts) >= 4:
                try:
                    extracted_telegram_id = int(parts[2])  # hosting_123_[telegram_id]_timestamp
                    
                    # SINGLE-TABLE CONSOLIDATION: Look up in hosting_orders table using blockbee_order_id
                    from database import execute_query
                    order_results = await execute_query(
                        "SELECT id, user_id, domain_name, subscription_id FROM hosting_orders WHERE blockbee_order_id = %s LIMIT 1",
                        (order_id,)
                    )
                    
                    if order_results:
                        integer_order_id = order_results[0]['id']
                        user_id = order_results[0]['user_id']
                        domain_name = order_results[0]['domain_name']
                        subscription_id = order_results[0].get('subscription_id')
                        logger.info(f"✅ Found hosting order: ID={integer_order_id}, user={user_id}, domain={domain_name}, subscription={subscription_id}")
                        
                        # SECURITY FIX: Get expected amount for underpayment validation
                        from decimal import Decimal, ROUND_HALF_UP
                        from database import execute_update
                        
                        # Get expected amount from hosting_orders
                        expected_result = await execute_query(
                            "SELECT expected_amount FROM hosting_orders WHERE id = %s",
                            (integer_order_id,)
                        )
                        
                        if expected_result and expected_result[0].get('expected_amount'):
                            expected_amount = Decimal(str(expected_result[0]['expected_amount']))
                            received_raw = payment_details.get('amount_usd', payment_details.get('amount_paid', 0))
                            
                            try:
                                if isinstance(received_raw, str):
                                    received_amount = Decimal(received_raw)
                                else:
                                    received_amount = Decimal(str(float(received_raw)))
                            except:
                                received_amount = Decimal('0')
                            
                            minimum_acceptable = expected_amount * Decimal('0.97')  # 3% tolerance
                            
                            if received_amount < minimum_acceptable:
                                shortfall = expected_amount - received_amount
                                logger.error(f"🚨 HOSTING UNDERPAYMENT DETECTED: Expected ${expected_amount:.2f}, Received ${received_amount:.2f}, Short by ${shortfall:.2f}")
                                logger.error(f"   Hosting provisioning BLOCKED for order {order_id}")
                                
                                # Update order status to payment_insufficient
                                await execute_update(
                                    "UPDATE hosting_orders SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                                    (integer_order_id,)
                                )
                                
                                # Send admin alert
                                try:
                                    from admin_alerts import send_warning_alert
                                    await send_warning_alert(
                                        component="PaymentSecurity",
                                        message=f"Hosting underpayment blocked: {domain_name}",
                                        category="security",
                                        details={
                                            "domain": domain_name,
                                            "expected_usd": float(expected_amount),
                                            "received_usd": float(received_amount),
                                            "shortfall_usd": float(shortfall),
                                            "user_id": user_id,
                                            "order_id": order_id
                                        }
                                    )
                                except Exception as alert_error:
                                    logger.warning(f"Could not send hosting underpayment alert: {alert_error}")
                                
                                return  # Block provisioning
                    
                        # Update order status to paid and track amount received
                        amount_received = Decimal(str(payment_details.get('amount_paid', '0.0')))
                        
                        affected = await execute_update(
                            """UPDATE hosting_orders 
                               SET status = 'paid', 
                                   amount_received = %s,
                                   overpayment_detected = %s,
                                   paid_at = CURRENT_TIMESTAMP,
                                   updated_at = CURRENT_TIMESTAMP
                               WHERE id = %s AND status = 'pending_payment'""",
                            (str(amount_received), payment_details.get('overpayment_detected', False), integer_order_id)
                        )
                        
                        if affected:
                            logger.info(f"✅ Updated hosting order {integer_order_id} status to 'paid' (amount: {amount_received})")
                        else:
                            logger.warning(f"⚠️ Hosting order {integer_order_id} status not updated (may already be processed)")
                    else:
                        # DEFENSIVE ALERTING: Missing order critical alert (mirrors domain pattern)
                        logger.error(f"🚨 CRITICAL: Hosting order not found in hosting_orders for tracking ID: {order_id}")
                        try:
                            from admin_alerts import send_critical_alert
                            asyncio.create_task(send_critical_alert(
                                "WebhookHandler",
                                f"🚨 HOSTING PAYMENT STUCK: Order not found for tracking ID {order_id}",
                                "webhook_hosting_missing_order",
                                {
                                    "tracking_id": order_id,
                                    "extracted_telegram_id": extracted_telegram_id,
                                    "payment_amount": payment_details.get('amount_paid', 'unknown'),
                                    "payment_details": payment_details
                                }
                            ))
                        except Exception as alert_error:
                            logger.error(f"❌ Failed to send critical alert: {alert_error}")
                except (ValueError, IndexError) as e:
                    logger.error(f"❌ Error parsing hosting tracking ID {order_id}: {e}")
        
        # Fallback: Try as integer order ID (legacy hosting_provision_intents lookup)
        if not integer_order_id:
            try:
                intent_id = int(order_id)
                logger.info(f"🔍 Trying as integer hosting intent ID: {intent_id}")
                
                # Look up hosting intent details
                from database import execute_query
                intent_results = await execute_query(
                    "SELECT user_id, domain_name FROM hosting_provision_intents WHERE id = %s LIMIT 1",
                    (intent_id,)
                )
                
                if intent_results:
                    user_id = intent_results[0]['user_id']
                    domain_name = intent_results[0]['domain_name']
                    integer_order_id = intent_id
                    logger.info(f"✅ Found hosting intent: order {intent_id}, user {user_id}, domain {domain_name}")
            except ValueError:
                logger.error(f"❌ Invalid hosting order_id format (not a tracking ID or integer): {order_id}")
        
        # Validate we found the order
        if not integer_order_id or not user_id or not domain_name:
            logger.error(f"❌ No hosting order found for {order_id} (order_id={integer_order_id}, user_id={user_id}, domain={domain_name})")
            return
        
        # UNIFIED UNDERPAYMENT CHECK: Validate payment amount before routing to orchestrator
        # SECURITY: Only trust pricing from hosting_orders (authoritative), NEVER from hosting_provision_intents
        from database import execute_query as exec_q, execute_update as exec_u
        from decimal import Decimal
        
        expected_amt = None
        
        # Try multiple identifiers to find the order in hosting_orders (authoritative source)
        # Method 1: By ID or blockbee_order_id or external_order_id
        hosting_order_check = await exec_q(
            "SELECT expected_amount, status FROM hosting_orders WHERE id = %s OR blockbee_order_id = %s OR external_order_id = %s LIMIT 1",
            (integer_order_id, order_id, order_id)
        )
        
        if hosting_order_check and hosting_order_check[0].get('expected_amount'):
            expected_amt = Decimal(str(hosting_order_check[0]['expected_amount']))
        
        # Method 2: Try by domain_name and user_id if not found
        if not expected_amt and domain_name and user_id:
            hosting_order_by_domain = await exec_q(
                "SELECT expected_amount, status FROM hosting_orders WHERE domain_name = %s AND user_id = %s AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
                (domain_name, user_id)
            )
            if hosting_order_by_domain and hosting_order_by_domain[0].get('expected_amount'):
                expected_amt = Decimal(str(hosting_order_by_domain[0]['expected_amount']))
        
        # SECURITY: We intentionally do NOT fall back to hosting_provision_intents for pricing
        # That table is legacy/optional and could be manipulated by attackers
        
        if expected_amt:
            received_raw = payment_details.get('amount_usd', payment_details.get('amount_paid', 0))
            
            try:
                received_amt = Decimal(str(float(received_raw))) if received_raw else Decimal('0')
            except:
                received_amt = Decimal('0')
            
            # AUDIT: Validate we have a reasonable USD amount (not crypto amount)
            if received_amt > Decimal('100000'):  # Sanity check - no hosting costs $100k+
                logger.warning(f"⚠️ AUDIT WARNING: Unusually high hosting amount_received ${received_amt:.2f} - may be crypto amount, not USD")
            
            # AUDIT: Store amount_received in hosting_orders for fraud detection (ALWAYS in USD)
            try:
                await exec_u(
                    "UPDATE hosting_orders SET amount_received = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s OR blockbee_order_id = %s",
                    (float(received_amt), integer_order_id, order_id)
                )
                logger.info(f"✅ Stored hosting amount_received ${received_amt:.2f} USD for order {integer_order_id}")
            except Exception as store_err:
                logger.warning(f"⚠️ Could not store hosting amount_received: {store_err}")
            
            min_acceptable = expected_amt  # Require exact payment
            
            if received_amt < min_acceptable:
                shortfall = expected_amt - received_amt
                logger.error(f"🚨 HOSTING UNDERPAYMENT (UNIFIED CHECK): Expected ${expected_amt:.2f}, Received ${received_amt:.2f}, Short ${shortfall:.2f}")
                
                # SECURITY FIX: Update BOTH tables to prevent "pending" artifacts that hide the block
                # Update hosting_orders if found
                await exec_u(
                    "UPDATE hosting_orders SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s OR blockbee_order_id = %s",
                    (integer_order_id, order_id)
                )
                # Also update hosting_provision_intents
                await exec_u(
                    "UPDATE hosting_provision_intents SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (integer_order_id,)
                )
                
                try:
                    from admin_alerts import send_warning_alert
                    await send_warning_alert(
                        component="PaymentSecurity",
                        message=f"Hosting underpayment blocked: {domain_name}",
                        category="security",
                        details={
                            "domain": domain_name,
                            "expected_usd": float(expected_amt),
                            "received_usd": float(received_amt),
                            "shortfall_usd": float(shortfall),
                            "user_id": user_id,
                            "order_id": order_id,
                            "integer_order_id": integer_order_id,
                            "source_table": "hosting_orders"
                        }
                    )
                except Exception as alert_err:
                    logger.warning(f"Could not send hosting underpayment alert: {alert_err}")
                
                return  # Block provisioning
        else:
            # SECURITY FIX: No expected amount found - BLOCK provisioning to prevent fraud
            # Legacy orders without pricing should not be provisioned without manual review
            logger.error(f"🚨 HOSTING SECURITY BLOCK: No expected amount found for order {order_id} - blocking provisioning")
            
            # Update BOTH tables to 'payment_insufficient' to prevent pending artifacts
            await exec_u(
                "UPDATE hosting_orders SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s OR blockbee_order_id = %s",
                (integer_order_id, order_id)
            )
            await exec_u(
                "UPDATE hosting_provision_intents SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (integer_order_id,)
            )
            
            try:
                from admin_alerts import send_critical_alert
                await send_critical_alert(
                    component="PaymentSecurity",
                    message=f"Hosting order blocked - no expected amount: {domain_name}",
                    category="security",
                    details={
                        "domain": domain_name,
                        "user_id": user_id,
                        "order_id": order_id,
                        "integer_order_id": integer_order_id,
                        "reason": "No expected_amount in hosting_orders (authoritative source only)"
                    }
                )
            except Exception as alert_err:
                logger.warning(f"Could not send hosting security alert: {alert_err}")
            
            return  # Block provisioning - require manual review
        
        # ASYNC HOSTING: Queue job instead of blocking webhook
        # This ensures webhook responds instantly while hosting provisioning happens in background
        from services.domain_registration_job_service import get_hosting_order_job_service
        
        hosting_job_service = get_hosting_order_job_service()
        job_id = await hosting_job_service.enqueue_hosting(
            order_id=integer_order_id,
            user_id=user_id,
            domain_name=domain_name,
            payment_details=payment_details
        )
        
        if job_id:
            logger.info(f"✅ Hosting order queued as job #{job_id} for {domain_name} - webhook returning immediately")
        else:
            logger.error(f"❌ Failed to queue hosting order {integer_order_id} - falling back to sync")
            # Fallback to synchronous processing if queue fails
            from services.hosting_orchestrator import HostingBundleOrchestrator
            orchestrator = HostingBundleOrchestrator()
            query_adapter = WebhookQueryAdapter(user_id)
            await orchestrator.start_hosting_bundle(
                order_id=integer_order_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter
            )
        
    except Exception as e:
        logger.error(f"❌ Error processing hosting payment for order {order_id}: {e}")
        import traceback
        logger.error(f"❌ Full traceback: {traceback.format_exc()}")

async def _process_rdp_payment(order_id: str, payment_details: Dict[str, Any]):
    """
    Process RDP server payment and trigger server provisioning
    """
    try:
        # Validate payment
        if not _is_payment_successful(payment_details):
            logger.warning(f"❌ RDP payment not successful: {order_id}")
            return
        
        logger.info(f"🖥️ Processing RDP server payment for order: {order_id}")
        
        # Look up order in orders table by uuid_id
        from database import execute_query, execute_update
        from decimal import Decimal
        
        order_results = await execute_query(
            """SELECT id, user_id, total_amount, metadata, status
               FROM orders
               WHERE uuid_id = %s AND order_type = 'rdp'
               LIMIT 1""",
            (order_id,)
        )
        
        if not order_results:
            # DEFENSIVE ALERTING: Missing order critical alert
            logger.error(f"🚨 CRITICAL: RDP order not found for UUID: {order_id}")
            try:
                from admin_alerts import send_critical_alert
                asyncio.create_task(send_critical_alert(
                    "WebhookHandler",
                    f"🚨 RDP PAYMENT STUCK: Order not found for UUID {order_id}",
                    "webhook_rdp_missing_order",
                    {
                        "order_uuid": order_id,
                        "payment_amount": payment_details.get('amount_usd', 'unknown'),
                        "payment_details": payment_details
                    }
                ))
            except Exception as alert_error:
                logger.error(f"❌ Failed to send critical alert: {alert_error}")
            return
        
        order = order_results[0]
        order_db_id = order['id']
        user_id = order['user_id']
        total_amount = Decimal(str(order['total_amount']))
        metadata = order['metadata']
        current_status = order['status']
        
        # Check if already processed
        if current_status != 'pending':
            logger.warning(f"⚠️ RDP order {order_db_id} already processed: {current_status}")
            return
        
        # SECURITY FIX: Underpayment validation for RDP orders with safe parsing
        # Parse failures are TERMINAL ERRORS - block provisioning explicitly
        raw_amount = payment_details.get('amount_usd', None)
        amount_received = None
        parse_failed = False
        
        try:
            if raw_amount is None:
                parse_failed = True
            elif isinstance(raw_amount, (int, float, Decimal)):
                amount_received = Decimal(str(raw_amount))
            elif isinstance(raw_amount, str) and raw_amount.strip():
                amount_received = Decimal(raw_amount.strip())
            else:
                parse_failed = True
        except Exception as parse_err:
            logger.error(f"🚨 RDP SECURITY: Failed to parse amount_usd '{raw_amount}': {parse_err}")
            parse_failed = True
        
        # TERMINAL ERROR: Block provisioning when amount cannot be parsed
        if parse_failed or amount_received is None:
            logger.error(f"🚨 RDP SECURITY BLOCK: Cannot parse payment amount for order {order_id} - raw_amount: {raw_amount}")
            
            await execute_update(
                "UPDATE orders SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (order_db_id,)
            )
            
            try:
                from admin_alerts import send_critical_alert
                await send_critical_alert(
                    component="PaymentSecurity",
                    message=f"RDP payment blocked - unparseable amount: order {order_id}",
                    category="security",
                    details={
                        "order_uuid": order_id,
                        "raw_amount": str(raw_amount),
                        "user_id": user_id,
                        "expected_usd": float(total_amount),
                        "reason": "amount_usd missing or unparseable"
                    }
                )
            except Exception as alert_err:
                logger.warning(f"Could not send RDP parse failure alert: {alert_err}")
            
            return  # Block provisioning - terminal error
        
        # AUDIT: Validate we have a reasonable USD amount (not crypto amount)
        if amount_received > Decimal('100000'):  # Sanity check - no RDP costs $100k+
            logger.warning(f"⚠️ AUDIT WARNING: Unusually high RDP amount_received ${amount_received:.2f} - may be crypto amount, not USD")
        
        # AUDIT: Store amount_received in orders table for fraud detection (ALWAYS in USD)
        try:
            await execute_update(
                "UPDATE orders SET amount_received = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (float(amount_received), order_db_id)
            )
            logger.info(f"✅ Stored RDP amount_received ${amount_received:.2f} USD for order {order_db_id}")
        except Exception as store_err:
            logger.warning(f"⚠️ Could not store RDP amount_received: {store_err}")
        
        minimum_acceptable = total_amount  # Require exact payment
        
        if amount_received < minimum_acceptable:
            shortfall = total_amount - amount_received
            logger.error(f"🚨 RDP UNDERPAYMENT DETECTED: Expected ${total_amount:.2f}, Received ${amount_received:.2f}, Short by ${shortfall:.2f}")
            logger.error(f"   RDP provisioning BLOCKED for order {order_id}")
            
            # Update order status to payment_insufficient
            await execute_update(
                "UPDATE orders SET status = 'payment_insufficient', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (order_db_id,)
            )
            
            # Send admin alert
            try:
                from admin_alerts import send_warning_alert
                await send_warning_alert(
                    component="PaymentSecurity",
                    message=f"RDP underpayment blocked: order {order_id}",
                    category="security",
                    details={
                        "order_uuid": order_id,
                        "expected_usd": float(total_amount),
                        "received_usd": float(amount_received),
                        "shortfall_usd": float(shortfall),
                        "user_id": user_id,
                        "plan_id": metadata.get('plan_id'),
                        "region": metadata.get('region')
                    }
                )
            except Exception as alert_error:
                logger.warning(f"Could not send RDP underpayment alert: {alert_error}")
            
            return  # Block provisioning
        
        # Update order status to paid
        
        affected = await execute_update(
            """UPDATE orders 
               SET status = 'paid',
                   completed_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
               WHERE id = %s AND status = 'pending'""",
            (order_db_id,)
        )
        
        if affected:
            logger.info(f"✅ Updated RDP order {order_db_id} status to 'paid' (amount: {amount_received})")
        else:
            logger.warning(f"⚠️ RDP order {order_db_id} status not updated (may already be processed)")
            return
        
        # Extract metadata for provisioning
        plan_id = metadata.get('plan_id')
        region = metadata.get('region')  # Fixed: use 'region' not 'region_id'
        template_id = metadata.get('template_id')
        billing_cycle = metadata.get('billing_cycle', 'monthly')
        period_months = metadata.get('period_months', 1)
        
        logger.info(f"🔧 RDP server details: plan={plan_id}, region={region}, template={template_id}, billing={billing_cycle}, period={period_months}")
        
        # Trigger server provisioning asynchronously
        # The provision_rdp_server function is in handlers.py and handles the full provisioning flow
        if _bot_loop:
            try:
                # Import here to avoid circular imports
                from handlers import provision_rdp_server
                
                # Get telegram_id from user_id for the provisioning function
                telegram_id_result = await execute_query(
                    "SELECT telegram_id FROM users WHERE id = %s",
                    (user_id,)
                )
                
                if telegram_id_result:
                    telegram_id = telegram_id_result[0]['telegram_id']
                    
                    # Send provisioning notification to user
                    try:
                        from localization import t_for_user
                        from telegram import Bot
                        
                        bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
                        if not bot_token:
                            raise ValueError("TELEGRAM_BOT_TOKEN not configured")
                        bot = Bot(token=bot_token)
                        
                        provision_title = await t_for_user('rdp.provision.title', telegram_id)
                        provision_msg = await t_for_user('rdp.provision.message', telegram_id)
                        
                        message = f"""
⏳ <b>{provision_title}</b>

{provision_msg}
"""
                        
                        # Send notification in bot loop
                        asyncio.run_coroutine_threadsafe(
                            bot.send_message(
                                chat_id=telegram_id,
                                text=message,
                                parse_mode='HTML'
                            ),
                            _bot_loop
                        )
                        logger.info(f"✅ Sent provisioning notification to user {telegram_id}")
                    except Exception as notify_error:
                        logger.warning(f"⚠️ Could not send provisioning notification: {notify_error}")
                    
                    # Trigger provisioning in the bot loop
                    asyncio.run_coroutine_threadsafe(
                        provision_rdp_server(telegram_id, order_db_id, metadata),
                        _bot_loop
                    )
                    logger.info(f"✅ RDP server provisioning started for order {order_db_id}")
                else:
                    logger.error(f"❌ Could not find telegram_id for user_id {user_id}")
                    
            except Exception as provision_error:
                logger.error(f"❌ Failed to start RDP provisioning: {provision_error}")
                # Send failure alert
                try:
                    from admin_alerts import send_critical_alert
                    asyncio.create_task(send_critical_alert(
                        "RDP Provisioner",
                        f"Failed to provision RDP server for paid order {order_db_id}",
                        "rdp_provision_failed",
                        {
                            "order_id": order_db_id,
                            "order_uuid": order_id,
                            "user_id": user_id,
                            "error": str(provision_error)
                        }
                    ))
                except:
                    pass
        else:
            logger.error("❌ Bot loop not available for RDP provisioning")
        
    except Exception as e:
        logger.error(f"❌ Error processing RDP payment for order {order_id}: {e}")
        import traceback
        logger.error(f"🔍 Full traceback: {traceback.format_exc()}")
        raise

async def _route_domain_payment(order_id: str, telegram_id: int, domain_name: str, payment_details: Dict[str, Any]):
        """Route domain payment to hosting or domain-only orchestrator"""
        try:
            # CRITICAL FIX: Map string tracking ID to integer database ID
            # The order_id here is a string like "domain_registerthisname.sbs_5590563715_1758089473" 
            # where 5590563715 is the telegram_id, not the user_id
            # But the orchestrator needs the integer database ID
            integer_order_id = await _get_integer_order_id_from_tracking_id(order_id, telegram_id, domain_name)
            if integer_order_id is None:
                logger.error(f"❌ Could not find integer order ID for tracking ID: {order_id}")
                return
            
            logger.info(f"✅ Mapped tracking ID {order_id} to database order ID {integer_order_id}")
            
            # CRITICAL FIX: Conditional and idempotent order status update 
            # Update the 'domain_orders' table - ALL domain orders (crypto + wallet) stored here
            from database import execute_update, execute_query
            
            # Conditional update - only from pending states to 'paid'
            affected_rows = await execute_update(
                "UPDATE domain_orders SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = %s AND status IN ('pending', 'pending_payment', 'awaiting_payment')",
                (integer_order_id,)
            )
            
            # Handle update result with proper idempotency
            if affected_rows == 1:
                logger.info(f"✅ Updated domain order {integer_order_id} status from pending to 'paid'")
            elif affected_rows == 0:
                # Check current status - if already paid or beyond, that's OK (idempotent)
                current_status_result = await execute_query(
                    "SELECT status FROM domain_orders WHERE id = %s",
                    (integer_order_id,)
                )
                
                if current_status_result and len(current_status_result) > 0:
                    current_status = current_status_result[0]['status']
                    if current_status in ['paid', 'processing', 'completed']:
                        logger.info(f"✅ Order {integer_order_id} already advanced (status: {current_status}) - idempotent webhook handling")
                    else:
                        logger.warning(f"⚠️ Order {integer_order_id} in unexpected status '{current_status}' - manual review needed")
                        return  # Don't proceed to orchestrator for unexpected states
                else:
                    logger.error(f"❌ Order {integer_order_id} not found in database")
                    return
            
            # Convert telegram_id to user_id for hosting intent check
            user_results = await execute_query("SELECT id FROM users WHERE telegram_id = %s", (telegram_id,))
            if not user_results:
                logger.error(f"❌ Could not find user for telegram_id {telegram_id}")
                return
            user_id = user_results[0]['id']
            
            # Check for hosting intent
            has_hosting_intent = await check_for_hosting_intent(user_id, domain_name)
            
            if has_hosting_intent:
                # CRITICAL FIX: Update hosting intent status to payment_confirmed
                # This allows the hosting orchestrator to claim the lock and process the intent
                hosting_update_result = await execute_update(
                    """UPDATE hosting_provision_intents 
                       SET status = 'payment_confirmed', updated_at = CURRENT_TIMESTAMP 
                       WHERE user_id = %s AND domain_name = %s 
                       AND status IN ('pending_payment', 'awaiting_payment')""",
                    (user_id, domain_name)
                )
                
                if hosting_update_result > 0:
                    logger.info(f"✅ Updated hosting intent status to 'payment_confirmed' for {domain_name}")
                else:
                    logger.warning(f"⚠️ No hosting intent updated for {domain_name} - may already be processed")
                
                logger.info(f"📦 HOSTING BUNDLE: Routing {domain_name} to hosting orchestrator")
                orchestrator = HostingBundleOrchestrator()
                
                # CRITICAL FIX: Check if we're already in the target loop  
                if _bot_loop:
                    try:
                        current_loop = asyncio.get_running_loop()
                        in_same_loop = (current_loop == _bot_loop)
                    except RuntimeError:
                        in_same_loop = False
                    
                    if in_same_loop:
                        # We're already in the bot loop, await directly
                        logger.info(f"🔄 Directly awaiting hosting bundle in same loop for {integer_order_id}")
                        await orchestrator.start_hosting_bundle(
                            order_id=integer_order_id,
                            user_id=user_id,
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=WebhookQueryAdapter(user_id)
                        )
                        logger.info(f"✅ Hosting bundle registration completed for {integer_order_id}")
                    else:
                        # Different thread, use run_coroutine_threadsafe
                        logger.info(f"🔄 Using run_coroutine_threadsafe for hosting bundle {integer_order_id}")
                        future_hosting = asyncio.run_coroutine_threadsafe(
                            orchestrator.start_hosting_bundle(
                                order_id=integer_order_id,
                                user_id=user_id,
                                domain_name=domain_name,
                                payment_details=payment_details,
                                query_adapter=WebhookQueryAdapter(user_id)
                            ),
                            _bot_loop
                        )
                        try:
                            future_hosting.result(timeout=90.0)
                            logger.info(f"✅ Hosting bundle registration completed for {integer_order_id}")
                        except TimeoutError:
                            error_msg = f"Hosting bundle registration timed out after 90s for order {integer_order_id}"
                            logger.error(f"⏰ HOSTING TIMEOUT: {error_msg}")
                            from admin_alerts import send_warning_alert
                            await send_warning_alert(
                                component="hosting_bundle",
                                message=error_msg,
                                category="hosting",
                                details={
                                    "order_id": str(integer_order_id),
                                    "domain_name": domain_name,
                                    "timeout_seconds": 90.0,
                                    "registration_type": "hosting_bundle"
                                }
                            )
                            raise
                else:
                    # Fallback: no bot loop available, await directly
                    await orchestrator.start_hosting_bundle(
                        order_id=integer_order_id,
                        user_id=user_id,
                        domain_name=domain_name,
                        payment_details=payment_details,
                        query_adapter=WebhookQueryAdapter(user_id)
                    )
            else:
                logger.info(f"📄 DOMAIN ONLY: Routing {domain_name} to domain orchestrator")
                # CRITICAL FIX: Check if we're already in the target loop
                if _bot_loop:
                    try:
                        current_loop = asyncio.get_running_loop()
                        in_same_loop = (current_loop == _bot_loop)
                    except RuntimeError:
                        in_same_loop = False
                    
                    if in_same_loop:
                        # We're already in the bot loop, await directly
                        logger.info(f"🔄 Directly awaiting domain registration in same loop for {integer_order_id}")
                        await start_domain_registration(
                            order_id=str(integer_order_id),
                            user_id=user_id,
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=WebhookQueryAdapter(user_id)
                        )
                        logger.info(f"✅ Domain-only registration routing completed for {integer_order_id}")
                    else:
                        # Different thread, use run_coroutine_threadsafe
                        logger.info(f"🔄 Using run_coroutine_threadsafe for domain registration {integer_order_id}")
                        future_domain = asyncio.run_coroutine_threadsafe(
                            start_domain_registration(
                                order_id=str(integer_order_id),
                                user_id=user_id,
                                domain_name=domain_name,
                                payment_details=payment_details,
                                query_adapter=WebhookQueryAdapter(user_id)
                            ),
                            _bot_loop
                        )
                        try:
                            future_domain.result(timeout=75.0)
                            logger.info(f"✅ Domain-only registration routing completed for {integer_order_id}")
                        except TimeoutError:
                            error_msg = f"Domain-only registration timed out after 75s for order {integer_order_id}"
                            logger.error(f"⏰ DOMAIN TIMEOUT: {error_msg}")
                            from admin_alerts import send_warning_alert
                            await send_warning_alert(
                                component="domain_registration", 
                                message=error_msg,
                                category="domain_registration",
                                details={
                                    "order_id": str(integer_order_id),
                                    "domain_name": domain_name,
                                    "timeout_seconds": 75.0,
                                    "registration_type": "domain_only"
                                }
                            )
                            raise
                else:
                    # Fallback: no bot loop available, await directly
                    await start_domain_registration(
                        order_id=str(integer_order_id),
                        user_id=user_id,
                        domain_name=domain_name,
                        payment_details=payment_details,
                        query_adapter=WebhookQueryAdapter(user_id)
                    )
                
        except Exception as e:
            logger.error(f"❌ Error routing domain payment: {e}")
            import traceback
            logger.error(f"🔍 Full traceback for domain payment routing: {traceback.format_exc()}")
            # Re-raise to propagate error
            raise
    
async def _get_hosting_order_id_from_tracking_id(tracking_id: str, extracted_telegram_id: int) -> Optional[int]:
        """
        Map hosting tracking ID to integer database order ID
        
        Similar to domain lookup, but for hosting orders.
        Format: hosting_[subscription_id]_[telegram_id]_[timestamp]
        """
        try:
            from database import execute_query
            
            # Step 1: Convert telegram_id to actual user_id from users table
            user_results = await execute_query(
                "SELECT id FROM users WHERE telegram_id = %s LIMIT 1",
                (extracted_telegram_id,)
            )
            
            if not user_results:
                logger.error(f"❌ No user found for telegram_id {extracted_telegram_id}")
                return None
            
            actual_user_id = user_results[0]['id']
            logger.info(f"✅ Converted telegram_id {extracted_telegram_id} to user_id {actual_user_id}")
            
            # Step 2: Look up the order in the 'orders' table using external_order_id
            # Hosting crypto payment orders are stored here with order_type='hosting'
            order_results = await execute_query(
                """SELECT id FROM orders 
                   WHERE external_order_id = %s 
                   AND user_id = %s 
                   AND order_type = 'hosting'
                   LIMIT 1""",
                (tracking_id, actual_user_id)
            )
            
            if order_results:
                integer_order_id = order_results[0]['id']
                logger.info(f"✅ Found integer order ID {integer_order_id} for hosting tracking ID {tracking_id}")
                return integer_order_id
            else:
                logger.error(f"❌ No order found in 'orders' table for hosting tracking ID {tracking_id}, user {actual_user_id} (telegram_id: {extracted_telegram_id})")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error mapping hosting tracking ID to integer order ID: {e}")
            return None

async def _get_integer_order_id_from_tracking_id(tracking_id: str, extracted_telegram_id: int, domain_name: str) -> Optional[int]:
        """
        Map string tracking ID to integer database order ID
        
        CRITICAL FIX: Query the 'orders' table using 'external_order_id' instead of 
        'domain_orders' table using 'blockbee_order_id'. The crypto payment flow creates
        orders in the 'orders' table with external_order_id field.
        
        Format: domain_[domain]_[telegram_id]_[timestamp]
        """
        try:
            from database import execute_query
            
            # Step 1: Convert telegram_id to actual user_id from users table
            user_results = await execute_query(
                "SELECT id FROM users WHERE telegram_id = %s LIMIT 1",
                (extracted_telegram_id,)
            )
            
            if not user_results:
                logger.error(f"❌ No user found for telegram_id {extracted_telegram_id}")
                return None
            
            actual_user_id = user_results[0]['id']
            logger.info(f"✅ Converted telegram_id {extracted_telegram_id} to user_id {actual_user_id}")
            
            # Step 2: Look up the order in the 'domain_orders' table
            # ALL domain orders (crypto + wallet) are now stored here
            # tracking_id is stored in blockbee_order_id field (misnomer - also stores DynoPay IDs)
            order_results = await execute_query(
                """SELECT id FROM domain_orders 
                   WHERE blockbee_order_id = %s 
                   AND user_id = %s 
                   AND domain_name = %s 
                   LIMIT 1""",
                (tracking_id, actual_user_id, domain_name)
            )
            
            if order_results:
                integer_order_id = order_results[0]['id']
                logger.info(f"✅ Found integer order ID {integer_order_id} for tracking ID {tracking_id}")
                return integer_order_id
            else:
                # CRITICAL ALERT: Domain order not found in domain_orders table
                # This should NEVER happen post-consolidation since all domain orders go to domain_orders
                logger.error(f"❌ CRITICAL: No order found in 'domain_orders' table for tracking ID {tracking_id}, user {actual_user_id} (telegram_id: {extracted_telegram_id}), domain {domain_name}")
                logger.error(f"   This indicates a stuck payment - order may have been created in wrong table or not created at all")
                
                # Send admin alert for immediate investigation
                from admin_alerts import send_critical_alert
                try:
                    await send_critical_alert(
                        component="domain_payment_webhook",
                        message=f"Domain order not found in domain_orders table",
                        category="payment",
                        details={
                            "tracking_id": tracking_id,
                            "user_id": actual_user_id,
                            "telegram_id": extracted_telegram_id,
                            "domain_name": domain_name,
                            "issue": "Payment received but order record missing - possible stuck payment"
                        }
                    )
                except Exception as alert_error:
                    logger.error(f"Failed to send admin alert: {alert_error}")
                
                return None
                
        except Exception as e:
            logger.error(f"❌ Error mapping tracking ID to integer order ID: {e}")
            return None
    

async def _get_hosting_order_details(order_id: str) -> Optional[Dict[str, Any]]:
        """Get hosting order details from database"""
        try:
            # Handle both string and integer order IDs
            if order_id.startswith('hosting_'):
                # Parse hosting order ID format: hosting_[domain]_[user_id]_[timestamp] 
                parts = order_id.split('_')
                if len(parts) >= 4:
                    user_id_str = parts[2]
                    domain_name = parts[1]
                    
                    # Look up by user_id and domain_name in hosting_intents
                    from database import execute_query
                    results = await execute_query(
                        """SELECT hi.id, hi.user_id, hi.domain_name, hi.lang_code, hi.service_type
                           FROM hosting_intents hi 
                           WHERE hi.user_id = %s AND hi.domain_name = %s 
                           ORDER BY hi.created_at DESC LIMIT 1""",
                        (int(user_id_str), domain_name)
                    )
                    
                    if results:
                        order_data = results[0]
                        logger.info(f"✅ Found hosting intent: {order_data}")
                        return order_data
            else:
                # Try as integer order ID - look in hosting_orders or domain_orders
                try:
                    int_order_id = int(order_id)
                    
                    # Check hosting_orders first
                    from database import execute_query
                    results = await execute_query(
                        """SELECT id, user_id, domain_name, lang_code 
                           FROM hosting_orders WHERE id = %s""",
                        (int_order_id,)
                    )
                    
                    if results:
                        return results[0]
                    
                    # Fallback to domain_orders (might be hosting+domain bundle)
                    from database import execute_query
                    results = await execute_query(
                        """SELECT id, user_id, domain_name, lang_code 
                           FROM domain_orders WHERE id = %s""",
                        (int_order_id,)
                    )
                    
                    if results:
                        return results[0]
                        
                except ValueError:
                    pass
            
            logger.warning(f"⚠️ No hosting order found for order_id: {order_id}")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting hosting order details for {order_id}: {e}")
            return None
    
def _is_payment_successful(payment_details: Dict[str, Any]) -> bool:
    """Check if payment is successful with proper provider-specific validation"""
    status = payment_details.get('status')
    confirmations = payment_details.get('confirmations', 0)
    
    # Normalize status across providers
    if isinstance(status, list) and len(status) > 0:
        status = status[0]  # Handle query param arrays
    
    from models.payment_models import PaymentStatus
    
    # Handle both string and enum status values
    if isinstance(status, str):
        # Map provider-specific strings to standard PaymentStatus enums
        status_mapping = {
            'successful': PaymentStatus.SUCCESSFUL,
            'confirmed': PaymentStatus.CONFIRMED,
            'completed': PaymentStatus.COMPLETED,
            'paid': PaymentStatus.SUCCESSFUL,      # BlockBee alias
            'sent': PaymentStatus.PROCESSING,      # BlockBee alias (needs confirmations)
        }
        
        # Convert string to enum, or keep original if not in mapping
        if status.lower() in status_mapping:
            status = status_mapping[status.lower()]
        else:
            logger.warning(f"❌ Unknown payment status string: {status}")
            return False
    
    # Check if status is a successful final state
    if status in [PaymentStatus.SUCCESSFUL, PaymentStatus.CONFIRMED, PaymentStatus.COMPLETED]:
        return True
    
    # Handle PROCESSING status - requires confirmations
    if status == PaymentStatus.PROCESSING:
        if confirmations >= 1:
            logger.info(f"✅ Payment processing with {confirmations} confirmations")
            return True
        else:
            logger.info(f"⏳ Payment processing but waiting for confirmations: {confirmations}")
            return False
    
    logger.warning(f"❌ Payment not successful - Status: {status}, Confirmations: {confirmations}")
    return False

class WebhookQueryAdapter:
    """Adapter for sending messages via webhook handler"""
    
    def __init__(self, user_id: int):
        self.user_id = user_id
    
    async def send_message(self, text: str, parse_mode: str = 'HTML', **kwargs):
        """Send message via webhook queue"""
        await queue_user_message(self.user_id, text, parse_mode)
    
    async def edit_message_text(self, text: str, parse_mode: str = 'HTML', **kwargs):
        """Edit message (treated as send for webhook)"""
        await queue_user_message(self.user_id, text, parse_mode)

# Legacy start_webhook_server function removed - now using FastAPI webhook gateway
        
# Legacy aiohttp server startup code removed - now using FastAPI webhook gateway
# All webhook routing is now handled by fastapi_server.py
