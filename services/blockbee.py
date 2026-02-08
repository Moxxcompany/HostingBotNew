"""
BlockBee service implementation for cryptocurrency payment processing
"""

import logging
import os
import httpx
import uuid
import time
from typing import Dict, Optional, Callable, Any
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

# Import centralized payment logging utilities
from utils.payment_logging import (
    get_payment_logger, PaymentLogContext, PaymentEventType, PaymentLogLevel,
    track_payment_operation, PAYMENT_LOGGING_AVAILABLE, PaymentLogger
)

payment_logger: PaymentLogger = get_payment_logger()

logger = logging.getLogger(__name__)

class BlockBeeService:
    """BlockBee cryptocurrency payment service"""
    
    def __init__(self) -> None:
        self.api_key = os.getenv('BLOCKBEE_API_KEY')
        self.base_url = "https://api.blockbee.io"
        if self.api_key:
            logger.info("🔧 BlockBee service initialized with API key")
        else:
            logger.info("🔧 BlockBee service initialized (no API key configured)")
    
    def is_available(self) -> bool:
        """Check if BlockBee service is available"""
        return bool(self.api_key)
    
    @track_payment_operation("blockbee_create_payment_address")
    async def create_payment_address(self, currency: str, order_id: str, value: float, user_id: int, idempotency_key: Optional[str] = None, intent_id: Optional[int] = None) -> Optional[Dict]:
        """Create payment address via BlockBee API with comprehensive logging"""
        operation_start = time.time()
        correlation_id = None
        
        # FIX: Convert Decimal to float for JSON serialization
        # Decimal objects cannot be serialized to JSON by default
        value = float(value) if value is not None else 0.0
        
        # Enhanced BlockBee API call logging
        payment_logger = get_payment_logger()
        correlation_id = str(uuid.uuid4())
        
        # Log BlockBee API call start
        context = PaymentLogContext(
            correlation_id=correlation_id,
            user_id=user_id,
            order_id=order_id,
            provider="blockbee",
            currency=currency,
            amount_usd=value,
            current_status="creating_address",
            metadata={
                'api_operation': 'create_payment_address',
                'currency': currency,
                'amount': value,
                'idempotency_key': idempotency_key
            }
        )
        
        payment_logger.log_payment_event(
            PaymentEventType.PROVIDER_API_CALL,
            f"Starting BlockBee payment address creation for {currency.upper()}: ${value}",
            context,
            PaymentLogLevel.INFO
        )
        
        if not self.api_key:
            error_msg = "BlockBee create_payment_address called but service not configured"
            logger.warning(f"⚠️ {error_msg}")
            
            # Enhanced configuration error logging
            payment_logger.log_payment_error(
                ValueError("BlockBee service not configured"),
                PaymentLogContext(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    order_id=order_id,
                    provider="blockbee",
                    metadata={'api_key_provided': bool(self.api_key)}
                ),
                error_category="configuration_error",
                actionable_steps=[
                    "Set BLOCKBEE_API_KEY environment variable",
                    "Verify BlockBee service configuration"
                ]
            )
            return None
        
        try:
            # BlockBee API format: GET /{ticker}/create/?callback={webhook_url}&apikey={api_key}
            from utils.environment import get_webhook_url
            webhook_url = get_webhook_url('blockbee')
            
            async with httpx.AsyncClient() as client:
                params = {
                    'apikey': self.api_key,
                    'callback': f"{webhook_url}?order_id={order_id}&user_id={user_id}",
                    'pending': '1',  # Receive webhooks for unconfirmed transactions
                    'convert': '1'   # Auto-convert to preferred currency
                }
                
                response = await client.get(
                    f"{self.base_url}/{currency.lower()}/create/",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        address_in = result.get('address_in')
                        # Calculate API response time
                        duration_ms = (time.time() - operation_start) * 1000
                        
                        logger.info(f"✅ BlockBee created payment address for {currency.upper()}: {address_in}")
                        
                        # Calculate crypto amount using the same FastForex service as DynoPay
                        crypto_amount_display = 'TBD'
                        try:
                            from services.fastforex import fastforex_service
                            crypto_amount, crypto_amount_display = await fastforex_service.get_usd_to_crypto_amount(
                                value, currency.upper()
                            )
                            logger.info(f"📈 BlockBee real-time rate: ${value} USD = {crypto_amount_display}")
                        except Exception as e:
                            logger.warning(f"⚠️ FastForex failed for BlockBee, using fallback: {str(e)}")
                            # Fallback to static rates if FastForex fails
                            crypto_rates = {
                                'BTC': 100000,     # ~$100k per BTC (Dec 2025)
                                'ETH': 3000,       # ~$3k per ETH  
                                'LTC': 83,         # ~$83 per LTC
                                'DOGE': 0.14,      # ~$0.14 per DOGE
                                'USDT': 1.0,       # ~$1 per USDT
                                'USDT-ERC20': 1.0, # ~$1 per USDT
                                'USDT-TRC20': 1.0  # ~$1 per USDT
                            }
                            
                            rate = crypto_rates.get(currency.upper(), 1.0)
                            crypto_amount = value / rate
                            
                            # Format crypto amount for display (strip trailing zeros)
                            from pricing_utils import format_crypto_amount
                            crypto_amount_display = format_crypto_amount(crypto_amount, currency.upper())
                        
                        # Enhanced API success logging
                        if PAYMENT_LOGGING_AVAILABLE:
                            payment_logger.log_payment_event(
                                PaymentEventType.PROVIDER_API_CALL,
                                f"BlockBee API success: Payment address created for {currency.upper()}",
                                PaymentLogContext(
                                    correlation_id=correlation_id,
                                    user_id=user_id,
                                    order_id=order_id,
                                    provider="blockbee",
                                    currency=currency.upper(),
                                    amount_usd=value,
                                    payment_address=address_in,
                                    current_status="address_created",
                                    duration_ms=duration_ms,
                                    metadata={
                                        'api_success': True,
                                        'payment_address': address_in,
                                        'crypto_amount_display': crypto_amount_display,
                                        'callback_url': result.get('callback_url'),
                                        'minimum_transaction': result.get('minimum_transaction_coin'),
                                        'exchange_rate_source': 'fastforex'
                                    }
                                ),
                                PaymentLogLevel.INFO
                            )
                        
                        # PARITY FIX: Store payment_address in payment_intents (matching DynoPay behavior)
                        try:
                            from database import execute_update, execute_query
                            import secrets
                            
                            # Generate auth token for webhook validation (matching DynoPay)
                            auth_token = secrets.token_urlsafe(32)
                            
                            target_intent_id = None
                            
                            # OPTIMIZED: If intent_id is provided directly, use it without search
                            if intent_id:
                                logger.info(f"✅ BlockBee: Using provided intent_id={intent_id} directly")
                                target_intent_id = intent_id
                            else:
                                # FALLBACK: Search for the payment intent by order_id
                                logger.info(f"🔍 BlockBee: Searching for payment intent with order_id='{order_id}'")
                                
                                existing_intents = await execute_query("""
                                    SELECT id, order_id, payment_provider, status
                                    FROM payment_intents 
                                    WHERE (
                                        order_id = %s OR
                                        order_id ILIKE %s
                                    )
                                    AND status IN ('creating_address', 'pending', 'created')
                                    ORDER BY created_at DESC
                                """, (order_id, f'%{order_id}%'))
                                
                                if existing_intents:
                                    target_intent_id = existing_intents[0]['id']
                            
                            if target_intent_id:
                                # Update payment intent with address and auth token
                                # Also update payment_provider to 'blockbee' since we're using BlockBee now
                                update_result = await execute_update("""
                                    UPDATE payment_intents 
                                    SET auth_token = %s, 
                                        payment_address = %s, 
                                        payment_provider = 'blockbee',
                                        status = 'address_created',
                                        updated_at = CURRENT_TIMESTAMP
                                    WHERE id = %s
                                """, (auth_token, address_in, target_intent_id))
                                
                                logger.info(f"✅ BlockBee: Updated payment intent {target_intent_id} with address {address_in}")
                                logger.info(f"   ✅ Auth token length: {len(auth_token)} chars")
                                logger.info(f"   ✅ Status: address_created")
                            else:
                                logger.warning(f"⚠️ BlockBee: No payment intent found for order_id='{order_id}' - address not stored")
                                
                        except Exception as db_error:
                            logger.warning(f"⚠️ BlockBee: Failed to store payment address in DB: {db_error}")
                        
                        return {
                            'address': address_in,
                            'currency': currency.upper(),
                            'amount': value,
                            'amount_display': value,
                            'crypto_amount': crypto_amount_display,  # Add crypto amount display
                            'callback_url': result.get('callback_url'),
                            'minimum_transaction': result.get('minimum_transaction_coin'),
                            'priority': result.get('priority', 'default')
                        }
                    else:
                        error_msg = result.get('error', 'Unknown error')
                        logger.error(f"❌ BlockBee API error: {error_msg}")
                        # Send admin alert for BlockBee API error
                        await send_error_alert(
                            "BlockBee",
                            f"Payment address creation failed: {error_msg}",
                            "payment_processing",
                            {
                                "currency": currency,
                                "order_id": order_id,
                                "user_id": user_id,
                                "api_error": error_msg,
                                "api_response": result
                            }
                        )
                        return None
                else:
                    logger.error(f"❌ BlockBee API error: {response.status_code} - {response.text}")
                    # Send admin alert for BlockBee HTTP error
                    await send_critical_alert(
                        "BlockBee",
                        f"Payment address creation API failure: HTTP {response.status_code}",
                        "external_api",
                        {
                            "currency": currency,
                            "order_id": order_id,
                            "user_id": user_id,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return None
                    
        except Exception as e:
            logger.error(f"❌ BlockBee payment address creation failed: {str(e)}")
            # Send admin alert for BlockBee exception
            await send_critical_alert(
                "BlockBee",
                f"Payment address creation exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "order_id": order_id,
                    "user_id": user_id,
                    "exception": str(e)
                }
            )
            return None
    
    async def process_refund(
        self, 
        currency: str,
        payment_address: str, 
        amount: float, 
        reason: str = "Hosting bundle failure"
    ) -> Optional[Dict]:
        """Process refund via BlockBee API (Note: BlockBee may not support automated refunds)"""
        if not self.is_available():
            logger.warning("⚠️ BlockBee process_refund called but service not configured")
            return None
        
        try:
            # Note: BlockBee may not have an automated refund API
            # This implementation logs the refund request and returns pending status
            # for manual processing by the support team
            
            logger.info(f"📝 BlockBee refund request logged: {payment_address} - ${amount}")
            logger.info(f"📝 Refund reason: {reason}")
            
            # In a production implementation, you might:
            # 1. Log to a refund queue for manual processing
            # 2. Send notification to support team
            # 3. Create a support ticket automatically
            
            return {
                'status': 'pending',
                'refund_method': 'manual_processing',
                'amount': amount,
                'currency': currency.upper(),
                'payment_address': payment_address,
                'provider_response': 'Refund request logged for manual processing by support team'
            }
                    
        except Exception as e:
            logger.error(f"❌ BlockBee refund processing failed: {str(e)}")
            # Send admin alert for BlockBee refund exception
            await send_error_alert(
                "BlockBee",
                f"Refund processing exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "payment_address": payment_address,
                    "amount": amount,
                    "reason": reason,
                    "exception": str(e)
                }
            )
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def check_payment_status(self, currency: str, payment_address: str) -> Optional[Dict]:
        """Check payment status via BlockBee API"""
        if not self.api_key:
            logger.warning("⚠️ BlockBee check_payment_status called but service not configured")
            return None
            
        try:
            async with httpx.AsyncClient() as client:
                params = {
                    'apikey': self.api_key
                }
                
                response = await client.get(
                    f"{self.base_url}/{currency.lower()}/info/{payment_address}/",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        return result
                    else:
                        logger.error(f"❌ BlockBee status error: {result.get('error', 'Unknown error')}")
                        return None
                else:
                    logger.error(f"❌ BlockBee status check error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ BlockBee status check failed: {str(e)}")
            return None