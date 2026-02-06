"""
DynoPay service implementation for cryptocurrency payment processing
"""

import logging
import os
import httpx
import uuid
import time
from typing import Dict, Optional, Callable, Any
from datetime import datetime, timedelta
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

# Import centralized payment logging utilities
from utils.payment_logging import (
    get_payment_logger, PaymentLogContext, PaymentEventType, PaymentLogLevel,
    track_payment_operation, PAYMENT_LOGGING_AVAILABLE, PaymentLogger
)

payment_logger: PaymentLogger = get_payment_logger()

logger = logging.getLogger(__name__)

class DynoPayService:
    """DynoPay cryptocurrency payment service"""
    
    def __init__(self) -> None:
        self.api_key = os.getenv('DYNOPAY_API_KEY')
        self.wallet_token = os.getenv('DYNOPAY_WALLET_TOKEN')
        self.base_url = os.getenv('DYNOPAY_BASE_URL', 'https://dynobackendconsolidated.up.railway.app/api')
        
        if self.api_key and self.wallet_token:
            logger.info("🔧 DynoPay service initialized with API key and wallet token")
        else:
            logger.info("🔧 DynoPay service initialized (missing credentials)")
    
    def is_available(self) -> bool:
        """Check if DynoPay service is available"""
        return bool(self.api_key and self.wallet_token)
    
    @track_payment_operation("dynopay_create_payment_address")
    async def create_payment_address(self, currency: str, order_id: str, value: float, user_id: int, idempotency_key: Optional[str] = None, intent_id: Optional[int] = None) -> Optional[Dict]:
        """Create payment address via DynoPay API with comprehensive logging"""
        operation_start = time.time()
        correlation_id = None
        
        # FIX: Convert Decimal to float for JSON serialization
        # Decimal objects cannot be serialized to JSON by default
        value = float(value) if value is not None else 0.0
        
        # Enhanced DynoPay API call logging
        payment_logger = get_payment_logger()
        correlation_id = str(uuid.uuid4())
        
        # Log DynoPay API call start
        context = PaymentLogContext(
            correlation_id=correlation_id,
            user_id=user_id,
            order_id=order_id,
            provider="dynopay",
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
            f"Starting DynoPay payment address creation for {currency.upper()}: ${value}",
            context,
            PaymentLogLevel.INFO
        )
        
        if not self.is_available():
            error_msg = "DynoPay create_payment_address called but service not configured"
            logger.warning(f"⚠️ {error_msg}")
            
            # Enhanced configuration error logging
            payment_logger.log_payment_error(
                ValueError("DynoPay service not configured"),
                PaymentLogContext(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    order_id=order_id,
                    provider="dynopay",
                    metadata={
                        'api_key_provided': bool(self.api_key),
                        'wallet_token_provided': bool(self.wallet_token)
                    }
                ),
                error_category="configuration_error",
                actionable_steps=[
                    "Set DYNOPAY_API_KEY environment variable",
                    "Set DYNOPAY_WALLET_TOKEN environment variable",
                    "Verify DynoPay service configuration"
                ]
            )
            return None
        
        try:
            # Get webhook URL using environment detection
            from utils.environment import get_webhook_url
            webhook_url = get_webhook_url('dynopay')
            
            # Map currency to DynoPay format
            currency_map = {
                'btc': 'BTC',
                'eth': 'ETH', 
                'ltc': 'LTC',
                'doge': 'DOGE',
                'usdt': 'USDT',  # ERC20
                'usdt_erc20': 'USDT-ERC20',  # Fixed: handle underscore format
                'usdt-erc20': 'USDT-ERC20',  # Also handle dash format
                'usdt_trc20': 'USDT-TRC20',  # Fixed: handle underscore format
                'usdt-trc20': 'USDT-TRC20'   # Also handle dash format
            }
            
            dynopay_currency = currency_map.get(currency.lower(), currency.upper())
            
            # DynoPay requires minimum $1 USD - adjust amount if needed
            if value == 0 or value < 1:
                value = 1.0  # Set minimum $1 USD for wallet deposits
                logger.info(f"💰 DynoPay: Adjusted amount to ${value} USD (minimum required)")
            
            amount_to_use = value
            logger.info(f"💰 DynoPay: Using amount ${amount_to_use} USD for {dynopay_currency}")
            
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "content-type": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                # Generate secure callback token for webhook authentication
                import secrets
                auth_token = secrets.token_urlsafe(32)
                
                data = {
                    "amount": amount_to_use,
                    "currency": dynopay_currency,
                    "redirect_uri": f"{webhook_url}?order_id={order_id}&auth_token={auth_token}",
                    "product_id": f"crypto_{dynopay_currency.lower()}",  # FIX: DynoPay now requires product_id
                    "meta_data": {
                        "product_name": "crypto_payment",
                        "refId": order_id,
                        "user_id": str(user_id),
                        "order_id": order_id,
                        "original_amount": value,  # Store original amount for reference
                        "wallet_deposit": value <= 0  # Flag for wallet deposits
                    }
                }
                
                response = await client.post(
                    f"{self.base_url}/user/cryptoPayment",
                    json=data,
                    headers=headers,
                    timeout=10.0  # PERFORMANCE OPTIMIZATION: Reduced from 15s to 10s
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # DynoPay returns address in nested 'data' object
                    response_data = result.get('data', {})
                    payment_address = response_data.get('address') or result.get('payment_address') or result.get('address')
                    
                    if payment_address:
                        # Calculate API response time
                        duration_ms = (time.time() - operation_start) * 1000
                        
                        logger.info(f"✅ DynoPay created payment address for {dynopay_currency}: {payment_address}")
                        
                        # Enhanced API success logging
                        payment_logger.log_payment_event(
                            PaymentEventType.PROVIDER_API_CALL,
                            f"DynoPay API success: Payment address created for {dynopay_currency}",
                            PaymentLogContext(
                                correlation_id=correlation_id,
                                user_id=user_id,
                                order_id=order_id,
                                provider="dynopay",
                                currency=dynopay_currency,
                                amount_usd=amount_to_use,
                                payment_address=payment_address,
                                current_status="address_created",
                                duration_ms=duration_ms,
                                metadata={
                                    'api_success': True,
                                    'payment_address': payment_address,
                                    'auth_token_generated': bool(auth_token),
                                    'webhook_url': webhook_url,
                                    'currency_mapping': f"{currency} -> {dynopay_currency}",
                                    'amount_adjustment': value != amount_to_use,
                                    'original_amount': value,
                                    'final_amount': amount_to_use
                                }
                            ),
                            PaymentLogLevel.INFO
                        )
                        
                        # SECURITY FIX: Update payment_intent with auth_token and payment_address
                        try:
                            from database import execute_update, execute_query
                            
                            target_intent_id = None
                            intent_order_id = order_id
                            
                            # OPTIMIZED: If intent_id is provided directly, use it without search
                            if intent_id:
                                logger.info(f"✅ DIRECT: Using provided intent_id={intent_id} for auth_token storage")
                                target_intent_id = intent_id
                            else:
                                # FALLBACK SEARCH: Find the payment intent by order_id
                                logger.info(f"🔍 SEARCH: Looking for payment intent with order_id='{order_id}' provider='dynopay'")
                                
                                existing_intents = await execute_query("""
                                    SELECT id, order_id, payment_provider, status, auth_token, payment_address, uuid_id
                                    FROM payment_intents 
                                    WHERE payment_provider = %s AND (
                                        order_id = %s OR
                                        order_id ILIKE %s
                                    )
                                    ORDER BY created_at DESC
                                """, ('dynopay', order_id, f'%{order_id}%'))
                                
                                logger.info(f"🔍 SEARCH: Found {len(existing_intents)} payment intent(s) for order_id '{order_id}' and provider 'dynopay'")
                                
                                if existing_intents:
                                    target_intent_id = existing_intents[0]['id']
                                    intent_order_id = existing_intents[0]['order_id']
                                else:
                                    # Last resort: Look for recent pending intents
                                    logger.warning(f"⚠️ FALLBACK: No exact match for order_id='{order_id}', checking recent pending intents")
                                    fallback_intents = await execute_query("""
                                        SELECT id, order_id, payment_provider, status, created_at
                                        FROM payment_intents 
                                        WHERE payment_provider = 'dynopay' 
                                        AND auth_token IS NULL 
                                        AND status = 'creating_address'
                                        AND created_at >= NOW() - INTERVAL '30 seconds'
                                        ORDER BY created_at DESC
                                        LIMIT 1
                                    """)
                                    
                                    if fallback_intents:
                                        target_intent_id = fallback_intents[0]['id']
                                        intent_order_id = fallback_intents[0]['order_id']
                                        logger.warning(f"⚠️ FALLBACK: Using recent intent ID {target_intent_id} for order_id='{order_id}'")
                            
                            if not target_intent_id:
                                logger.error(f"❌ CRITICAL ERROR: No payment intent found for order_id='{order_id}' - cannot store auth_token!")
                                return None
                            
                            logger.info(f"🔍 Updating intent ID {target_intent_id} with:")
                            logger.info(f"  - auth_token = '{auth_token[:10]}...' (length: {len(auth_token)})")
                            logger.info(f"  - payment_address = '{payment_address}'")
                            logger.info(f"  - target order_id = '{intent_order_id}'")
                            
                            # RELIABLE UPDATE: Use intent ID for guaranteed match
                            # Note: expires_at is already set correctly by payment_timeout_config during intent creation
                            update_result = await execute_update("""
                                UPDATE payment_intents 
                                SET auth_token = %s, 
                                    payment_address = %s, 
                                    status = 'address_created',
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE id = %s AND payment_provider = 'dynopay'
                            """, (
                                auth_token, payment_address, 
                                target_intent_id
                            ))
                            
                            logger.info(f"✅ UPDATE by intent ID {target_intent_id} affected {update_result} rows")
                            
                            # MANDATORY VALIDATION: Ensure exactly 1 row was updated
                            if update_result != 1:
                                logger.error(f"❌ CRITICAL ERROR: UPDATE affected {update_result} rows (expected 1) for intent ID {target_intent_id}")
                                raise Exception(f"UPDATE operation failed: affected {update_result} rows instead of 1")
                            else:
                                logger.info(f"✅ Successfully updated 1 row for intent ID {target_intent_id}")
                            
                            # COMPREHENSIVE VALIDATION: Verify the update worked with enhanced assertions
                            verify_result = await execute_query("""
                                SELECT id, auth_token, order_id, payment_address, status 
                                FROM payment_intents 
                                WHERE id = %s AND payment_provider = 'dynopay'
                            """, (target_intent_id,))
                            
                            # CRITICAL ASSERTION: Auth token must be stored for security
                            if verify_result and verify_result[0]['auth_token']:
                                stored_auth_token = verify_result[0]['auth_token']
                                verified_intent_id = verify_result[0]['id']
                                stored_address = verify_result[0]['payment_address']
                                
                                # VALIDATION ASSERTIONS: Ensure data integrity
                                assert stored_auth_token == auth_token, f"Auth token mismatch: stored='{stored_auth_token[:10]}...' vs expected='{auth_token[:10]}...'"
                                assert stored_address == payment_address, f"Payment address mismatch: stored='{stored_address}' vs expected='{payment_address}'"
                                assert len(stored_auth_token) >= 32, f"Auth token too short: {len(stored_auth_token)} chars (minimum 32)"
                                
                                logger.info(f"🔒 Successfully stored auth_token for order {order_id} (intent_id: {verified_intent_id})")
                                logger.info(f"  ✅ Auth token length: {len(stored_auth_token)} chars")
                                logger.info(f"  ✅ Payment address: {stored_address}")
                                logger.info(f"  ✅ Status: {verify_result[0]['status']}")
                                
                                # Enhanced database update success logging
                                if PAYMENT_LOGGING_AVAILABLE:
                                    payment_logger.log_payment_event(
                                        PaymentEventType.INTENT_UPDATED,
                                        f"Payment intent updated with DynoPay address and auth token",
                                        PaymentLogContext(
                                            correlation_id=correlation_id,
                                            user_id=user_id,
                                            order_id=order_id,
                                            payment_intent_id=verify_result[0]['id'],
                                            provider="dynopay",
                                            payment_address=payment_address,
                                            current_status="address_created",
                                            metadata={'database_update': 'success', 'auth_token_stored': True}
                                        ),
                                        PaymentLogLevel.INFO
                                    )
                            else:
                                # CRITICAL SECURITY FAILURE: Auth token storage verification failed
                                error_details = {
                                    'verification_query_results': len(verify_result) if verify_result else 0,
                                    'auth_token_present': bool(verify_result and verify_result[0].get('auth_token')) if verify_result else False,
                                    'expected_auth_token_length': len(auth_token),
                                    'order_id': order_id,
                                    'payment_address': payment_address,
                                    'provider': 'dynopay'
                                }
                                
                                logger.error(f"❌ CRITICAL SECURITY FAILURE: Auth token storage verification failed for order {order_id}")
                                logger.error(f"  📊 Verification Details: {error_details}")
                                
                                if verify_result:
                                    for i, result in enumerate(verify_result):
                                        logger.error(f"  📝 Result {i+1}: id={result.get('id')}, has_auth_token={bool(result.get('auth_token'))}, status='{result.get('status')}'")
                                
                                # ASSERTION: This should never happen in production
                                assert False, f"CRITICAL: Auth token storage failed for order {order_id}. Webhook validation will be insecure!"
                                
                                # Enhanced database update failure logging
                                if PAYMENT_LOGGING_AVAILABLE:
                                    payment_logger.log_payment_error(
                                        Exception("Auth token storage verification failed"),
                                        PaymentLogContext(
                                            correlation_id=correlation_id,
                                            user_id=user_id,
                                            order_id=order_id,
                                            provider="dynopay",
                                            payment_address=payment_address,
                                            metadata={'database_update': 'verification_failed'}
                                        ),
                                        error_category="database_update_error",
                                        actionable_steps=[
                                            "Check payment_intents table constraints",
                                            "Verify business_order_id uniqueness",
                                            "Review database transaction completion"
                                        ]
                                    )
                                
                        except AssertionError as assertion_error:
                            # CRITICAL: Assertion failures indicate data integrity issues
                            logger.error(f"❌ CRITICAL ASSERTION FAILURE: Auth token validation failed for order {order_id}")
                            logger.error(f"  🔍 Assertion Details: {assertion_error}")
                            
                            # Enhanced assertion failure logging
                            if PAYMENT_LOGGING_AVAILABLE:
                                payment_logger.log_payment_error(
                                    assertion_error,
                                    PaymentLogContext(
                                        correlation_id=correlation_id,
                                        user_id=user_id,
                                        order_id=order_id,
                                        provider="dynopay",
                                        payment_address=payment_address,
                                        metadata={
                                            'error_type': 'assertion_failure',
                                            'auth_token_length': len(auth_token),
                                            'payment_address': payment_address
                                        }
                                    ),
                                    error_category="data_integrity_error",
                                    actionable_steps=[
                                        "Investigate execute_update transaction management",
                                        "Check payment_intents table constraints",
                                        "Review database connection pool state",
                                        "Verify SQL parameter binding"
                                    ]
                                )
                            
                            # Don't return payment address if security storage failed
                            return None
                            
                        except Exception as db_error:
                            logger.error(f"❌ CRITICAL: Failed to store auth_token for order {order_id}: {db_error}")
                            
                            # Enhanced database error logging
                            if PAYMENT_LOGGING_AVAILABLE:
                                payment_logger.log_payment_error(
                                    db_error,
                                    PaymentLogContext(
                                        correlation_id=correlation_id,
                                        user_id=user_id,
                                        order_id=order_id,
                                        provider="dynopay",
                                        payment_address=payment_address,
                                        metadata={'error_type': 'database_error'}
                                    ),
                                    error_category="database_error",
                                    actionable_steps=[
                                        "Check database connectivity",
                                        "Review execute_update implementation",
                                        "Verify payment_intents table schema"
                                    ]
                                )
                            
                            # Don't fail payment creation entirely, but security is compromised
                            
                        # Get crypto amount using NON-BLOCKING cached exchange rate
                        # This ensures payment address creation never blocks on API calls
                        try:
                            from services.fastforex import fastforex_service
                            
                            # Use fetch_cached_rate instead of blocking get_crypto_rate
                            # Returns immediately with cached/fallback rate, refreshes in background if stale
                            rate, rate_source = await fastforex_service.fetch_cached_rate(dynopay_currency, "USD")
                            
                            # Calculate crypto amount (rate is crypto per USD)
                            crypto_amount = amount_to_use * rate
                            
                            # Format crypto amount for display (same logic as before)
                            if crypto_amount >= 1:
                                crypto_amount_display = f"{crypto_amount:.3f} {dynopay_currency}"
                            elif crypto_amount >= 0.001:
                                crypto_amount_display = f"{crypto_amount:.4f} {dynopay_currency}"
                            else:
                                crypto_amount_display = f"{crypto_amount:.6f} {dynopay_currency}"
                            
                            logger.info(f"📈 Crypto amount: ${amount_to_use} USD = {crypto_amount_display} (source: {rate_source})")
                            
                        except Exception as e:
                            # Extreme fallback if even fetch_cached_rate fails (should never happen)
                            logger.error(f"❌ CRITICAL: Non-blocking rate fetch failed: {str(e)}")
                            # Use static fallback rates as last resort
                            crypto_rates = {
                                'BTC': 0.00001,     # ~$100k per BTC (Dec 2025)
                                'ETH': 0.00033,     # ~$3k per ETH  
                                'LTC': 0.012,       # ~$83 per LTC
                                'DOGE': 7.0,        # ~$0.14 per DOGE
                                'USDT-ERC20': 1.0,  # ~$1 per USDT
                                'USDT-TRC20': 1.0   # ~$1 per USDT
                            }
                            rate = crypto_rates.get(dynopay_currency, 1.0)
                            crypto_amount = amount_to_use * rate
                            
                            # Format with same logic
                            if crypto_amount >= 1:
                                crypto_amount_display = f"{crypto_amount:.3f} {dynopay_currency}"
                            elif crypto_amount >= 0.001:
                                crypto_amount_display = f"{crypto_amount:.4f} {dynopay_currency}"
                            else:
                                crypto_amount_display = f"{crypto_amount:.6f} {dynopay_currency}"
                            
                            logger.warning(f"⚠️ Using static fallback rate: ${amount_to_use} USD = {crypto_amount_display}")
                        
                        return {
                            'address': payment_address,
                            'currency': dynopay_currency,
                            'amount': amount_to_use,
                            'amount_display': amount_to_use,
                            'crypto_amount': crypto_amount_display,  # Add estimated crypto amount
                            'original_amount': value,
                            'is_wallet_deposit': value <= 0,
                            'redirect_uri': data['redirect_uri'],  # Use original request data
                            'auth_token': auth_token,
                            'meta_data': data['meta_data']  # Use original request data
                        }
                    else:
                        logger.error(f"❌ DynoPay API response missing payment address: {result}")
                        # Send admin alert for missing payment address
                        await send_error_alert(
                            "DynoPay",
                            f"Payment address creation failed - missing address in response",
                            "payment_processing",
                            {
                                "currency": dynopay_currency,
                                "amount": amount_to_use,
                                "order_id": order_id,
                                "user_id": user_id,
                                "api_response": result
                            }
                        )
                        return None
                else:
                    logger.error(f"❌ DynoPay API error: {response.status_code} - {response.text}")
                    # Send admin alert for DynoPay API error
                    await send_critical_alert(
                        "DynoPay",
                        f"Payment address creation API failure: HTTP {response.status_code}",
                        "external_api",
                        {
                            "currency": dynopay_currency,
                            "amount": amount_to_use,
                            "order_id": order_id,
                            "user_id": user_id,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return None
                    
        except Exception as e:
            logger.error(f"❌ DynoPay payment address creation failed: {str(e)}")
            # Send admin alert for DynoPay exception
            await send_critical_alert(
                "DynoPay",
                f"Payment address creation exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "amount": value,
                    "order_id": order_id,
                    "user_id": user_id,
                    "exception": str(e)
                }
            )
            return None
    
    async def process_refund(
        self, 
        payment_id: str, 
        amount: float, 
        currency: str = "USD",
        reason: str = "Hosting bundle failure"
    ) -> Optional[Dict]:
        """Process refund via DynoPay API"""
        if not self.is_available():
            logger.warning("⚠️ DynoPay process_refund called but service not configured")
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "content-type": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                data = {
                    "payment_id": payment_id,
                    "amount": amount,
                    "currency": currency,
                    "reason": reason
                }
                
                response = await client.post(
                    f"{self.base_url}/user/refund",
                    json=data,
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"✅ DynoPay refund processed: {payment_id}")
                    return {
                        'status': 'success',
                        'refund_id': result.get('refund_id'),
                        'amount': amount,
                        'currency': currency,
                        'provider_response': result
                    }
                else:
                    logger.error(f"❌ DynoPay refund API error: {response.status_code} - {response.text}")
                    # Send admin alert for DynoPay refund failure
                    await send_critical_alert(
                        "DynoPay",
                        f"Refund processing failed: HTTP {response.status_code}",
                        "payment_processing",
                        {
                            "payment_id": payment_id,
                            "amount": amount,
                            "currency": currency,
                            "reason": reason,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return {
                        'status': 'failed',
                        'error': f"API error: {response.status_code}",
                        'response_text': response.text
                    }
                    
        except Exception as e:
            logger.error(f"❌ DynoPay refund processing failed: {str(e)}")
            # Send admin alert for DynoPay refund exception
            await send_critical_alert(
                "DynoPay",
                f"Refund processing exception: {str(e)}",
                "payment_processing",
                {
                    "payment_id": payment_id,
                    "amount": amount,
                    "currency": currency,
                    "reason": reason,
                    "exception": str(e)
                }
            )
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def check_payment_status(self, currency: str, payment_address: str) -> Optional[Dict]:
        """Check payment status via DynoPay API"""
        if not self.is_available():
            logger.warning("⚠️ DynoPay check_payment_status called but service not configured")
            return None
            
        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                # DynoPay status endpoint (adjust based on actual API)
                response = await client.get(
                    f"{self.base_url}/payment/status/{currency.upper()}/{payment_address}",
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"❌ DynoPay status check error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ DynoPay status check failed: {str(e)}")
            return None
    
    def get_supported_currencies(self) -> list:
        """Get list of supported cryptocurrencies"""
        return ['BTC', 'ETH', 'LTC', 'DOGE', 'USDT-TRC20', 'USDT']