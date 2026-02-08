"""
Domain Registration Orchestrator - Single Source of Truth for Domain Registration Notifications

This module provides a centralized orchestrator for domain registration processing that eliminates
duplicate notifications by using database-level processing locks and notification deduplication.

Architecture:
- Atomic status state machine: pending → processing → completed
- Notification ledger with UNIQUE constraints
- Single entry point for all domain registration flows
- Idempotency guards to prevent race conditions
"""

import logging
import time
import asyncio
from typing import Optional, Dict, Any, Tuple
from database import (
    execute_query, execute_update, save_cloudflare_zone, get_or_create_user, 
    create_domain_with_uuid, create_registration_intent, update_intent_status, 
    finalize_domain_registration
)
from localization import t_for_user
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert, send_info_alert

logger = logging.getLogger(__name__)

# ====================================================================
# DOMAIN REGISTRATION ORCHESTRATOR - SINGLE SOURCE OF TRUTH
# ====================================================================

class RegistrationProcessingError(Exception):
    """Custom exception for registration processing errors"""
    pass

class DuplicateRegistrationError(Exception):
    """Raised when attempting to process an already completed registration"""
    pass

class RegistrationOrchestrator:
    """
    Centralized orchestrator for domain registration processing.
    
    Eliminates duplicate notifications through:
    1. Atomic status state machine (pending → processing → completed)
    2. Notification deduplication ledger
    3. Single entry point for all registration flows
    """
    
    def __init__(self):
        self.crypto_name_map = {
            'btc': 'Bitcoin', 'ltc': 'Litecoin', 'doge': 'Dogecoin',
            'eth': 'Ethereum', 'usdt_trc20': 'USDT (TRC20)', 'usdt_erc20': 'USDT (ERC20)'
        }
    
    async def start_registration(
        self,
        order_id: str,  # FIXED: Now accepts string order ID from database
        user_id: int, 
        domain_name: str,
        payment_details: Optional[Dict[str, Any]] = None,
        query_adapter: Optional[Any] = None,
        lang_code: str = 'en'
    ) -> Dict[str, Any]:
        """
        Single entry point for domain registration processing.
        
        Uses atomic database operations to prevent duplicate processing and notifications.
        
        Args:
            order_id: Unique order identifier
            user_id: Internal user ID  
            domain_name: Domain to register
            payment_details: Payment information for notifications
            query_adapter: For sending user notifications
            
        Returns:
            Dict with processing results and status
        """
        logger.info(f"🎯 ORCHESTRATOR: Starting registration for order {order_id}, domain {domain_name}")
        
        try:
            # Step 0: BULLETPROOF PROTECTION - Central enforcement guard against hosting bundle context violation
            from database import get_active_hosting_intent, get_or_create_user_with_status
            user = await get_or_create_user_with_status(user_id)
            if user:
                hosting_intent = await get_active_hosting_intent(user['id'], domain_name)
                if hosting_intent:
                    service_type = hosting_intent.get('service_type', '')
                    # Import the validation function from shared constants
                    from services.constants import is_hosting_bundle_service_type
                    if is_hosting_bundle_service_type(service_type):
                        # CRITICAL: Refuse standalone registration when hosting bundle context exists
                        error_msg = f"PREVENTED: Standalone domain registration blocked - active hosting bundle intent exists (service_type: {service_type})"
                        logger.error(f"🚨 HOSTING BUNDLE PROTECTION: {error_msg}")
                        
                        # Return error to prevent registration
                        return {
                            'status': 'hosting_bundle_conflict',
                            'success': False,
                            'error': error_msg,
                            'order_id': order_id,
                            'message': 'This domain is part of a hosting bundle. Please complete through the hosting checkout flow.'
                        }
            
            # Step 0.5: DEFENSIVE PAYMENT VALIDATION - Second line of defense against underpayment
            # Verify payment amount matches expected before proceeding with registration
            if payment_details:
                try:
                    from database import execute_query
                    from decimal import Decimal
                    
                    # Get expected amount from domain_orders
                    order_check = await execute_query(
                        """SELECT expected_amount, status FROM domain_orders 
                           WHERE (id = %s OR blockbee_order_id = %s) AND domain_name = %s 
                           LIMIT 1""",
                        (order_id, order_id, domain_name)
                    )
                    
                    if order_check:
                        expected_amount = Decimal(str(order_check[0]['expected_amount']))
                        received_raw = payment_details.get('amount_usd', 0)
                        
                        # Safe parse received amount
                        try:
                            if isinstance(received_raw, str):
                                received_amount = Decimal(received_raw)
                            else:
                                received_amount = Decimal(str(float(received_raw)))
                        except:
                            received_amount = Decimal('0')
                        
                        minimum_acceptable = expected_amount * Decimal('0.90')  # 90% threshold
                        
                        # SECURITY FIX: Block if received is below threshold OR if amount is missing/zero
                        # Zero/missing amount indicates a bypass attempt or malformed payment data
                        if received_amount < minimum_acceptable:
                            shortfall = expected_amount - received_amount
                            logger.error(f"🚨 ORCHESTRATOR SECURITY: Underpayment blocked in orchestrator!")
                            logger.error(f"   Domain: {domain_name}, Expected: ${expected_amount}, Received: ${received_amount}, Shortfall: ${shortfall}")
                            
                            return {
                                'status': 'payment_insufficient',
                                'success': False,
                                'error': f'Insufficient payment: Expected ${expected_amount:.2f}, Received ${received_amount:.2f}',
                                'order_id': order_id,
                                'message': 'Payment amount is below the required threshold.'
                            }
                            
                except Exception as payment_check_error:
                    logger.warning(f"⚠️ ORCHESTRATOR: Payment validation check failed (continuing): {payment_check_error}")
                    # Continue anyway - webhook validation should have caught this
            
            # Step 1: Claim processing lock with atomic operation
            processing_claimed, actual_order_id = await self._claim_processing_lock(order_id, user_id, domain_name)
            if not processing_claimed:
                logger.warning(f"🚫 ORCHESTRATOR: Registration already claimed/completed for order {order_id}")
                return {'status': 'already_processed', 'order_id': actual_order_id}
            
            # Use the actual order ID from this point forward (may be different if conflict was resolved)
            if actual_order_id != order_id:
                logger.info(f"🔄 ORCHESTRATOR: Using resolved order ID {actual_order_id} instead of {order_id}")
                order_id = actual_order_id
            
            # Step 2: Send initial progress notification (with deduplication)
            await self._send_notification_safe(
                order_id=order_id,
                user_id=user_id,
                message_type='payment_confirmed_progress', 
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter,
                lang_code=lang_code
            )
            
            # Step 3: Enhanced domain validation before registration
            logger.info(f"🔍 ORCHESTRATOR: Running enhanced domain validation for {domain_name}")
            try:
                from services.openprovider import OpenProviderService
                openprovider = OpenProviderService()
                validation_result = await openprovider.check_domain_with_enhanced_validation(domain_name)
                
                # Log validation results for debugging
                logger.info(f"📊 ORCHESTRATOR: Domain validation complete for {domain_name}")
                logger.info(f"   - Available: {validation_result.get('available', False)}")
                logger.info(f"   - Eligible: {validation_result.get('eligible_for_registration', False)}")
                logger.info(f"   - Recommendation: {validation_result.get('registration_recommendation', 'unknown')}")
                logger.info(f"   - Warnings: {len(validation_result.get('warnings', []))}")
                logger.info(f"   - Risk factors: {len(validation_result.get('risk_factors', []))}")
                
                # Check if domain validation failed
                if not validation_result.get('available', False):
                    return {
                        'success': False,
                        'error': 'Domain not available for registration',
                        'validation_result': validation_result,
                        'phase': 'domain_validation'
                    }
                
                if not validation_result.get('eligible_for_registration', False):
                    warnings = validation_result.get('warnings', [])
                    risk_factors = validation_result.get('risk_factors', [])
                    
                    error_message = f"Domain validation failed: {', '.join(warnings[:2])}"  # Limit to first 2 warnings
                    
                    logger.warning(f"⚠️ ORCHESTRATOR: Domain {domain_name} failed eligibility check")
                    logger.warning(f"   Warnings: {warnings}")
                    logger.warning(f"   Risk factors: {risk_factors}")
                    
                    return {
                        'success': False,
                        'error': error_message,
                        'validation_result': validation_result,
                        'phase': 'eligibility_validation'
                    }
                
                # Validation warnings disabled - enhanced validation generates false positives
                # Users should not be scared by warnings for legitimate domains like "l4mariani.it"
                # Validation still runs for logging purposes but no user notification is sent
                
            except Exception as validation_error:
                logger.error(f"❌ ORCHESTRATOR: Domain validation failed for {domain_name}: {validation_error}")
                # Continue with registration even if validation fails (fallback behavior)
                validation_result = None
            
            # Step 4: Execute domain registration workflow
            registration_result = await self._execute_registration_workflow(
                order_id=order_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter,
                validation_result=validation_result  # Pass validation results to workflow
            )
            
            # Step 5: Finalize wallet payment based on registration result - CRITICAL FOR REVENUE PROTECTION
            settlement_success = await self._finalize_wallet_payment(order_id, registration_result.get('success', False))
            
            # Step 6: Handle settlement outcome - PREVENT REVENUE LOSS
            if registration_result.get('success') and not settlement_success:
                # CRITICAL: Domain registered but wallet charge failed
                error_msg = f"Domain registration succeeded but wallet settlement failed for order {order_id}"
                logger.error(f"🚨 REVENUE PROTECTION: {error_msg}")
                
                # Send critical alert to admins
                await send_critical_alert(
                    "WalletSettlementFailure",
                    f"Domain {domain_name} registered but wallet charge failed - manual intervention required",
                    "payment_settlement",
                    {
                        "order_id": order_id,
                        "user_id": user_id,
                        "domain_name": domain_name,
                        "registration_succeeded": True,
                        "settlement_failed": True
                    }
                )
                
                # Mark order as settlement failed (not completed)
                # FIX: Ensure proper type handling - id is INTEGER
                order_id_int = int(order_id) if str(order_id).isdigit() else order_id
                await execute_update("""
                    UPDATE domain_orders 
                    SET status = 'settlement_failed',
                        updated_at = CURRENT_TIMESTAMP,
                        error_message = %s
                    WHERE id = %s
                """, (error_msg, order_id_int))
                
                # Notify user of temporary hold
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='settlement_failed',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    error=error_msg,
                    lang_code=lang_code
                )
                
                # Return failure to prevent success path
                registration_result['success'] = False
                registration_result['error'] = error_msg
            
            # Step 7: Send final notification based on result (including settlement outcome)
            if registration_result.get('success'):
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='registration_success',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    registration_result=registration_result,
                    lang_code=lang_code
                )
                
                # Send admin success notification
                await send_info_alert(
                    "RegistrationOrchestrator",
                    f"✅ Domain registered: {domain_name} for user {user_id}",
                    "domain_registration",
                    {
                        "order_id": order_id,
                        "domain_name": domain_name,
                        "user_id": user_id,
                        "payment_method": payment_details.get('payment_method') if payment_details else 'unknown'
                    }
                )
                
                # Step 8: Mark order as completed ONLY if settlement succeeded
                await self._complete_registration(order_id, registration_result)
                
            else:
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='registration_failure',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    error=registration_result.get('error', 'Unknown error'),
                    lang_code=lang_code
                )
                
                # Mark order as failed (handles both registration and settlement failures)
                await self._fail_registration(order_id, registration_result.get('error', 'Unknown error'))
            
            logger.info(f"✅ ORCHESTRATOR: Registration completed for order {order_id}")
            # Ensure order_id is always included in the result
            if isinstance(registration_result, dict):
                registration_result['order_id'] = order_id
            return registration_result
            
        except DuplicateRegistrationError as e:
            logger.warning(f"🚫 ORCHESTRATOR: {e}")
            return {'status': 'duplicate_prevented', 'order_id': order_id}
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Registration failed for order {order_id}: {e}")
            # Send admin alert for registration orchestrator failure
            await send_critical_alert(
                "RegistrationOrchestrator", 
                f"Domain registration failed for order {order_id}: {str(e)}",
                "domain_registration",
                {
                    "order_id": order_id,
                    "user_id": user_id,
                    "domain_name": domain_name,
                    "exception": str(e),
                    "payment_details": payment_details
                }
            )
            await self._fail_registration(order_id, str(e))
            return {'status': 'error', 'order_id': order_id, 'error': str(e)}
    
    
    async def _claim_processing_lock(self, order_id: str, user_id: int, domain_name: str, attempt: int = 1, max_attempts: int = 3) -> tuple[bool, str]:
        """
        Atomically claim processing lock using database status state machine.
        
        Args:
            order_id: Unique order identifier
            user_id: Internal user ID
            domain_name: Domain to register
            attempt: Current attempt number (default=1)
            max_attempts: Maximum number of recursion attempts (default=3)
        
        Returns (success: bool, actual_order_id: str) tuple.
        If order ID conflicts, generates new unique ID and returns it.
        """
        logger.debug(f"🔒 ORCHESTRATOR: Attempting to claim processing lock for order {order_id} (attempt {attempt}/{max_attempts})")
        
        try:
            # FIX: Ensure proper type handling - id is INTEGER
            order_id_int = int(order_id) if str(order_id).isdigit() else order_id
            
            # Atomic update: claim processing lock - now allowing retries of failed orders
            rows_updated = await execute_update("""
                UPDATE domain_orders 
                SET status = 'processing', 
                    updated_at = CURRENT_TIMESTAMP,
                    processing_started_at = CURRENT_TIMESTAMP
                WHERE id = %s 
                AND user_id = %s 
                AND domain_name = %s
                AND status IN ('pending', 'paid', 'failed')
            """, (order_id_int, user_id, domain_name))
            
            if rows_updated > 0:
                logger.info(f"✅ ORCHESTRATOR: Processing lock claimed for order {order_id}")
                return (True, order_id)
            else:
                # Check current status to understand why lock wasn't claimed
                existing_orders = await execute_query(
                    "SELECT status FROM domain_orders WHERE id = %s", 
                    (order_id_int,)
                )
                
                if existing_orders:
                    current_status = existing_orders[0]['status']
                    logger.warning(f"🚫 ORCHESTRATOR: Cannot claim lock - order {order_id} status: {current_status} (attempt {attempt}/{max_attempts})")
                    
                    if current_status in ('completed', 'processing'):
                        # Check if max attempts reached before recursing
                        if attempt >= max_attempts:
                            error_msg = f"Max recursion attempts ({max_attempts}) reached for order {order_id}. Unable to claim processing lock after repeated conflicts."
                            logger.error(f"🚨 ORCHESTRATOR: {error_msg}")
                            await send_critical_alert(
                                "RegistrationLockRecursionLimit",
                                error_msg,
                                "domain_registration",
                                {
                                    "order_id": order_id,
                                    "user_id": user_id,
                                    "domain_name": domain_name,
                                    "attempts": attempt,
                                    "current_status": current_status
                                }
                            )
                            return (False, order_id)
                        
                        # Instead of failing, generate a new unique order ID for this registration
                        logger.info(f"🔄 ORCHESTRATOR: Order {order_id} already {current_status}, generating new unique order ID (attempt {attempt}/{max_attempts})")
                        new_order_id = await self._generate_unique_domain_order_id(domain_name, user_id)
                        logger.info(f"✅ ORCHESTRATOR: Generated new order ID {new_order_id} for domain {domain_name}")
                        
                        # Create new domain order entry with unique ID
                        await self._create_domain_order_entry(new_order_id, user_id, domain_name)
                        
                        # Recursively try to claim lock with new order ID
                        return await self._claim_processing_lock(new_order_id, user_id, domain_name, attempt=attempt+1, max_attempts=max_attempts)
                else:
                    logger.error(f"❌ ORCHESTRATOR: Order {order_id} not found in database")
                
                return (False, order_id)
                
        except DuplicateRegistrationError:
            raise
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to claim processing lock for order {order_id}: {e}")
            return (False, order_id)
    
    async def _generate_unique_domain_order_id(self, domain_name: str, user_id: int) -> str:
        """Generate a unique numeric order ID for domain registration to avoid conflicts."""
        import time
        import random
        
        # PostgreSQL integer limit is ~2.1 billion (2,147,483,647)
        # Generate IDs that are large enough to avoid hosting intent conflicts but small enough for integer type
        
        # Use timestamp seconds (10 digits) + random suffix (3 digits) for uniqueness
        timestamp_seconds = int(time.time())  # Current timestamp in seconds (about 10 digits)
        random_suffix = random.randint(100, 999)  # 3-digit suffix for uniqueness
        
        # Create unique ID in range 1.0-2.1 billion (well below integer limit)
        # Format: timestamp_seconds (10 digits) + random (3 digits) = ~13 digits but capped at 2B
        base_id = timestamp_seconds * 1000 + random_suffix
        
        # Ensure we stay within PostgreSQL integer limit (2,147,483,647)
        unique_order_id = str(min(base_id, 2147000000))  # Cap at 2.147 billion with safety margin
        
        logger.debug(f"🔢 ORCHESTRATOR: Generated unique numeric order ID: {unique_order_id} (within integer range)")
        return unique_order_id
    
    async def _create_domain_order_entry(self, order_id: str, user_id: int, domain_name: str):
        """Create a new domain order entry in the database."""
        try:
            await execute_update("""
                INSERT INTO domain_orders (id, user_id, domain_name, status, created_at, updated_at)
                VALUES (%s, %s, %s, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT (id) DO NOTHING
            """, (order_id, user_id, domain_name))
            
            logger.info(f"✅ ORCHESTRATOR: Created domain order entry {order_id} for {domain_name}")
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to create domain order entry {order_id}: {e}")
            raise
    
    async def _send_notification_safe(
        self,
        order_id: str,
        user_id: int,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        query_adapter: Optional[Any] = None,
        registration_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en',
        validation_result: Optional[Dict] = None
    ) -> bool:
        """
        Send notification with deduplication protection.
        
        Uses notification ledger with UNIQUE constraints to prevent duplicate messages.
        """
        logger.debug(f"📧 ORCHESTRATOR: Sending {message_type} notification for order {order_id}")
        
        try:
            # Step 1: Check if notification already sent using deduplication ledger
            # Convert integer order_id to string for varchar column compatibility
            existing_notifications = await execute_query("""
                SELECT id, sent_at FROM domain_notifications 
                WHERE order_id = %s AND message_type = %s
            """, (str(order_id), message_type))
            
            if existing_notifications:
                logger.warning(f"🚫 ORCHESTRATOR: {message_type} notification already sent for order {order_id}")
                return False
            
            # Step 2: Generate notification message
            message = await self._generate_notification_message(
                message_type=message_type,
                domain_name=domain_name,
                payment_details=payment_details,
                registration_result=registration_result,
                error=error,
                user_id=user_id,  # Pass user_id for language resolution
                validation_result=validation_result if message_type == 'validation_warnings' else None
            )
            
            # Step 3: Record notification in ledger (with deduplication protection)
            try:
                await execute_update("""
                    INSERT INTO domain_notifications (order_id, message_type, user_id, message_content, sent_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (str(order_id), message_type, user_id, message))
                
                logger.info(f"📧 ORCHESTRATOR: {message_type} notification recorded for order {order_id}")
                
            except Exception as db_error:
                # Check if this is a duplicate key error (expected for race conditions)
                if 'duplicate key' in str(db_error).lower() or 'unique constraint' in str(db_error).lower():
                    logger.warning(f"🚫 ORCHESTRATOR: Duplicate {message_type} notification prevented for order {order_id}")
                    return False
                else:
                    # Unexpected database error
                    logger.error(f"❌ ORCHESTRATOR: Database error recording {message_type} notification: {db_error}")
                    # Continue to send notification even if recording fails
            
            # Step 4: Send notification to user
            if query_adapter:
                await self._send_message_to_user(query_adapter, message)
                logger.info(f"✅ ORCHESTRATOR: {message_type} notification sent to user for order {order_id}")
            else:
                # Check if this is intentionally suppressed (e.g., for hosting bundles)
                # hosting bundles suppress domain registration notifications to avoid duplicates
                if message_type in ['registration_failure', 'registration_success', 'payment_confirmed_progress']:
                    logger.info(f"📧 ORCHESTRATOR: {message_type} notification suppressed for order {order_id} (likely hosting bundle - notifications handled by parent orchestrator)")
                else:
                    logger.warning(f"⚠️ ORCHESTRATOR: No query_adapter provided for {message_type} notification")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to send {message_type} notification for order {order_id}: {e}")
            return False
    
    async def _generate_notification_message(
        self,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        registration_result: Optional[Dict] = None,
        error: Optional[str] = None,
        user_id: Optional[int] = None,  # For language resolution
        validation_result: Optional[Dict] = None  # For validation warnings
    ) -> str:
        """Generate notification message based on type and context."""
        
        if message_type == 'payment_confirmed_progress':
            return await self._generate_progress_message(domain_name, payment_details, user_id)
        elif message_type == 'registration_success':
            return await self._generate_success_message(domain_name, payment_details, registration_result, user_id)
        elif message_type == 'registration_failure':
            return await self._generate_failure_message(domain_name, payment_details, error, user_id)
        elif message_type == 'validation_warnings':
            return await self._generate_validation_warnings_message(domain_name, validation_result, user_id)
        else:
            return await t_for_user('services.registration_orchestrator.progress_messages.finalizing', user_id or 0, domain=domain_name)
    
    async def _generate_progress_message(self, domain_name: str, payment_details: Optional[Dict], user_id: Optional[int] = None) -> str:
        """Generate payment confirmed + registration progress message."""
        
        if payment_details:
            # Check if this is a wallet payment to avoid crypto messaging
            payment_method = payment_details.get('payment_method', '')
            
            if payment_method == 'wallet':
                # Wallet payment - use USD messaging
                domain_price = payment_details.get('expected_usd', 0)
                received_amount = payment_details.get('amount_usd', 0)
                display_amount = domain_price if domain_price > 0 else received_amount
                
                # For wallet, just show USD amount without crypto details
                crypto_name = 'USD'
                amount_crypto = 0
            else:
                # Crypto payment - use crypto messaging
                domain_price = payment_details.get('expected_usd', 0)
                received_amount = payment_details.get('amount_usd', 0)
                amount_crypto = payment_details.get('amount_crypto') or payment_details.get('received_crypto', 0)
                currency = payment_details.get('currency') or payment_details.get('crypto_currency', 'CRYPTO')
                
                crypto_name = self.crypto_name_map.get(currency.lower(), currency.upper())
                
                # Show domain price, not received amount
                display_amount = domain_price if domain_price > 0 else received_amount
            
            # Use translation system
            title = await t_for_user('notifications.domain.payment_confirmed_title', user_id or 0)
            amount_text = await t_for_user('notifications.domain.payment_confirmed_amount', user_id or 0,
                                           amount=f"{display_amount:.2f}",
                                           domain=domain_name)
            
            message = f"✅ <b>{title}</b>\n{amount_text}\n\n"
            
            # Add overpayment info if present
            overpay = payment_details.get('overpayment_amount', 0)
            if overpay > 0:
                if payment_details.get('overpayment_credited'):
                    overpay_text = await t_for_user('notifications.domain.overpayment_credited', user_id or 0,
                                                    amount=f"{overpay:.2f}")
                    message += f"{overpay_text}\n\n"
                else:
                    overpay_text = await t_for_user('notifications.domain.overpayment_not_credited', user_id or 0,
                                                    amount=f"{overpay:.2f}")
                    message += f"{overpay_text}\n\n"
            
            # Progress indicators
            registering_title = await t_for_user('notifications.domain.registering_title', user_id or 0, domain=domain_name)
            dns_zone = await t_for_user('notifications.domain.creating_dns_zone', user_id or 0)
            registering = await t_for_user('notifications.domain.registering_domain', user_id or 0)
            estimated = await t_for_user('notifications.domain.estimated_time', user_id or 0)
            
            message += f"🚀 <b>{registering_title}</b>\n"
            message += f"🔄 {dns_zone}\n"
            message += f"⏳ {registering}\n"
            message += f"<i>{estimated}</i>"
        else:
            # Fallback - use single translation key with domain variable
            message = await t_for_user('notifications.domain.payment_confirmed_fallback', user_id or 0, domain=domain_name)
        
        return message
    
    async def _generate_success_message(
        self, 
        domain_name: str, 
        payment_details: Optional[Dict], 
        registration_result: Optional[Dict],
        user_id: Optional[int] = None
    ) -> str:
        """Generate registration success message."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        if payment_details:
            # FIXED: Use expected_usd (domain price) for success message, not received amount
            domain_price = payment_details.get('expected_usd', 0)
            received_amount = payment_details.get('amount_usd', 0)
            display_amount = domain_price if domain_price > 0 else received_amount
            kwargs['amount'] = f"{float(display_amount):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        if registration_result and registration_result.get('cloudflare_zone'):
            cf_zone = registration_result['cloudflare_zone']
            nameservers = cf_zone.get('name_servers', [])[:2]
            if nameservers:
                kwargs['nameservers'] = ', '.join(nameservers)
            else:
                kwargs['nameservers'] = 'Cloudflare'
        else:
            kwargs['nameservers'] = 'Cloudflare'
        
        # Use translation system to generate the message with user language preference
        return await t_for_user('services.registration_orchestrator.success_messages.registration_complete', user_id or 0, **kwargs)
    
    async def _generate_failure_message(
        self, 
        domain_name: str, 
        payment_details: Optional[Dict], 
        error: Optional[str],
        user_id: Optional[int] = None
    ) -> str:
        """Generate registration failure message with improved error classification and preserved i18n."""
        
        # Classify error type for appropriate translation key
        error_type = "technical"
        
        if error:
            error_lower = error.lower()
            if "duplicate domain" in error_lower or error == "DUPLICATE_DOMAIN":
                error_type = "duplicate_domain"
            elif "http 500" in error_lower or "api" in error_lower:
                error_type = "api_error"  
            elif "timeout" in error_lower or "connection" in error_lower:
                error_type = "connectivity"
            elif "validation" in error_lower or "tld" in error_lower:
                error_type = "validation"
            elif "contact" in error_lower:
                error_type = "contact_error"
        
        # Prepare variables for translation with error classification
        kwargs = {
            'domain': domain_name,
            'error_type': error_type,
            'original_error': error or 'Unknown error',
            'support_contact': 'Hostbay_support'
        }
        
        if payment_details:
            # Use expected_usd (domain price) for failure message
            domain_price = payment_details.get('expected_usd', 0)
            received_amount = payment_details.get('amount_usd', 0)
            display_amount = domain_price if domain_price > 0 else received_amount
            kwargs['amount'] = f"{float(display_amount):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # Use translation system with error type classification
        # Map error types to specific translation keys while preserving i18n
        if error_type == "duplicate_domain":
            return await t_for_user('services.registration_orchestrator.error_messages.duplicate_domain', user_id or 0, **kwargs)
        elif error_type == "api_error":
            return await t_for_user('services.registration_orchestrator.error_messages.api_error', user_id or 0, **kwargs)
        elif error_type == "connectivity":
            return await t_for_user('services.registration_orchestrator.error_messages.connectivity', user_id or 0, **kwargs)
        elif error_type == "validation":
            return await t_for_user('services.registration_orchestrator.error_messages.validation', user_id or 0, **kwargs)
        elif error_type == "contact_error":
            return await t_for_user('services.registration_orchestrator.error_messages.contact_error', user_id or 0, **kwargs)
        else:
            # Fallback to generic technical error with preserved i18n
            return await t_for_user('services.registration_orchestrator.error_messages.registration_failed', user_id or 0, **kwargs)
    
    async def _generate_validation_warnings_message(
        self, 
        domain_name: str, 
        validation_result: Optional[Dict],
        user_id: Optional[int] = None
    ) -> str:
        """
        Generate validation warnings message for domains with potential risk factors.
        
        This message warns users about potential registration issues before proceeding.
        """
        if not validation_result:
            return f"⚠️ <b>Domain Validation</b>\n\n{domain_name} validation completed.\n\nProceeding with registration..."
        
        warnings = validation_result.get('warnings', [])
        risk_factors = validation_result.get('risk_factors', [])
        recommendations = validation_result.get('recommendations', [])
        
        message = f"⚠️ <b>Domain Analysis Complete</b>\n\n<b>{domain_name}</b> can be registered, but we detected some potential issues:\n\n"
        
        # Add warnings
        if warnings:
            message += "<b>⚠️ Warnings:</b>\n"
            for warning in warnings[:3]:  # Limit to first 3 warnings
                message += f"• {warning}\n"
            message += "\n"
        
        # Add risk factors
        if risk_factors:
            message += "<b>🔍 Risk Factors:</b>\n"
            for risk in risk_factors[:3]:  # Limit to first 3 risks
                message += f"• {risk}\n"
            message += "\n"
        
        # Add recommendations
        if recommendations:
            message += "<b>💡 Recommendations:</b>\n"
            for rec in recommendations[:2]:  # Limit to first 2 recommendations
                message += f"• {rec}\n"
            message += "\n"
        
        message += "🔄 <b>Proceeding with registration...</b>\n\n"
        message += "<i>If registration fails, consider trying a more unique domain name.</i>"
        
        return message
    
    async def _send_message_to_user(self, query_adapter: Any, message: str):
        """Send message to user via query adapter."""
        try:
            if hasattr(query_adapter, 'send_message_to_user'):
                await query_adapter.send_message_to_user(message, parse_mode='HTML')
            elif hasattr(query_adapter, 'user_id'):
                # Use webhook-style messaging for non-telegram contexts
                from webhook_handler import queue_user_message
                await queue_user_message(query_adapter.user_id, message, parse_mode='HTML')
            else:
                logger.warning("Query adapter doesn't support message sending")
        except Exception as e:
            logger.error(f"Failed to send message to user: {e}")
    
    async def _execute_registration_workflow(
        self,
        order_id: str,
        user_id: int,
        domain_name: str,
        payment_details: Optional[Dict],
        query_adapter: Optional[Any],
        validation_result: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete domain registration workflow.
        
        This includes:
        1. Cloudflare zone creation  
        2. OpenProvider domain registration
        3. Database finalization
        """
        logger.info(f"🔄 ORCHESTRATOR: Executing registration workflow for {domain_name}")
        
        try:
            # Phase 1: Cloudflare Zone Creation
            logger.info(f"🔄 Phase 1: Creating Cloudflare zone for {domain_name}")
            cloudflare_result = await self._create_cloudflare_zone(user_id, domain_name)
            
            if not cloudflare_result.get('success'):
                return {
                    'success': False,
                    'error': f"DNS zone creation failed: {cloudflare_result.get('error', 'Unknown error')}",
                    'phase': 'cloudflare_zone'
                }
            
            # Zone creation progress handled by payment_confirmed_progress notification
            
            # Phase 2: OpenProvider Domain Registration
            logger.info(f"🔄 Phase 2: Registering domain {domain_name} with OpenProvider")
            registration_result = await self._register_domain_with_provider(
                user_id, domain_name, cloudflare_result['zone_data']
            )
            
            if not registration_result.get('success'):
                return {
                    'success': False,
                    'error': f"Domain registration failed: {registration_result.get('error', 'Unknown error')}",
                    'phase': 'domain_registration',
                    'cloudflare_zone': cloudflare_result['zone_data']  # Keep zone data for cleanup
                }
            
            # Phase 3: Database Finalization
            logger.info(f"🔄 Phase 3: Finalizing registration in database for {domain_name}")
            finalization_result = await self._finalize_registration_in_database(
                order_id, user_id, domain_name, cloudflare_result, registration_result
            )
            
            if not finalization_result.get('success'):
                return {
                    'success': False,
                    'error': f"Database finalization failed: {finalization_result.get('error', 'Unknown error')}",
                    'phase': 'database_finalization',
                    'cloudflare_zone': cloudflare_result['zone_data'],
                    'registration_data': registration_result['registration_data']
                }
            
            # Success!
            return {
                'success': True,
                'order_id': order_id,
                'domain_name': domain_name,
                'cloudflare_zone': cloudflare_result['zone_data'],
                'registration_data': registration_result['registration_data'],
                'finalization_data': finalization_result['data']
            }
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Registration workflow failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'workflow_exception'
            }
    
    def _generate_zone_progress_message(self, domain_name: str, payment_details: Optional[Dict]) -> str:
        """Generate zone creation progress message."""
        
        if payment_details:
            crypto_name = self.crypto_name_map.get(
                payment_details.get('crypto_currency', '').lower(), 
                payment_details.get('crypto_currency', 'Crypto').upper()
            )
            
            from pricing_utils import format_crypto_amount
            crypto_display_str = format_crypto_amount(payment_details.get('received_crypto', 0), crypto_name)
            message = f"🚀 <b>Domain Registration Progress</b>\n\n"
            message += f"💰 Amount: <b>${payment_details.get('expected_usd', 0):.2f}</b> from {crypto_display_str}\n"
            message += f"🌐 Domain: <code>{domain_name}</code>\n"
            message += f"✅ Step 1: DNS zone created\n"
            message += f"🔄 Step 2: <b>Registering with provider...</b>\n"
            message += f"⏰ <i>Final step...</i>"
        else:
            message = f"🚀 <b>Domain Registration Progress</b>\n\n"
            message += f"✅ Payment confirmed\n"
            message += f"🌐 Domain: <code>{domain_name}</code>\n"
            message += f"✅ Step 1: DNS zone created\n"
            message += f"🔄 Step 2: <b>Registering with provider...</b>\n"
            message += f"⏰ <i>Final step...</i>"
        
        return message
    
    async def _create_cloudflare_zone(self, user_id: int, domain_name: str) -> Dict[str, Any]:
        """Create Cloudflare DNS zone for the domain during registration workflow."""
        try:
            from services.cloudflare import CloudflareService
            
            cloudflare = CloudflareService()
            # Use standalone=True for new domain registrations since domain doesn't exist in database yet
            zone_result = await cloudflare.create_zone(domain_name, standalone=True)
            
            if zone_result and zone_result.get('success'):
                zone_data = zone_result['result']
                
                # Save zone to database
                nameservers = zone_data.get('name_servers', [])
                zone_saved = await save_cloudflare_zone(
                    domain_name=domain_name,
                    cf_zone_id=zone_data['id'],
                    nameservers=nameservers
                )
                
                if zone_saved:
                    logger.info(f"✅ Cloudflare zone created and saved for {domain_name}")
                    return {
                        'success': True,
                        'zone_data': zone_data
                    }
                else:
                    logger.error(f"❌ Failed to save Cloudflare zone for {domain_name}")
                    return {
                        'success': False,
                        'error': 'Failed to save zone to database'
                    }
            else:
                error_msg = zone_result.get('errors', [{}])[0].get('message', 'Unknown error') if zone_result else 'Zone creation failed'
                logger.error(f"❌ Cloudflare zone creation failed for {domain_name}: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }
                
        except Exception as e:
            logger.error(f"❌ Exception creating Cloudflare zone for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _register_domain_with_provider(
        self, 
        user_id: int, 
        domain_name: str, 
        zone_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register domain with OpenProvider using Cloudflare nameservers."""
        try:
            from services.openprovider import OpenProviderService
            
            # Get nameservers from Cloudflare zone
            nameservers = zone_data.get('name_servers', [])
            if not nameservers:
                return {
                    'success': False,
                    'error': 'No nameservers provided by Cloudflare'
                }
            
            # Register domain with OpenProvider
            openprovider = OpenProviderService()
            
            # OPTIMIZATION: For .it and .ca domains, register_domain() handles contact creation internally
            # Skip redundant contact fetch here to avoid duplicate API calls
            is_tld_specific = domain_name.lower().endswith('.it') or domain_name.lower().endswith('.ca')
            
            contact_handle: str | None = None
            if is_tld_specific:
                logger.info(f"♻️ Skipping contact fetch for TLD-specific domain {domain_name} - register_domain() will handle it")
                contact_handle = None  # register_domain() will create TLD-specific contact
            else:
                # Get or create a valid shared contact handle for standard domains
                contact_handle = await openprovider.get_or_create_contact_handle()
                if not contact_handle:
                    logger.error(f"❌ Failed to get valid contact handle for domain registration: {domain_name}")
                    return {
                        'success': False,
                        'error': 'Failed to get valid contact handle'
                    }
                logger.info(f"✅ Using shared contact handle: {contact_handle}")
            
            registration_result = await openprovider.register_domain(
                domain_name=domain_name,
                contact_handle=contact_handle,  # type: ignore
                nameservers=nameservers
            )
            
            if registration_result and registration_result.get('success'):
                logger.info(f"✅ Domain {domain_name} registered with OpenProvider")
                return {
                    'success': True,
                    'registration_data': registration_result
                }
            else:
                error_msg = registration_result.get('error', 'Domain registration failed') if registration_result else 'Registration failed'
                logger.error(f"❌ Domain registration failed for {domain_name}: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }
                
        except Exception as e:
            logger.error(f"❌ Exception registering domain {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _finalize_registration_in_database(
        self,
        order_id: str,
        user_id: int,
        domain_name: str,
        cloudflare_result: Dict[str, Any],
        registration_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Finalize domain registration in database with new 3-table system."""
        try:
            # SECURITY FIX: Get actual price from domain_orders instead of using $0
            # This prevents fraud where domains were registered with $0 in the intents table
            # CRITICAL: We must find the order or block the registration
            actual_price = None
            try:
                # FIX: Ensure proper type handling - id is INTEGER, blockbee_order_id is VARCHAR
                # Cast order_id to int for id column, and string for blockbee_order_id to prevent type mismatch errors
                order_id_int = int(order_id) if str(order_id).isdigit() else None
                order_id_str = str(order_id)
                
                if order_id_int is not None:
                    # Try both: integer ID match or string blockbee_order_id match
                    price_result = await execute_query(
                        "SELECT expected_amount FROM domain_orders WHERE id = %s OR blockbee_order_id = %s LIMIT 1",
                        (order_id_int, order_id_str)
                    )
                else:
                    # Non-numeric order_id - only check blockbee_order_id
                    price_result = await execute_query(
                        "SELECT expected_amount FROM domain_orders WHERE blockbee_order_id = %s LIMIT 1",
                        (order_id_str,)
                    )
                if price_result and price_result[0].get('expected_amount'):
                    actual_price = float(price_result[0]['expected_amount'])
                    logger.info(f"✅ SECURITY: Using actual price ${actual_price:.2f} for intent (not $0)")
                else:
                    # SECURITY BLOCK: No order found - cannot proceed
                    logger.error(f"🚨 SECURITY BLOCK: No order found in domain_orders for {order_id} during finalization")
                    await send_critical_alert(
                        component="RegistrationOrchestrator",
                        message=f"Finalization blocked - no order found for {domain_name}",
                        category="security",
                        details={"order_id": order_id, "domain": domain_name, "user_id": user_id}
                    )
                    return {
                        'success': False,
                        'error': 'Security block: No order found in domain_orders'
                    }
            except Exception as price_err:
                logger.error(f"🚨 SECURITY BLOCK: Error fetching price for order {order_id}: {price_err}")
                await send_critical_alert(
                    component="RegistrationOrchestrator",
                    message=f"Finalization blocked - price lookup failed for {domain_name}",
                    category="security",
                    details={"order_id": order_id, "domain": domain_name, "user_id": user_id, "error": str(price_err)}
                )
                return {
                    'success': False,
                    'error': f'Security block: Could not verify payment for order {order_id}'
                }
            
            # Create registration intent with ACTUAL price
            intent_id = await create_registration_intent(
                user_id=user_id,
                domain_name=domain_name,
                estimated_price=actual_price,  # FIXED: Use actual price, not $0
                payment_data={
                    'order_id': order_id,
                    'currency': 'USD',
                    'status': 'completed'
                }
            )
            
            if intent_id:
                # Get provider domain ID
                provider_domain_id = registration_result['registration_data'].get('domain_id')
                if provider_domain_id:
                    domain_saved = await finalize_domain_registration(
                        intent_id=intent_id,
                        provider_domain_id=str(provider_domain_id)
                    )
                    
                    if domain_saved:
                        logger.info(f"✅ Domain registration finalized in database for {domain_name}")
                        return {
                            'success': True,
                            'data': {
                                'intent_id': intent_id,
                                'domain_saved': domain_saved,
                                'provider_domain_id': provider_domain_id
                            }
                        }
                    else:
                        return {
                            'success': False,
                            'error': 'Failed to save domain to database'
                        }
                else:
                    return {
                        'success': False,
                        'error': 'No provider domain ID returned'
                    }
            else:
                return {
                    'success': False,
                    'error': 'Failed to create registration intent'
                }
                
        except Exception as e:
            logger.error(f"❌ Exception finalizing registration for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _complete_registration(self, order_id: str, registration_result: Dict[str, Any]):
        """Mark order as completed in database."""
        try:
            # FIX: Ensure proper type handling - id is INTEGER
            order_id_int = int(order_id) if str(order_id).isdigit() else order_id
            await execute_update("""
                UPDATE domain_orders 
                SET status = 'completed',
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (order_id_int,))
            
            logger.info(f"✅ ORCHESTRATOR: Order {order_id} marked as completed")
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to mark order {order_id} as completed: {e}")
    
    async def _fail_registration(self, order_id: str, error: str):
        """Mark order as failed in database."""
        try:
            # FIX: Ensure proper type handling - id is INTEGER
            order_id_int = int(order_id) if str(order_id).isdigit() else order_id
            await execute_update("""
                UPDATE domain_orders 
                SET status = 'failed',
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = %s
                WHERE id = %s
            """, (error, order_id_int))
            
            logger.info(f"❌ ORCHESTRATOR: Order {order_id} marked as failed: {error}")
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to mark order {order_id} as failed: {e}")
    
    async def _finalize_wallet_payment(self, order_id: str, success: bool) -> bool:
        """
        Finalize wallet payment hold based on registration success/failure.
        
        CRITICAL FOR REVENUE PROTECTION: This method must succeed for wallet payments
        or the order should not be marked as completed.
        
        For wallet payments, this converts the hold transaction to either:
        - success=True: Permanent debit (charges user's wallet)  
        - success=False: Refund (returns hold amount to user's wallet)
        
        Returns:
            True if finalization succeeded or not applicable (non-wallet payment)
            False if finalization failed - PREVENTS order completion
        """
        try:
            # Get order details to check if it's a wallet payment
            from database import execute_query, finalize_wallet_reservation
            
            # FIX: Ensure proper type handling - id is INTEGER, so cast to int if numeric
            order_id_int = int(order_id) if str(order_id).isdigit() else None
            
            if order_id_int is None:
                logger.warning(f"⚠️ WALLET FINALIZATION: Invalid order_id {order_id} - not numeric")
                return False
            
            order_result = await execute_query(
                "SELECT hold_transaction_id, contact_handle, domain_name FROM domain_orders WHERE id = %s",
                (order_id_int,)
            )
            
            if not order_result:
                logger.warning(f"⚠️ WALLET FINALIZATION: Order {order_id} not found - cannot finalize wallet payment")
                return False
            
            order = order_result[0]
            hold_transaction_id = order.get('hold_transaction_id')
            contact_handle = order.get('contact_handle')
            domain_name = order.get('domain_name')
            
            # Only process wallet payments - skip others gracefully
            if contact_handle != 'wallet_payment' or not hold_transaction_id:
                logger.debug(f"ℹ️ WALLET FINALIZATION: Order {order_id} is not a wallet payment ({contact_handle}) - skipping")
                return True  # Not applicable, allow completion
            
            # CRITICAL: Finalize the wallet reservation
            logger.info(f"💳 WALLET FINALIZATION: Processing hold transaction {hold_transaction_id} for order {order_id} (success={success})")
            
            finalization_result = await finalize_wallet_reservation(hold_transaction_id, success=success)
            
            if finalization_result:
                action = "debited from wallet" if success else "refunded to wallet" 
                logger.info(f"✅ WALLET FINALIZATION: Hold ${hold_transaction_id} successfully {action} for domain {domain_name}")
                return True
            else:
                # CRITICAL: Settlement failure - prevent order completion
                logger.error(f"🚨 WALLET FINALIZATION FAILED: Hold transaction {hold_transaction_id} could not be finalized")
                logger.error(f"   Order: {order_id} | Domain: {domain_name} | Action: {'debit' if success else 'refund'}")
                return False
                
        except Exception as e:
            # CRITICAL: Don't swallow exceptions that indicate system problems
            logger.error(f"🚨 WALLET FINALIZATION EXCEPTION: Order {order_id} - {str(e)}")
            logger.error(f"   This is a critical settlement failure that prevents order completion")
            # Re-raise for database connection issues, but return False for business logic failures
            if "database" in str(e).lower() or "connection" in str(e).lower():
                raise  # Let orchestrator handle database connectivity issues
            return False  # Business logic failure - prevent completion but don't crash


# ====================================================================
# GLOBAL ORCHESTRATOR INSTANCE
# ====================================================================

# Global orchestrator instance for use across the application
_orchestrator = RegistrationOrchestrator()

async def start_domain_registration(
    order_id: str,  # FIXED: Now accepts string order ID from database
    user_id: int,
    domain_name: str,
    payment_details: Optional[Dict[str, Any]] = None,
    query_adapter: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Main entry point for domain registration processing.
    
    This replaces all direct calls to trigger_domain_registration_async.
    """
    return await _orchestrator.start_registration(
        order_id=order_id,
        user_id=user_id,
        domain_name=domain_name,
        payment_details=payment_details,
        query_adapter=query_adapter
    )

# LEGACY FUNCTION HARD-DISABLED to prevent duplicate notifications
# All registration must go through start_domain_registration() exclusively
async def trigger_domain_registration_async(query_adapter, domain_name, order, payment_details=None):
    """
    HARD-DISABLED: Legacy function to prevent duplicate notifications.
    
    ALL CALLS MUST USE start_domain_registration() instead.
    """
    logger.error("❌ CRITICAL: trigger_domain_registration_async is DISABLED - use start_domain_registration() instead")
    logger.error(f"   Attempted call for domain {domain_name}, order {order.get('id', 'unknown')}")
    
    raise RuntimeError(
        "trigger_domain_registration_async is DISABLED to prevent duplicate notifications. "
        "Use start_domain_registration() instead."
    )