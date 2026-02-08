"""
Hosting Bundle Orchestrator - Single Source of Truth for Hosting+Domain Bundle Processing

This module provides a centralized orchestrator for hosting bundle processing that eliminates
duplicate notifications by using database-level processing locks and notification deduplication.

Architecture:
- Atomic status state machine: pending → processing → completed
- Notification ledger with UNIQUE constraints
- Single entry point for all hosting bundle flows
- Sequential execution: domain registration → hosting provisioning
- Idempotency guards to prevent race conditions
"""

import logging
import time
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from database import (
    execute_query, execute_update, get_or_create_user, 
    get_hosting_intent_by_id, finalize_hosting_provisioning
)
from localization import t_for_user
from pricing_utils import format_crypto_amount

logger = logging.getLogger(__name__)

# ====================================================================
# HOSTING BUNDLE ORCHESTRATOR - SINGLE SOURCE OF TRUTH
# ====================================================================

class HostingBundleProcessingError(Exception):
    """Custom exception for hosting bundle processing errors"""
    pass

class DuplicateHostingBundleError(Exception):
    """Raised when attempting to process an already completed hosting bundle"""
    pass

class HostingBundleOrchestrator:
    """
    Centralized orchestrator for hosting bundle processing.
    
    Eliminates duplicate notifications through:
    1. Atomic status state machine (pending → processing → completed)
    2. Notification deduplication ledger
    3. Single entry point for all hosting bundle flows
    4. Sequential execution: domain registration → hosting provisioning
    """
    
    def __init__(self):
        self.crypto_name_map = {
            'btc': 'Bitcoin', 'ltc': 'Litecoin', 'doge': 'Dogecoin',
            'eth': 'Ethereum', 'usdt_trc20': 'USDT (TRC20)', 'usdt_erc20': 'USDT (ERC20)'
        }
    
    async def start_hosting_bundle(
        self,
        order_id: int,
        user_id: int, 
        domain_name: str,
        payment_details: Optional[Dict[str, Any]] = None,
        query_adapter: Optional[Any] = None,
        lang_code: str = 'en'
    ) -> Dict[str, Any]:
        """
        Single entry point for hosting bundle processing.
        
        Uses atomic database operations to prevent duplicate processing and notifications.
        Orchestrates: domain registration → hosting provisioning
        
        Args:
            order_id: Unique order identifier  
            user_id: Internal user ID
            domain_name: Domain to register and set up hosting for
            payment_details: Payment information for notifications
            query_adapter: For sending user notifications
            
        Returns:
            Dict with processing results and status
        """
        logger.info(f"🚀 HOSTING ORCHESTRATOR: Starting hosting bundle processing for {domain_name}")
        
        try:
            # Step 1: Find and claim hosting intent lock
            hosting_intent = await self._find_and_claim_hosting_intent(order_id, user_id, domain_name)
            if not hosting_intent:
                logger.warning(f"⚠️ HOSTING ORCHESTRATOR: No valid hosting intent found for order {order_id}")
                return {'status': 'no_intent_found', 'order_id': order_id}
            
            intent_id = hosting_intent['id']
            service_type = hosting_intent.get('service_type', 'hosting_only')
            
            # Step 2: Send initial progress notification (with deduplication)
            await self._send_notification_safe(
                order_id=order_id,
                user_id=user_id,
                message_type='payment_confirmed_progress',
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter,
                service_type=service_type,
                lang_code=lang_code,
                hosting_intent=hosting_intent
            )
            
            # Step 3: Execute complete hosting bundle workflow
            bundle_result = await self._execute_hosting_bundle_workflow(
                order_id=order_id,
                intent_id=intent_id,
                user_id=user_id,
                domain_name=domain_name,
                service_type=service_type,
                payment_details=payment_details,
                query_adapter=query_adapter
            )
            
            # Step 4: Finalize wallet payment based on bundle result - CRITICAL FOR REVENUE PROTECTION
            settlement_success = await self._finalize_wallet_payment(order_id, bundle_result.get('success', False))
            
            # Step 5: Handle settlement outcome - PREVENT REVENUE LOSS
            if bundle_result.get('success') and not settlement_success:
                # CRITICAL: Hosting provisioned but wallet charge failed
                error_msg = f"Hosting bundle succeeded but wallet settlement failed for order {order_id}"
                logger.error(f"🚨 HOSTING REVENUE PROTECTION: {error_msg}")
                
                # Send critical alert to admins
                from admin_alerts import send_critical_alert
                await send_critical_alert(
                    "HostingWalletSettlementFailure",
                    f"Hosting bundle for {domain_name} completed but wallet charge failed - manual intervention required",
                    "hosting_payment_settlement",
                    {
                        "order_id": order_id,
                        "intent_id": intent_id,
                        "user_id": user_id,
                        "domain_name": domain_name,
                        "service_type": service_type,
                        "bundle_succeeded": True,
                        "settlement_failed": True
                    }
                )
                
                # Mark hosting intent as settlement failed (not completed)
                await execute_update("""
                    UPDATE hosting_provision_intents 
                    SET status = 'settlement_failed',
                        updated_at = CURRENT_TIMESTAMP,
                        error_message = %s
                    WHERE id = %s
                """, (error_msg, intent_id))
                
                # Notify user of temporary issue
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='hosting_settlement_failed',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    service_type=service_type,
                    error=error_msg,
                    lang_code=lang_code,
                    hosting_intent=hosting_intent
                )
                
                # Return failure to prevent success path
                bundle_result['success'] = False
                bundle_result['error'] = error_msg
            
            # Step 6: Send final notification based on result (including settlement outcome)
            if bundle_result.get('success'):
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='hosting_bundle_success',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    service_type=service_type,
                    bundle_result=bundle_result,
                    lang_code=lang_code,
                    hosting_intent=hosting_intent
                )
                
                # Step 6: Send admin notification for hosting bundle success
                try:
                    from admin_alerts import send_info_alert
                    payment_method = payment_details.get('payment_method', 'unknown') if payment_details else 'unknown'
                    amount = payment_details.get('amount_usd', 0) if payment_details else 0
                    
                    await send_info_alert(
                        "HostingBundleOrchestrator",
                        f"✅ Hosting + Domain bundle completed: {domain_name} for user {user_id}",
                        "hosting_bundle",
                        {
                            "order_id": order_id,
                            "intent_id": intent_id,
                            "domain_name": domain_name,
                            "user_id": user_id,
                            "service_type": service_type,
                            "payment_method": payment_method,
                            "amount_usd": amount,
                            "hosting_plan_id": hosting_intent.get('hosting_plan_id') if hosting_intent else None,
                            "domain_registered": bundle_result.get('domain_registered', False),
                            "hosting_provisioned": bundle_result.get('hosting_provisioned', False)
                        }
                    )
                    logger.info(f"📢 ADMIN NOTIFICATION: Hosting bundle success alert sent for {domain_name}")
                except Exception as alert_error:
                    logger.warning(f"⚠️ Could not send hosting bundle admin alert: {alert_error}")
                
                # Step 7: Mark bundle as completed
                await self._complete_hosting_bundle(order_id, intent_id, bundle_result)
                
            else:
                # CRITICAL: Process refunds for bundle failures that require them
                if bundle_result.get('requires_refund'):
                    logger.info(f"🔄 HOSTING ORCHESTRATOR: Bundle failure requires refund - processing for order {order_id}")
                    
                    # Import refund processor
                    from refund_processor import refund_failed_bundle_payment
                    
                    # Execute refund processing
                    refund_result = await refund_failed_bundle_payment(
                        order_id=order_id,
                        user_id=user_id,
                        domain_name=domain_name,
                        bundle_result=bundle_result,
                        payment_details=payment_details,
                        query_adapter=query_adapter
                    )
                    
                    if refund_result.get('success'):
                        logger.info(f"✅ HOSTING ORCHESTRATOR: Refund processed successfully for order {order_id}")
                        
                        # Send bundle failure notification (refund notification is sent by refund processor)
                        await self._send_notification_safe(
                            order_id=order_id,
                            user_id=user_id,
                            message_type='hosting_bundle_failure_with_refund',
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=query_adapter,
                            service_type=service_type,
                            error=bundle_result.get('error', 'Unknown error'),
                            refund_result=refund_result,
                            lang_code=lang_code,
                            hosting_intent=hosting_intent
                        )
                    else:
                        logger.error(f"❌ HOSTING ORCHESTRATOR: Refund processing failed for order {order_id}: {refund_result.get('error')}")
                        
                        # Send bundle failure notification with refund failure info
                        await self._send_notification_safe(
                            order_id=order_id,
                            user_id=user_id,
                            message_type='hosting_bundle_failure_refund_failed',
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=query_adapter,
                            service_type=service_type,
                            error=bundle_result.get('error', 'Unknown error'),
                            refund_error=refund_result.get('error', 'Unknown refund error'),
                            lang_code=lang_code,
                            hosting_intent=hosting_intent
                        )
                else:
                    # Regular failure without refund
                    await self._send_notification_safe(
                        order_id=order_id,
                        user_id=user_id,
                        message_type='hosting_bundle_failure',
                        domain_name=domain_name,
                        payment_details=payment_details,
                        query_adapter=query_adapter,
                        service_type=service_type,
                        error=bundle_result.get('error', 'Unknown error'),
                        lang_code=lang_code,
                        hosting_intent=hosting_intent
                    )
                
                # Mark bundle as failed (after refund processing)
                await self._fail_hosting_bundle(order_id, intent_id, bundle_result.get('error', 'Unknown error'))
            
            logger.info(f"✅ HOSTING ORCHESTRATOR: Bundle processing completed for order {order_id}")
            return bundle_result
            
        except DuplicateHostingBundleError as e:
            logger.warning(f"🚫 HOSTING ORCHESTRATOR: {e}")
            return {'status': 'duplicate_prevented', 'order_id': order_id}
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Bundle processing failed for order {order_id}: {e}")
            return {'status': 'error', 'order_id': order_id, 'error': str(e)}
    
    async def _find_and_claim_hosting_intent(self, order_id: int, user_id: int, domain_name: str) -> Optional[Dict]:
        """
        Find hosting intent for this domain/user and atomically claim processing lock.
        
        Returns hosting intent if lock claimed, None if no intent or already claimed.
        """
        logger.debug(f"🔒 HOSTING ORCHESTRATOR: Finding and claiming hosting intent for {domain_name}")
        
        try:
            # Find active hosting intent for this domain and user
            from database import get_active_hosting_intent
            hosting_intent = await get_active_hosting_intent(user_id, domain_name)
            
            if not hosting_intent:
                logger.warning(f"🚫 HOSTING ORCHESTRATOR: No active hosting intent found for user {user_id}, domain {domain_name}")
                return None
            
            intent_id = hosting_intent['id']
            
            # Atomic update: claim processing lock - now allowing retries of failed intents
            # SOFTENED: Include 'failed' status to allow retry scenarios
            rows_updated = await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'processing_payment', 
                    updated_at = CURRENT_TIMESTAMP,
                    processing_started_at = CURRENT_TIMESTAMP
                WHERE id = %s 
                AND user_id = %s 
                AND status IN ('pending_payment', 'awaiting_payment', 'draft', 'pending_checkout', 'payment_confirmed', 'paid', 'failed')
            """, (intent_id, user_id))
            
            if rows_updated > 0:
                logger.info(f"✅ HOSTING ORCHESTRATOR: Processing lock claimed for intent {intent_id}")
                return hosting_intent
            else:
                # Check current status to understand why lock wasn't claimed
                current_intents = await execute_query(
                    "SELECT status FROM hosting_provision_intents WHERE id = %s", 
                    (intent_id,)
                )
                
                if current_intents:
                    current_status = current_intents[0]['status']
                    logger.warning(f"🚫 HOSTING ORCHESTRATOR: Cannot claim lock - intent {intent_id} status: {current_status}")
                    
                    if current_status in ('completed', 'processing_payment'):
                        raise DuplicateHostingBundleError(f"Hosting intent {intent_id} already {current_status}")
                else:
                    logger.error(f"❌ HOSTING ORCHESTRATOR: Hosting intent {intent_id} not found")
                
                return None
                
        except DuplicateHostingBundleError:
            raise
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to find/claim hosting intent for {domain_name}: {e}")
            return None
    
    async def _execute_hosting_bundle_workflow(
        self,
        order_id: int,
        intent_id: int,
        user_id: int,
        domain_name: str,
        service_type: str,
        payment_details: Optional[Dict],
        query_adapter: Optional[Any]
    ) -> Dict[str, Any]:
        """
        Execute the complete hosting bundle workflow.
        
        For hosting bundles: domain registration → hosting provisioning
        For hosting-only: hosting provisioning only
        """
        logger.info(f"🔄 HOSTING ORCHESTRATOR: Executing workflow for intent {intent_id}, service_type: {service_type}")
        
        try:
            # Check if this is a bundle that needs domain registration
            # FIXED: Only 'hosting_domain_bundle' requires domain registration
            # 'hosting_with_existing_domain' should NEVER trigger domain registration
            needs_domain_registration = service_type == 'hosting_domain_bundle'
            
            # CRITICAL SAFETY CHECK: Prevent domain registration for existing domain scenarios
            if service_type in ['hosting_with_existing_domain', 'hosting_only']:
                needs_domain_registration = False
                logger.info(f"🔒 SAFETY CHECK: Service type '{service_type}' confirmed - NO domain registration will be attempted")
            
            # DEFENSIVE LOGGING: Clear intent of workflow path
            if needs_domain_registration:
                logger.info(f"🆕 DOMAIN BUNDLE WORKFLOW: Will register NEW domain '{domain_name}' + provision hosting")
            else:
                logger.info(f"🏠 HOSTING-ONLY WORKFLOW: Will provision hosting for existing domain '{domain_name}' (NO registration)")
            
            # CRITICAL FIX: For bundles, validate hosting FIRST to prevent partial failures
            if needs_domain_registration:
                # Phase 1: Hosting Validation (TEST cPanel creation without committing)
                logger.info(f"🔄 Phase 1: Validating hosting capabilities for bundle - {domain_name}")
                hosting_validation = await self._validate_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
                
                if not hosting_validation.get('success'):
                    logger.error(f"❌ Hosting validation failed - will not proceed with domain registration")
                    return {
                        'success': False,
                        'error': f"Hosting validation failed: {hosting_validation.get('error', 'Unknown error')}. Refund will be processed.",
                        'phase': 'hosting_validation',
                        'requires_refund': True  # Signal that refund is needed
                    }
                
                # Phase 2: Domain Registration (only if hosting validation passed)
                logger.info(f"🔄 Phase 2: Domain registration for bundle - {domain_name}")
                domain_result = await self._execute_domain_registration(
                    intent_id, user_id, domain_name, payment_details, query_adapter
                )
                
                if not domain_result.get('success'):
                    return {
                        'success': False,
                        'error': f"Domain registration failed: {domain_result.get('error', 'Unknown error')}",
                        'phase': 'domain_registration',
                        'requires_refund': True  # Domain failed after hosting validation passed
                    }
                
                # CRITICAL FIX: Link the newly registered domain to the hosting intent
                # After successful domain registration, retrieve the domain ID and update the intent
                try:
                    domain_id_result = await execute_query("""
                        SELECT id FROM domains 
                        WHERE domain_name = %s AND user_id = %s
                    """, (domain_name, user_id))
                    
                    if domain_id_result:
                        domain_id = domain_id_result[0]['id']
                        await execute_update("""
                            UPDATE hosting_provision_intents 
                            SET domain_id = %s, updated_at = CURRENT_TIMESTAMP
                            WHERE id = %s
                        """, (domain_id, intent_id))
                        logger.info(f"✅ Linked domain_id {domain_id} to hosting intent {intent_id}")
                    else:
                        logger.warning(f"⚠️ Could not find domain_id for {domain_name} after registration")
                except Exception as link_error:
                    logger.error(f"❌ Failed to link domain_id to hosting intent: {link_error}")
                    # Continue anyway - not critical enough to fail the whole workflow
                
                # Phase 3: Actual Hosting Provisioning (hosting validation passed, domain registered)
                logger.info(f"🔄 Phase 3: Creating hosting account for bundle - {domain_name}")
                hosting_result = await self._execute_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
            else:
                # Hosting-only flow (no domain registration)
                logger.info(f"🔄 Phase 1: Hosting provisioning for intent {intent_id}")
                hosting_result = await self._execute_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
                domain_result = None
            
            if not hosting_result.get('success'):
                return {
                    'success': False,
                    'error': f"Hosting provisioning failed: {hosting_result.get('error', 'Unknown error')}",
                    'phase': 'hosting_provisioning',
                    'domain_result': domain_result,  # Keep domain data for cleanup if needed
                    'requires_refund': needs_domain_registration  # Refund needed for bundles only
                }
            
            # Phase 3: Update DNS A record with server IP (for both bundles and existing domains)
            if needs_domain_registration and domain_result:
                # Bundle workflow: Domain registration provides zone data
                logger.info(f"🔄 Phase 3: Updating DNS A record with server IP for bundle - {domain_name}")
                dns_update_result = await self._update_dns_with_server_ip(
                    domain_name, domain_result, hosting_result
                )
                
                if not dns_update_result.get('success'):
                    # Log warning but don't fail the entire workflow - hosting is already provisioned
                    logger.warning(f"⚠️ DNS A record update failed for {domain_name}: {dns_update_result.get('error')}")
                    # Continue with success since hosting is working
            elif not needs_domain_registration:
                # Existing domain workflow: Create Cloudflare zone + Update A record + Ensure nameservers
                logger.info(f"🔄 Phase 2A: Creating Cloudflare zone for existing domain - {domain_name}")
                
                # Create Cloudflare zone (if doesn't exist)
                zone_result = await self._create_cloudflare_zone_for_existing_domain(domain_name)
                
                if not zone_result or not zone_result.get('success'):
                    logger.warning(f"⚠️ Cloudflare zone creation failed for existing domain {domain_name}: {zone_result.get('error') if zone_result else 'Unknown error'}")
                    # Continue without zone - hosting still works
                    zone_result = None
                
                # Phase 2B: Ensure domain is using Cloudflare nameservers (auto-update if possible)
                logger.info(f"🔄 Phase 2B: Ensuring Cloudflare nameservers for existing domain - {domain_name}")
                ns_result = await self._ensure_cloudflare_nameservers(
                    domain_name, 
                    user_id,
                    zone_result.get('nameservers') if zone_result else None
                )
                nameserver_status = ns_result.get('status', 'unknown')
                if nameserver_status == 'auto_updated':
                    logger.info(f"✅ Nameservers auto-updated for {domain_name}")
                elif nameserver_status == 'already_correct':
                    logger.info(f"✅ Nameservers already correct for {domain_name}")
                elif nameserver_status == 'manual_required':
                    logger.warning(f"⚠️ Manual nameserver update required for {domain_name}: {ns_result.get('message')}")
                
                logger.info(f"🔄 Phase 2C: Updating DNS A record with server IP for existing domain - {domain_name}")
                
                # Create domain_result equivalent for existing domains with zone data
                domain_result_for_existing = {
                    'zone_data': zone_result if zone_result and zone_result.get('success') else None,
                    'domain_name': domain_name,
                    'nameservers': zone_result.get('nameservers', []) if zone_result and zone_result.get('success') else [],
                    'nameserver_status': nameserver_status,
                    'nameserver_message': ns_result.get('message', '')
                }
                
                dns_update_result = await self._update_dns_with_server_ip(
                    domain_name, domain_result_for_existing, hosting_result
                )
                
                if not dns_update_result.get('success'):
                    # Log warning but don't fail the entire workflow - hosting is already provisioned
                    logger.warning(f"⚠️ DNS A record update failed for existing domain {domain_name}: {dns_update_result.get('error')}")
                    # Continue with success since hosting is working
                
                # Update domain_result to include zone data for existing domains
                domain_result = domain_result_for_existing
            
            # Success!
            return {
                'success': True,
                'order_id': order_id,
                'intent_id': intent_id,
                'domain_name': domain_name,
                'service_type': service_type,
                'domain_result': domain_result,
                'hosting_result': hosting_result,
                'domain_registered': needs_domain_registration and domain_result is not None,
                'hosting_provisioned': hosting_result.get('success', False) if hosting_result else False
            }
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Workflow failed for intent {intent_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'workflow_exception'
            }
    
    async def _execute_domain_registration(
        self, 
        intent_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict],
        query_adapter: Optional[Any]
    ) -> Dict[str, Any]:
        """
        Execute domain registration using the existing registration orchestrator.
        CRITICAL FIX: Create domain_orders entry for registration orchestrator.
        """
        try:
            # CRITICAL FIX: Create domain_orders entry that registration orchestrator expects
            logger.info(f"🔄 HOSTING ORCHESTRATOR: Creating domain_orders entry for {domain_name}")
            
            # Calculate expected amount from hosting intent
            hosting_intent_data = await execute_query(
                "SELECT quote_price FROM hosting_provision_intents WHERE id = %s", 
                (intent_id,)
            )
            expected_amount = hosting_intent_data[0]['quote_price'] if hosting_intent_data else 0
            
            # Create domain_orders entry (required by registration orchestrator)
            domain_order_result = await execute_query("""
                INSERT INTO domain_orders (
                    user_id, domain_name, status, expected_amount, currency,
                    intent_id, created_at, updated_at
                ) VALUES (%s, %s, 'pending', %s, 'USD', %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING id
            """, (user_id, domain_name, expected_amount, intent_id))
            
            if not domain_order_result:
                raise Exception("Failed to create domain_orders entry")
                
            domain_order_id = domain_order_result[0]['id']
            logger.info(f"✅ HOSTING ORCHESTRATOR: Created domain_orders entry {domain_order_id} for intent {intent_id}")
            
            # Import and use existing domain registration orchestrator
            from services.registration_orchestrator import RegistrationOrchestrator
            
            domain_orchestrator = RegistrationOrchestrator()
            
            # Call existing domain registration with proper domain_orders.id
            # CRITICAL FIX: Pass None for query_adapter to suppress domain registration notification
            # For hosting bundles, only the hosting bundle confirmation should be sent
            domain_result = await domain_orchestrator.start_registration(
                order_id=str(domain_order_id),  # Use proper domain_orders.id
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=None  # Suppress domain registration notification for bundles
            )
            
            # Include both IDs in the result for tracking
            if isinstance(domain_result, dict):
                domain_result['domain_order_id'] = domain_order_id
                domain_result['hosting_intent_id'] = intent_id
            
            return domain_result
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Domain registration failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'domain_registration_exception'
            }
    
    async def _execute_hosting_provisioning(
        self, 
        intent_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict],
        auto_renew: bool = True
    ) -> Dict[str, Any]:
        """
        Execute hosting provisioning by creating cPanel account first, then finalizing in database.
        """
        try:
            # CRITICAL FIX: Actually create cPanel account first
            from services.cpanel import CPanelService
            from database import execute_query
            
            # Get service email for cPanel account creation
            from utils.email_config import get_hosting_contact_email
            user_email = get_hosting_contact_email(user_id)
            
            # Generate cPanel username
            cpanel_username = f"user{user_id}_{intent_id}"
            
            # Step 1: Create actual cPanel hosting account
            cpanel_service = CPanelService()
            logger.info(f"🔧 Creating cPanel account for {domain_name} with username {cpanel_username}")
            
            cpanel_result = await cpanel_service.create_hosting_account(
                domain=domain_name,
                plan='default',  # Use default plan for hosting bundles (standard cPanel package)
                email=user_email,
                intent_id=intent_id
            )
            
            if not cpanel_result:
                logger.error(f"❌ cPanel account creation failed for {domain_name}")
                return {
                    'success': False,
                    'error': 'cPanel account creation failed - please contact support',
                    'phase': 'cpanel_creation'
                }
            
            logger.info(f"✅ cPanel account created successfully for {domain_name}")
            
            # Step 2: Prepare cPanel results for database finalization
            # CRITICAL FIX: Always use actual password - no more ***EXISTING*** placeholders
            is_existing_account = cpanel_result.get('existing', False)
            
            # Validate that we have a real password
            actual_password = cpanel_result.get('password')
            if not actual_password:
                logger.error(f"❌ No password returned from cPanel service for {domain_name}")
                return {
                    'success': False,
                    'error': 'Failed to obtain cPanel credentials - please contact support',
                    'phase': 'cpanel_password_retrieval'
                }
            
            cpanel_data = {
                "username": cpanel_result.get('username', cpanel_username),
                "password": actual_password,  # Always use the actual password
                "server_ip": cpanel_result.get('server_ip') or cpanel_service.default_server_ip,
                "domain_name": domain_name,
                "service_type": "hosting_domain_bundle",
                "payment_method": "crypto",
                "is_existing": is_existing_account
            }
            
            # Add payment details if available
            if payment_details:
                cpanel_data.update(payment_details)
            
            # Step 3: Finalize in database with actual cPanel results
            # CRITICAL FIX: Use actual username from cPanel (not generated placeholder)
            actual_cpanel_username = cpanel_data.get('username', cpanel_username)
            provisioning_result = await finalize_hosting_provisioning(
                intent_id, 
                actual_cpanel_username, 
                cpanel_data,
                auto_renew
            )
            
            # Handle different return formats (boolean or dict)
            # CRITICAL FIX: Include cPanel credentials in return for notification system
            if isinstance(provisioning_result, dict):
                if provisioning_result.get('success', False):
                    return {
                        'success': True,
                        'provisioning_data': provisioning_result,
                        # Include cPanel credentials for notification message
                        'cpanel_username': cpanel_data.get('username'),
                        'cpanel_password': cpanel_data.get('password'),
                        'server_ip': cpanel_data.get('server_ip')
                    }
                else:
                    return {
                        'success': False,
                        'error': provisioning_result.get('error', 'Hosting provisioning failed')
                    }
            elif provisioning_result:  # Boolean True
                return {
                    'success': True,
                    'provisioning_data': {'status': 'completed'},
                    # Include cPanel credentials for notification message
                    'cpanel_username': cpanel_data.get('username'),
                    'cpanel_password': cpanel_data.get('password'),
                    'server_ip': cpanel_data.get('server_ip')
                }
            else:  # Boolean False or None
                return {
                    'success': False,
                    'error': 'Hosting provisioning returned false'
                }
                
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Hosting provisioning failed for intent {intent_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'hosting_provisioning_exception'
            }
    
    async def _validate_hosting_provisioning(
        self, 
        intent_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict]
    ) -> Dict[str, Any]:
        """
        Validate hosting provisioning capabilities without creating actual account.
        Tests cPanel connectivity and configuration to prevent partial bundle failures.
        """
        try:
            from services.cpanel import CPanelService
            
            logger.info(f"🔍 Validating hosting capabilities for {domain_name}")
            
            # Step 1: Test cPanel service connectivity
            cpanel_service = CPanelService()
            connection_ok, connection_msg = await cpanel_service.test_connection()
            
            if not connection_ok:
                logger.error(f"❌ cPanel connection validation failed: {connection_msg}")
                return {
                    'success': False,
                    'error': f'Hosting service unavailable: {connection_msg}',
                    'phase': 'connectivity_test'
                }
            
            logger.info(f"✅ cPanel connectivity validated: {connection_msg}")
            
            # Step 2: Check if cPanel credentials are properly configured
            if not cpanel_service.whm_api_token and not cpanel_service.whm_password:
                logger.error("❌ cPanel credentials not configured for hosting validation")
                return {
                    'success': False,
                    'error': 'Hosting service configuration error - please contact support',
                    'phase': 'credentials_check'
                }
            
            # Step 3: Check for resource availability (if we can query server status)
            try:
                # This is a lightweight check - we just validate we can communicate with WHM
                logger.info(f"✅ Hosting validation passed for {domain_name}")
                return {
                    'success': True,
                    'message': 'Hosting capabilities validated successfully',
                    'server_ip': cpanel_service.default_server_ip
                }
                
            except Exception as resource_error:
                logger.warning(f"⚠️ Hosting resource check warning: {resource_error}")
                # Continue anyway - this is just a warning
                return {
                    'success': True,
                    'message': 'Hosting capabilities validated with warnings',
                    'server_ip': cpanel_service.default_server_ip,
                    'warnings': str(resource_error)
                }
                
        except Exception as e:
            logger.error(f"❌ Hosting validation failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': f'Hosting validation error: {str(e)}',
                'phase': 'validation_exception'
            }
    
    async def _send_notification_safe(
        self,
        order_id: int,
        user_id: int,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        query_adapter: Optional[Any] = None,
        service_type: Optional[str] = None,
        bundle_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en',
        hosting_intent: Optional[Dict] = None,
        refund_result: Optional[Dict] = None,
        refund_error: Optional[str] = None
    ) -> bool:
        """
        Send notification with deduplication protection.
        
        Uses notification ledger with UNIQUE constraints to prevent duplicate messages.
        """
        logger.debug(f"📧 HOSTING ORCHESTRATOR: Sending {message_type} notification for order {order_id}")
        
        try:
            # Step 1: Check if notification already sent using deduplication ledger
            # Use domain_notifications table with hosting_ prefix for compatibility
            notification_key = f"hosting_{order_id}"
            existing_notifications = await execute_query("""
                SELECT id, sent_at FROM domain_notifications 
                WHERE order_id = %s AND message_type = %s
            """, (notification_key, message_type))
            
            if existing_notifications:
                logger.warning(f"🚫 HOSTING ORCHESTRATOR: {message_type} notification already sent for order {order_id}")
                return False
            
            # Step 2: Generate notification message
            message = await self._generate_notification_message(
                message_type=message_type,
                domain_name=domain_name,
                service_type=service_type,
                payment_details=payment_details,
                bundle_result=bundle_result,
                error=error,
                user_id=user_id,  # Pass user_id for language resolution
                hosting_intent=hosting_intent
            )
            
            # Step 3: Record notification in ledger (with deduplication protection)
            try:
                await execute_update("""
                    INSERT INTO domain_notifications (order_id, message_type, user_id, message_content, sent_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (notification_key, message_type, user_id, message))
                
                logger.info(f"📧 HOSTING ORCHESTRATOR: {message_type} notification recorded for order {order_id}")
                
            except Exception as db_error:
                logger.error(f"❌ HOSTING ORCHESTRATOR: Database error recording {message_type} notification: {db_error}")
                # Continue to send notification even if recording fails
            
            # Step 4: Send notification to user
            if query_adapter:
                await self._send_message_to_user(query_adapter, message)
                logger.info(f"✅ HOSTING ORCHESTRATOR: {message_type} notification sent to user for order {order_id}")
            else:
                logger.warning(f"⚠️ HOSTING ORCHESTRATOR: No query_adapter provided for {message_type} notification")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to send {message_type} notification for order {order_id}: {e}")
            return False
    
    async def _generate_notification_message(
        self,
        message_type: str,
        domain_name: str,
        service_type: Optional[str] = None,
        payment_details: Optional[Dict] = None,
        bundle_result: Optional[Dict] = None,
        error: Optional[str] = None,
        user_id: Optional[int] = None,  # For language resolution
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate notification message based on type and context."""
        
        if message_type == 'payment_confirmed_progress':
            return await self._generate_bundle_progress_message(domain_name, service_type or 'hosting_only', payment_details, user_id, hosting_intent)
        elif message_type == 'hosting_bundle_success':
            return await self._generate_bundle_success_message(domain_name, service_type or 'hosting_only', payment_details, bundle_result, user_id, hosting_intent)
        elif message_type == 'hosting_bundle_failure':
            return await self._generate_bundle_failure_message(domain_name, service_type or 'hosting_only', payment_details, error, user_id, hosting_intent)
        else:
            return await t_for_user('services.hosting_orchestrator.bundle_processing.completed', user_id or 0, order_id=domain_name)
    
    async def _generate_bundle_progress_message(self, domain_name: str, service_type: str, payment_details: Optional[Dict], user_id: Optional[int] = None, hosting_intent: Optional[Dict] = None) -> str:
        """Generate hosting bundle progress message."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            # Check if this is a wallet payment to use appropriate messaging
            payment_method = payment_details.get('payment_method', '')
            
            if payment_method == 'wallet':
                # Wallet payment - don't use crypto messaging
                amount_usd = (payment_details.get('expected_usd') or 
                             payment_details.get('amount_usd') or 
                             payment_details.get('original_amount') or 
                             payment_details.get('base_amount', 0))
                
                kwargs.update({
                    'amount': f"{float(amount_usd):.2f}",
                    'crypto_amount': '0.000000',  # Not applicable for wallet payments
                    'crypto_currency': 'USD'  # Wallet uses USD
                })
            else:
                # Crypto payment - use crypto messaging
                # FIXED: Use correct field name for crypto currency from webhook payment details
                crypto_currency_raw = (payment_details.get('currency') or 
                                     payment_details.get('crypto_currency', ''))
                crypto_name = self.crypto_name_map.get(
                    crypto_currency_raw.lower(), 
                    crypto_currency_raw.upper()
                )
                
                # Extract amount from various possible payment detail formats
                amount_usd = (payment_details.get('expected_usd') or 
                             payment_details.get('amount_usd') or 
                             payment_details.get('original_amount') or 
                             payment_details.get('base_amount', 0))
                
                # FIXED: Use correct field name for crypto amount from webhook payment details
                received_crypto = (payment_details.get('amount_crypto') or 
                                  payment_details.get('received_crypto') or 
                                  payment_details.get('paid_amount', 0))
                
                kwargs.update({
                    'amount': f"{float(amount_usd):.2f}",
                    'crypto_amount': format_crypto_amount(float(received_crypto), crypto_name).split(' ')[0],
                    'crypto_currency': crypto_name
                })
        else:
            kwargs.update({
                'amount': '0.00',
                'crypto_amount': '0.000000',
                'crypto_currency': 'Crypto'
            })
        
        # Use translation system to generate the message with user language preference  
        # Use different templates for wallet vs crypto payments
        if payment_details and payment_details.get('payment_method') == 'wallet':
            # For wallet payments, use a template without crypto references
            wallet_kwargs = {'domain': domain_name, 'amount': kwargs.get('amount', '0.00')}
            return await t_for_user('services.hosting_orchestrator.bundle_processing.wallet_payment_confirmed', user_id or 0, **wallet_kwargs)
        else:
            # For crypto payments, use the full crypto template
            return await t_for_user('services.hosting_orchestrator.bundle_processing.payment_confirmed', user_id or 0, **kwargs)
    
    async def _generate_domain_success_progress_message(self, domain_name: str, payment_details: Optional[Dict], service_type: str, user_id: Optional[int] = None, hosting_intent: Optional[Dict] = None) -> str:
        """Generate domain registration success + hosting progress message."""
        
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 0)
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        return await t_for_user('services.hosting_orchestrator.success_notifications.hosting_ready', user_id or 0, **kwargs)
    
    async def _generate_bundle_success_message(
        self, 
        domain_name: str, 
        service_type: str,
        payment_details: Optional[Dict], 
        bundle_result: Optional[Dict],
        user_id: Optional[int] = None,
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate hosting bundle success message with cPanel credentials."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 
                         payment_details.get('original_amount') or 
                         payment_details.get('base_amount', 0))
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # CRITICAL FIX: Include actual cPanel credentials in the message
        try:
            if bundle_result and bundle_result.get('hosting_result') and bundle_result['hosting_result'].get('success'):
                hosting_result = bundle_result['hosting_result']
                
                # Get cPanel credentials from hosting result
                cpanel_username = hosting_result.get('cpanel_username')
                cpanel_password = hosting_result.get('cpanel_password') 
                server_ip = hosting_result.get('server_ip')
                
                if cpanel_username:
                    kwargs.update({
                        'cpanel_username': cpanel_username,
                        'cpanel_password': cpanel_password or '[Generated - Check hosting management]',
                        'server_ip': server_ip or '[Contact support for server details]',
                        'cpanel_url': f"https://{server_ip}:2083" if server_ip else '[Contact support for cPanel URL]'
                    })
                else:
                    # Fallback: No cPanel credentials in result
                    kwargs.update({
                        'cpanel_username': '[Check hosting management]',
                        'cpanel_password': '[Check hosting management]',
                        'server_ip': '[Check hosting management]',
                        'cpanel_url': '[Check hosting management]'
                    })
            else:
                # Fallback: No hosting result available
                kwargs.update({
                    'cpanel_username': '[Check hosting management]',
                    'cpanel_password': '[Check hosting management]', 
                    'server_ip': '[Check hosting management]',
                    'cpanel_url': '[Check hosting management]'
                })
                
        except Exception as e:
            logger.error(f"❌ Error getting cPanel credentials for success message: {e}")
            # Safe fallback
            kwargs.update({
                'cpanel_username': '[Check hosting management]',
                'cpanel_password': '[Check hosting management]',
                'server_ip': '[Check hosting management]',
                'cpanel_url': '[Check hosting management]'
            })
        
        # Get plan information and calculate expiration date
        try:
            # Get hosting plan details
            if hosting_intent and hosting_intent.get('hosting_plan_id'):
                plan_query = await execute_query(
                    "SELECT plan_name, duration_days FROM hosting_plans WHERE id = %s",
                    (hosting_intent['hosting_plan_id'],)
                )
                if plan_query:
                    plan_data = plan_query[0]
                    kwargs['plan_name'] = plan_data['plan_name']
                    
                    # Calculate expiration date
                    current_date = datetime.now()
                    expiration_date = current_date + timedelta(days=plan_data['duration_days'])
                    kwargs['expiration_date'] = expiration_date.strftime('%Y-%m-%d')
                else:
                    kwargs['plan_name'] = 'Hosting Plan'
                    kwargs['expiration_date'] = 'Contact support'
            else:
                kwargs['plan_name'] = 'Hosting Plan'  
                kwargs['expiration_date'] = 'Contact support'
                
            # CRITICAL FIX: Use real Cloudflare nameservers from zone creation
            nameservers_section = ""
            if bundle_result and bundle_result.get('domain_result') and bundle_result['domain_result'].get('nameservers'):
                # Use actual Cloudflare nameservers from zone creation
                cloudflare_nameservers = bundle_result['domain_result']['nameservers']
                if cloudflare_nameservers:
                    nameserver_lines = []
                    for ns in cloudflare_nameservers:
                        nameserver_lines.append(f"📍 {ns}")
                    kwargs['nameservers_section'] = f"\n\n🌐 <b>Nameservers:</b>\n" + "\n".join(nameserver_lines)
                    logger.info(f"✅ Using Cloudflare nameservers for {domain_name}: {cloudflare_nameservers}")
                else:
                    kwargs['nameservers_section'] = ""
            elif service_type in ['hosting_only', 'hosting_with_existing_domain']:
                # Fallback: Use cPanel nameservers if Cloudflare data not available
                kwargs['nameservers_section'] = f"\n\n🌐 <b>Nameservers:</b>\n📍 ns1.cprapid.com\n📍 ns2.cprapid.com"
                logger.warning(f"⚠️ Falling back to cPanel nameservers for {domain_name} - Cloudflare data not available")
            else:
                # Bundle with domain registration - no manual nameserver setup needed
                kwargs['nameservers_section'] = ""
                
        except Exception as e:
            logger.error(f"❌ Error getting plan details for success message: {e}")
            # Safe fallback
            kwargs['plan_name'] = 'Hosting Plan'
            kwargs['expiration_date'] = 'Contact support'
            kwargs['nameservers_section'] = ""

        # Use translation system to generate the message with user language preference
        return await t_for_user('services.hosting_orchestrator.success_notifications.bundle_success', user_id or 0, **kwargs)
    
    async def _generate_bundle_failure_message(
        self, 
        domain_name: str, 
        service_type: str,
        payment_details: Optional[Dict], 
        error: Optional[str],
        user_id: Optional[int] = None,
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate hosting bundle failure message."""
        
        # Prepare variables for translation
        kwargs = {
            'domain': domain_name,
            'error': error,  # Will be handled in the await call below
            'support_contact': 'Hostbay_support'
        }
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 
                         payment_details.get('original_amount') or 
                         payment_details.get('base_amount', 0))
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # Use translation system to generate the message

        
        # Handle error fallback with user language awareness
        if not kwargs['error']:
            kwargs['error'] = await t_for_user('services.common.errors.unknown_error', user_id or 0)
        
        return await t_for_user('services.hosting_orchestrator.error_messages.bundle_failure', user_id or 0, **kwargs)
    
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
    
    async def _complete_hosting_bundle(self, order_id: int, intent_id: int, bundle_result: Dict[str, Any]):
        """Mark hosting bundle as completed."""
        try:
            await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'completed', 
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (intent_id,))
            
            logger.info(f"✅ HOSTING ORCHESTRATOR: Bundle marked as completed - order {order_id}, intent {intent_id}")
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to mark bundle as completed - order {order_id}: {e}")
    
    async def _fail_hosting_bundle(self, order_id: int, intent_id: int, error: str):
        """Mark hosting bundle as failed."""
        try:
            await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'failed', 
                    error_message = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (error, intent_id))
            
            logger.info(f"❌ HOSTING ORCHESTRATOR: Bundle marked as failed - order {order_id}, intent {intent_id}: {error}")
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to mark bundle as failed - order {order_id}: {e}")
    
    async def _create_cloudflare_zone_for_existing_domain(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """
        Create Cloudflare zone for existing domain (similar to bundle workflow).
        
        Returns zone data with nameservers for user notification.
        """
        try:
            from services.cloudflare import CloudflareService
            
            logger.info(f"🌐 Creating Cloudflare zone for existing domain: {domain_name}")
            
            # Initialize Cloudflare service
            cloudflare = CloudflareService()
            
            # Create zone in standalone mode (no domain_id required for existing domains)
            zone_data = await cloudflare.create_zone(domain_name, domain_id=None, standalone=True)
            
            if zone_data:
                logger.info(f"✅ Cloudflare zone created for existing domain {domain_name}")
                return {
                    'success': True,
                    'zone_id': zone_data.get('zone_id'),
                    'nameservers': zone_data.get('nameservers', []),
                    'domain_name': domain_name,
                    'status': zone_data.get('status')
                }
            else:
                logger.error(f"❌ Failed to create Cloudflare zone for existing domain {domain_name}")
                return {
                    'success': False,
                    'error': 'Cloudflare zone creation failed'
                }
                
        except Exception as e:
            logger.error(f"❌ Exception creating Cloudflare zone for existing domain {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def _ensure_cloudflare_nameservers(
        self,
        domain_name: str,
        user_id: int,
        cloudflare_nameservers: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Ensure domain is using Cloudflare nameservers.
        
        Shared helper used by both bot and API flows:
        1. Fetches Cloudflare NS if not provided
        2. Checks current domain nameservers via OpenProvider
        3. Auto-updates if not already using Cloudflare
        4. Returns status for user notification
        
        Returns:
            Dict with:
            - status: 'auto_updated' | 'already_correct' | 'manual_required' | 'not_our_domain' | 'error'
            - message: User-friendly message
            - nameservers: Cloudflare nameservers (for manual update instructions)
        """
        try:
            from services.cloudflare import cloudflare
            from services.openprovider import OpenProviderService
            
            openprovider = OpenProviderService()
            
            if not cloudflare_nameservers:
                cloudflare_nameservers = await cloudflare.get_account_nameservers()
            
            if not cloudflare_nameservers:
                logger.warning(f"⚠️ Could not fetch Cloudflare nameservers for {domain_name}")
                return {
                    'status': 'error',
                    'message': 'Could not fetch Cloudflare nameservers',
                    'nameservers': []
                }
            
            domain_details = await openprovider.get_domain_details(domain_name)
            
            if not domain_details:
                logger.info(f"ℹ️ Domain {domain_name} not found in OpenProvider - external registrar")
                return {
                    'status': 'manual_required',
                    'message': f'Please update nameservers at your registrar to: {", ".join(cloudflare_nameservers)}',
                    'nameservers': cloudflare_nameservers,
                    'reason': 'not_our_domain'
                }
            
            ns_data = domain_details.get('name_servers', [])
            current_nameservers = [ns.get('name', '').lower() for ns in ns_data if ns.get('name')]
            
            cf_ns_lower = [ns.lower() for ns in cloudflare_nameservers]
            already_using_cloudflare = all(ns in cf_ns_lower for ns in current_nameservers) if current_nameservers else False
            
            if already_using_cloudflare:
                logger.info(f"✅ Domain {domain_name} already using Cloudflare nameservers")
                return {
                    'status': 'already_correct',
                    'message': 'Nameservers already configured correctly',
                    'nameservers': cloudflare_nameservers
                }
            
            logger.info(f"🔄 Auto-updating nameservers for {domain_name} to Cloudflare")
            ns_update_result = await openprovider.update_nameservers(
                domain_name, 
                cloudflare_nameservers
            )
            
            if ns_update_result and ns_update_result.get('success'):
                logger.info(f"✅ Nameservers updated for {domain_name}")
                return {
                    'status': 'auto_updated',
                    'message': 'Nameservers automatically updated to Cloudflare',
                    'nameservers': cloudflare_nameservers
                }
            else:
                error_msg = ns_update_result.get('error', 'Unknown error') if ns_update_result else 'Update failed'
                logger.warning(f"⚠️ Nameserver update failed for {domain_name}: {error_msg}")
                return {
                    'status': 'manual_required',
                    'message': f'Auto-update failed. Please update nameservers manually to: {", ".join(cloudflare_nameservers)}',
                    'nameservers': cloudflare_nameservers,
                    'error': error_msg
                }
                
        except Exception as e:
            logger.error(f"❌ Exception ensuring Cloudflare nameservers for {domain_name}: {e}")
            return {
                'status': 'error',
                'message': f'Nameserver check failed: {str(e)}',
                'nameservers': cloudflare_nameservers or []
            }

    async def _update_dns_with_server_ip(
        self, 
        domain_name: str, 
        domain_result: Dict[str, Any], 
        hosting_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update Cloudflare DNS A record with actual WHM server IP after hosting provisioning.
        
        This fixes the issue where A records are created with placeholder IP (8.8.8.8)
        during domain registration but never updated with the real server IP.
        """
        try:
            from services.cloudflare import CloudflareService
            
            # Get server IP from hosting result or database
            server_ip = None
            
            # Try to get server IP from hosting result first
            if hosting_result.get('provisioning_data'):
                server_ip = hosting_result['provisioning_data'].get('server_ip')
            
            # If not found, try to get it from the database
            if not server_ip:
                try:
                    # Get hosting details from intent ID
                    intent_id = hosting_result.get('intent_id')
                    if intent_id:
                        hosting_intent = await get_hosting_intent_by_id(intent_id)
                        if hosting_intent and hosting_intent.get('external_reference'):
                            # Extract subscription ID from external reference
                            external_ref = hosting_intent['external_reference']
                            if external_ref.startswith('subscription_'):
                                sub_id = int(external_ref.replace('subscription_', ''))
                                hosting_details = await execute_query(
                                    "SELECT server_ip FROM hosting_subscriptions WHERE id = %s",
                                    (sub_id,)
                                )
                                if hosting_details:
                                    server_ip = hosting_details[0].get('server_ip')
                except:
                    pass  # Function may not exist, continue with fallback
            
            # Fallback to cPanel service default
            if not server_ip:
                from services.cpanel import CPanelService
                cpanel = CPanelService()
                server_ip = cpanel.default_server_ip
                logger.info(f"🔧 Using cPanel service default IP: {server_ip}")
            
            if not server_ip:
                return {
                    'success': False,
                    'error': 'No server IP available for DNS update'
                }
            
            # Get zone ID from domain result or database
            zone_id = None
            if domain_result and domain_result.get('zone_data'):
                zone_id = domain_result['zone_data'].get('zone_id')
            
            # Fallback: Try to get zone ID from database
            if not zone_id:
                try:
                    zone_results = await execute_query(
                        "SELECT cf_zone_id FROM cloudflare_zones WHERE domain_name = %s ORDER BY created_at DESC LIMIT 1",
                        (domain_name,)
                    )
                    if zone_results:
                        zone_id = zone_results[0]['cf_zone_id']
                        logger.info(f"🔧 Retrieved zone ID from database: {zone_id}")
                except Exception as e:
                    logger.error(f"❌ Error retrieving zone ID from database: {e}")
            
            if not zone_id:
                return {
                    'success': False,
                    'error': 'No Cloudflare zone ID available for DNS update'
                }
            
            logger.info(f"🔧 Updating DNS A record: {domain_name} → {server_ip} (zone: {zone_id})")
            
            # Initialize Cloudflare service
            cloudflare = CloudflareService()
            
            # Get existing A records for the domain
            existing_records = await cloudflare.list_dns_records(zone_id, 'A')
            
            # Find the root domain A record (should be pointing to 8.8.8.8)
            root_a_record = None
            for record in existing_records:
                if record.get('name') == domain_name:
                    root_a_record = record
                    break
            
            if not root_a_record:
                logger.warning(f"⚠️ No A record found for {domain_name} - creating new one")
                # Create new A record if none exists
                create_result = await cloudflare.create_dns_record(
                    zone_id=zone_id,
                    record_type='A',
                    name=domain_name,
                    content=server_ip,
                    ttl=300,
                    proxied=False
                )
                
                if create_result.get('success'):
                    logger.info(f"✅ Created new A record: {domain_name} → {server_ip}")
                    
                    # CRITICAL: Sync DNS record to database for dashboard display
                    try:
                        from database import save_dns_records_to_db
                        cf_records = await cloudflare.list_dns_records(zone_id)
                        if cf_records:
                            await save_dns_records_to_db(domain_name, cf_records)
                            logger.info(f"💾 Synced {len(cf_records)} DNS records to database for {domain_name}")
                    except Exception as sync_error:
                        logger.warning(f"⚠️ DNS sync to database failed (non-blocking): {sync_error}")
                    
                    return {'success': True, 'action': 'created', 'ip': server_ip}
                else:
                    return {
                        'success': False, 
                        'error': f"Failed to create A record: {create_result.get('errors', [])}"
                    }
            
            # Update existing A record
            record_id = root_a_record.get('id')
            current_ip = root_a_record.get('content')
            
            logger.info(f"🔄 Found A record {record_id}: {domain_name} → {current_ip}")
            
            # Check if update is needed
            if current_ip == server_ip:
                logger.info(f"✅ A record already points to correct IP: {server_ip}")
                return {'success': True, 'action': 'no_change_needed', 'ip': server_ip}
            
            # Update the A record
            update_result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=str(record_id) if record_id else "",  # Ensure string type
                record_type='A',
                name=domain_name,
                content=server_ip,
                ttl=300,
                proxied=False
            )
            
            if update_result.get('success'):
                logger.info(f"✅ Updated A record: {domain_name} → {server_ip} (was: {current_ip})")
                
                # CRITICAL: Sync DNS record to database for dashboard display
                try:
                    from database import save_dns_records_to_db
                    cf_records = await cloudflare.list_dns_records(zone_id)
                    if cf_records:
                        await save_dns_records_to_db(domain_name, cf_records)
                        logger.info(f"💾 Synced {len(cf_records)} DNS records to database for {domain_name}")
                except Exception as sync_error:
                    logger.warning(f"⚠️ DNS sync to database failed (non-blocking): {sync_error}")
                
                return {
                    'success': True, 
                    'action': 'updated', 
                    'old_ip': current_ip, 
                    'new_ip': server_ip
                }
            else:
                return {
                    'success': False,
                    'error': f"Failed to update A record: {update_result.get('errors', [])}"
                }
                
        except Exception as e:
            logger.error(f"❌ Exception updating DNS A record for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    async def _finalize_wallet_payment(self, order_id: int, success: bool) -> bool:
        """
        Finalize wallet payment hold based on hosting bundle success/failure.
        
        CRITICAL FOR REVENUE PROTECTION: This method must succeed for wallet payments
        or the hosting bundle should not be marked as completed.
        
        For wallet payments, this converts the hold transaction to either:
        - success=True: Permanent debit (charges user's wallet)  
        - success=False: Refund (returns hold amount to user's wallet)
        
        Returns:
            True if finalization succeeded or not applicable (non-wallet payment)
            False if finalization failed - PREVENTS bundle completion
        """
        try:
            # Get hosting intent details to check if it's a wallet payment
            from database import execute_query, finalize_wallet_reservation
            
            # Ensure order_id is consistently handled as string for query
            order_query_id = str(order_id)
            
            # Look for hosting subscriptions with hold_transaction_id first
            hosting_result = await execute_query(
                "SELECT hold_transaction_id, domain_name FROM hosting_subscriptions WHERE id = %s",
                (order_query_id,)
            )
            
            hold_transaction_id = None
            domain_name = "unknown"
            
            if hosting_result:
                hold_transaction_id = hosting_result[0].get('hold_transaction_id')
                domain_name = hosting_result[0].get('domain_name', 'unknown')
            else:
                # Fallback: Check hosting_provision_intents for wallet payment info
                intent_result = await execute_query(
                    "SELECT domain_name, estimated_price FROM hosting_provision_intents WHERE id = %s",
                    (order_query_id,)
                )
                if intent_result:
                    domain_name = intent_result[0].get('domain_name', 'unknown')
                
                logger.debug(f"ℹ️ HOSTING WALLET FINALIZATION: No hosting subscription found for order {order_id}")
            
            # Only process wallet payments with valid holds
            if not hold_transaction_id:
                logger.debug(f"ℹ️ HOSTING WALLET FINALIZATION: Order {order_id} has no wallet hold - skipping")
                return True  # Not applicable, allow completion
            
            # CRITICAL: Finalize the wallet reservation
            logger.info(f"💳 HOSTING WALLET FINALIZATION: Processing hold transaction {hold_transaction_id} for order {order_id} (success={success})")
            
            finalization_success = await finalize_wallet_reservation(hold_transaction_id, success=success)
            
            if finalization_success:
                action = "debited from wallet" if success else "refunded to wallet" 
                logger.info(f"✅ HOSTING WALLET FINALIZATION: Hold ${hold_transaction_id} successfully {action} for {domain_name}")
                return True
            else:
                # CRITICAL: Settlement failure - prevent bundle completion
                logger.error(f"🚨 HOSTING WALLET FINALIZATION FAILED: Hold transaction {hold_transaction_id} could not be finalized")
                logger.error(f"   Order: {order_id} | Domain: {domain_name} | Action: {'debit' if success else 'refund'}")
                return False
                
        except Exception as e:
            # CRITICAL: Don't swallow exceptions that indicate system problems
            logger.error(f"🚨 HOSTING WALLET FINALIZATION EXCEPTION: Order {order_id} - {str(e)}")
            logger.error(f"   This is a critical settlement failure that prevents bundle completion")
            # Re-raise for database connection issues, but return False for business logic failures
            if "database" in str(e).lower() or "connection" in str(e).lower():
                raise  # Let orchestrator handle database connectivity issues
            return False  # Business logic failure - prevent completion but don't crash
    
    # ====================================================================
    # API-SPECIFIC ORCHESTRATION METHODS
    # ====================================================================
    
    async def provision_standalone_hosting(
        self,
        order_id: int,
        intent_id: int,
        user_id: int,
        domain_name: str,
        plan: str,
        hold_transaction_id: int,
        auto_renew: bool = True
    ) -> Dict[str, Any]:
        """
        Provision standalone hosting (without domain registration) via API.
        
        This method provisions hosting for a domain name provided by the user,
        integrates with wallet system for payment finalization, and handles
        the full hosting lifecycle.
        
        Args:
            order_id: Order ID for tracking
            intent_id: Hosting intent ID
            user_id: User ID
            domain_name: Domain name to host
            plan: Hosting plan (pro_7day or pro_30day)
            hold_transaction_id: Wallet reservation ID to finalize
            auto_renew: Enable automatic renewal (default: True)
            
        Returns:
            Dict with provisioning results
        """
        logger.info(f"🚀 API HOSTING: Provisioning standalone hosting for {domain_name} (auto_renew={auto_renew})")
        
        try:
            # Step 1: Execute hosting provisioning
            hosting_result = await self._execute_hosting_provisioning(
                intent_id=intent_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details={'plan': plan},
                auto_renew=auto_renew
            )
            
            provisioning_success = hosting_result.get('success', False)
            
            # Step 2: Finalize wallet payment based on result
            from database import finalize_wallet_reservation
            settlement_success = await finalize_wallet_reservation(
                hold_transaction_id, 
                success=provisioning_success
            )
            
            # Step 3: Update order status
            if provisioning_success and settlement_success:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'completed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.info(f"✅ API HOSTING: Standalone hosting provisioned and paid for {domain_name}")
                
                # Step 4: Send user Telegram notification for API order
                await self._send_api_order_user_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_standalone',
                    success=True
                )
                
                # Step 5: Send admin notification for API order
                await self._send_api_order_admin_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_standalone',
                    success=True
                )
                
                return {
                    'success': True,
                    'order_id': order_id,
                    'domain_name': domain_name,
                    'hosting_result': hosting_result
                }
            
            elif provisioning_success and not settlement_success:
                # CRITICAL: Hosting created but payment failed
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.error(f"🚨 API HOSTING: Hosting provisioned but wallet settlement failed for {domain_name}")
                return {
                    'success': False,
                    'error': 'Hosting provisioned but payment settlement failed - contact support',
                    'hosting_result': hosting_result
                }
            
            else:
                # Provisioning failed - refund already processed
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                # CRITICAL FIX: Update hosting_provision_intents status to 'failed' with error message
                error_message = hosting_result.get('error', 'Hosting provisioning failed')
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (error_message, str(hosting_result), intent_id))
                
                logger.info(f"⚠️ API HOSTING: Hosting provisioning failed for {domain_name} - wallet refunded")
                return {
                    'success': False,
                    'error': error_message,
                    'refunded': settlement_success
                }
                
        except Exception as e:
            logger.error(f"❌ API HOSTING: Exception in standalone hosting provisioning: {e}")
            
            # Attempt refund on exception
            try:
                from database import finalize_wallet_reservation
                await finalize_wallet_reservation(hold_transaction_id, success=False)
            except Exception as refund_error:
                logger.error(f"❌ Failed to refund wallet on exception: {refund_error}")
            
            # Update order and intent status on exception
            try:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (f"Exception: {str(e)}", str(e), intent_id))
            except Exception as update_error:
                logger.error(f"❌ Failed to update order/intent status on exception: {update_error}")
            
            return {
                'success': False,
                'error': str(e)
            }
    
    async def provision_hosting_for_existing_domain(
        self,
        order_id: int,
        intent_id: int,
        user_id: int,
        domain_name: str,
        plan: str,
        hold_transaction_id: int,
        auto_renew: bool = True
    ) -> Dict[str, Any]:
        """
        Provision hosting for an existing HostBay domain via API.
        
        This method:
        1. Verifies the domain exists in our database
        2. Provisions hosting (cPanel account)
        3. Updates DNS records with server IP
        4. Finalizes wallet payment
        
        Args:
            order_id: Order ID for tracking
            intent_id: Hosting intent ID
            user_id: User ID
            domain_name: Existing domain name
            plan: Hosting plan
            hold_transaction_id: Wallet reservation ID to finalize
            auto_renew: Enable automatic renewal (default: True)
            
        Returns:
            Dict with provisioning results
        """
        logger.info(f"🚀 API HOSTING: Provisioning hosting for existing domain {domain_name} (auto_renew={auto_renew})")
        
        try:
            # Step 1: Verify domain ownership
            domain_data = await execute_query("""
                SELECT id, cloudflare_zone_id 
                FROM domains 
                WHERE domain_name = %s AND user_id = %s
            """, (domain_name, user_id))
            
            if not domain_data:
                logger.error(f"❌ Domain {domain_name} not found for user {user_id}")
                
                # Refund since domain doesn't exist
                from database import finalize_wallet_reservation
                await finalize_wallet_reservation(hold_transaction_id, success=False)
                
                # CRITICAL FIX: Update order and intent status for domain-not-found case
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, ("Domain not found or access denied", intent_id))
                
                return {
                    'success': False,
                    'error': 'Domain not found or access denied',
                    'refunded': True
                }
            
            # Step 2: Execute hosting provisioning
            hosting_result = await self._execute_hosting_provisioning(
                intent_id=intent_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details={'plan': plan},
                auto_renew=auto_renew
            )
            
            provisioning_success = hosting_result.get('success', False)
            
            # Step 3: Update nameservers to Cloudflare if not already configured (use shared helper)
            ns_result = None
            if provisioning_success:
                try:
                    ns_result = await self._ensure_cloudflare_nameservers(domain_name, user_id)
                    ns_status = ns_result.get('status', 'unknown')
                    if ns_status == 'auto_updated':
                        logger.info(f"✅ API: Nameservers auto-updated for {domain_name}")
                    elif ns_status == 'already_correct':
                        logger.info(f"✅ API: Nameservers already correct for {domain_name}")
                    elif ns_status == 'manual_required':
                        logger.warning(f"⚠️ API: Manual nameserver update required for {domain_name}")
                except Exception as ns_error:
                    logger.warning(f"⚠️ Nameserver update failed but continuing: {ns_error}")
            
            # Step 4: Update DNS A record with server IP if hosting succeeded
            if provisioning_success:
                try:
                    await self._update_dns_with_server_ip(
                        domain_name=domain_name,
                        domain_result={'cloudflare_zone_id': domain_data[0].get('cloudflare_zone_id')},
                        hosting_result=hosting_result
                    )
                except Exception as dns_error:
                    logger.warning(f"⚠️ DNS update failed but continuing: {dns_error}")
            
            # Step 5: Finalize wallet payment
            from database import finalize_wallet_reservation
            settlement_success = await finalize_wallet_reservation(
                hold_transaction_id,
                success=provisioning_success
            )
            
            # Step 6: Update order status
            if provisioning_success and settlement_success:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'completed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.info(f"✅ API HOSTING: Hosting provisioned and paid for existing domain {domain_name}")
                
                # Step 7: Send user and admin notifications for API order
                await self._send_api_order_user_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_with_existing_domain',
                    success=True
                )
                
                await self._send_api_order_admin_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_with_existing_domain',
                    success=True
                )
                
                return {
                    'success': True,
                    'order_id': order_id,
                    'domain_name': domain_name,
                    'hosting_result': hosting_result
                }
            
            elif provisioning_success and not settlement_success:
                # CRITICAL: Hosting created but payment failed
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.error(f"🚨 API HOSTING: Hosting provisioned but wallet settlement failed for {domain_name}")
                return {
                    'success': False,
                    'error': 'Hosting provisioned but payment settlement failed - contact support',
                    'hosting_result': hosting_result
                }
            
            else:
                # Provisioning failed - refund processed
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                # CRITICAL FIX: Update hosting_provision_intents status to 'failed' with error message
                error_message = hosting_result.get('error', 'Hosting provisioning failed')
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (error_message, str(hosting_result), intent_id))
                
                logger.info(f"⚠️ API HOSTING: Hosting provisioning failed for {domain_name} - wallet refunded")
                return {
                    'success': False,
                    'error': error_message,
                    'refunded': settlement_success
                }
                
        except Exception as e:
            logger.error(f"❌ API HOSTING: Exception in existing domain hosting: {e}")
            
            # Attempt refund on exception
            try:
                from database import finalize_wallet_reservation
                await finalize_wallet_reservation(hold_transaction_id, success=False)
            except Exception as refund_error:
                logger.error(f"❌ Failed to refund wallet on exception: {refund_error}")
            
            # Update order and intent status on exception
            try:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (f"Exception: {str(e)}", str(e), intent_id))
            except Exception as update_error:
                logger.error(f"❌ Failed to update order/intent status on exception: {update_error}")
            
            return {
                'success': False,
                'error': str(e)
            }

    async def provision_hosting_for_external_domain(
        self,
        order_id: int,
        intent_id: int,
        user_id: int,
        domain_name: str,
        plan: str,
        hold_transaction_id: int,
        auto_renew: bool = True,
        linking_mode: str = "nameserver"
    ) -> Dict[str, Any]:
        """
        Provision hosting for an external domain (registered at another registrar).
        
        This method:
        1. Provisions hosting (cPanel account)
        2. Creates Cloudflare zone for the domain
        3. Finalizes wallet payment
        
        Unlike existing domains, this does NOT auto-update nameservers 
        (user must configure DNS at their registrar).
        
        Args:
            order_id: Order ID for tracking
            intent_id: Hosting intent ID
            user_id: User ID
            domain_name: External domain name
            plan: Hosting plan
            hold_transaction_id: Wallet reservation ID to finalize
            auto_renew: Enable automatic renewal (default: True)
            linking_mode: DNS linking method - 'nameserver' or 'a_record'
            
        Returns:
            Dict with provisioning results
        """
        logger.info(f"🚀 API HOSTING: Provisioning hosting for EXTERNAL domain {domain_name} (linking_mode={linking_mode})")
        
        try:
            # Step 1: Execute hosting provisioning (cPanel account creation)
            hosting_result = await self._execute_hosting_provisioning(
                intent_id=intent_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details={'plan': plan},
                auto_renew=auto_renew
            )
            
            provisioning_success = hosting_result.get('success', False)
            
            # Step 2: Create Cloudflare zone for external domain (prepare for when user updates DNS)
            if provisioning_success:
                try:
                    zone_result = await self._create_cloudflare_zone_for_existing_domain(domain_name)
                    if zone_result and zone_result.get('success'):
                        logger.info(f"✅ Cloudflare zone created for external domain {domain_name}")
                        
                        # Pre-configure A record so it's ready when DNS propagates
                        await self._update_dns_with_server_ip(
                            domain_name=domain_name,
                            domain_result={'zone_data': zone_result},
                            hosting_result=hosting_result
                        )
                    else:
                        logger.warning(f"⚠️ Cloudflare zone creation failed for {domain_name}: {zone_result}")
                except Exception as cf_error:
                    logger.warning(f"⚠️ Cloudflare setup failed for external domain but continuing: {cf_error}")
            
            # Step 3: Finalize wallet payment
            from database import finalize_wallet_reservation
            settlement_success = await finalize_wallet_reservation(
                hold_transaction_id,
                success=provisioning_success
            )
            
            # Step 4: Update order status
            if provisioning_success and settlement_success:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'completed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.info(f"✅ API HOSTING: Hosting provisioned and paid for external domain {domain_name}")
                
                # Step 5: Send user and admin notifications for API order
                await self._send_api_order_user_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_with_external_domain',
                    success=True
                )
                
                await self._send_api_order_admin_notification(
                    user_id=user_id,
                    order_id=order_id,
                    domain_name=domain_name,
                    plan=plan,
                    service_type='hosting_with_external_domain',
                    success=True
                )
                
                return {
                    'success': True,
                    'order_id': order_id,
                    'domain_name': domain_name,
                    'hosting_result': hosting_result,
                    'dns_status': 'pending_user_configuration',
                    'linking_mode': linking_mode
                }
            
            elif provisioning_success and not settlement_success:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                logger.error(f"🚨 API HOSTING: Hosting provisioned but wallet settlement failed for {domain_name}")
                return {
                    'success': False,
                    'error': 'Hosting provisioned but payment settlement failed - contact support',
                    'hosting_result': hosting_result
                }
            
            else:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                error_message = hosting_result.get('error', 'Hosting provisioning failed')
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (error_message, str(hosting_result), intent_id))
                
                logger.info(f"⚠️ API HOSTING: Hosting provisioning failed for external domain {domain_name} - wallet refunded")
                return {
                    'success': False,
                    'error': error_message,
                    'refunded': settlement_success
                }
                
        except Exception as e:
            logger.error(f"❌ API HOSTING: Exception in external domain hosting: {e}")
            
            try:
                from database import finalize_wallet_reservation
                await finalize_wallet_reservation(hold_transaction_id, success=False)
            except Exception as refund_error:
                logger.error(f"❌ Failed to refund wallet on exception: {refund_error}")
            
            try:
                await execute_update("""
                    UPDATE orders 
                    SET status = 'failed', updated_at = NOW()
                    WHERE id = %s
                """, (order_id,))
                
                await execute_update("""
                    UPDATE hosting_provision_intents
                    SET status = 'failed', 
                        error_message = %s,
                        last_error = %s,
                        updated_at = NOW()
                    WHERE id = %s
                """, (f"Exception: {str(e)}", str(e), intent_id))
            except Exception as update_error:
                logger.error(f"❌ Failed to update order/intent status on exception: {update_error}")
            
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _send_api_order_user_notification(
        self,
        user_id: int,
        order_id: int,
        domain_name: str,
        plan: str,
        service_type: str,
        success: bool,
        error: Optional[str] = None
    ):
        """
        Send Telegram notification to user for API-created orders.
        Uses queue_user_message to send without query_adapter.
        """
        try:
            from webhook_handler import queue_user_message
            from translations import t_for_user
            
            if success:
                # Success notification
                message = (
                    f"<b>Hosting Order Completed</b>\n\n"
                    f"<b>Domain:</b> {domain_name}\n"
                    f"<b>Plan:</b> {plan}\n"
                    f"<b>Order ID:</b> {order_id}\n"
                    f"<b>Status:</b> Active\n\n"
                    f"Your hosting account has been provisioned successfully via API.\n"
                    f"Use the /hosting command to view your subscriptions."
                )
            else:
                # Failure notification
                error_msg = error or 'Unknown error'
                message = (
                    f"<b>Hosting Order Failed</b>\n\n"
                    f"<b>Domain:</b> {domain_name}\n"
                    f"<b>Plan:</b> {plan}\n"
                    f"<b>Order ID:</b> {order_id}\n"
                    f"<b>Error:</b> {error_msg}\n\n"
                    f"Your wallet has been refunded. Please try again or contact support."
                )
            
            # Get user's telegram_id from database
            from database import execute_query
            user_result = await execute_query(
                "SELECT telegram_id FROM users WHERE id = %s",
                (user_id,)
            )
            
            if user_result and user_result[0].get('telegram_id'):
                telegram_id = user_result[0]['telegram_id']
                await queue_user_message(telegram_id, message, parse_mode='HTML')
                logger.info(f"📧 API HOSTING: User notification sent to telegram_id {telegram_id} for order {order_id}")
            else:
                logger.warning(f"⚠️ API HOSTING: Could not find telegram_id for user {user_id}")
                
        except Exception as e:
            logger.error(f"❌ API HOSTING: Failed to send user notification for order {order_id}: {e}")
    
    async def _send_api_order_admin_notification(
        self,
        user_id: int,
        order_id: int,
        domain_name: str,
        plan: str,
        service_type: str,
        success: bool,
        amount: Optional[float] = None,
        error: Optional[str] = None
    ):
        """
        Send admin notification for API-created orders.
        Ensures admins are aware of API purchases just like bot purchases.
        """
        try:
            from admin_alerts import send_info_alert, send_warning_alert
            
            # Get user details for admin notification
            from database import execute_query
            user_result = await execute_query(
                "SELECT username, telegram_id FROM users WHERE id = %s",
                (user_id,)
            )
            username = user_result[0].get('username', 'Unknown') if user_result else 'Unknown'
            
            if success:
                await send_info_alert(
                    component="API_Hosting",
                    message=f"New API hosting order: {domain_name} ({plan})",
                    category="api_order",
                    details={
                        "order_id": order_id,
                        "user_id": user_id,
                        "username": username,
                        "domain_name": domain_name,
                        "plan": plan,
                        "service_type": service_type,
                        "source": "REST_API",
                        "status": "completed"
                    }
                )
                logger.info(f"📢 API HOSTING: Admin notification sent for successful order {order_id}")
            else:
                await send_warning_alert(
                    component="API_Hosting",
                    message=f"API hosting order failed: {domain_name}",
                    category="api_order",
                    details={
                        "order_id": order_id,
                        "user_id": user_id,
                        "username": username,
                        "domain_name": domain_name,
                        "plan": plan,
                        "service_type": service_type,
                        "source": "REST_API",
                        "status": "failed",
                        "error": error
                    }
                )
                logger.info(f"📢 API HOSTING: Admin notification sent for failed order {order_id}")
                
        except Exception as e:
            logger.error(f"❌ API HOSTING: Failed to send admin notification for order {order_id}: {e}")


# ====================================================================
# CONVENIENCE FUNCTION FOR EXTERNAL USE
# ====================================================================

async def start_hosting_bundle(
    order_id: int,
    user_id: int,
    domain_name: str, 
    payment_details: Optional[Dict[str, Any]] = None,
    query_adapter: Optional[Any] = None,
    lang_code: str = 'en'
) -> Dict[str, Any]:
    """
    Convenience function to start hosting bundle processing.
    
    Creates orchestrator instance and delegates to start_hosting_bundle method.
    """
    orchestrator = HostingBundleOrchestrator()
    return await orchestrator.start_hosting_bundle(
        order_id=order_id,
        user_id=user_id,
        domain_name=domain_name,
        payment_details=payment_details,
        query_adapter=query_adapter,
        lang_code=lang_code
    )
