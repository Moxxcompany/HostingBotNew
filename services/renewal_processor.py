"""
Hosting Renewal Processor Service
Automated wallet-based billing for hosting subscriptions with comprehensive renewal management
"""

import os
import logging
import asyncio
import time
from datetime import datetime, timedelta, timezone, date as date_type
from typing import Dict, List, Optional, Tuple, Any, cast, Union
from decimal import Decimal, ROUND_HALF_UP

# Import database functions
from database import (
    execute_query, execute_update, debit_wallet_balance, get_user_wallet_balance,
    get_user_hosting_subscriptions, get_hosting_subscription_details, 
    get_hosting_plan, update_hosting_subscription_status, get_or_create_user_with_status,
    ensure_financial_operations_allowed, verify_financial_operation_safety, run_db
)

# Import existing utilities
from pricing_utils import format_money, PricingConfig
from message_utils import create_success_message, create_error_message, format_bold, format_inline_code
from brand_config import get_platform_name, get_service_error_message
from localization import t

logger = logging.getLogger(__name__)

class HostingRenewalProcessor:
    """
    Production hosting renewal processor with automated wallet-based billing
    Handles subscription renewals, grace periods, and comprehensive user notifications
    """
    
    def __init__(self):
        self.warning_days_before = int(os.getenv('RENEWAL_WARNING_DAYS', '3'))
        self.batch_size = int(os.getenv('RENEWAL_BATCH_SIZE', '50'))
        self.max_retries = int(os.getenv('RENEWAL_MAX_RETRIES', '3'))
        self.processing_enabled = True
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
        
        # Global bot application reference for notifications
        self._bot_application = None
        
        logger.info(f"🔄 HostingRenewalProcessor initialized: plan-specific grace periods (7d→1d, 30d→2d), warning={self.warning_days_before}d ahead")
    
    def get_grace_period_days(self, billing_cycle: str) -> int:
        """Get grace period days based on billing cycle duration"""
        if billing_cycle == '7days':
            return 1  # 7 days plan has only 1 day grace
        elif billing_cycle == '30days':
            return 2  # 30 days plan has 2 days grace
        else:
            # Default grace periods for other cycles
            if billing_cycle in ('monthly', 'yearly'):
                return 7  # Traditional monthly/yearly plans keep 7 days
            else:
                return 2  # Default fallback
    
    def _ensure_timezone_aware_datetime(self, dt: Union[datetime, date_type, None]) -> Optional[datetime]:
        """
        Safely convert date/datetime objects to timezone-aware datetime objects.
        Handles both datetime.date and datetime.datetime types from database.
        """
        if dt is None:
            return None
        
        # If it's a plain date object (not datetime), convert to datetime at midnight UTC
        if isinstance(dt, date_type) and not isinstance(dt, datetime):
            dt = datetime.combine(dt, datetime.min.time(), tzinfo=timezone.utc)
        
        # If it's a datetime without timezone info, add UTC timezone
        if isinstance(dt, datetime) and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        
        return dt
    
    def set_bot_application(self, bot_application):
        """Set bot application reference for sending notifications"""
        self._bot_application = bot_application
        logger.info("🤖 Bot application reference set for renewal notifications")
    
    async def process_all_renewals(self) -> Dict[str, Any]:
        """
        Main entry point for processing all hosting renewals
        Designed to be called by APScheduler or manual admin trigger
        """
        if not self.processing_enabled:
            logger.debug("🔇 Renewal processing is disabled")
            return {"status": "disabled", "reason": "Processing disabled"}
        
        try:
            # Security check for financial operations with comprehensive error handling
            try:
                safety_check = verify_financial_operation_safety("hosting_renewal_processing")
                if not safety_check:
                    logger.error("🚫 RENEWAL BLOCKED: Financial operations not allowed")
                    return {"status": "blocked", "reason": "Financial operations blocked"}
            except Exception as safety_error:
                # Handle case where safety check raises exception instead of returning False
                logger.error(f"🚫 RENEWAL BLOCKED: Financial safety check exception: {safety_error}")
                return {"status": "blocked", "reason": f"Financial operations blocked: {str(safety_error)}"}
            
            logger.info("🔄 Starting automated hosting renewal processing...")
            
            # Reset statistics
            self._reset_stats()
            
            # Get subscriptions due for renewal
            subscriptions_to_process = await self._get_subscriptions_for_renewal()
            
            if not subscriptions_to_process:
                logger.info("✅ No hosting subscriptions require renewal processing")
                return {"status": "success", "message": "No renewals needed", "stats": self.stats}
            
            logger.info(f"📊 Found {len(subscriptions_to_process)} subscriptions requiring renewal processing")
            
            # Process renewals in batches
            batch_results = []
            for i in range(0, len(subscriptions_to_process), self.batch_size):
                batch = subscriptions_to_process[i:i + self.batch_size]
                batch_result = await self._process_renewal_batch(batch, i // self.batch_size + 1)
                batch_results.append(batch_result)
                
                # Small delay between batches to prevent overwhelming the system
                if i + self.batch_size < len(subscriptions_to_process):
                    await asyncio.sleep(2)
            
            # Generate final summary
            final_stats = self.stats.copy()
            success_rate = (final_stats['successful'] / final_stats['processed'] * 100) if final_stats['processed'] > 0 else 0
            
            logger.info(f"✅ Renewal processing completed: {final_stats['successful']}/{final_stats['processed']} successful ({success_rate:.1f}%)")
            if final_stats['failed'] > 0:
                logger.warning(f"⚠️ {final_stats['failed']} renewals failed, {final_stats['grace_period']} in grace period")
            
            return {
                "status": "success",
                "stats": final_stats,
                "success_rate": success_rate,
                "batch_results": batch_results
            }
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Critical error in renewal processing: {e}")
            return {"status": "error", "error": str(e), "stats": self.stats}
    
    async def _get_subscriptions_for_renewal(self) -> List[Dict]:
        """Get all subscriptions that need renewal processing"""
        try:
            # Calculate dates for renewal logic
            now = datetime.now(timezone.utc)
            warning_threshold = now + timedelta(days=self.warning_days_before)
            # Use maximum grace period for query (7 days) to capture all potentially expiring subscriptions
            max_grace_period = 7  # Conservative approach to catch all subscriptions that might need processing
            grace_cutoff = now - timedelta(days=max_grace_period)
            
            query = """
                SELECT hs.*, hp.plan_name, hp.monthly_price, hp.yearly_price,
                       u.telegram_id, u.wallet_balance, u.username, u.first_name
                FROM hosting_subscriptions hs
                JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
                JOIN users u ON hs.user_id = u.id
                WHERE hs.status IN ('active', 'pending_renewal', 'grace_period')
                  AND (
                    -- Due for renewal (past due or approaching)
                    hs.next_billing_date <= %s
                    -- Warning notifications (approaching renewal)
                    OR (hs.next_billing_date <= %s AND hs.last_warning_sent IS NULL)
                    -- Grace period expiring soon
                    OR (hs.status = 'grace_period' AND hs.grace_period_started <= %s)
                  )
                ORDER BY hs.next_billing_date ASC, hs.status ASC
            """
            
            return await execute_query(query, (now, warning_threshold, grace_cutoff))
            
        except Exception as e:
            logger.error(f"❌ Error fetching subscriptions for renewal: {e}")
            return []
    
    async def _process_renewal_batch(self, batch: List[Dict], batch_number: int) -> Dict[str, Any]:
        """Process a batch of renewals with parallel processing where safe"""
        logger.info(f"🔄 Processing renewal batch {batch_number} ({len(batch)} subscriptions)")
        
        batch_stats = {'processed': 0, 'successful': 0, 'failed': 0, 'warnings': 0}
        
        # Process each subscription in the batch
        for subscription in batch:
            try:
                result = await self.process_subscription_renewal(subscription)
                batch_stats['processed'] += 1
                
                if result['status'] == 'success':
                    batch_stats['successful'] += 1
                elif result['status'] == 'warning_sent':
                    batch_stats['warnings'] += 1
                else:
                    batch_stats['failed'] += 1
                    
                # Small delay between individual subscription processing
                await asyncio.sleep(0.5)
                
            except Exception as e:
                batch_stats['failed'] += 1
                self.stats['errors'] += 1
                logger.error(f"❌ Error processing subscription {subscription.get('id', 'unknown')}: {e}")
        
        logger.info(f"✅ Batch {batch_number} completed: {batch_stats['successful']}/{batch_stats['processed']} successful")
        return batch_stats
    
    async def process_subscription_renewal(self, subscription: Dict) -> Dict[str, Any]:
        """
        Process renewal for a single hosting subscription
        Handles the complete renewal lifecycle including payments and notifications
        """
        subscription_id = subscription['id']
        user_id = subscription['user_id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        current_status = subscription['status']
        
        try:
            logger.info(f"🔄 Processing renewal for subscription {subscription_id} ({domain_name})")
            
            # Determine what action is needed
            now = datetime.now(timezone.utc)
            next_billing_date = subscription['next_billing_date']
            
            # Convert to timezone-aware datetime (handles both date and datetime objects)
            next_billing_date = self._ensure_timezone_aware_datetime(next_billing_date)
            
            renewal_action = self._determine_renewal_action(subscription, now)
            
            if renewal_action == 'warning':
                return await self._send_renewal_warning(subscription)
            elif renewal_action == 'move_to_grace':
                return await self._move_to_grace_and_suspend(subscription)
            elif renewal_action == 'grace_period_warning':
                return await self._handle_grace_period_warning(subscription)
            elif renewal_action == 'suspend':
                return await self._suspend_expired_subscription(subscription)
            else:
                logger.debug(f"📅 No action needed for subscription {subscription_id}")
                return {'status': 'no_action', 'subscription_id': subscription_id}
                
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Error processing renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    def _determine_renewal_action(self, subscription: Dict, now: datetime) -> str:
        """Determine what renewal action is needed with comprehensive multi-period overdue handling"""
        next_billing_date = subscription['next_billing_date']
        current_status = subscription['status']
        last_warning_sent = subscription.get('last_warning_sent')
        grace_period_started = subscription.get('grace_period_started')
        billing_cycle = subscription.get('billing_cycle', 'monthly')
        
        # Convert to timezone-aware datetime (handles both date and datetime objects)
        next_billing_date = self._ensure_timezone_aware_datetime(next_billing_date)
        
        # Handle one-time subscriptions - they should not renew, only expire
        if billing_cycle == 'one_time' and next_billing_date <= now:
            logger.info(f"🔚 One-time subscription {subscription['id']} expired, marking for suspension")
            return 'suspend'
        
        days_until_billing = (next_billing_date - now).days
        
        # Handle overdue subscriptions - move to grace period (no auto-renewal)
        if next_billing_date < now:
            days_overdue = (now - next_billing_date).days
            
            # Log overdue status
            if billing_cycle == 'monthly' and days_overdue > 60:
                logger.warning(f"⚠️ Subscription {subscription['id']} severely overdue: {days_overdue} days ({days_overdue//30} months)")
            elif billing_cycle == 'yearly' and days_overdue > 730:
                logger.warning(f"⚠️ Subscription {subscription['id']} severely overdue: {days_overdue} days ({days_overdue//365} years)")
            
            # Move overdue subscriptions to grace period (no automatic wallet charging)
            if current_status in ('active', 'pending_renewal'):
                return 'move_to_grace'
        
        # Check if renewal warning is needed (only for active subscriptions approaching due date)
        if (days_until_billing <= self.warning_days_before and 
            days_until_billing > 0 and 
            current_status == 'active' and 
            not last_warning_sent):
            return 'warning'
        
        # Check if subscription is due - move to grace period (no auto-renewal)
        if next_billing_date <= now and current_status in ('active', 'pending_renewal'):
            return 'move_to_grace'
        
        # Check grace period status with enhanced validation
        if current_status == 'grace_period':
            if grace_period_started:
                # Convert to timezone-aware datetime (handles both date and datetime objects)
                grace_period_started = self._ensure_timezone_aware_datetime(grace_period_started)
                
                days_in_grace = (now - grace_period_started).days
                
                # Get plan-specific grace period
                grace_period_days = self.get_grace_period_days(billing_cycle)
                
                # Validate grace period hasn't exceeded maximum allowed time
                if days_in_grace >= grace_period_days:
                    logger.warning(f"😨 Subscription {subscription['id']} grace period expired: {days_in_grace}/{grace_period_days} days (billing cycle: {billing_cycle})")
                    return 'suspend'
                elif days_in_grace >= grace_period_days - 1:  # Warning 1 day before suspension
                    return 'grace_period_warning'
            else:
                # Grace period without start date - this is a data issue
                logger.error(f"❌ Subscription {subscription['id']} in grace_period status but no grace_period_started date")
                # Move to suspend to resolve the inconsistent state
                return 'suspend'
        
        return 'no_action'
    
    async def _process_subscription_payment(self, subscription: Dict) -> Dict[str, Any]:
        """Process the actual renewal payment for a subscription with atomic transactions"""
        subscription_id = subscription['id']
        user_id = subscription['user_id']
        telegram_id = subscription['telegram_id']
        billing_cycle = subscription['billing_cycle']
        domain_name = subscription.get('domain_name', 'unknown')
        
        try:
            # Calculate renewal cost
            renewal_cost = self._calculate_renewal_cost(subscription)
            if renewal_cost <= 0:
                logger.error(f"❌ Invalid renewal cost for subscription {subscription_id}: ${renewal_cost:.2f}")
                return {'status': 'error', 'reason': 'Invalid renewal cost'}
            
            # Generate idempotency key for this renewal attempt
            import hashlib
            import time
            idempotency_data = f"{subscription_id}_{subscription['next_billing_date']}_{renewal_cost}"
            idempotency_key = hashlib.sha256(idempotency_data.encode()).hexdigest()[:32]
            
            # Attempt atomic renewal with comprehensive safety checks
            renewal_result = await self._process_renewal_atomically(
                subscription_id, user_id, renewal_cost, billing_cycle, idempotency_key, domain_name
            )
            
            # Handle result and send appropriate notifications
            if renewal_result['status'] == 'success':
                # Send success notification with fallback logging
                await self._send_renewal_notification_with_fallback(
                    telegram_id, 'success', {
                        'domain_name': domain_name,
                        'amount': renewal_cost,
                        'next_billing_date': renewal_result['next_billing_date'],
                        'billing_cycle': billing_cycle
                    }
                )
                
                self.stats['successful'] += 1
                logger.info(f"✅ Atomic renewal successful for {domain_name}: ${renewal_cost:.2f} charged, next billing {renewal_result['next_billing_date'].date()}")
                
            elif renewal_result['status'] == 'payment_failed':
                # Move to grace period atomically if not already done
                if renewal_result.get('moved_to_grace_period'):
                    # Send failure notification with fallback logging
                    grace_period_days = self.get_grace_period_days(billing_cycle)
                    await self._send_renewal_notification_with_fallback(
                        telegram_id, 'payment_failed', {
                            'domain_name': domain_name,
                            'amount': renewal_cost,
                            'current_balance': renewal_result.get('current_balance', 0),
                            'grace_period_days': grace_period_days
                        }
                    )
                    
                    self.stats['failed'] += 1
                    self.stats['grace_period'] += 1
                    logger.warning(f"💸 Atomic renewal failed for {domain_name}: insufficient funds (needed ${renewal_cost:.2f})")
                else:
                    logger.error(f"❌ Failed to move subscription {subscription_id} to grace period after payment failure")
                    
            return renewal_result
                
        except Exception as e:
            logger.error(f"❌ Critical error processing renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _process_renewal_atomically(self, subscription_id: int, user_id: int, renewal_cost: Decimal, 
                                         billing_cycle: str, idempotency_key: str, domain_name: str) -> Dict[str, Any]:
        """
        Process renewal payment and subscription update in a single atomic transaction
        Uses row-level locking and idempotency to prevent race conditions and double-charging
        """
        from database import get_connection, return_connection
        import psycopg2
        
        conn = None
        try:
            # Perform comprehensive financial safety check with amount
            try:
                safety_check = verify_financial_operation_safety("hosting_renewal_deduction", renewal_cost)
                if not safety_check:
                    logger.error(f"🚫 Financial operation blocked for subscription {subscription_id}: safety check failed")
                    return {
                        'status': 'blocked', 
                        'subscription_id': subscription_id, 
                        'reason': 'Financial operations blocked by security system'
                    }
            except Exception as safety_error:
                # Handle case where safety check raises exception instead of returning False
                logger.error(f"🚫 Financial safety check exception for subscription {subscription_id}: {safety_error}")
                return {
                    'status': 'blocked', 
                    'subscription_id': subscription_id, 
                    'reason': f'Financial operations blocked: {str(safety_error)}'
                }
            
            # Get database connection for atomic transaction
            conn = get_connection()
            conn.autocommit = False  # Enable transaction mode
            
            with conn.cursor() as cursor:
                # Step 1: Check for duplicate processing using idempotency key
                cursor.execute(
                    "SELECT id FROM wallet_transactions WHERE description LIKE %s AND status = 'completed'",
                    (f"%renewal%{subscription_id}%{idempotency_key}%",)
                )
                existing_transaction = cursor.fetchone()
                
                if existing_transaction:
                    conn.rollback()
                    logger.warning(f"🔄 Duplicate renewal attempt detected for subscription {subscription_id} - idempotency key: {idempotency_key}")
                    return {
                        'status': 'duplicate',
                        'subscription_id': subscription_id,
                        'reason': 'Renewal already processed for this billing period'
                    }
                
                # Step 2: Lock subscription row to prevent concurrent processing
                cursor.execute(
                    "SELECT next_billing_date, status, cpanel_username FROM hosting_subscriptions WHERE id = %s FOR UPDATE",
                    (subscription_id,)
                )
                locked_subscription = cursor.fetchone()
                
                if not locked_subscription:
                    conn.rollback()
                    logger.error(f"❌ Subscription {subscription_id} not found for atomic renewal")
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'reason': 'Subscription not found'
                    }
                
                # Step 3: Lock user wallet and check balance
                cursor.execute(
                    "SELECT wallet_balance FROM users WHERE id = %s FOR UPDATE",
                    (user_id,)
                )
                user_wallet = cursor.fetchone()
                
                if not user_wallet:
                    conn.rollback()
                    logger.error(f"❌ User {user_id} not found for atomic renewal")
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'reason': 'User not found'
                    }
                
                current_balance = Decimal(str(cast(Dict[str, Any], user_wallet)['wallet_balance'] or 0))
                
                # Step 4: Check sufficient funds
                if current_balance < renewal_cost:
                    logger.warning(f"💸 Insufficient funds for atomic renewal: user {user_id}, subscription {subscription_id}")
                    logger.warning(f"💸 Required: ${renewal_cost:.2f}, Available: ${current_balance:.2f}")
                    
                    # Move to grace period atomically
                    cursor.execute(
                        "UPDATE hosting_subscriptions SET status = 'grace_period', grace_period_started = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (subscription_id,)
                    )
                    
                    # Record failed transaction attempt
                    cursor.execute(
                        "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                        (user_id, 'debit', renewal_cost, 'USD', 'failed', f"Failed hosting renewal for {domain_name} (insufficient funds) - {idempotency_key}")
                    )
                    
                    conn.commit()
                    return {
                        'status': 'payment_failed',
                        'subscription_id': subscription_id,
                        'current_balance': current_balance,
                        'amount_needed': renewal_cost,
                        'shortfall': renewal_cost - current_balance,
                        'moved_to_grace_period': True
                    }
                
                # Step 5: Process wallet deduction atomically
                new_balance = current_balance - renewal_cost
                
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # Step 6: Record successful transaction
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, 'debit', renewal_cost, 'USD', 'completed', f"Hosting renewal for {domain_name} - {idempotency_key}")
                )
                
                # Step 7: Update subscription with new billing date and clear warning flags
                next_billing_date = self.calculate_next_billing_date(
                    cast(Dict[str, Any], locked_subscription)['next_billing_date'], billing_cycle
                )
                
                # Validate the calculated next billing date
                if next_billing_date <= cast(Dict[str, Any], locked_subscription)['next_billing_date']:
                    logger.error(f"❌ Invalid next billing date calculation: {next_billing_date} <= {cast(Dict[str, Any], locked_subscription)['next_billing_date']}")
                    conn.rollback()
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'error': 'Invalid billing date calculation'
                    }
                
                cursor.execute(
                    "UPDATE hosting_subscriptions SET next_billing_date = %s, status = 'active', grace_period_started = NULL, last_warning_sent = NULL, last_renewed = CURRENT_TIMESTAMP, cpanel_suspension_status = NULL, cpanel_suspension_attempts = 0, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (next_billing_date, subscription_id)
                )
                
                # Commit the entire transaction
                conn.commit()
                
                # Step 8: Auto-unsuspend cPanel account if subscription was previously suspended
                if cast(Dict[str, Any], locked_subscription)['status'] == 'suspended':
                    cpanel_username = cast(Dict[str, Any], locked_subscription).get('cpanel_username')
                    if cpanel_username:
                        try:
                            from services.cpanel import CPanelService
                            cpanel = CPanelService()
                            unsuspend_success = await cpanel.unsuspend_account(cpanel_username)
                            if unsuspend_success:
                                logger.info(f"✅ Auto-unsuspended cPanel account after renewal: {cpanel_username}")
                            else:
                                logger.error(f"❌ Failed to unsuspend cPanel account after renewal: {cpanel_username}")
                        except Exception as unsuspend_error:
                            logger.error(f"❌ Error auto-unsuspending cPanel account {cpanel_username}: {unsuspend_error}")
                    else:
                        logger.warning(f"⚠️ Suspended subscription renewed but no cPanel username for auto-unsuspension")
                
                logger.info(f"✅ Atomic renewal completed successfully: subscription {subscription_id}, user {user_id}")
                logger.info(f"💰 Wallet: ${current_balance:.2f} → ${new_balance:.2f} (charged ${renewal_cost:.2f})")
                logger.info(f"📅 Next billing: {next_billing_date.date()}")
                
                return {
                    'status': 'success',
                    'subscription_id': subscription_id,
                    'amount_charged': renewal_cost,
                    'previous_balance': current_balance,
                    'new_balance': new_balance,
                    'next_billing_date': next_billing_date
                }
                
        except psycopg2.Error as db_error:
            if conn:
                conn.rollback()
            logger.error(f"❌ Database error in atomic renewal for subscription {subscription_id}: {db_error}")
            return {
                'status': 'error',
                'subscription_id': subscription_id,
                'error': f'Database error: {str(db_error)}'
            }
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"❌ Critical error in atomic renewal for subscription {subscription_id}: {e}")
            return {
                'status': 'error',
                'subscription_id': subscription_id,
                'error': str(e)
            }
            
        finally:
            if conn:
                conn.autocommit = True  # Restore autocommit
                return_connection(conn)
    
    def _calculate_renewal_cost(self, subscription: Dict) -> Decimal:
        """Calculate the renewal cost for a subscription based on billing cycle"""
        billing_cycle = subscription['billing_cycle']
        monthly_price = Decimal(str(subscription.get('monthly_price', 0)))
        yearly_price = Decimal(str(subscription.get('yearly_price', 0)))
        
        # One-time subscriptions do not renew
        if billing_cycle == 'one_time':
            logger.warning(f"⚠️ Attempted to calculate renewal cost for one_time subscription {subscription.get('id', 'unknown')} - one-time subscriptions do not renew")
            return Decimal('0')
        
        if billing_cycle == 'yearly' and yearly_price > 0:
            return yearly_price
        elif billing_cycle == 'monthly' and monthly_price > 0:
            return monthly_price
        else:
            logger.warning(f"⚠️ Unknown billing cycle or invalid pricing: {billing_cycle}, monthly=${monthly_price}, yearly=${yearly_price}")
            return monthly_price if monthly_price > 0 else Decimal('0')
    
    def calculate_next_billing_date(self, current_billing_date: datetime, billing_cycle: str) -> datetime:
        """Calculate the next billing date with comprehensive edge case handling"""
        import calendar
        
        # Ensure timezone consistency from the start (handles both date and datetime objects)
        current_billing_date = self._ensure_timezone_aware_datetime(current_billing_date)
        
        # One-time subscriptions do not renew
        if billing_cycle == 'one_time':
            logger.warning(f"⚠️ One-time subscriptions do not renew - cannot calculate next billing date")
            raise ValueError("One-time subscriptions do not have a next billing date")
        
        # Handle different billing cycles with robust edge case protection
        if billing_cycle == 'yearly':
            try:
                # Try direct year increment
                next_date = current_billing_date.replace(year=current_billing_date.year + 1)
            except ValueError:
                # Handle leap year edge case (Feb 29 -> Feb 28)
                if current_billing_date.month == 2 and current_billing_date.day == 29:
                    next_date = current_billing_date.replace(year=current_billing_date.year + 1, day=28)
                    logger.info(f"📅 Leap year adjustment: Feb 29 → Feb 28 for yearly billing")
                else:
                    # Fallback to safe date calculation
                    next_date = current_billing_date.replace(year=current_billing_date.year + 1, day=1) + timedelta(days=current_billing_date.day - 1)
                    
        elif billing_cycle == 'monthly':
            # Calculate next month and year
            next_month = current_billing_date.month + 1
            next_year = current_billing_date.year
            
            if next_month > 12:
                next_month = 1
                next_year += 1
            
            # Handle month-end edge cases (e.g., Jan 31 → Feb 28/29, May 31 → Jun 30)
            try:
                next_date = current_billing_date.replace(year=next_year, month=next_month)
            except ValueError:
                # Get the last valid day of the target month
                last_day = calendar.monthrange(next_year, next_month)[1]
                safe_day = min(current_billing_date.day, last_day)
                next_date = current_billing_date.replace(year=next_year, month=next_month, day=safe_day)
                
                if safe_day != current_billing_date.day:
                    logger.info(f"📅 Month-end adjustment: Day {current_billing_date.day} → Day {safe_day} for {calendar.month_name[next_month]} {next_year}")
        
        elif billing_cycle == '7days':
            # 7-day billing cycle - simple week increment
            next_date = current_billing_date + timedelta(days=7)
        elif billing_cycle == '30days':
            # 30-day billing cycle - simple month increment
            next_date = current_billing_date + timedelta(days=30)
        else:
            # Unknown billing cycle - default to 30-day increment with warning
            logger.warning(f"⚠️ Unknown billing cycle: '{billing_cycle}', using 30-day increment")
            next_date = current_billing_date + timedelta(days=30)
        
        # Ensure timezone consistency (handles both date and datetime objects)
        next_date = self._ensure_timezone_aware_datetime(next_date)
        
        # Validation: next date must be in the future
        if next_date <= current_billing_date:
            logger.error(f"❌ Invalid billing date calculation: {next_date} <= {current_billing_date}")
            # Emergency fallback: add appropriate time period
            if billing_cycle == 'yearly':
                next_date = current_billing_date + timedelta(days=365)
            elif billing_cycle == '7days':
                next_date = current_billing_date + timedelta(days=7)
            elif billing_cycle == '30days':
                next_date = current_billing_date + timedelta(days=30)
            else:  # monthly or unknown
                next_date = current_billing_date + timedelta(days=30)
            logger.warning(f"🚫 Emergency fallback: Using {next_date} as next billing date")
        
        return next_date
    
    async def _update_subscription_after_successful_renewal(self, subscription_id: int, next_billing_date: datetime) -> bool:
        """Update subscription after successful renewal"""
        try:
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET next_billing_date = %s, 
                    status = 'active',
                    grace_period_started = NULL,
                    last_renewed = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (next_billing_date, subscription_id))
            
            logger.debug(f"📅 Updated subscription {subscription_id}: next billing {next_billing_date.date()}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error updating subscription after renewal: {e}")
            return False
    
    async def _move_subscription_to_grace_period(self, subscription_id: int) -> bool:
        """Move subscription to grace period after payment failure"""
        try:
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET status = 'grace_period',
                    grace_period_started = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (subscription_id,))
            
            logger.info(f"⏰ Moved subscription {subscription_id} to grace period")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error moving subscription to grace period: {e}")
            return False
    
    async def _move_to_grace_and_suspend(self, subscription: Dict) -> Dict[str, Any]:
        """
        Move expired subscription to grace period and suspend cPanel account.
        No automatic wallet charging - user must manually renew.
        """
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        cpanel_username = subscription.get('cpanel_username')
        billing_cycle = subscription.get('billing_cycle', 'monthly')
        
        try:
            # Suspend cPanel account
            cpanel_suspended = False
            if cpanel_username:
                from services.cpanel import CPanelService
                cpanel = CPanelService()
                try:
                    cpanel_suspended = await cpanel.suspend_account(cpanel_username)
                    if cpanel_suspended:
                        logger.info(f"✅ cPanel suspended for expired subscription: {cpanel_username}")
                    else:
                        logger.warning(f"⚠️ Failed to suspend cPanel for: {cpanel_username}")
                except Exception as cpanel_error:
                    logger.error(f"❌ Error suspending cPanel {cpanel_username}: {cpanel_error}")
            
            # Move to grace period with suspension tracking
            grace_period_days = self.get_grace_period_days(billing_cycle)
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET status = 'grace_period',
                    grace_period_started = CURRENT_TIMESTAMP,
                    cpanel_suspension_status = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, ('success' if cpanel_suspended else 'failed', subscription_id))
            
            # Send expiration notification
            await self._send_renewal_notification_with_fallback(
                telegram_id, 'expired', {
                    'domain_name': domain_name,
                    'amount': self._calculate_renewal_cost(subscription),
                    'grace_period_days': grace_period_days
                }
            )
            
            self.stats['grace_period'] += 1
            logger.warning(f"⏰ Subscription expired and suspended: {domain_name} (cPanel: {'✅' if cpanel_suspended else '❌'}, grace period: {grace_period_days} days)")
            
            return {
                'status': 'moved_to_grace',
                'subscription_id': subscription_id,
                'cpanel_suspended': cpanel_suspended,
                'grace_period_days': grace_period_days
            }
            
        except Exception as e:
            logger.error(f"❌ Error moving subscription to grace: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _send_renewal_warning(self, subscription: Dict) -> Dict[str, Any]:
        """Send renewal warning notification to user"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        next_billing_date = subscription['next_billing_date']
        
        try:
            # Send warning notification
            await self.send_renewal_notification(
                telegram_id, 'warning', {
                    'domain_name': domain_name,
                    'next_billing_date': next_billing_date,
                    'days_remaining': (next_billing_date - datetime.now(timezone.utc)).days,
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            # Mark warning as sent
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET last_warning_sent = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (subscription_id,))
            
            self.stats['warnings_sent'] += 1
            logger.info(f"⚠️ Renewal warning sent for {domain_name}")
            
            return {'status': 'warning_sent', 'subscription_id': subscription_id}
            
        except Exception as e:
            logger.error(f"❌ Error sending renewal warning: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _handle_grace_period_warning(self, subscription: Dict) -> Dict[str, Any]:
        """Handle grace period warning (near suspension)"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        grace_period_started = subscription.get('grace_period_started')
        billing_cycle = subscription.get('billing_cycle', 'monthly')
        
        try:
            if grace_period_started is None:
                logger.error(f"❌ Grace period started date is None for subscription {subscription_id}")
                return {'status': 'error', 'subscription_id': subscription_id, 'error': 'Grace period start date not available'}
            
            grace_period_days = self.get_grace_period_days(billing_cycle)
            days_remaining = grace_period_days - (datetime.now(timezone.utc) - grace_period_started).days
            
            await self.send_renewal_notification(
                telegram_id, 'grace_period_warning', {
                    'domain_name': domain_name,
                    'days_remaining': max(0, days_remaining),
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            logger.warning(f"🚨 Grace period warning sent for {domain_name} ({days_remaining} days left)")
            
            return {'status': 'grace_warning_sent', 'subscription_id': subscription_id}
            
        except Exception as e:
            logger.error(f"❌ Error sending grace period warning: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _suspend_expired_subscription(self, subscription: Dict) -> Dict[str, Any]:
        """Suspend subscription after grace period expires"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        cpanel_username = subscription.get('cpanel_username')
        
        try:
            # Actually suspend the cPanel account
            cpanel_suspended = False
            cpanel_suspension_status = 'failed'  # Default to failed
            current_attempts = subscription.get('cpanel_suspension_attempts', 0)
            
            if cpanel_username:
                from services.cpanel import CPanelService
                cpanel = CPanelService()
                try:
                    cpanel_suspended = await cpanel.suspend_account(cpanel_username)
                    if cpanel_suspended:
                        cpanel_suspension_status = 'success'
                        current_attempts = 0  # Reset attempts on success
                        logger.info(f"✅ cPanel suspension SUCCESS: {cpanel_username} for {domain_name}")
                    else:
                        cpanel_suspension_status = 'failed'
                        current_attempts += 1
                        logger.error(f"❌ cPanel suspension FAILED: {cpanel_username} for {domain_name} (attempt {current_attempts})")
                except Exception as cpanel_error:
                    cpanel_suspension_status = 'failed'
                    current_attempts += 1
                    logger.error(f"❌ cPanel suspension ERROR: {cpanel_username} for {domain_name}: {cpanel_error} (attempt {current_attempts})")
            else:
                logger.warning(f"⚠️ No cPanel username found for subscription {subscription_id}")
                cpanel_suspension_status = None  # No username, so no tracking needed
            
            # Calculate deletion schedule (7 days from suspension - 1 week grace to renew)
            suspension_timestamp = datetime.now(timezone.utc)
            deletion_scheduled = suspension_timestamp + timedelta(days=7)
            
            # Update subscription status to suspended WITH timestamps AND cPanel tracking
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET status = 'suspended',
                    suspended_at = %s,
                    deletion_scheduled_for = %s,
                    cpanel_suspension_status = %s,
                    cpanel_suspension_attempts = %s,
                    last_cpanel_sync_attempt = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (suspension_timestamp, deletion_scheduled, cpanel_suspension_status, current_attempts, subscription_id))
            
            # Send suspension notification
            await self.send_renewal_notification(
                telegram_id, 'suspended', {
                    'domain_name': domain_name,
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            self.stats['suspended'] += 1
            logger.warning(f"🚫 Subscription suspended: {domain_name} (grace period expired, cPanel: {'✅' if cpanel_suspended else '❌'}, status: {cpanel_suspension_status}, attempts: {current_attempts}, deletion scheduled: {deletion_scheduled.date()})")
            
            return {'status': 'suspended', 'subscription_id': subscription_id, 'cpanel_suspended': cpanel_suspended}
            
        except Exception as e:
            logger.error(f"❌ Error suspending subscription: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _send_renewal_notification_with_fallback(self, telegram_id: int, status: str, details: Dict[str, Any]) -> bool:
        """
        Send renewal notification with comprehensive fallback logging
        Ensures critical renewal information is always logged even if notification fails
        """
        domain_name = details.get('domain_name', 'unknown')
        amount = details.get('amount', 0)
        
        # CRITICAL: Always log renewal status regardless of notification success
        log_message = f"🔄 RENEWAL {status.upper()}: Domain={domain_name}, User={telegram_id}, Amount=${amount:.2f}"
        if status == 'success':
            next_billing = details.get('next_billing_date')
            log_message += f", NextBilling={next_billing.date() if next_billing else 'unknown'}"
        elif status == 'payment_failed':
            current_balance = details.get('current_balance', 0)
            log_message += f", CurrentBalance=${current_balance:.2f}, Shortfall=${amount - current_balance:.2f}"
        
        logger.info(log_message)
        
        # Try to send notification, but don't fail if bot is unavailable
        notification_sent = await self.send_renewal_notification(telegram_id, status, details)
        
        if not notification_sent:
            # Fallback logging for failed notifications
            logger.warning(f"📱 NOTIFICATION FAILED: {status} notification for user {telegram_id} domain {domain_name}")
            logger.warning(f"📱 USER ACTION REQUIRED: User {telegram_id} may not be aware of renewal status: {status}")
        
        return notification_sent
    
    async def send_renewal_notification(self, telegram_id: int, status: str, details: Dict[str, Any]) -> bool:
        """
        Send renewal status notification to user
        Integrates with existing bot notification system
        """
        try:
            if not self._bot_application:
                logger.warning("⚠️ Bot application not set - cannot send renewal notifications")
                logger.warning(f"📱 MISSED NOTIFICATION: User {telegram_id} renewal {status} - bot unavailable")
                return False
            
            # Get user language preference
            user_result = await execute_query(
                "SELECT preferred_language FROM users WHERE telegram_id = %s",
                (telegram_id,)
            )
            lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
            
            domain_name = details.get('domain_name', 'your hosting')
            
            # Generate appropriate message based on status using translations
            if status == 'success':
                amount = details.get('amount', 0)
                next_billing = details.get('next_billing_date')
                billing_cycle = details.get('billing_cycle', 'monthly')
                
                title = t('notifications.renewal.hosting_success_title', lang)
                body = t('notifications.renewal.hosting_success', lang,
                        title=format_bold(title),
                        domain=format_inline_code(domain_name),
                        amount=format_bold(format_money(amount)),
                        next_billing=format_inline_code(next_billing.date().strftime('%Y-%m-%d') if next_billing else 'N/A'),
                        billing_cycle=format_inline_code(billing_cycle.title()))
                message = create_success_message(body)
                
            elif status == 'warning':
                days_remaining = details.get('days_remaining', 0)
                amount = details.get('amount', 0)
                next_billing = details.get('next_billing_date')
                
                title = t('notifications.renewal.hosting_warning_title', lang)
                message = t('notifications.renewal.hosting_warning', lang,
                           title=format_bold(title),
                           domain=format_inline_code(domain_name),
                           days_remaining=format_bold(f'{days_remaining} days'),
                           renewal_date=format_inline_code(next_billing.date().strftime('%Y-%m-%d') if next_billing else 'N/A'),
                           amount=format_bold(format_money(amount)))
                
            elif status == 'payment_failed':
                amount = details.get('amount', 0)
                current_balance = details.get('current_balance', 0)
                grace_days = details.get('grace_period_days', 7)
                shortfall = amount - current_balance
                
                title = t('notifications.renewal.hosting_failed_title', lang)
                body = t('notifications.renewal.hosting_failed', lang,
                        title=format_bold(title),
                        domain=format_inline_code(domain_name),
                        amount=format_bold(format_money(amount)),
                        current_balance=format_bold(format_money(current_balance)),
                        shortfall=format_bold(format_money(shortfall)),
                        grace_days=format_bold(f'{grace_days}-day grace period'))
                message = create_error_message(body)
                
            elif status == 'grace_period_warning':
                days_remaining = details.get('days_remaining', 0)
                amount = details.get('amount', 0)
                
                title = t('notifications.renewal.hosting_grace_warning_title', lang)
                message = t('notifications.renewal.hosting_grace_warning', lang,
                           title=format_bold(title),
                           domain=format_inline_code(domain_name),
                           days_remaining=format_bold(f'{days_remaining} days'),
                           amount=format_bold(format_money(amount)))
                
            elif status == 'suspended':
                amount = details.get('amount', 0)
                
                title = t('notifications.renewal.hosting_suspended_title', lang)
                body = t('notifications.renewal.hosting_suspended', lang,
                        title=format_bold(title),
                        domain=format_inline_code(domain_name),
                        amount=format_bold(format_money(amount)))
                # Add 7-day deletion warning
                deletion_warning = f"\n\n⚠️ Your account will be automatically deleted in 7 days if not renewed. You can still renew to restore service."
                message = create_error_message(body + deletion_warning)
                
            elif status == 'deleted':
                title = "🗑️ Hosting Account Deleted"
                body = f"{format_bold(title)}\n\nYour hosting for {format_inline_code(domain_name)} has been permanently deleted after the 7-day grace period expired.\n\nTo restore hosting, please create a new subscription."
                message = create_error_message(body)
                
            else:
                logger.warning(f"⚠️ Unknown renewal notification status: {status}")
                return False
            
            # Send the message using bot application
            await self._bot_application.bot.send_message(
                chat_id=telegram_id,
                text=message,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
            logger.debug(f"📱 Renewal notification sent to user {telegram_id}: {status} (lang: {lang})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error sending renewal notification to {telegram_id}: {e}")
            return False
    
    def _reset_stats(self):
        """Reset processing statistics"""
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        return self.stats.copy()
    
    async def process_manual_renewal(self, subscription_id: int, user_id: int) -> Dict[str, Any]:
        """
        Manually process renewal for a specific subscription
        Used for admin operations or user-triggered renewals
        """
        try:
            # Get subscription details
            subscription = await get_hosting_subscription_details(subscription_id, user_id)
            if not subscription:
                return {'status': 'error', 'reason': 'Subscription not found'}
            
            # Add user details for processing
            user_query = await execute_query(
                "SELECT telegram_id, wallet_balance, username, first_name FROM users WHERE id = %s",
                (user_id,)
            )
            if user_query:
                subscription.update(user_query[0])
            
            logger.info(f"🔧 Manual renewal requested for subscription {subscription_id}")
            
            # Process the renewal
            result = await self.process_subscription_renewal(subscription)
            
            # Log manual renewal attempt
            if result['status'] == 'success':
                logger.info(f"✅ Manual renewal successful for subscription {subscription_id}")
            else:
                logger.warning(f"⚠️ Manual renewal failed for subscription {subscription_id}: {result.get('reason', 'unknown')}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error in manual renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'reason': str(e)}

    async def process_scheduled_deletions(self) -> Dict[str, Any]:
        """
        Process hosting subscriptions scheduled for automatic deletion.
        Deletes cPanel accounts 7 days after suspension if not renewed.
        Users can still renew during this 7-day window before deletion.
        """
        try:
            now = datetime.now(timezone.utc)
            
            # Find suspended subscriptions past their deletion deadline
            query = """
                SELECT hs.id, hs.domain_name, hs.cpanel_username, hs.user_id,
                       hs.deletion_scheduled_for, hs.suspended_at,
                       u.telegram_id
                FROM hosting_subscriptions hs
                JOIN users u ON hs.user_id = u.id
                WHERE hs.status = 'suspended'
                  AND hs.deletion_scheduled_for IS NOT NULL
                  AND hs.deletion_scheduled_for <= %s
                ORDER BY hs.deletion_scheduled_for ASC
            """
            
            subscriptions_to_delete = await execute_query(query, (now,))
            
            if not subscriptions_to_delete:
                logger.debug("✅ No hosting subscriptions scheduled for deletion")
                return {"status": "success", "deleted": 0}
            
            logger.info(f"🗑️ Processing {len(subscriptions_to_delete)} subscriptions for auto-deletion")
            
            deleted_count = 0
            failed_count = 0
            
            for subscription in subscriptions_to_delete:
                try:
                    result = await self._delete_hosting_subscription(subscription)
                    if result.get('success'):
                        deleted_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"❌ Error deleting subscription {subscription['id']}: {e}")
                    failed_count += 1
            
            logger.info(f"🗑️ Deletion processing complete: {deleted_count} deleted, {failed_count} failed")
            
            return {
                "status": "success",
                "deleted": deleted_count,
                "failed": failed_count,
                "total_processed": len(subscriptions_to_delete)
            }
            
        except Exception as e:
            logger.error(f"❌ Error processing scheduled deletions: {e}")
            return {"status": "error", "error": str(e)}

    async def _delete_hosting_subscription(self, subscription: Dict) -> Dict[str, Any]:
        """
        Delete a hosting subscription and its cPanel account.
        Called after the 7-day post-suspension grace period expires.
        """
        subscription_id = subscription['id']
        domain_name = subscription['domain_name']
        cpanel_username = subscription.get('cpanel_username')
        telegram_id = subscription.get('telegram_id')
        
        logger.warning(f"🗑️ Auto-deleting subscription {subscription_id}: {domain_name} (cPanel: {cpanel_username})")
        
        cpanel_deleted = False
        
        # Delete the cPanel account if it exists
        if cpanel_username:
            try:
                from services.cpanel import CPanelService
                cpanel = CPanelService()
                cpanel_deleted = await cpanel.terminate_account(cpanel_username)
                if cpanel_deleted:
                    logger.info(f"✅ cPanel account terminated: {cpanel_username}")
                else:
                    logger.warning(f"⚠️ cPanel termination returned False: {cpanel_username}")
            except Exception as e:
                logger.error(f"❌ cPanel termination error for {cpanel_username}: {e}")
        
        # Update subscription status to deleted
        await execute_update("""
            UPDATE hosting_subscriptions 
            SET status = 'deleted',
                deleted_at = CURRENT_TIMESTAMP,
                deleted_by = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (subscription_id,))
        
        # Update cPanel account record if exists
        await execute_update("""
            UPDATE cpanel_accounts
            SET status = 'terminated',
                deleted_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE subscription_id = %s
        """, (subscription_id,))
        
        # Send deletion notification to user
        if telegram_id:
            await self.send_renewal_notification(
                telegram_id, 'deleted', {
                    'domain_name': domain_name
                }
            )
        
        logger.warning(f"🗑️ Subscription {subscription_id} deleted: {domain_name} (cPanel terminated: {'✅' if cpanel_deleted else '❌'})")
        
        return {'success': True, 'subscription_id': subscription_id, 'cpanel_deleted': cpanel_deleted}


class RDPRenewalProcessor:
    """
    RDP Server Renewal Processor with automated wallet-based billing
    Handles RDP server renewals, grace periods, and suspensions
    """
    
    def __init__(self):
        self.warning_days_before = 3
        self.grace_period_hours = 72  # 72-hour grace period before suspension
        self.processing_enabled = True
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
        self._bot_application = None
        logger.info(f"🔄 RDPRenewalProcessor initialized: grace_period={self.grace_period_hours}h, warning={self.warning_days_before}d")
    
    def set_bot_application(self, bot_application):
        """Set bot application reference for sending notifications"""
        self._bot_application = bot_application
        logger.info("🤖 Bot application reference set for RDP renewal notifications")
    
    async def process_all_rdp_renewals(self) -> Dict[str, Any]:
        """Main entry point for processing all RDP server renewals"""
        if not self.processing_enabled:
            return {"status": "disabled", "reason": "Processing disabled"}
        
        try:
            safety_check = verify_financial_operation_safety("rdp_renewal_processing")
            if not safety_check:
                logger.error("🚫 RDP RENEWAL BLOCKED: Financial operations not allowed")
                return {"status": "blocked", "reason": "Financial operations blocked"}
            
            logger.info("🔄 Starting automated RDP server renewal processing...")
            self._reset_stats()
            
            # Get servers due for renewal
            servers_to_process = await self._get_servers_for_renewal()
            
            if not servers_to_process:
                logger.info("✅ No RDP servers require renewal processing")
                return {"status": "success", "message": "No renewals needed", "stats": self.stats}
            
            logger.info(f"📊 Found {len(servers_to_process)} RDP servers requiring renewal processing")
            
            # Process renewals
            for server in servers_to_process:
                await self._process_server_renewal(server)
                await asyncio.sleep(1)  # Small delay between processings
            
            final_stats = self.stats.copy()
            success_rate = (final_stats['successful'] / final_stats['processed'] * 100) if final_stats['processed'] > 0 else 0
            
            logger.info(f"✅ RDP renewal processing completed: {final_stats['successful']}/{final_stats['processed']} successful ({success_rate:.1f}%)")
            
            return {
                "status": "success",
                "stats": final_stats,
                "success_rate": success_rate
            }
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Critical error in RDP renewal processing: {e}")
            return {"status": "error", "error": str(e), "stats": self.stats}
    
    async def _get_servers_for_renewal(self) -> List[Dict]:
        """Get all RDP servers that need renewal processing"""
        try:
            now = datetime.now(timezone.utc)
            warning_threshold = now + timedelta(days=self.warning_days_before)
            grace_cutoff = now - timedelta(hours=self.grace_period_hours)
            
            query = """
                SELECT rs.*, rp.plan_name, rp.our_monthly_price,
                       rt.windows_version, rt.edition,
                       u.telegram_id, u.wallet_balance, u.username, u.first_name
                FROM rdp_servers rs
                JOIN rdp_plans rp ON rs.plan_id = rp.id
                JOIN rdp_templates rt ON rs.template_id = rt.id
                JOIN users u ON rs.user_id = u.id
                WHERE rs.deleted_at IS NULL
                  AND rs.auto_renew = true
                  AND rs.status IN ('active', 'grace_period')
                  AND (
                    rs.next_renewal_date <= %s  -- Due for renewal
                    OR (rs.next_renewal_date <= %s AND rs.status = 'active')  -- Warning needed
                  )
                ORDER BY rs.next_renewal_date ASC
            """
            
            servers = await execute_query(query, (now, warning_threshold))
            return servers if servers else []
            
        except Exception as e:
            logger.error(f"❌ Error fetching RDP servers for renewal: {e}")
            return []
    
    async def _process_server_renewal(self, server: Dict) -> Dict[str, Any]:
        """Process renewal for a single RDP server"""
        self.stats['processed'] += 1
        server_id = server['id']
        user_id = server['user_id']
        
        try:
            now = datetime.now(timezone.utc)
            next_renewal = server['next_renewal_date']
            if isinstance(next_renewal, date_type) and not isinstance(next_renewal, datetime):
                next_renewal = datetime.combine(next_renewal, datetime.min.time(), tzinfo=timezone.utc)
            elif isinstance(next_renewal, datetime) and next_renewal.tzinfo is None:
                next_renewal = next_renewal.replace(tzinfo=timezone.utc)
            
            # Calculate billing amount based on cycle
            monthly_price = Decimal(str(server['our_monthly_price']))
            billing_cycle = server['billing_cycle']
            
            if billing_cycle == 'monthly':
                renewal_amount = monthly_price
                period_months = 1
            elif billing_cycle == 'quarterly':
                renewal_amount = monthly_price * 3 * Decimal('0.94')
                period_months = 3
            elif billing_cycle == 'yearly':
                renewal_amount = monthly_price * 12 * Decimal('0.89')
                period_months = 12
            else:
                renewal_amount = monthly_price
                period_months = 1
            
            # Check if renewal is due
            if now < next_renewal:
                # Send warning notification
                days_until = (next_renewal - now).days
                if days_until <= self.warning_days_before:
                    await self._send_rdp_renewal_notification(
                        server['telegram_id'],
                        server,
                        'warning',
                        renewal_amount,
                        days_until
                    )
                    self.stats['warnings_sent'] += 1
                return {'status': 'warning_sent', 'server_id': server_id}
            
            # Renewal is due - attempt payment
            wallet_balance = Decimal(str(server['wallet_balance']))
            
            if wallet_balance >= renewal_amount:
                # Process payment
                payment_success = await debit_wallet_balance(
                    user_id,
                    renewal_amount,
                    reference_type='rdp_renewal',
                    reference_id=server_id,
                    description=f"RDP Server renewal - {server['hostname']}"
                )
                
                if payment_success:
                    # Update next renewal date
                    new_renewal_date = next_renewal + timedelta(days=period_months * 30)
                    
                    await execute_update("""
                        UPDATE rdp_servers
                        SET next_renewal_date = %s,
                            status = 'active',
                            last_renewed_at = NOW()
                        WHERE id = %s
                    """, (new_renewal_date, server_id))
                    
                    # Create renewal order
                    from database import create_order_with_uuid
                    order_uuid = await create_order_with_uuid(
                        user_id=user_id,
                        order_type='rdp_renewal',
                        total_amount=renewal_amount,
                        currency='USD',
                        metadata={'server_id': server_id, 'billing_cycle': billing_cycle}
                    )
                    
                    order = await execute_query("SELECT id FROM orders WHERE uuid_id = %s", (order_uuid,))
                    if order:
                        order_id = order[0]['id']
                        await execute_update("""
                            UPDATE orders SET status = 'completed', completed_at = NOW() WHERE id = %s
                        """, (order_id,))
                        
                        # Get current renewal number
                        renewal_count = await execute_query("""
                            SELECT COUNT(*) as count FROM rdp_orders WHERE rdp_server_id = %s
                        """, (server_id,))
                        renewal_number = renewal_count[0]['count'] if renewal_count else 0
                        
                        # Link order
                        await execute_update("""
                            INSERT INTO rdp_orders (order_id, rdp_server_id, renewal_number)
                            VALUES (%s, %s, %s)
                        """, (order_id, server_id, renewal_number))
                    
                    # Send success notification
                    await self._send_rdp_renewal_notification(
                        server['telegram_id'],
                        server,
                        'success',
                        renewal_amount,
                        0
                    )
                    
                    self.stats['successful'] += 1
                    logger.info(f"✅ RDP server {server_id} renewed successfully for ${float(renewal_amount):.2f}")
                    return {'status': 'success', 'server_id': server_id}
                else:
                    raise Exception("Payment processing failed")
            else:
                # Insufficient funds - enter grace period
                hours_overdue = (now - next_renewal).total_seconds() / 3600
                
                if hours_overdue < self.grace_period_hours:
                    # Still in grace period
                    await execute_update("""
                        UPDATE rdp_servers
                        SET status = 'grace_period'
                        WHERE id = %s
                    """, (server_id,))
                    
                    await self._send_rdp_renewal_notification(
                        server['telegram_id'],
                        server,
                        'grace_period',
                        renewal_amount,
                        int(self.grace_period_hours - hours_overdue)
                    )
                    
                    self.stats['grace_period'] += 1
                    logger.warning(f"⚠️ RDP server {server_id} in grace period: {hours_overdue:.1f}h overdue")
                    return {'status': 'grace_period', 'server_id': server_id}
                else:
                    # Grace period expired - DELETE IMMEDIATELY from Vultr to stop all charges
                    from services.vultr import vultr_service
                    
                    vultr_deleted = False
                    if server['vultr_instance_id']:
                        try:
                            vultr_deleted = vultr_service.delete_instance(server['vultr_instance_id'])
                            if vultr_deleted:
                                logger.info(f"✅ Vultr instance deleted: {server['vultr_instance_id']}")
                            else:
                                logger.error(f"❌ Failed to delete Vultr instance: {server['vultr_instance_id']}")
                        except Exception as vultr_error:
                            logger.error(f"❌ Error deleting Vultr instance {server['vultr_instance_id']}: {vultr_error}")
                    
                    # Mark server as deleted in database (immediate deletion, no suspension period)
                    await execute_update("""
                        UPDATE rdp_servers
                        SET status = 'deleted',
                            power_status = 'stopped',
                            auto_renew = false,
                            suspended_at = %s,
                            deleted_at = %s
                        WHERE id = %s
                    """, (now, now, server_id))
                    
                    # Send deletion notification (immediate, no recovery period)
                    await self._send_rdp_renewal_notification(
                        server['telegram_id'],
                        server,
                        'deleted',
                        renewal_amount,
                        0,
                        vultr_deleted=vultr_deleted
                    )
                    
                    self.stats['suspended'] += 1
                    logger.warning(f"🗑️ RDP server {server_id} DELETED immediately due to non-payment (Vultr: {'✅' if vultr_deleted else '❌'})")
                    return {'status': 'deleted', 'server_id': server_id, 'vultr_deleted': vultr_deleted}
        
        except Exception as e:
            self.stats['failed'] += 1
            logger.error(f"❌ Error processing RDP renewal for server {server_id}: {e}")
            return {'status': 'error', 'server_id': server_id, 'error': str(e)}
    
    async def _send_rdp_renewal_notification(self, telegram_id: int, server: Dict, status: str, amount: Decimal, time_value: int, vultr_deleted: bool = False) -> bool:
        """Send renewal notification to user"""
        if not self._bot_application:
            logger.warning("⚠️ Cannot send RDP renewal notification: bot not initialized")
            return False
        
        try:
            # Get user language preference
            user_result = await execute_query(
                "SELECT preferred_language FROM users WHERE telegram_id = %s",
                (telegram_id,)
            )
            lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
            
            hostname = server['hostname']
            plan_name = server['plan_name']
            
            if status == 'warning':
                message = t('notifications.renewal.rdp_warning', lang,
                           hostname=hostname,
                           plan_name=plan_name,
                           days=time_value,
                           amount=f"{float(amount):.2f}")
            elif status == 'success':
                message = t('notifications.renewal.rdp_success', lang,
                           hostname=hostname,
                           plan_name=plan_name,
                           amount=f"{float(amount):.2f}",
                           billing_cycle=server['billing_cycle'])
            elif status == 'grace_period':
                message = t('notifications.renewal.rdp_grace', lang,
                           hostname=hostname,
                           plan_name=plan_name,
                           amount=f"{float(amount):.2f}",
                           hours=time_value)
            elif status == 'deleted':
                # Immediate deletion notification
                from datetime import datetime, timezone
                vultr_status = "✅ Removed" if vultr_deleted else "⚠️ Manual cleanup may be required"
                
                message = f"""
🗑️ <b>RDP Server Deleted</b>

Your RDP server <code>{hostname}</code> has been permanently deleted due to non-payment.

📦 <b>Plan:</b> {plan_name}
💰 <b>Amount Due:</b> ${float(amount):.2f}
📅 <b>Deleted:</b> {datetime.now(timezone.utc).strftime('%B %d, %Y')}
☁️ <b>Vultr Status:</b> {vultr_status}

⚠️ <b>All server data has been permanently removed.</b>

💡 You can purchase a new RDP server anytime at /dashboard → 🖥️ RDP Servers
"""
            else:
                return False
            
            await self._bot_application.bot.send_message(
                chat_id=telegram_id,
                text=message,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
            logger.debug(f"📱 RDP renewal notification sent to user {telegram_id}: {status} (lang: {lang})")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error sending RDP renewal notification to {telegram_id}: {e}")
            return False
    
    def _reset_stats(self):
        """Reset processing statistics"""
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        return self.stats.copy()

# Create global instances
renewal_processor = HostingRenewalProcessor()
rdp_renewal_processor = RDPRenewalProcessor()

# Convenience functions for external usage
async def process_all_hosting_renewals() -> Dict[str, Any]:
    """Process all hosting renewals - main entry point for scheduler"""
    return await renewal_processor.process_all_renewals()

async def process_all_rdp_renewals() -> Dict[str, Any]:
    """Process all RDP server renewals - main entry point for scheduler"""
    return await rdp_renewal_processor.process_all_rdp_renewals()

async def process_manual_hosting_renewal(subscription_id: int, user_id: int) -> Dict[str, Any]:
    """Process manual renewal for specific subscription"""
    return await renewal_processor.process_manual_renewal(subscription_id, user_id)

def set_renewal_bot_application(bot_application):
    """Set bot application reference for notifications"""
    renewal_processor.set_bot_application(bot_application)
    rdp_renewal_processor.set_bot_application(bot_application)

def get_renewal_processor_stats() -> Dict[str, Any]:
    """Get current renewal processor statistics"""
    return renewal_processor.get_stats()

def get_rdp_renewal_processor_stats() -> Dict[str, Any]:
    """Get current RDP renewal processor statistics"""
    return rdp_renewal_processor.get_stats()
