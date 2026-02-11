#!/usr/bin/env python3
"""
Payment Expiration Notification System
Handles user notifications for expired payment addresses via Telegram
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict
from database import queue_user_notification_by_user_id, execute_query
from localization import t, resolve_user_language

logger = logging.getLogger(__name__)

async def send_expiration_notifications(expired_payments: List[Dict[str, Any]]) -> int:
    """
    Send user notifications for expired payments via Telegram
    Groups expired payments by user_id and sends one consolidated notification per user
    
    Args:
        expired_payments: List of payment dictionaries with user_id, amount, crypto_currency, order_id
        
    Returns:
        Number of notifications successfully sent
    """
    notifications_sent = 0
    
    if not expired_payments:
        logger.debug("📢 NOTIFICATIONS: No expired payments to notify")
        return 0
    
    logger.info(f"📢 NOTIFICATIONS: Processing {len(expired_payments)} expired payments")
    
    # Group expired payments by user_id to consolidate notifications
    user_payments = defaultdict(list)
    for payment in expired_payments:
        user_id = payment.get('user_id')
        if user_id:
            user_payments[user_id].append(payment)
        else:
            logger.warning(f"⚠️ NOTIFICATION: Cannot notify - no user_id for payment {payment.get('id', 'unknown')}")
    
    logger.info(f"📢 NOTIFICATIONS: Sending consolidated notifications to {len(user_payments)} users")
    
    # Send one consolidated notification per user
    for user_id, payments in user_payments.items():
        try:
            # Get user language preference
            user_result = await execute_query(
                "SELECT preferred_language FROM users WHERE id = %s",
                (user_id,)
            )
            lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
            
            payment_count = len(payments)
            # Defensive: Handle NULL/None amounts properly
            total_amount = sum(float(p.get('amount') or 0) for p in payments if p.get('amount') is not None)
            
            # Skip $0 amount payments - these are data integrity issues, not real expired payments
            if total_amount == 0:
                logger.warning(f"⚠️ NOTIFICATION: Skipping $0 payment notification for user {user_id}")
                logger.warning(f"   Payment IDs: {[p.get('id') for p in payments]}")
                logger.warning(f"   These are likely data integrity issues from failed webhook processing")
                continue
            
            # Create compact mobile-friendly message using translations
            if payment_count == 1:
                # Single payment
                payment = payments[0]
                crypto_currency = payment.get('crypto_currency', 'crypto').upper()
                
                # Use base_amount (original user-intended amount) if available,
                # otherwise fall back to subtracting $2 crypto padding
                if payment.get('base_amount') is not None:
                    amount = float(payment.get('base_amount'))
                else:
                    amount = float(payment.get('amount') or 0)
                    CRYPTO_PADDING = 2.0
                    stablecoins = ('USDT', 'USDT_TRC20', 'USDT_ERC20')
                    if crypto_currency and crypto_currency.upper() not in stablecoins and amount > CRYPTO_PADDING:
                        amount = amount - CRYPTO_PADDING
                
                title = t('notifications.payment.expired_single_title', lang)
                body = t('notifications.payment.expired_single_body', lang,
                        amount=f"{amount:.2f}",
                        crypto_currency=crypto_currency)
                message = f"{title}\n\n{body}"
            else:
                # Multiple payments - use base_amount when available
                adjusted_total = 0.0
                for p in payments:
                    if p.get('base_amount') is not None:
                        p_amount = float(p.get('base_amount'))
                    else:
                        p_amount = float(p.get('amount') or 0)
                        CRYPTO_PADDING = 2.0
                        stablecoins = ('USDT', 'USDT_TRC20', 'USDT_ERC20')
                        p_crypto = (p.get('crypto_currency') or '').upper()
                        if p_crypto and p_crypto not in stablecoins and p_amount > CRYPTO_PADDING:
                            p_amount = p_amount - CRYPTO_PADDING
                    adjusted_total += p_amount
                
                title = t('notifications.payment.expired_multiple_title', lang, count=payment_count)
                body = t('notifications.payment.expired_multiple_body', lang,
                        total=f"{adjusted_total:.2f}",
                        count=payment_count)
                message = f"{title}\n\n{body}"
            
            # Queue notification using bot-independent method
            success = await queue_user_notification_by_user_id(user_id, message, 'HTML')
            
            if success:
                notifications_sent += 1
                logger.info(f"📢 NOTIFICATION: Sent consolidated expiration notice to user {user_id} for {payment_count} payment(s) totaling ${total_amount:.2f} (lang: {lang})")
            else:
                logger.warning(f"⚠️ NOTIFICATION: Failed to queue consolidated expiration notice for user {user_id}")
                
        except Exception as e:
            logger.error(f"❌ NOTIFICATION: Error sending consolidated expiration notice for user {user_id}: {e}")
            logger.error(f"   User payments data: {payments}")
    
    if notifications_sent > 0:
        logger.info(f"✅ NOTIFICATIONS: Successfully sent {notifications_sent} consolidated notifications for {len(expired_payments)} expired payments")
    else:
        logger.warning(f"⚠️ NOTIFICATIONS: Failed to send any consolidated notifications for {len(expired_payments)} expired payments")
    
    return notifications_sent

async def send_payment_timeout_warning(user_id: int, payment_info: Dict[str, Any], minutes_until_expiry: int) -> bool:
    """
    Send early warning notification before payment expires
    
    Args:
        user_id: Database user ID
        payment_info: Payment information dictionary
        minutes_until_expiry: Minutes remaining until expiration
        
    Returns:
        True if notification was sent successfully
    """
    try:
        # Get user language preference
        user_result = await execute_query(
            "SELECT preferred_language FROM users WHERE id = %s",
            (user_id,)
        )
        lang = user_result[0]['preferred_language'] if (user_result and user_result[0].get('preferred_language')) else 'en'
        
        crypto_currency = payment_info.get('crypto_currency', 'cryptocurrency').upper()
        order_id = payment_info.get('order_id', 'unknown')
        
        # Use base_amount (original user-intended amount) if available,
        # otherwise fall back to subtracting $2 crypto padding
        if payment_info.get('base_amount') is not None:
            amount = float(payment_info.get('base_amount'))
        else:
            amount = float(payment_info.get('amount', 0))
            CRYPTO_PADDING = 2.0
            stablecoins = ('USDT', 'USDT_TRC20', 'USDT_ERC20')
            if crypto_currency and crypto_currency.upper() not in stablecoins and amount > CRYPTO_PADDING:
                amount = amount - CRYPTO_PADDING
        
        # Build translated message
        title = t('notifications.payment.expiring_soon_title', lang)
        body = t('notifications.payment.expiring_soon_body', lang,
                 crypto_currency=crypto_currency,
                 minutes=minutes_until_expiry,
                 amount=f"{amount:.2f}",
                 order_id=order_id)
        
        message = f"{title}\n\n{body}"
        
        success = await queue_user_notification_by_user_id(user_id, message, 'HTML')
        
        if success:
            logger.info(f"⏰ WARNING: Sent timeout warning to user {user_id} for payment expiring in {minutes_until_expiry}min (lang: {lang})")
        else:
            logger.warning(f"⚠️ WARNING: Failed to send timeout warning to user {user_id}")
            
        return success
        
    except Exception as e:
        logger.error(f"❌ WARNING: Error sending timeout warning to user {user_id}: {e}")
        return False