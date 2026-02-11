#!/usr/bin/env python3
"""
Promotional Broadcast Service for HostBay Telegram Bot

Timezone-aware promotional messages sent 3x daily per user's local time.
Runs hourly via APScheduler, selects users whose local time matches the target hour.

Schedule (in user's local time):
  - 10:00 AM → Offshore DMCA-ignored domains
  - 15:00 PM → Offshore cPanel hosting  
  - 20:00 PM → URL shortener + @nomadlybot

Features:
  - Respects user's preferred_language (en/es/fr)
  - Respects timezone_offset for local-time delivery
  - Respects promo_opted_out flag (/stop_promos)
  - @nomadlybot cross-promotion footer on every message
"""

import asyncio
import logging
from typing import Dict, Any, List

from database import execute_query, queue_user_notification_by_user_id, get_promo_eligible_users_for_hour
from localization import t

logger = logging.getLogger(__name__)

# Local-time hours for each promo theme
PROMO_SLOTS = {
    10: "offshore_domains",   # 10 AM local
    15: "offshore_hosting",   # 3 PM local
    20: "url_shortener",      # 8 PM local
}


def build_promo_message(theme: str, lang: str) -> str:
    """Build a fully localized promo message with @nomadlybot footer."""
    title = t(f'promo.{theme}.title', lang)
    body = t(f'promo.{theme}.body', lang)
    cta = t(f'promo.{theme}.cta', lang)
    footer = t('promo.common.footer', lang)
    opt_out_hint = t('promo.common.opt_out_hint', lang)

    return f"{title}\n\n{body}\n\n{cta}\n\n{footer}\n{opt_out_hint}"


async def run_hourly_promo_check():
    """
    Hourly job: Determine which promo themes match the current local hour
    for each user (based on their timezone_offset) and send accordingly.
    
    This runs once per hour. For each of the 3 promo slots (10, 15, 20),
    it queries users whose local time IS that hour right now.
    """
    logger.info("📢 PROMO HOURLY CHECK: Starting timezone-aware promo dispatch")
    
    total_stats = {"sent": 0, "failed": 0, "skipped": 0}
    
    for target_hour, theme in PROMO_SLOTS.items():
        try:
            users = await get_promo_eligible_users_for_hour(target_hour)
            
            if not users:
                continue
            
            logger.info(f"📢 PROMO: Sending '{theme}' to {len(users)} users (local hour = {target_hour}:00)")
            
            batch_size = 25
            for i in range(0, len(users), batch_size):
                batch = users[i:i + batch_size]
                
                for user in batch:
                    user_id = user['id']
                    lang = user.get('preferred_language') or 'en'
                    
                    try:
                        message = build_promo_message(theme, lang)
                        success = await queue_user_notification_by_user_id(user_id, message, 'HTML')
                        
                        if success:
                            total_stats["sent"] += 1
                        else:
                            total_stats["failed"] += 1
                    except Exception as e:
                        logger.warning(f"📢 PROMO: Failed for user {user_id}: {e}")
                        total_stats["failed"] += 1
                
                # Rate limiting between batches
                if i + batch_size < len(users):
                    await asyncio.sleep(1.0)
                    
        except Exception as e:
            logger.error(f"📢 PROMO ERROR: Theme '{theme}' failed: {e}")
    
    if total_stats["sent"] > 0 or total_stats["failed"] > 0:
        logger.info(
            f"📢 PROMO HOURLY COMPLETE: Sent={total_stats['sent']}, "
            f"Failed={total_stats['failed']}"
        )


async def send_test_promo(theme: str, user_id: int, lang: str = 'en') -> bool:
    """Send a single test promo to a specific user (admin testing)."""
    try:
        message = build_promo_message(theme, lang)
        return await queue_user_notification_by_user_id(user_id, message, 'HTML')
    except Exception as e:
        logger.error(f"Test promo failed: {e}")
        return False
