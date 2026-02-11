#!/usr/bin/env python3
"""
Promotional Broadcast Service for HostBay Telegram Bot

Sends 3 daily promotional messages to all bot users, localized to their preferred language.
Messages focus on:
  - Offshore DMCA-ignored domains (country-level TLDs)
  - Offshore cPanel hosting
  - @nomadlybot for custom URL shortener, Bitly alternative, and domain registration

Schedule: 3x daily (morning, afternoon, evening UTC)
"""

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from database import execute_query, queue_user_notification_by_user_id
from localization import t

logger = logging.getLogger(__name__)

# ============================================================================
# PROMOTIONAL MESSAGE SETS
# Each set contains a unique theme. 3 sets rotate across 3 daily time slots.
# Messages are keyed by locale path and rendered via the localization system.
# ============================================================================

# Time slots (UTC): Morning=9:00, Afternoon=15:00, Evening=21:00
PROMO_SCHEDULE = [
    {"slot": "morning",   "hour": 9,  "minute": 0},
    {"slot": "afternoon", "hour": 15, "minute": 0},
    {"slot": "evening",   "hour": 21, "minute": 0},
]

# 3 promo themes rotating across the 3 daily slots
PROMO_THEMES = ["offshore_domains", "offshore_hosting", "url_shortener"]


def _get_promo_message(theme: str, lang: str) -> str:
    """Build a fully localized promotional message for the given theme."""
    title = t(f'promo.{theme}.title', lang)
    body = t(f'promo.{theme}.body', lang)
    cta = t(f'promo.{theme}.cta', lang)
    footer = t('promo.common.footer', lang)

    # Use inline graphics via Unicode box-drawing + emoji for visual appeal
    message = f"{title}\n\n{body}\n\n{cta}\n\n{footer}"
    return message


async def get_broadcast_recipients() -> List[Dict[str, Any]]:
    """Get all users who accepted terms with their language preferences."""
    users = await execute_query(
        """SELECT id, telegram_id, preferred_language, first_name 
           FROM users 
           WHERE terms_accepted = true 
           AND deleted_at IS NULL
           ORDER BY id"""
    )
    return users or []


async def send_promotional_broadcast(theme: str) -> Dict[str, int]:
    """
    Send a promotional message to all bot users, respecting their language preference.
    
    Args:
        theme: One of 'offshore_domains', 'offshore_hosting', 'url_shortener'
    
    Returns:
        Dict with 'sent', 'failed', 'total' counts
    """
    logger.info(f"📢 PROMO BROADCAST: Starting '{theme}' promotional broadcast")
    
    stats = {"sent": 0, "failed": 0, "total": 0, "skipped": 0}
    
    try:
        users = await get_broadcast_recipients()
        stats["total"] = len(users)
        
        if not users:
            logger.warning("📢 PROMO BROADCAST: No eligible recipients found")
            return stats
        
        logger.info(f"📢 PROMO BROADCAST: Sending '{theme}' to {len(users)} users")
        
        # Process in batches for Telegram rate limiting
        batch_size = 25
        
        for i in range(0, len(users), batch_size):
            batch = users[i:i + batch_size]
            
            for user in batch:
                user_id = user['id']
                lang = user.get('preferred_language') or 'en'
                
                try:
                    message = _get_promo_message(theme, lang)
                    
                    success = await queue_user_notification_by_user_id(
                        user_id, message, 'HTML'
                    )
                    
                    if success:
                        stats["sent"] += 1
                    else:
                        stats["failed"] += 1
                        
                except Exception as user_error:
                    logger.warning(f"📢 PROMO: Failed to queue promo for user {user_id}: {user_error}")
                    stats["failed"] += 1
            
            # Rate limiting pause between batches
            if i + batch_size < len(users):
                await asyncio.sleep(1.0)
        
        logger.info(
            f"📢 PROMO BROADCAST COMPLETE: '{theme}' - "
            f"Sent: {stats['sent']}, Failed: {stats['failed']}, Total: {stats['total']}"
        )
        
    except Exception as e:
        logger.error(f"📢 PROMO BROADCAST ERROR: Failed to send '{theme}' broadcast: {e}")
    
    return stats


# ============================================================================
# SCHEDULED JOB ENTRY POINTS (called by APScheduler)
# ============================================================================

async def send_morning_promo():
    """Morning promo: Offshore DMCA-ignored domains"""
    logger.info("📢 PROMO: Morning broadcast triggered (offshore_domains)")
    return await send_promotional_broadcast("offshore_domains")


async def send_afternoon_promo():
    """Afternoon promo: Offshore cPanel hosting"""
    logger.info("📢 PROMO: Afternoon broadcast triggered (offshore_hosting)")
    return await send_promotional_broadcast("offshore_hosting")


async def send_evening_promo():
    """Evening promo: URL shortener & domain registration via @nomadlybot"""
    logger.info("📢 PROMO: Evening broadcast triggered (url_shortener)")
    return await send_promotional_broadcast("url_shortener")


# ============================================================================
# MANUAL TRIGGER (for admin testing)
# ============================================================================

async def send_all_promos_now() -> Dict[str, Dict[str, int]]:
    """Send all 3 promotional messages immediately (for testing)."""
    results = {}
    for theme in PROMO_THEMES:
        results[theme] = await send_promotional_broadcast(theme)
        await asyncio.sleep(2.0)  # Pause between themes
    return results
