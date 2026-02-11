#!/usr/bin/env python3
"""
Promotional Broadcast Service for HostBay Telegram Bot

Timezone-aware promotional messages sent 3x daily per user's local time.
Runs hourly via APScheduler, selects users whose local time matches the target hour.

Schedule (in user's local time):
  - 10:00 AM → Offshore DMCA-ignored domains
  - 15:00 PM → Offshore cPanel hosting
  - 20:00 PM → Windows RDP servers

Features:
  - AI-generated dynamic messages via OpenAI GPT-4o-mini (friendly, varied copy)
  - Automatic fallback to static locale strings if OpenAI unavailable
  - Per-hour cache (1 GPT call per theme×lang, not per user)
  - Respects user's preferred_language (en/es/fr)
  - Respects timezone_offset for local-time delivery
  - Respects promo_opted_out flag (/stop_promos)
"""

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

from database import queue_user_notification_by_user_id, get_promo_eligible_users_for_hour
from localization import t

import re

logger = logging.getLogger(__name__)


def _sanitize_html(text: str) -> str:
    """Convert any stray markdown to HTML and clean up for Telegram."""
    # Bold: **text** or __text__ → <b>text</b>
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    # Italic: *text* or _text_ (single) → <i>text</i>
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
    # Inline code: `text` → <code>text</code>
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    # Bullet points: • → -
    text = text.replace('•', '-')
    return text.strip()

# Local-time hours for each promo theme
PROMO_SLOTS = {
    10: "offshore_domains",   # 10 AM local
    15: "offshore_hosting",   # 3 PM local
    20: "rdp_servers",        # 8 PM local
}

# Hourly cache: key = "YYYY-MM-DD-HH:theme:lang" → generated message
_message_cache: Dict[str, str] = {}

# Product briefs fed to GPT so it has accurate facts
THEME_BRIEFS = {
    "offshore_domains": {
        "product": "Offshore DMCA-Ignored Domain Registration",
        "details": (
            "HostBay lets users register country-level TLD domains: "
            ".is (Iceland), .ru (Russia), .md (Moldova), .ws (Samoa), .to (Tonga), "
            ".cc (Cocos Islands), .sx (Sint Maarten), .ly (Libya), .ro (Romania), .bg (Bulgaria). "
            "Prices from $2.99/year. No DMCA takedowns. "
            "Users type /start to search & register."
        ),
        "cta_options": [
            "Use /start to search & register your offshore domain",
        ],
    },
    "offshore_hosting": {
        "product": "Offshore cPanel Hosting (DMCA-Ignored Servers)",
        "details": (
            "Three plans: STARTER $4.99/mo (SSD, unlimited bandwidth), "
            "PROFESSIONAL $9.99/mo (more power, priority support), "
            "BUSINESS $19.99/mo (max resources, dedicated IP). "
            "Every plan: full cPanel, one-click WordPress, free SSL, "
            "DMCA-ignored infrastructure, 99.9% uptime SLA. "
            "Users type /start to explore plans."
        ),
        "cta_options": [
            "/start to explore hosting plans",
        ],
    },
    "rdp_servers": {
        "product": "Windows RDP Servers (Offshore Cloud VPS)",
        "details": (
            "HostBay offers Windows RDP servers powered by Vultr cloud infrastructure. "
            "Multiple plans available with SSD storage, dedicated vCPUs, and full admin access. "
            "Global locations: US, Europe, Asia, South America. "
            "Perfect for remote desktop work, running bots, automation, or hosting Windows apps offshore. "
            "Plans start from affordable monthly pricing. "
            "Users type /start to browse RDP plans and deploy instantly."
        ),
        "cta_options": [
            "Use /start to browse RDP server plans",
        ],
    },
}

LANG_NAMES = {"en": "English", "es": "Spanish", "fr": "French"}

SYSTEM_PROMPT = """\
You are a friendly, persuasive copywriter for HostBay, an offshore hosting & domain service on Telegram.

Rules:
- Write ONE short promotional message (max 800 chars) using ONLY Telegram HTML tags.
- ONLY allowed tags: <b>bold</b>, <i>italic</i>, <code>monospace</code>. Nothing else.
- NEVER use markdown syntax like **bold**, _italic_, or bullet characters like •. Use plain dashes - instead.
- Tone: friendly, warm, casual-professional. Like a helpful friend sharing a cool tip, NOT a pushy ad.
- Be creative: vary greetings, angles, hooks, analogies. Never start with the same opening twice.
- Include the key product facts but rephrase naturally — don't just list specs robotically.
- End with a clear call-to-action using the provided CTA.
- Do NOT add any footer, separator lines, or opt-out text — those are appended automatically.
- Do NOT mention @nomadlybot or any other bots. Only promote HostBay services.
- Max 2-3 emoji per message. Keep it clean.
- Write entirely in {language}.\
"""


async def _generate_dynamic_message(theme: str, lang: str) -> Optional[str]:
    """Generate a dynamic promo message using GPT-4o-mini. Returns None on failure."""
    api_key = os.environ.get("APP_OPEN_API_KEY")
    if not api_key:
        logger.warning("📢 PROMO: APP_OPEN_API_KEY not set, falling back to static messages")
        return None

    brief = THEME_BRIEFS.get(theme)
    if not brief:
        return None

    language = LANG_NAMES.get(lang, "English")
    system = SYSTEM_PROMPT.format(language=language)
    user_prompt = (
        f"Product: {brief['product']}\n"
        f"Details: {brief['details']}\n"
        f"CTA: {brief['cta_options'][0]}\n\n"
        f"Write a fresh, friendly promo message in {language}."
    )

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except ImportError:
        logger.warning("📢 PROMO AI: emergentintegrations not available, skipping AI generation")
        return None

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=f"promo-{theme}-{lang}-{uuid.uuid4().hex[:8]}",
            system_message=system,
        ).with_model("openai", "gpt-4o-mini")

        response = await chat.send_message(UserMessage(text=user_prompt))
        if response and len(response.strip()) > 20:
            clean = _sanitize_html(response)
            logger.info(f"📢 PROMO AI: Generated dynamic '{theme}' message in {lang} ({len(clean)} chars)")
            return clean
        return None
    except Exception as e:
        logger.error(f"📢 PROMO AI ERROR: {e}")
        return None


def _build_static_message(theme: str, lang: str) -> str:
    """Build the original static promo message from locale strings (fallback)."""
    title = t(f'promo.{theme}.title', lang)
    body = t(f'promo.{theme}.body', lang)
    cta = t(f'promo.{theme}.cta', lang)
    return f"{title}\n\n{body}\n\n{cta}"


def _append_footer(message: str, lang: str) -> str:
    """Append the HostBay footer to any message."""
    footer = t('promo.common.footer', lang)
    return f"{message}\n\n{footer}"


async def build_promo_message(theme: str, lang: str) -> str:
    """
    Build a promo message — dynamic (AI) with static fallback.
    Caches per hour so we only call GPT once per theme×lang per hour.
    """
    now = datetime.now(timezone.utc)
    cache_key = f"{now.strftime('%Y-%m-%d-%H')}:{theme}:{lang}"

    if cache_key in _message_cache:
        return _message_cache[cache_key]

    # Try dynamic generation
    dynamic = await _generate_dynamic_message(theme, lang)
    if dynamic:
        full_msg = _append_footer(dynamic, lang)
    else:
        full_msg = _append_footer(_build_static_message(theme, lang), lang)

    _message_cache[cache_key] = full_msg

    # Prune old cache entries (keep only current hour)
    current_prefix = now.strftime('%Y-%m-%d-%H')
    stale = [k for k in _message_cache if not k.startswith(current_prefix)]
    for k in stale:
        del _message_cache[k]

    return full_msg


async def run_hourly_promo_check():
    """
    Hourly job: Determine which promo themes match the current local hour
    for each user (based on their timezone_offset) and send accordingly.

    This runs once per hour. For each of the 3 promo slots (10, 15, 20),
    it queries users whose local time IS that hour right now.
    """
    logger.info("📢 PROMO HOURLY CHECK: Starting timezone-aware promo dispatch")

    total_stats = {"sent": 0, "failed": 0}

    for target_hour, theme in PROMO_SLOTS.items():
        try:
            users = await get_promo_eligible_users_for_hour(target_hour)
            if not users:
                continue

            logger.info(f"📢 PROMO: Sending '{theme}' to {len(users)} users (local hour = {target_hour}:00)")

            # Pre-generate messages for each language this batch needs
            langs_needed = {(u.get('preferred_language') or 'en') for u in users}
            for ln in langs_needed:
                await build_promo_message(theme, ln)

            batch_size = 25
            for i in range(0, len(users), batch_size):
                batch = users[i:i + batch_size]

                for user in batch:
                    user_id = user['id']
                    lang = user.get('preferred_language') or 'en'

                    try:
                        message = await build_promo_message(theme, lang)
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
        message = await build_promo_message(theme, lang)
        return await queue_user_notification_by_user_id(user_id, message, 'HTML')
    except Exception as e:
        logger.error(f"Test promo failed: {e}")
        return False
