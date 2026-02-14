"""
Group Notification System for HostBay Bot
Broadcasts persuasive marketing events to all registered Telegram groups.
Auto-detects group additions, masks usernames, and sends hype+trust messages.
"""

import os
import logging
import asyncio
import random
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Bot username - resolved once at runtime
_bot_username: Optional[str] = None

def _get_bot_username() -> str:
    """Get bot username, with fallback"""
    global _bot_username
    if _bot_username:
        return _bot_username
    return os.getenv('BOT_USERNAME', 'HostBay_bot')

def set_bot_username(username: str):
    """Set the bot username after bot initializes"""
    global _bot_username
    _bot_username = username.lstrip('@')
    logger.info(f"Group notifications: bot username set to @{_bot_username}")


def mask_username(username: Optional[str], first_name: Optional[str] = None) -> str:
    """Mask username: show first 2 chars + asterisks. e.g. @us***"""
    if username:
        clean = username.lstrip('@')
        if len(clean) <= 2:
            return f"@{'*' * 4}"
        visible = clean[:2]
        return f"@{visible}{'*' * max(3, len(clean) - 2)}"
    
    # Fallback to first_name masking
    if first_name:
        if len(first_name) <= 2:
            return f"{first_name[0]}***"
        return f"{first_name[:2]}{'*' * max(3, len(first_name) - 2)}"
    
    return "Someone"


# ─── Group Registration (PostgreSQL) ─────────────────────────────────────────

async def _ensure_groups_table():
    """Create notification_groups table if it doesn't exist"""
    try:
        from database import execute_update
        await execute_update("""
            CREATE TABLE IF NOT EXISTS notification_groups (
                id SERIAL PRIMARY KEY,
                chat_id BIGINT UNIQUE NOT NULL,
                chat_title TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
    except Exception as e:
        logger.warning(f"Could not ensure notification_groups table: {e}")


async def register_group(chat_id: int, chat_title: Optional[str] = None):
    """Register a group chat for event notifications"""
    try:
        await _ensure_groups_table()
        from database import execute_update
        await execute_update("""
            INSERT INTO notification_groups (chat_id, chat_title, is_active)
            VALUES (%s, %s, TRUE)
            ON CONFLICT (chat_id) DO UPDATE SET
                chat_title = EXCLUDED.chat_title,
                is_active = TRUE
        """, (chat_id, chat_title))
        logger.info(f"Registered group for notifications: {chat_title} ({chat_id})")
    except Exception as e:
        logger.error(f"Failed to register group {chat_id}: {e}")


async def unregister_group(chat_id: int):
    """Mark a group as inactive when bot is removed"""
    try:
        from database import execute_update
        await execute_update("""
            UPDATE notification_groups SET is_active = FALSE WHERE chat_id = %s
        """, (chat_id,))
        logger.info(f"Unregistered group from notifications: {chat_id}")
    except Exception as e:
        logger.error(f"Failed to unregister group {chat_id}: {e}")


async def get_active_groups() -> List[Dict[str, Any]]:
    """Get all active notification groups"""
    try:
        from database import execute_query
        groups = await execute_query(
            "SELECT chat_id, chat_title FROM notification_groups WHERE is_active = TRUE"
        )
        return groups or []
    except Exception as e:
        logger.warning(f"Failed to fetch active groups: {e}")
        return []


# ─── Chat Member Handler ─────────────────────────────────────────────────────

async def handle_my_chat_member(update, context):
    """
    Detect when bot is added to or removed from a group.
    Registers/unregisters automatically.
    """
    try:
        member_update = update.my_chat_member
        if not member_update:
            return

        chat = member_update.chat
        new_status = member_update.new_chat_member.status

        # Only handle group/supergroup chats
        if chat.type not in ('group', 'supergroup'):
            return

        if new_status in ('member', 'administrator'):
            await register_group(chat.id, chat.title)
            # Send welcome message to the group
            bot_user = _get_bot_username()
            welcome = (
                f"<b>HostBay is now live in this group!</b>\n\n"
                f"You'll see real-time updates whenever someone makes a purchase, "
                f"registers a domain, or joins the platform.\n\n"
                f"<i>Powered by</i> @{bot_user}"
            )
            try:
                await context.bot.send_message(
                    chat_id=chat.id,
                    text=welcome,
                    parse_mode='HTML'
                )
            except Exception as send_err:
                logger.warning(f"Could not send welcome to group {chat.id}: {send_err}")

        elif new_status in ('left', 'kicked'):
            await unregister_group(chat.id)

    except Exception as e:
        logger.error(f"Error handling my_chat_member update: {e}")


# ─── Event Broadcasting ──────────────────────────────────────────────────────

async def _broadcast_to_groups(message: str):
    """Send a message to all registered active groups"""
    groups = await get_active_groups()
    if not groups:
        return

    # Get bot application
    bot = None
    try:
        import builtins
        bot_app = getattr(builtins, '_global_bot_application', None)
        if bot_app and hasattr(bot_app, 'bot'):
            bot = bot_app.bot
    except Exception:
        pass

    if not bot:
        try:
            from fastapi_server import _bot_application_instance
            if _bot_application_instance and hasattr(_bot_application_instance, 'bot'):
                bot = _bot_application_instance.bot
        except Exception:
            pass

    if not bot:
        logger.warning("No bot instance available for group broadcast")
        return

    for group in groups:
        try:
            await bot.send_message(
                chat_id=group['chat_id'],
                text=message,
                parse_mode='HTML'
            )
        except Exception as e:
            error_str = str(e).lower()
            # If bot was kicked or chat not found, deactivate
            if any(phrase in error_str for phrase in ['chat not found', 'bot was kicked', 'forbidden', 'bot was blocked']):
                await unregister_group(group['chat_id'])
                logger.info(f"Auto-unregistered group {group['chat_id']} - bot removed")
            else:
                logger.warning(f"Failed to send to group {group['chat_id']}: {e}")
        
        # Small delay to avoid flood limits
        await asyncio.sleep(0.3)


# ─── Event Messages (Hype + Trust) ───────────────────────────────────────────

_ONBOARDING_MESSAGES = [
    "just joined the HostBay family! The community keeps growing",
    "signed up and is ready to build something amazing",
    "is now part of the HostBay revolution",
    "just hopped on board! Welcome to the future of hosting",
    "joined the movement. Another builder in the house",
]

_WALLET_MESSAGES = [
    "just loaded up their wallet! Ready to make moves",
    "topped up and is ready to build. Smart move",
    "just funded their account. Things are about to get real",
    "loaded their wallet. Another power user in action",
    "is stacking funds and preparing for launch",
]

_DOMAIN_MESSAGES = [
    "just secured a brand new domain! Another name off the market",
    "locked in their domain. Building something big",
    "grabbed a fresh domain. The internet just got more interesting",
    "just claimed their digital real estate. Smart investment",
    "registered a new domain. One step closer to launch day",
]

_HOSTING_MESSAGES = [
    "just launched their website! Another site goes live",
    "activated hosting and is going live. Unstoppable",
    "just powered up their hosting. The web just got better",
    "secured hosting. Their project is officially in motion",
    "is now live on the web. From idea to reality, just like that",
]

_RDP_MESSAGES = [
    "just deployed a Windows server! Power at their fingertips",
    "spun up a remote server. Serious business moves",
    "just launched an RDP server. Productivity unlocked",
    "deployed a Windows VPS. Working smarter, not harder",
    "just set up their remote workspace. Next-level operations",
]

_EMOJIS_BY_EVENT = {
    'onboarding': ['🎉', '🚀', '⚡', '🔥', '💫'],
    'wallet_deposit': ['💰', '💵', '🏦', '💎', '📈'],
    'domain_purchase': ['🌐', '🔗', '🏷️', '✨', '🎯'],
    'hosting_purchase': ['🖥️', '🏠', '⚡', '🌍', '🔥'],
    'rdp_purchase': ['🖥️', '💻', '⚙️', '🔧', '🚀'],
}


def _build_event_message(
    event_type: str,
    masked_user: str,
    messages_pool: list,
    detail_line: Optional[str] = None,
    extra_line: Optional[str] = None
) -> str:
    """Build a formatted event message with hype + trust tone"""
    bot_user = _get_bot_username()
    emoji = random.choice(_EMOJIS_BY_EVENT.get(event_type, ['🔔']))
    action_text = random.choice(messages_pool)

    lines = [
        f"{emoji} <b>{masked_user}</b> {action_text}!",
    ]

    if detail_line:
        lines.append(f"    {detail_line}")

    if extra_line:
        lines.append(f"    {extra_line}")

    # Trust / social proof footer
    trust_footers = [
        "Join thousands who trust HostBay for domains, hosting & more.",
        "HostBay — where builders launch their ideas.",
        "Trusted by a growing community of creators worldwide.",
        "Your next project starts here. What are you waiting for?",
        "The HostBay community never stops building.",
    ]
    lines.append("")
    lines.append(f"<i>{random.choice(trust_footers)}</i>")
    lines.append(f"@{bot_user}")

    return "\n".join(lines)


# ─── Public Event Functions (called from handlers/webhook_handler) ────────────

async def notify_new_user(username: Optional[str] = None, first_name: Optional[str] = None):
    """Broadcast: new user onboarding"""
    try:
        masked = mask_username(username, first_name)
        msg = _build_event_message('onboarding', masked, _ONBOARDING_MESSAGES)
        await _broadcast_to_groups(msg)
    except Exception as e:
        logger.warning(f"Group notification (onboarding) failed: {e}")


async def notify_wallet_deposit(
    username: Optional[str] = None,
    first_name: Optional[str] = None,
    amount_usd: float = 0.0
):
    """Broadcast: wallet top-up"""
    try:
        masked = mask_username(username, first_name)
        detail = f"💲 <b>${amount_usd:.2f}</b> deposited" if amount_usd > 0 else None
        msg = _build_event_message('wallet_deposit', masked, _WALLET_MESSAGES, detail_line=detail)
        await _broadcast_to_groups(msg)
    except Exception as e:
        logger.warning(f"Group notification (wallet) failed: {e}")


async def notify_domain_purchase(
    username: Optional[str] = None,
    first_name: Optional[str] = None,
    domain_name: Optional[str] = None
):
    """Broadcast: domain registration"""
    try:
        masked = mask_username(username, first_name)
        # Partially mask domain too: show TLD but mask most of the name
        detail = None
        if domain_name:
            parts = domain_name.split('.')
            if len(parts) >= 2:
                name_part = parts[0]
                tld = '.'.join(parts[1:])
                if len(name_part) > 3:
                    visible = name_part[:2]
                    detail = f"🏷️ Domain: <b>{visible}{'*' * (len(name_part) - 2)}.{tld}</b>"
                else:
                    detail = f"🏷️ Domain: <b>{'*' * len(name_part)}.{tld}</b>"
            else:
                detail = f"🏷️ A new <b>.{domain_name.split('.')[-1]}</b> domain"
        msg = _build_event_message('domain_purchase', masked, _DOMAIN_MESSAGES, detail_line=detail)
        await _broadcast_to_groups(msg)
    except Exception as e:
        logger.warning(f"Group notification (domain) failed: {e}")


async def notify_hosting_purchase(
    username: Optional[str] = None,
    first_name: Optional[str] = None,
    domain_name: Optional[str] = None,
    plan_name: Optional[str] = None
):
    """Broadcast: hosting purchase"""
    try:
        masked = mask_username(username, first_name)
        detail = None
        if plan_name:
            detail = f"📦 Plan: <b>{plan_name}</b>"
        extra = None
        if domain_name:
            parts = domain_name.split('.')
            if len(parts) >= 2:
                name_part = parts[0]
                tld = '.'.join(parts[1:])
                if len(name_part) > 3:
                    extra = f"🌐 Site: <b>{name_part[:2]}{'*' * (len(name_part) - 2)}.{tld}</b>"
                else:
                    extra = f"🌐 Site going live on <b>.{tld}</b>"
        msg = _build_event_message('hosting_purchase', masked, _HOSTING_MESSAGES, detail_line=detail, extra_line=extra)
        await _broadcast_to_groups(msg)
    except Exception as e:
        logger.warning(f"Group notification (hosting) failed: {e}")


async def notify_rdp_purchase(
    username: Optional[str] = None,
    first_name: Optional[str] = None,
    plan_name: Optional[str] = None
):
    """Broadcast: RDP/VPS server purchase"""
    try:
        masked = mask_username(username, first_name)
        detail = None
        if plan_name:
            detail = f"⚙️ Server: <b>{plan_name}</b>"
        msg = _build_event_message('rdp_purchase', masked, _RDP_MESSAGES, detail_line=detail)
        await _broadcast_to_groups(msg)
    except Exception as e:
        logger.warning(f"Group notification (rdp) failed: {e}")
