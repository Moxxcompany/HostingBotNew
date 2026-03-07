import sys
import os

sys.path.insert(0, '/app')
os.chdir('/app')

from dotenv import load_dotenv
load_dotenv('/app/.env', override=True)

# REDIRECT MODE: Ultra-lightweight standalone server
# Skips ALL heavy imports from fastapi_server.py (~70MB memory saved)
if os.getenv('REDIRECT_MODE', '').lower() == 'true':
    import logging
    import asyncio
    from contextlib import asynccontextmanager
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [REDIRECT] %(message)s')
    logger = logging.getLogger('redirect_bot')

    bot_app = None

    # Admin IDs from env (no DB needed)
    _admin_ids = set()
    for _key in ('ADMIN_USER_IDS', 'ADMIN_USER_ID'):
        for _chunk in os.getenv(_key, '').split(','):
            _chunk = _chunk.strip()
            if _chunk.isdigit():
                _admin_ids.add(int(_chunk))

    def _is_admin(uid: int) -> bool:
        return uid in _admin_ids

    @asynccontextmanager
    async def lifespan(fastapi_app: FastAPI):
        global bot_app
        logger.info("Starting redirect-only bot...")

        token = os.getenv('TELEGRAM_BOT_TOKEN', '')
        if not token:
            logger.error("TELEGRAM_BOT_TOKEN missing")
            yield
            return

        from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, Bot
        from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, Defaults, ContextTypes

        REDIRECT_TEXT = (
            "Hey! We moved \u2014 and leveled up.\n\n"
            "@Nomadlybot now has:\n"
            "\u2601\ufe0f Cloud IVR  \u2022  \U0001f4de SIP &amp; OTP Calls\n"
            "\u26a1 Quick &amp; Batch IVR  \u2022  \U0001f4ec Bozzmail\n\n"
            "\U0001f195 Bozzmail: Print shipping labels, send letters &amp; postcards \u2014 all from your phone.\n\n"
            "Your domains, hosting &amp; wallet are\n"
            "already there waiting for you.\n\n"
            "Don\u2019t get left behind \U0001f447"
        )
        REDIRECT_KB = InlineKeyboardMarkup([
            [InlineKeyboardButton("\u27a1\ufe0f Open @Nomadlybot", url="https://t.me/Nomadlybot")],
            [InlineKeyboardButton("\U0001f4ec Bozzmail \u2014 Send Mail", url="https://bozzmail.com")]
        ])

        # --- Handlers ---
        async def start_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            user = update.effective_user
            msg = update.effective_message
            if not user or not msg:
                return
            if _is_admin(user.id):
                await msg.reply_text(
                    "<b>Admin Panel (Redirect Mode)</b>\n\n"
                    "<b>Commands:</b>\n"
                    "/broadcast \u2014 Send message to all users\n"
                    "/send &lt;id&gt; &lt;msg&gt; \u2014 Message a specific user\n"
                    "/cancel \u2014 Exit broadcast mode\n\n"
                    "<i>All non-admin users see the redirect message.</i>",
                    parse_mode='HTML'
                )
                return
            await msg.reply_text(REDIRECT_TEXT, reply_markup=REDIRECT_KB)

        async def _do_broadcast(reply_to, text, admin_user):
            try:
                import psycopg2
                import psycopg2.extras
                db_url = os.getenv('DATABASE_URL', '')
                if not db_url:
                    await reply_to.reply_text("DATABASE_URL not set.")
                    return
                conn = psycopg2.connect(db_url, connect_timeout=10)
                cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                cur.execute("SELECT telegram_id FROM users WHERE terms_accepted = true ORDER BY id")
                rows = cur.fetchall()
                conn.close()

                if not rows:
                    await reply_to.reply_text("No users found in database.")
                    return

                total = len(rows)
                status_msg = await reply_to.reply_text(f"Broadcasting to {total} users...")
                sent = 0
                failed = 0
                for row in rows:
                    tid = row['telegram_id']
                    if tid in _admin_ids:
                        continue
                    try:
                        await bot_app.bot.send_message(
                            chat_id=tid,
                            text=f"<b>\U0001f4e2 Broadcast</b>\n\n{text}",
                            parse_mode='HTML'
                        )
                        sent += 1
                    except Exception:
                        failed += 1
                    if sent % 30 == 0 and sent > 0:
                        await asyncio.sleep(1)

                await status_msg.edit_text(
                    f"<b>Broadcast Complete</b>\n\nSent: {sent}\nFailed: {failed}\nTotal: {total}",
                    parse_mode='HTML'
                )
                logger.info(f"BROADCAST: Admin {admin_user.id} sent to {sent}/{total}")
            except Exception as e:
                logger.error(f"Broadcast error: {e}")
                await reply_to.reply_text(f"Broadcast failed: {str(e)[:200]}")

        async def broadcast_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            user = update.effective_user
            msg = update.effective_message
            if not user or not msg:
                return
            if not _is_admin(user.id):
                await msg.reply_text(REDIRECT_TEXT, reply_markup=REDIRECT_KB)
                return
            text = ' '.join(ctx.args) if ctx.args else ''
            if not text.strip():
                ctx.user_data['awaiting_broadcast'] = True
                await msg.reply_text(
                    "<b>Broadcast Mode</b>\n\nType your message below and it will be sent to all users.\n\nSend /cancel to exit.",
                    parse_mode='HTML'
                )
                return
            await _do_broadcast(msg, text, user)

        async def send_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            user = update.effective_user
            msg = update.effective_message
            if not user or not msg:
                return
            if not _is_admin(user.id):
                await msg.reply_text(REDIRECT_TEXT, reply_markup=REDIRECT_KB)
                return
            if not ctx.args or len(ctx.args) < 2:
                await msg.reply_text(
                    "<b>Usage:</b> /send &lt;telegram_id&gt; &lt;message&gt;\n\n"
                    "Example: /send 123456789 Hello!",
                    parse_mode='HTML'
                )
                return
            try:
                target_id = int(ctx.args[0])
            except ValueError:
                await msg.reply_text("Invalid Telegram ID.")
                return
            text = ' '.join(ctx.args[1:])
            try:
                await bot_app.bot.send_message(
                    chat_id=target_id,
                    text=f"<b>\U0001f4e9 Message from Hostbay</b>\n\n{text}",
                    parse_mode='HTML'
                )
                await msg.reply_text(f"Sent to <code>{target_id}</code>", parse_mode='HTML')
                logger.info(f"SEND: Admin {user.id} -> {target_id}")
            except Exception as e:
                await msg.reply_text(f"Failed: {str(e)[:200]}")

        async def cancel_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            user = update.effective_user
            msg = update.effective_message
            if not user or not msg:
                return
            if ctx.user_data and 'awaiting_broadcast' in ctx.user_data:
                del ctx.user_data['awaiting_broadcast']
            await msg.reply_text("Cancelled.")

        async def text_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            user = update.effective_user
            msg = update.effective_message
            if not user or not msg or not msg.text:
                return
            if _is_admin(user.id) and ctx.user_data and ctx.user_data.get('awaiting_broadcast'):
                del ctx.user_data['awaiting_broadcast']
                await _do_broadcast(msg, msg.text, user)
                return
            if not _is_admin(user.id):
                await msg.reply_text(REDIRECT_TEXT, reply_markup=REDIRECT_KB)

        async def callback_handler(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
            q = update.callback_query
            if q:
                await q.answer()
                await q.message.reply_text(REDIRECT_TEXT, reply_markup=REDIRECT_KB)

        # Build bot
        defaults = Defaults(parse_mode='HTML')
        bot_app = Application.builder().token(token).defaults(defaults).build()

        private = filters.ChatType.PRIVATE
        bot_app.add_handler(CommandHandler("start", start_handler, filters=private))
        bot_app.add_handler(CommandHandler("broadcast", broadcast_handler, filters=private))
        bot_app.add_handler(CommandHandler("send", send_handler, filters=private))
        bot_app.add_handler(CommandHandler("cancel", cancel_handler, filters=private))
        bot_app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND & private, text_handler))
        bot_app.add_handler(CallbackQueryHandler(callback_handler))

        await bot_app.initialize()
        await bot_app.start()
        logger.info("Bot initialized")

        # Register webhook
        domain = os.getenv('PRODUCTION_DOMAIN', '')
        if domain:
            webhook_url = f"https://{domain}/api/webhook/telegram"
            secret = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN', '')
            result = await bot_app.bot.set_webhook(
                url=webhook_url,
                secret_token=secret,
                max_connections=5,
                allowed_updates=["message", "callback_query"]
            )
            if result:
                logger.info(f"Webhook set: {webhook_url}")

        logger.info("REDIRECT MODE READY")
        yield

        # Cleanup
        if bot_app:
            try:
                await bot_app.stop()
                await bot_app.shutdown()
            except Exception:
                pass
        logger.info("Bot stopped")

    # --- Minimal FastAPI app ---
    app = FastAPI(title="Hostbay Redirect", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "mode": "redirect", "bot_ready": bot_app is not None}

    @app.get("/health")
    async def health_alt():
        return {"status": "ok", "mode": "redirect"}

    @app.post("/api/webhook/telegram")
    async def telegram_webhook(request: Request):
        if not bot_app:
            return JSONResponse({"error": "bot not ready"}, status_code=503)
        secret = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN', '')
        if secret:
            token_header = request.headers.get('x-telegram-bot-api-secret-token', '')
            if token_header != secret:
                return JSONResponse({"error": "unauthorized"}, status_code=403)
        try:
            from telegram import Update
            data = await request.json()
            update = Update.de_json(data, bot_app.bot)
            await bot_app.process_update(update)
        except Exception as e:
            logger.error(f"Webhook error: {e}")
        return JSONResponse({"ok": True})

    @app.post("/webhook/telegram")
    async def telegram_webhook_alt(request: Request):
        return await telegram_webhook(request)

    # Catch-all for any other API routes — return minimal response
    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def catch_all(path: str):
        return JSONResponse({"status": "redirect_mode", "message": "Service moved to @Nomadlybot"})

else:
    # Full mode — import heavy fastapi_server
    from fastapi_server import app
