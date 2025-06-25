import asyncio
from telegram.ext import ApplicationBuilder
import os
from FIXEDENCODE import CommandHandler, Update, ContextTypes

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Bot aktif dari Railway 🚀")

async def main():
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    await app.run_polling()

if __name__ == "__main__":
    import nest_asyncio
    import sys

    try:
        nest_asyncio.apply()
        asyncio.get_event_loop().run_until_complete(main())
    except RuntimeError:
        asyncio.run(main())
