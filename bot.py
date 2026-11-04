import asyncio
import logging
import os
from datetime import timedelta

import aiosqlite
from aiogram import Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command, CommandStart
from aiogram.types import (CallbackQuery, ChatPermissions, InlineKeyboardButton,
                           InlineKeyboardMarkup, Message)
from dotenv import load_dotenv

load_dotenv()
from moderation import check_text  # noqa: E402

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHANNEL_ID = os.environ["CHANNEL_ID"]
ADMIN_IDS = {int(x) for x in os.environ["ADMIN_IDS"].split(",") if x.strip()}
AUTO_APPROVE = os.getenv("AUTO_APPROVE", "0") == "1"
MAX_WARNS = int(os.getenv("MAX_WARNS", "3"))
MUTE_MINUTES = int(os.getenv("MUTE_MINUTES", "60"))
DB = os.getenv("DB_PATH", "bot.db")

router = Router()


# ---------------- БД ----------------
async def init_db():
    async with aiosqlite.connect(DB) as db:
        await db.executescript("""
        CREATE TABLE IF NOT EXISTS queue(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER, msg_id INTEGER, user_id INTEGER,
            status TEXT DEFAULT 'pending',
            created REAL DEFAULT (strftime('%s','now')));
        CREATE TABLE IF NOT EXISTS warns(
            user_id INTEGER, chat_id INTEGER, cnt INTEGER DEFAULT 0,
            PRIMARY KEY(user_id, chat_id));
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        """)
        await db.commit()


async def get_setting(key, default=None):
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = await cur.fetchone()
        return row[0] if row else default


async def set_setting(key, value):
    async with aiosqlite.connect(DB) as db:
        await db.execute("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, str(value)))
        await db.commit()


async def add_warn(user_id: int, chat_id: int) -> int:
    async with aiosqlite.connect(DB) as db:
        await db.execute("INSERT INTO warns(user_id,chat_id,cnt) VALUES(?,?,1) "
                         "ON CONFLICT(user_id,chat_id) DO UPDATE SET cnt=cnt+1", (user_id, chat_id))
        await db.commit()
        cur = await db.execute("SELECT cnt FROM warns WHERE user_id=? AND chat_id=?", (user_id, chat_id))
        return (await cur.fetchone())[0]


async def get_warns(user_id: int, chat_id: int) -> int:
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT cnt FROM warns WHERE user_id=? AND chat_id=?", (user_id, chat_id))
        row = await cur.fetchone()
        return row[0] if row else 0


async def enqueue(chat_id, msg_id, user_id, status) -> int:
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("INSERT INTO queue(chat_id,msg_id,user_id,status) VALUES(?,?,?,?)",
                               (chat_id, msg_id, user_id, status))
        await db.commit()
        return cur.lastrowid


async def set_status(qid, status):
    async with aiosqlite.connect(DB) as db:
        await db.execute("UPDATE queue SET status=? WHERE id=?", (status, qid))
        await db.commit()


def text_of(m: Message) -> str:
    return m.text or m.caption or ""


async def moderate(text: str):
    from moderation import check_text
    return await check_text(text)


# ---------------- Приватный чат: предложка ----------------
@router.message(CommandStart(), F.chat.type == "private")
async def start(m: Message):
    await m.answer("Привет! Пришли текст, фото или видео — я проверю и, если всё ок, "
                   "отправлю на публикацию в канал.\n\nНельзя: оскорбления, расизм, угрозы, "
                   "18+, наркотики, спам и ссылки.")


@router.message(Command("queue"), F.from_user.id.in_(ADMIN_IDS))
async def cmd_queue(m: Message):
    async with aiosqlite.connect(DB) as db:
        res = {}
        for s in ("pending", "approved", "posted", "rejected"):
            cur = await db.execute("SELECT COUNT(*) FROM queue WHERE status=?", (s,))
            res[s] = (await cur.fetchone())[0]
    await m.answer(f"На проверке: {res['pending']}\nГотово к публикации: {res['approved']}\n"
                   f"Опубликовано: {res['posted']}\nОтклонено: {res['rejected']}")


@router.message(Command("post_now"), F.from_user.id.in_(ADMIN_IDS))
async def cmd_post_now(m: Message, bot: Bot):
    ok = await publish_next(bot)
    await m.answer("Опубликовано ✅" if ok else "Очередь пуста")


@router.message(F.chat.type == "private", F.from_user.id.in_(ADMIN_IDS), ~F.text.startswith("/"))
async def admin_post(m: Message, bot: Bot):
    """Всё, что присылает админ, сразу проходит модерацию и публикуется в канал."""
    v = await moderate(text_of(m))
    if v:
        return await m.answer(f"⛔ Не принято: {v.label} ({v.detail})")
    qid = await enqueue(m.chat.id, m.message_id, m.from_user.id, "approved")
    ok = await publish_message(bot, m.chat.id, m.message_id, qid)
    await m.answer("✅ Опубликовано в канал ✅" if ok else f"✅ Принято (#{qid}), но ошибка публикации")


@router.message(F.chat.type == "private", ~F.text.startswith("/"))
async def user_submit(m: Message, bot: Bot):
    uid = m.from_user.id
    if await get_warns(uid, 0) >= MAX_WARNS:
        return
    if not (m.text or m.photo or m.video or m.animation or m.document):
        return await m.answer("Поддерживаются текст, фото, видео, gif и файлы.")

    v = await moderate(text_of(m))
    if v:
        n = await add_warn(uid, 0)
        left = MAX_WARNS - n
        extra = "Вы заблокированы." if left <= 0 else f"Осталось попыток: {left}."
        return await m.answer(f"⛔ Пост отклонён автомодерацией: {v.label}.\n{extra}")

    if AUTO_APPROVE:
        qid = await enqueue(m.chat.id, m.message_id, uid, "approved")
        ok = await publish_message(bot, m.chat.id, m.message_id, qid)
        return await m.answer("✅ Опубликовано в канал ✅" if ok else f"✅ Принято (#{qid}), но ошибка публикации")

    qid = await enqueue(m.chat.id, m.message_id, uid, "pending")
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Одобрить", callback_data=f"ok:{qid}"),
        InlineKeyboardButton(text="❌ Отклонить", callback_data=f"no:{qid}"),
    ]])
    for admin in ADMIN_IDS:
        try:
            await bot.copy_message(admin, m.chat.id, m.message_id, reply_markup=kb)
        except TelegramAPIError:
            logging.warning("Не удалось отправить админу %s", admin)
    await m.answer("📨 Пост отправлен на проверку.")


@router.callback_query(F.data.regexp(r"^(ok|no):\d+$"), F.from_user.id.in_(ADMIN_IDS))
async def review(c: CallbackQuery, bot: Bot):
    action, qid = c.data.split(":")
    qid = int(qid)
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT user_id,status FROM queue WHERE id=?", (qid,))
        row = await cur.fetchone()
    if not row or row[1] != "pending":
        return await c.answer("Уже обработано", show_alert=True)
    user_id = row[0]
    if action == "ok":
        async with aiosqlite.connect(DB) as db:
            cur = await db.execute("SELECT chat_id,msg_id FROM queue WHERE id=?", (qid,))
            prow = await cur.fetchone()
        await set_status(qid, "approved")
        if prow:
            ok = await publish_message(bot, prow[0], prow[1], qid)
            note = "✅ Опубликовано в канал ✅" if ok else "✅ Одобрено, но ошибка публикации"
        else:
            note = "✅ Одобрено"
    else:
        await set_status(qid, "rejected")
        note = "❌ Отклонено."
    await c.message.edit_reply_markup(reply_markup=None)
    await c.message.reply(note)
    try:
        await bot.send_message(user_id, f"Ваш пост #{qid}: {note}")
    except TelegramAPIError:
        pass
    await c.answer()


# ---------------- Группа (комментарии): автомодерация ----------------
@router.message(F.chat.type.in_({"group", "supergroup"}), F.text | F.caption)
async def group_moderation(m: Message, bot: Bot):
    if m.is_automatic_forward or m.sender_chat or not m.from_user or m.from_user.is_bot:
        return
    member = await bot.get_chat_member(m.chat.id, m.from_user.id)
    if member.status in ("administrator", "creator"):
        return

    v = await moderate(text_of(m))
    if not v:
        return
    try:
        await m.delete()
    except TelegramAPIError:
        logging.warning("Нет прав удалять сообщения в чате %s", m.chat.id)
        return

    n = await add_warn(m.from_user.id, m.chat.id)
    name = m.from_user.mention_html()
    if n >= MAX_WARNS:
        try:
            await bot.restrict_chat_member(
                m.chat.id, m.from_user.id, ChatPermissions(can_send_messages=False),
                until_date=timedelta(minutes=MUTE_MINUTES))
            await bot.send_message(m.chat.id, f"🔇 {name} в муте на {MUTE_MINUTES} мин ({v.label}).",
                                   parse_mode="HTML")
        except TelegramAPIError:
            pass
        async with aiosqlite.connect(DB) as db:
            await db.execute("UPDATE warns SET cnt=0 WHERE user_id=? AND chat_id=?",
                             (m.from_user.id, m.chat.id))
            await db.commit()
    else:
        msg = await bot.send_message(m.chat.id, f"⚠️ {name}, сообщение удалено: {v.label}. "
                                                f"Предупреждение {n}/{MAX_WARNS}.", parse_mode="HTML")
        await asyncio.sleep(10)
        try:
            await msg.delete()
        except TelegramAPIError:
            pass


@router.message(Command("unwarn"), F.from_user.id.in_(ADMIN_IDS), F.reply_to_message)
async def unwarn(m: Message):
    async with aiosqlite.connect(DB) as db:
        await db.execute("UPDATE warns SET cnt=0 WHERE user_id=? AND chat_id=?",
                         (m.reply_to_message.from_user.id, m.chat.id))
        await db.commit()
    await m.reply("Предупреждения сброшены.")


# ---------------- Автопостинг (мгновенно после проверки) ----------------
async def publish_message(bot: Bot, chat_id: int, msg_id: int, qid: int) -> bool:
    try:
        await bot.copy_message(CHANNEL_ID, chat_id, msg_id)
        await set_status(qid, "posted")
        return True
    except TelegramAPIError as e:
        logging.error("Ошибка публикации #%s: %s", qid, e)
        await set_status(qid, "failed")
        return False


async def publish_next(bot: Bot) -> bool:
    async with aiosqlite.connect(DB) as db:
        cur = await db.execute("SELECT id,chat_id,msg_id FROM queue WHERE status='approved' ORDER BY id LIMIT 1")
        row = await cur.fetchone()
    if not row:
        return False
    qid, chat_id, msg_id = row
    return await publish_message(bot, chat_id, msg_id, qid)


async def main():
    logging.basicConfig(level=logging.INFO)
    await init_db()
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
