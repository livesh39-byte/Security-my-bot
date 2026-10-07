import os
import re
import sqlite3
import asyncio
import logging
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

import discord
from discord.ext import commands
from discord import app_commands

# ============================================================
# BLASTMC CORE — CLEAN / SINGLE-EXECUTION BUILD
# ============================================================
# Features:
# AFK, AFK list, AutoResponder (slash only), AutoRole,
# Lockdown, Announce, Say, UserInfo, MemberCount, Slowmode,
# Warnings, Warn, Warnings Clear, Purge, Ban, Kick, Timeout,
# Log Channel, Mention Guard, Help.
#
# Prefixes: $ and !
# AutoResponder intentionally has NO prefix command.
# Mention Guard is the ONLY dropdown/menu.
# Legacy greeting module is intentionally absent.
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")
PORT = int(os.getenv("PORT", "10000"))
DB_FILE = os.getenv("DB_FILE", "bot.db")
PREFIXES = ("!", "$")

# Visible-message timings
BOT_WARNING_DELETE_AFTER = 30
AFK_REPLY_DELETE_AFTER = 15
ACTION_REPLY_DELETE_AFTER = 12
MODERATION_REPLY_DELETE_AFTER = 120
PURGE_REPLY_DELETE_AFTER = 20

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN environment variable is missing.")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s:%(name)s: %(message)s",
)
log = logging.getLogger("blastmc-core")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.messages = True

bot = commands.Bot(
    command_prefix=PREFIXES,
    intents=intents,
    help_command=None,
    case_insensitive=True,
)

# ============================================================
# DATABASE
# ============================================================

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = threading.RLock()


def db_exec(sql: str, params=(), fetch: bool = False):
    with db_lock:
        cur = db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        db.commit()
        return rows


def db_init():
    with db_lock:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS guilds (
                guild_id INTEGER PRIMARY KEY,
                autorole_id INTEGER NOT NULL DEFAULT 0,
                log_channel_id INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS afk (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                since TEXT NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS autoresponders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                reply TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'exact'
            );

            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                moderator_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outgoing_dedupe (
                dedupe_key TEXT PRIMARY KEY,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS protected_users (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS protected_roles (
                guild_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                PRIMARY KEY (guild_id, role_id)
            );
            """
        )

        # Migrations for old bot.db files.
        guild_cols = {row[1] for row in db.execute("PRAGMA table_info(guilds)").fetchall()}
        if "autorole_id" not in guild_cols:
            db.execute("ALTER TABLE guilds ADD COLUMN autorole_id INTEGER NOT NULL DEFAULT 0")
        if "log_channel_id" not in guild_cols:
            db.execute("ALTER TABLE guilds ADD COLUMN log_channel_id INTEGER NOT NULL DEFAULT 0")
        db.commit()


def ensure_guild(guild_id: int):
    db_exec("INSERT OR IGNORE INTO guilds(guild_id) VALUES (?)", (guild_id,))


def guild_row(guild_id: int):
    ensure_guild(guild_id)
    return db_exec("SELECT * FROM guilds WHERE guild_id=?", (guild_id,), True)[0]


def set_guild_value(guild_id: int, column: str, value: int):
    if column not in {"autorole_id", "log_channel_id"}:
        raise ValueError("Invalid guild setting")
    ensure_guild(guild_id)
    db_exec(f"UPDATE guilds SET {column}=? WHERE guild_id=?", (value, guild_id))


def afk_get(guild_id: int, user_id: int):
    rows = db_exec(
        "SELECT * FROM afk WHERE guild_id=? AND user_id=?",
        (guild_id, user_id),
        True,
    )
    return rows[0] if rows else None


def afk_set(guild_id: int, user_id: int, reason: str):
    since = datetime.now(timezone.utc).isoformat()
    db_exec(
        "INSERT OR REPLACE INTO afk(guild_id,user_id,reason,since) VALUES (?,?,?,?)",
        (guild_id, user_id, reason.strip() or "AFK", since),
    )
    return afk_get(guild_id, user_id)


def afk_remove(guild_id: int, user_id: int):
    db_exec("DELETE FROM afk WHERE guild_id=? AND user_id=?", (guild_id, user_id))


def afk_list(guild_id: int):
    return db_exec("SELECT * FROM afk WHERE guild_id=? ORDER BY since ASC", (guild_id,), True)


def ar_list(guild_id: int):
    return db_exec("SELECT * FROM autoresponders WHERE guild_id=? ORDER BY id ASC", (guild_id,), True)


def warning_add(guild_id: int, user_id: int, moderator_id: int, reason: str) -> int:
    with db_lock:
        cur = db.cursor()
        cur.execute(
            "INSERT INTO warnings(guild_id,user_id,moderator_id,reason,created_at) VALUES (?,?,?,?,?)",
            (
                guild_id,
                user_id,
                moderator_id,
                reason.strip() or "No reason provided",
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        warning_id = cur.lastrowid
        db.commit()
        return int(warning_id)


def warning_list(guild_id: int, user_id: int):
    return db_exec(
        "SELECT * FROM warnings WHERE guild_id=? AND user_id=? ORDER BY id DESC",
        (guild_id, user_id),
        True,
    )


def warning_clear(guild_id: int, user_id: int) -> int:
    with db_lock:
        cur = db.cursor()
        cur.execute("DELETE FROM warnings WHERE guild_id=? AND user_id=?", (guild_id, user_id))
        count = cur.rowcount
        db.commit()
        return int(count)


def protected_user(guild_id: int, user_id: int) -> bool:
    return bool(
        db_exec(
            "SELECT 1 FROM protected_users WHERE guild_id=? AND user_id=?",
            (guild_id, user_id),
            True,
        )
    )


def protected_role(guild_id: int, role_id: int) -> bool:
    return bool(
        db_exec(
            "SELECT 1 FROM protected_roles WHERE guild_id=? AND role_id=?",
            (guild_id, role_id),
            True,
        )
    )

# ============================================================
# UI / HELPERS
# ============================================================

COLORS = {
    "main": discord.Color.from_rgb(99, 102, 241),
    "success": discord.Color.from_rgb(34, 197, 94),
    "danger": discord.Color.from_rgb(239, 68, 68),
    "warning": discord.Color.from_rgb(245, 158, 11),
    "cyan": discord.Color.from_rgb(34, 211, 238),
    "pink": discord.Color.from_rgb(236, 72, 153),
    "dark": discord.Color.from_rgb(24, 24, 32),
}


def is_admin(member) -> bool:
    return isinstance(member, discord.Member) and member.guild_permissions.administrator


def human_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"


def parse_duration(value: str, max_seconds: int = 2_419_200) -> Optional[int]:
    match = re.fullmatch(r"(\d{1,6})(s|m|h|d|w)?", str(value).strip().lower())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
    return seconds if 1 <= seconds <= max_seconds else None


def fmt_since(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        seconds = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        if seconds < 60:
            return f"{seconds}s ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes}m ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        return f"{hours // 24}d ago"
    except Exception:
        return "just now"


def shorten(text: str, limit: int = 500) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def premium_embed(title: str, description: str = "", color=None) -> discord.Embed:
    embed = discord.Embed(
        title=title,
        description=description,
        color=color or COLORS["main"],
        timestamp=datetime.now(timezone.utc),
    )
    if bot.user:
        embed.set_author(name="BLASTMC CORE", icon_url=bot.user.display_avatar.url)
    embed.set_footer(text="BLASTMC • PREMIUM CORE")
    return embed


def afk_embed(reason: str, since: str) -> discord.Embed:
    return premium_embed(
        "💤 AFK Enabled",
        f"**Reason:** {discord.utils.escape_markdown(reason)}\n**Since:** {fmt_since(since)}",
        COLORS["main"],
    )


def mention_embed(guild: discord.Guild) -> discord.Embed:
    users = db_exec("SELECT user_id FROM protected_users WHERE guild_id=?", (guild.id,), True)
    roles = db_exec("SELECT role_id FROM protected_roles WHERE guild_id=?", (guild.id,), True)
    return premium_embed(
        "🎯 MENTION GUARD",
        "Protect selected users and roles from unwanted pings.\n\n"
        f"**Protected users:** `{len(users)}`\n"
        f"**Protected roles:** `{len(roles)}`\n\n"
        "Use the menu below to manage protected targets.",
        COLORS["danger"],
    )


async def safe_delete(message: discord.Message, delay: int):
    await asyncio.sleep(delay)
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def _claim_outgoing(dedupe_key: str, window: float = 4.0) -> bool:
    """Allow one identical bot output for a short window.

    This is deliberately done before sending so an accidental second execution
    never reaches Discord. SQLite also makes the guard useful if two bot
    workers happen to share the same bot.db.
    """
    now = time.time()
    with db_lock:
        cur = db.cursor()
        row = cur.execute(
            "SELECT created_at FROM outgoing_dedupe WHERE dedupe_key=?",
            (dedupe_key,),
        ).fetchone()
        if row and now - float(row[0]) < window:
            return False
        cur.execute(
            "INSERT OR REPLACE INTO outgoing_dedupe(dedupe_key, created_at) VALUES (?, ?)",
            (dedupe_key, now),
        )
        cur.execute("DELETE FROM outgoing_dedupe WHERE created_at < ?", (now - 30.0,))
        db.commit()
    return True


def _embed_fingerprint(embed: Optional[discord.Embed]) -> str:
    if embed is None:
        return ""
    return "|".join([
        str(embed.title or ""),
        str(embed.description or ""),
        str(embed.color.value if embed.color else ""),
    ])


async def safe_send(
    channel, *, content=None, embed=None, view=None, delete_after=None,
    allowed_mentions=None, dedupe_key: Optional[str] = None
):
    # If the caller does not supply a key, identical output in the same channel
    # is considered a duplicate for a few seconds. This covers accidental
    # double execution of announcements, logs, prefix replies, etc.
    if dedupe_key is None:
        dedupe_key = (
            f"send:{getattr(channel, 'id', 0)}:"
            f"{content or ''}:"
            f"{_embed_fingerprint(embed)}"
        )
    if not await _claim_outgoing(dedupe_key):
        return None
    try:
        msg = await channel.send(
            content=content,
            embed=embed,
            view=view,
            allowed_mentions=allowed_mentions,
        )
        if delete_after:
            asyncio.create_task(safe_delete(msg, delete_after))
        return msg
    except discord.HTTPException:
        log.exception("Failed to send message")
        return None


async def respond(
    interaction: discord.Interaction,
    *,
    embed=None,
    content=None,
    view=None,
    ephemeral=False,
    allowed_mentions=None,
    delete_after: Optional[int] = None,
):
    try:
        if interaction.response.is_done():
            msg = await interaction.followup.send(
                content=content,
                embed=embed,
                view=view,
                ephemeral=ephemeral,
                wait=True,
                allowed_mentions=allowed_mentions,
            )
        else:
            await interaction.response.send_message(
                content=content,
                embed=embed,
                view=view,
                ephemeral=ephemeral,
                allowed_mentions=allowed_mentions,
            )
            msg = await interaction.original_response() if not ephemeral else None
        if delete_after and msg is not None and not ephemeral:
            asyncio.create_task(safe_delete(msg, delete_after))
        return msg
    except discord.HTTPException:
        log.exception("Interaction response failed")
        return None


async def send_user_dm(member: discord.Member, *, embed=None, content=None):
    """Send a private moderation/security notice to a member.

    DMs are best-effort: a user may have DMs disabled, so a DM failure must
    never break or duplicate the moderation action itself.
    """
    try:
        return await member.send(content=content, embed=embed, allowed_mentions=discord.AllowedMentions.none())
    except (discord.Forbidden, discord.HTTPException):
        log.info("Could not DM %s in guild %s", member.id, member.guild.id if member.guild else "DM")
        return None


async def require_admin(interaction: discord.Interaction) -> bool:
    if interaction.guild is None:
        await respond(
            interaction,
            embed=premium_embed("SERVER ONLY", "This command can only be used inside a server.", COLORS["danger"]),
            ephemeral=True,
        )
        return False
    if not is_admin(interaction.user):
        await respond(
            interaction,
            embed=premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"]),
            ephemeral=True,
        )
        return False
    return True


async def require_admin_ctx(ctx: commands.Context) -> bool:
    if ctx.guild is None:
        await safe_send(
            ctx.channel,
            embed=premium_embed("SERVER ONLY", "This command can only be used inside a server.", COLORS["danger"]),
            delete_after=8,
        )
        return False
    if not is_admin(ctx.author):
        await safe_send(
            ctx.channel,
            embed=premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"]),
            delete_after=8,
        )
        return False
    return True


async def require_bot_permission(interaction: discord.Interaction, permission: str, label: str) -> bool:
    me = interaction.guild.me if interaction.guild else None
    if not me or not getattr(me.guild_permissions, permission, False):
        await respond(
            interaction,
            embed=premium_embed("BOT PERMISSION NEEDED", f"I need **{label}** permission to do that.", COLORS["danger"]),
            ephemeral=True,
        )
        return False
    return True


async def require_bot_permission_ctx(ctx: commands.Context, permission: str, label: str) -> bool:
    me = ctx.guild.me if ctx.guild else None
    if not me or not getattr(me.guild_permissions, permission, False):
        await safe_send(
            ctx.channel,
            embed=premium_embed("BOT PERMISSION NEEDED", f"I need **{label}** permission to do that.", COLORS["danger"]),
            delete_after=8,
        )
        return False
    return True


def can_target(actor: discord.Member, target: discord.Member, bot_member: discord.Member) -> tuple[bool, str]:
    if target.id == actor.id:
        return False, "You cannot target yourself."
    if bot.user and target.id == bot.user.id:
        return False, "I cannot target myself."
    if target.id == actor.guild.owner_id:
        return False, "You cannot target the server owner."
    if actor.id != actor.guild.owner_id and target.top_role >= actor.top_role:
        return False, "That member has an equal or higher role than yours."
    if target.top_role >= bot_member.top_role:
        return False, "My bot role must be higher than the target's highest role."
    return True, ""


async def get_log_channel(guild: discord.Guild):
    row = guild_row(guild.id)
    channel_id = int(row["log_channel_id"] or 0)
    if not channel_id:
        return None
    channel = guild.get_channel(channel_id)
    return channel if isinstance(channel, discord.TextChannel) else None


async def send_log(guild: discord.Guild, title: str, description: str, color=None):
    channel = await get_log_channel(guild)
    if not channel:
        return
    me = guild.me
    if not me:
        return
    perms = channel.permissions_for(me)
    if not (perms.view_channel and perms.send_messages and perms.embed_links):
        return
    await safe_send(
        channel,
        embed=premium_embed(title, description, color or COLORS["dark"]),
        dedupe_key=f"log:{guild.id}:{channel.id}:{title}:{description}",
    )

# ============================================================
# DUPLICATE-PROTECTION
# ============================================================

# on_message should normally arrive once. This guard makes the bot idempotent
# if Discord/reconnect timing ever causes the same message event to be seen twice.
_recent_message_ids: set[int] = set()
_message_ids_lock = asyncio.Lock()

# Interaction IDs are unique. This prevents accidental re-processing of the same
# interaction by our own code if it is ever delivered twice.
_recent_interaction_ids: set[int] = set()
_interaction_ids_lock = asyncio.Lock()


async def claim_message(message_id: int) -> bool:
    async with _message_ids_lock:
        if message_id in _recent_message_ids:
            return False
        _recent_message_ids.add(message_id)
        if len(_recent_message_ids) > 12000:
            _recent_message_ids.clear()
            _recent_message_ids.add(message_id)
        return True


async def claim_interaction(interaction_id: int) -> bool:
    async with _interaction_ids_lock:
        if interaction_id in _recent_interaction_ids:
            return False
        _recent_interaction_ids.add(interaction_id)
        if len(_recent_interaction_ids) > 12000:
            _recent_interaction_ids.clear()
            _recent_interaction_ids.add(interaction_id)
        return True

# ============================================================
# MENTION GUARD — ONLY DROPDOWN/MENU
# ============================================================

class MentionSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="Add Protected User", value="add_user", emoji="👤"),
            discord.SelectOption(label="Remove Protected User", value="remove_user", emoji="➖"),
            discord.SelectOption(label="Add Protected Role", value="add_role", emoji="🛡️"),
            discord.SelectOption(label="Remove Protected Role", value="remove_role", emoji="➖"),
            discord.SelectOption(label="View Protected List", value="list", emoji="📋"),
        ]
        super().__init__(
            placeholder="Choose an action…",
            min_values=1,
            max_values=1,
            options=options,
        )

    async def callback(self, interaction: discord.Interaction):
        if not await claim_interaction(interaction.id):
            return
        if not await require_admin(interaction):
            return

        action = self.values[0]
        if action == "list":
            users = db_exec(
                "SELECT user_id FROM protected_users WHERE guild_id=? ORDER BY user_id",
                (interaction.guild.id,),
                True,
            )
            roles = db_exec(
                "SELECT role_id FROM protected_roles WHERE guild_id=? ORDER BY role_id",
                (interaction.guild.id,),
                True,
            )
            user_text = "\n".join(f"• <@{r['user_id']}>" for r in users[:20]) or "• None"
            role_text = "\n".join(f"• <@&{r['role_id']}>" for r in roles[:20]) or "• None"
            await respond(
                interaction,
                embed=premium_embed("🎯 PROTECTED LIST", f"**Users**\n{user_text}\n\n**Roles**\n{role_text}"),
                ephemeral=True,
            )
            return

        await interaction.response.send_modal(ProtectedIDModal(action))


class MentionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(MentionSelect())


class ProtectedIDModal(discord.ui.Modal):
    def __init__(self, action: str):
        self.action = action
        super().__init__(title="Mention Guard")
        self.target = discord.ui.TextInput(
            label="Discord ID",
            placeholder="Paste a user or role ID",
            min_length=2,
            max_length=30,
            required=True,
        )
        self.add_item(self.target)

    async def on_submit(self, interaction: discord.Interaction):
        if not await claim_interaction(interaction.id):
            return
        if not await require_admin(interaction):
            return

        try:
            target_id = int(str(self.target.value).strip())
        except ValueError:
            await respond(
                interaction,
                embed=premium_embed("INVALID ID", "Use a numeric Discord ID.", COLORS["danger"]),
                ephemeral=True,
            )
            return

        if self.action == "add_user":
            if not interaction.guild.get_member(target_id):
                await respond(interaction, embed=premium_embed("USER NOT FOUND", "That user is not currently a member of this server.", COLORS["danger"]), ephemeral=True)
                return
            db_exec("INSERT OR IGNORE INTO protected_users(guild_id,user_id) VALUES (?,?)", (interaction.guild.id, target_id))
            result = f"Protected user: <@{target_id}>"
        elif self.action == "remove_user":
            db_exec("DELETE FROM protected_users WHERE guild_id=? AND user_id=?", (interaction.guild.id, target_id))
            result = f"Removed protected user: <@{target_id}>"
        elif self.action == "add_role":
            role = interaction.guild.get_role(target_id)
            if not role:
                await respond(interaction, embed=premium_embed("ROLE NOT FOUND", "That role does not exist in this server.", COLORS["danger"]), ephemeral=True)
                return
            if role.is_default() or role.managed:
                await respond(interaction, embed=premium_embed("ROLE NOT USABLE", "Choose a normal server role.", COLORS["danger"]), ephemeral=True)
                return
            db_exec("INSERT OR IGNORE INTO protected_roles(guild_id,role_id) VALUES (?,?)", (interaction.guild.id, target_id))
            result = f"Protected role: {role.mention}"
        else:
            db_exec("DELETE FROM protected_roles WHERE guild_id=? AND role_id=?", (interaction.guild.id, target_id))
            result = f"Removed protected role: <@&{target_id}>"

        await respond(interaction, embed=premium_embed("MENTION GUARD UPDATED", result, COLORS["success"]), ephemeral=True)
        await send_log(interaction.guild, "MENTION GUARD UPDATED", result, COLORS["danger"])

# ============================================================
# ACTION IMPLEMENTATIONS
# ============================================================

async def slowmode_action(guild: discord.Guild, channel: discord.TextChannel, actor: discord.Member, seconds: int, *, interaction=None, ctx=None):
    me = guild.me
    if not me or not channel.permissions_for(me).manage_channels:
        embed = premium_embed("SLOWMODE FAILED", "I need **Manage Channels** in this channel.", COLORS["danger"])
    else:
        try:
            await channel.edit(slowmode_delay=seconds, reason=f"Slowmode by {actor}")
            state = "disabled" if seconds == 0 else f"{human_duration(seconds)}"
            embed = premium_embed("✦ SLOWMODE UPDATED", f"{channel.mention} slowmode is now **{state}**.", COLORS["success"])
            await send_log(
                guild,
                "SLOWMODE",
                f"Channel: {channel.mention}\nValue: `{seconds}s`\nModerator: {actor.mention}",
                COLORS["success"],
            )
        except discord.Forbidden:
            embed = premium_embed("SLOWMODE FAILED", "Discord denied the channel change.", COLORS["danger"])
        except discord.HTTPException as exc:
            embed = premium_embed("SLOWMODE FAILED", f"Discord rejected the change: `{exc}`", COLORS["danger"])

    if interaction is not None:
        await respond(interaction, embed=embed, ephemeral=True)
    elif ctx is not None:
        await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)


async def lockdown_action(guild: discord.Guild, channel: discord.TextChannel, actor: discord.Member, action: str, *, interaction=None, ctx=None):
    me = guild.me
    if not me or not channel.permissions_for(me).manage_channels:
        embed = premium_embed("LOCKDOWN FAILED", "I need **Manage Channels** in this channel.", COLORS["danger"])
    else:
        try:
            overwrite = channel.overwrites_for(guild.default_role)
            overwrite.send_messages = False if action == "lock" else None
            await channel.set_permissions(guild.default_role, overwrite=overwrite, reason=f"Lockdown by {actor}")
            locked = action == "lock"
            embed = premium_embed(
                "🔒 CHANNEL LOCKED" if locked else "🔓 CHANNEL UNLOCKED",
                f"{channel.mention} is now **{'locked' if locked else 'unlocked'}** for @everyone.",
                COLORS["danger"] if locked else COLORS["success"],
            )
            await send_log(
                guild,
                "CHANNEL LOCKDOWN",
                f"Channel: {channel.mention}\nAction: `{action}`\nModerator: {actor.mention}",
                COLORS["danger"] if locked else COLORS["success"],
            )
        except discord.Forbidden:
            embed = premium_embed("LOCKDOWN FAILED", "Discord denied the channel permission change.", COLORS["danger"])
        except discord.HTTPException as exc:
            embed = premium_embed("LOCKDOWN FAILED", f"Discord rejected the change: `{exc}`", COLORS["danger"])

    if interaction is not None:
        await respond(interaction, embed=embed, ephemeral=True)
    elif ctx is not None:
        await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)


async def announce_action(guild: discord.Guild, channel: discord.TextChannel, message: str, actor, *, interaction=None, ctx=None):
    if not isinstance(channel, discord.TextChannel):
        embed = premium_embed("INVALID CHANNEL", "Choose a normal text channel.", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return

    message = message.strip()
    if not message:
        embed = premium_embed("EMPTY ANNOUNCEMENT", "Announcement text cannot be empty.", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    if len(message) > 4000:
        embed = premium_embed("ANNOUNCEMENT TOO LONG", "Keep the announcement under 4000 characters.", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return

    me = guild.me
    perms = channel.permissions_for(me) if me else discord.Permissions.none()
    if not me or not perms.view_channel or not perms.send_messages or not perms.embed_links:
        embed = premium_embed("CHANNEL NOT READY", "I need **View Channel**, **Send Messages**, and **Embed Links** there.", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return

    try:
        # EXACTLY ONE public announcement. The dedupe gate runs before the
        # Discord API call, so an accidental second execution is suppressed.
        sent = await safe_send(
            channel,
            embed=premium_embed("📣 ANNOUNCEMENT", message, COLORS["cyan"]),
            allowed_mentions=discord.AllowedMentions(users=True, roles=True, everyone=False),
            dedupe_key=f"announce:{guild.id}:{channel.id}:{message.casefold()}",
        )
        if sent is None:
            # A None here means either Discord rejected it OR it was a duplicate.
            # Do not send a second public message.
            if interaction is not None:
                await respond(interaction, embed=premium_embed("ANNOUNCEMENT", "This announcement was already sent.", COLORS["warning"]), ephemeral=True)
            return
    except discord.Forbidden:
        embed = premium_embed("ANNOUNCEMENT FAILED", "Discord denied sending in that channel.", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    except discord.HTTPException as exc:
        embed = premium_embed("ANNOUNCEMENT FAILED", f"Discord rejected the message: `{exc}`", COLORS["danger"])
        if interaction is not None:
            await respond(interaction, embed=embed, ephemeral=True)
        else:
            await safe_send(ctx.channel, embed=embed, delete_after=ACTION_REPLY_DELETE_AFTER)
        return

    await send_log(
        guild,
        "ANNOUNCEMENT",
        f"Channel: {channel.mention}\nBy: {actor.mention}",
        COLORS["cyan"],
    )

    # Only the slash version gets an ephemeral confirmation.
    # Prefix version simply leaves the one announcement in chat.
    if interaction is not None:
        await respond(
            interaction,
            embed=premium_embed("✦ ANNOUNCEMENT SENT", f"Published in {channel.mention}.", COLORS["success"]),
            ephemeral=True,
        )


async def kick_member(guild: discord.Guild, member: discord.Member, actor: discord.Member) -> tuple[bool, str]:
    me = guild.me
    if not me:
        return False, "Bot member information is unavailable."
    ok, reason = can_target(actor, member, me)
    if not ok:
        return False, reason
    if not me.guild_permissions.kick_members:
        return False, "I need **Kick Members** permission."
    try:
        await member.kick(reason=f"{actor}: moderation action")
        return True, ""
    except discord.Forbidden:
        return False, "Discord denied the kick. Check my role hierarchy and Kick Members permission."
    except discord.HTTPException:
        return False, "Discord rejected the kick request."

# ============================================================
# SLASH COMMANDS
# ============================================================

@bot.tree.command(name="afk", description="Set your AFK status")
@app_commands.guild_only()
@app_commands.describe(reason="Why you are AFK")
async def afk_slash(interaction: discord.Interaction, reason: str = "AFK"):
    if not await claim_interaction(interaction.id):
        return
    row = afk_set(interaction.guild.id, interaction.user.id, reason)
    await respond(interaction, embed=afk_embed(row["reason"], row["since"]))


@bot.tree.command(name="afklist", description="Show members currently marked AFK")
@app_commands.guild_only()
async def afklist_slash(interaction: discord.Interaction):
    if not await claim_interaction(interaction.id):
        return
    rows = afk_list(interaction.guild.id)
    if not rows:
        text = "No members are currently AFK."
    else:
        lines = []
        for row in rows[:20]:
            member = interaction.guild.get_member(row["user_id"])
            who = member.mention if member else f"<@{row['user_id']}>"
            lines.append(f"{who} • `{shorten(row['reason'], 55)}` • {fmt_since(row['since'])}")
        if len(rows) > 20:
            lines.append(f"…and {len(rows) - 20} more.")
        text = "\n".join(lines)
    await respond(interaction, embed=premium_embed("💤 AFK LIST", text, COLORS["main"]))


@bot.tree.command(name="autoresponder", description="Add, remove or list automatic replies")
@app_commands.guild_only()
@app_commands.describe(action="Add, remove or list", trigger="Trigger text", reply="Reply text", mode="Exact or contains")
@app_commands.choices(
    action=[
        app_commands.Choice(name="Add", value="add"),
        app_commands.Choice(name="Remove", value="remove"),
        app_commands.Choice(name="List", value="list"),
    ],
    mode=[
        app_commands.Choice(name="Exact", value="exact"),
        app_commands.Choice(name="Contains", value="contains"),
    ],
)
async def autoresponder_slash(
    interaction: discord.Interaction,
    action: app_commands.Choice[str],
    trigger: Optional[str] = None,
    reply: Optional[str] = None,
    mode: Optional[app_commands.Choice[str]] = None,
):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return

    act = action.value
    if act == "list":
        rows = ar_list(interaction.guild.id)
        text = "No AutoResponders are configured." if not rows else "\n".join(
            f"`{shorten(r['trigger'], 40)}` → `{shorten(r['reply'], 70)}` • `{str(r['mode']).upper()}`"
            for r in rows[:20]
        )
        await respond(interaction, embed=premium_embed("✦ AUTORESPONDER", text, COLORS["cyan"]), ephemeral=True)
        return

    if not trigger or not trigger.strip():
        await respond(interaction, embed=premium_embed("MISSING TRIGGER", "Provide the trigger text.", COLORS["danger"]), ephemeral=True)
        return
    trigger = trigger.strip()

    if act == "remove":
        with db_lock:
            cur = db.cursor()
            cur.execute(
                "DELETE FROM autoresponders WHERE guild_id=? AND lower(trigger)=lower(?)",
                (interaction.guild.id, trigger),
            )
            removed = cur.rowcount
            db.commit()
        text = f"Removed `{trigger}`." if removed else f"No responder matched `{trigger}`."
        await respond(interaction, embed=premium_embed("AUTORESPONDER", text, COLORS["success"] if removed else COLORS["warning"]), ephemeral=True)
        return

    if not reply or not reply.strip():
        await respond(interaction, embed=premium_embed("MISSING REPLY", "Provide the reply text.", COLORS["danger"]), ephemeral=True)
        return
    if len(trigger) > 200 or len(reply) > 1800:
        await respond(interaction, embed=premium_embed("TOO LONG", "Trigger max: 200 characters. Reply max: 1800 characters.", COLORS["danger"]), ephemeral=True)
        return

    selected_mode = mode.value if mode else "exact"
    # One trigger = one responder. Replace an older entry instead of allowing
    # duplicate rows to accumulate and reply twice.
    with db_lock:
        cur = db.cursor()
        cur.execute(
            "DELETE FROM autoresponders WHERE guild_id=? AND lower(trigger)=lower(?)",
            (interaction.guild.id, trigger),
        )
        cur.execute(
            "INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES (?,?,?,?)",
            (interaction.guild.id, trigger, reply.strip(), selected_mode),
        )
        db.commit()
    await respond(
        interaction,
        embed=premium_embed(
            "AUTORESPONDER SAVED",
            f"**Trigger:** `{shorten(trigger)}`\n**Reply:** {shorten(reply, 500)}\n**Mode:** `{selected_mode.upper()}`",
            COLORS["success"],
        ),
        ephemeral=True,
    )


@bot.tree.command(name="autorole", description="Set or disable the automatic role for new members")
@app_commands.guild_only()
@app_commands.describe(role="Role to give automatically; leave empty to disable")
async def autorole_slash(interaction: discord.Interaction, role: Optional[discord.Role] = None):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    me = interaction.guild.me
    if not me or not me.guild_permissions.manage_roles:
        await respond(interaction, embed=premium_embed("BOT PERMISSION NEEDED", "I need **Manage Roles**.", COLORS["danger"]), ephemeral=True)
        return
    if role is None:
        set_guild_value(interaction.guild.id, "autorole_id", 0)
        await respond(interaction, embed=premium_embed("AUTO ROLE DISABLED", "Automatic role assignment is now off.", COLORS["warning"]), ephemeral=True)
        return
    if role.is_default() or role.managed:
        await respond(interaction, embed=premium_embed("ROLE NOT USABLE", "Choose a normal, assignable role.", COLORS["danger"]), ephemeral=True)
        return
    if role.position >= me.top_role.position:
        await respond(interaction, embed=premium_embed("ROLE TOO HIGH", "Move my bot role above the selected role first.", COLORS["danger"]), ephemeral=True)
        return
    set_guild_value(interaction.guild.id, "autorole_id", role.id)
    await respond(interaction, embed=premium_embed("AUTO ROLE ENABLED", f"New members will receive {role.mention}.", COLORS["success"]), ephemeral=True)
    await send_log(interaction.guild, "AUTO ROLE UPDATED", f"Role: {role.mention}\nBy: {interaction.user.mention}", COLORS["success"])


@bot.tree.command(name="lockdown", description="Lock or unlock the current text channel")
@app_commands.guild_only()
@app_commands.describe(action="Lock or unlock this channel")
@app_commands.choices(action=[app_commands.Choice(name="Lock", value="lock"), app_commands.Choice(name="Unlock", value="unlock")])
async def lockdown_slash(interaction: discord.Interaction, action: app_commands.Choice[str]):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if not isinstance(interaction.channel, discord.TextChannel):
        await respond(interaction, embed=premium_embed("UNSUPPORTED CHANNEL", "Use this command in a text channel.", COLORS["danger"]), ephemeral=True)
        return
    await lockdown_action(interaction.guild, interaction.channel, interaction.user, action.value, interaction=interaction)


@bot.tree.command(name="announce", description="Send one announcement to a text channel")
@app_commands.guild_only()
@app_commands.describe(channel="Target text channel", message="Announcement text")
async def announce_slash(interaction: discord.Interaction, channel: discord.TextChannel, message: str):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    await announce_action(interaction.guild, channel, message, interaction.user, interaction=interaction)


@bot.tree.command(name="say", description="Make the bot send one message")
@app_commands.guild_only()
@app_commands.describe(message="Message the bot should send")
async def say_slash(interaction: discord.Interaction, message: str):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    message = message.strip()
    if not message:
        await respond(interaction, embed=premium_embed("SAY", "Message cannot be empty.", COLORS["danger"]), ephemeral=True)
        return
    if not interaction.channel or not hasattr(interaction.channel, "send"):
        await respond(interaction, embed=premium_embed("CHANNEL ERROR", "I cannot send a message here.", COLORS["danger"]), ephemeral=True)
        return
    # Responding to the interaction itself creates exactly ONE public bot message.
    await respond(
        interaction,
        content=message,
        allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
    )


@bot.tree.command(name="userinfo", description="Show information about a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to inspect")
async def userinfo_slash(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    if not await claim_interaction(interaction.id):
        return
    member = member or interaction.user
    embed = premium_embed(f"👤 {member.display_name}", member.mention, COLORS["main"])
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="USER ID", value=f"`{member.id}`", inline=False)
    embed.add_field(name="CREATED", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    embed.add_field(name="JOINED", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "Unknown", inline=True)
    embed.add_field(name="ROLES", value=str(max(0, len(member.roles) - 1)), inline=True)
    embed.add_field(name="BOT", value="Yes" if member.bot else "No", inline=True)
    embed.add_field(name="TOP ROLE", value=member.top_role.mention if member.top_role else "None", inline=True)
    await respond(interaction, embed=embed)


@bot.tree.command(name="membercount", description="Show server member count")
@app_commands.guild_only()
async def membercount_slash(interaction: discord.Interaction):
    if not await claim_interaction(interaction.id):
        return
    guild = interaction.guild
    total = guild.member_count or len(guild.members)
    humans = sum(1 for m in guild.members if not m.bot)
    bots = sum(1 for m in guild.members if m.bot)
    await respond(interaction, embed=premium_embed("✦ MEMBER COUNT", f"**Total members:** `{total:,}`\n\n**Humans:** `{humans:,}`\n**Bots:** `{bots:,}`", COLORS["pink"]))


@bot.tree.command(name="slowmode", description="Set the current channel slowmode")
@app_commands.guild_only()
@app_commands.describe(seconds="0 to disable, up to 21600 seconds")
async def slowmode_slash(interaction: discord.Interaction, seconds: app_commands.Range[int, 0, 21600]):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if not isinstance(interaction.channel, discord.TextChannel):
        await respond(interaction, embed=premium_embed("UNSUPPORTED CHANNEL", "Slowmode is supported for text channels.", COLORS["danger"]), ephemeral=True)
        return
    await slowmode_action(interaction.guild, interaction.channel, interaction.user, int(seconds), interaction=interaction)


@bot.tree.command(name="warnings", description="View warnings for a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to inspect")
async def warnings_slash(interaction: discord.Interaction, member: discord.Member):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    rows = warning_list(interaction.guild.id, member.id)
    if not rows:
        description = f"{member.mention} has **0 warnings**."
    else:
        lines = []
        for row in rows[:15]:
            mod = interaction.guild.get_member(row["moderator_id"])
            mod_text = mod.mention if mod else f"<@{row['moderator_id']}>"
            created = datetime.fromisoformat(row["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            lines.append(
                f"`#{row['id']}` • {discord.utils.format_dt(created, 'R')}\n"
                f"**Reason:** {shorten(row['reason'], 150)} • **By:** {mod_text}"
            )
        description = f"{member.mention} has **{len(rows)} warning(s)**.\n\n" + "\n\n".join(lines)
        if len(rows) > 15:
            description += f"\n\n…and {len(rows) - 15} more."
    await respond(interaction, embed=premium_embed("⚠️ WARNINGS", description, COLORS["warning"]), ephemeral=True)


@bot.tree.command(name="warn", description="Issue a warning to a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to warn", reason="Warning reason")
async def warn_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    me = interaction.guild.me
    if not me:
        await respond(interaction, embed=premium_embed("WARN BLOCKED", "Bot member information is unavailable.", COLORS["danger"]), ephemeral=True)
        return
    ok, problem = can_target(interaction.user, member, me)
    if not ok:
        await respond(interaction, embed=premium_embed("WARN BLOCKED", problem, COLORS["danger"]), ephemeral=True)
        return

    warning_id = warning_add(interaction.guild.id, member.id, interaction.user.id, reason)
    total = len(warning_list(interaction.guild.id, member.id))
    embed = premium_embed("⚠️ WARNING ISSUED", f"{member.mention} has received a moderation warning.", COLORS["warning"])
    embed.add_field(name="REASON", value=shorten(discord.utils.escape_markdown(reason), 900), inline=False)
    embed.add_field(name="WARNING", value=f"`#{warning_id}`", inline=True)
    embed.add_field(name="TOTAL", value=f"`{total}`", inline=True)
    embed.add_field(name="MODERATOR", value=interaction.user.mention, inline=True)
    await respond(interaction, embed=embed, delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("⚠️ YOU WERE WARNED", f"You have received a moderation warning in **{interaction.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Warning:** `#{warning_id}`\n**Moderator:** {interaction.user.mention}", COLORS["warning"]))
    await send_log(interaction.guild, "WARNING ISSUED", f"Member: {member.mention}\nWarning: `#{warning_id}`\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {interaction.user.mention}", COLORS["warning"])


@bot.tree.command(name="warnings-clear", description="Clear all warnings for a member")
@app_commands.guild_only()
@app_commands.describe(member="Member whose warnings should be cleared")
async def warnings_clear_slash(interaction: discord.Interaction, member: discord.Member):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    count = warning_clear(interaction.guild.id, member.id)
    await respond(interaction, embed=premium_embed("WARNINGS CLEARED", f"Cleared `{count}` warning(s) for {member.mention}.", COLORS["success"]), ephemeral=True)
    await send_log(interaction.guild, "WARNINGS CLEARED", f"Member: {member.mention}\nModerator: {interaction.user.mention}\nCount: `{count}`", COLORS["success"])


@bot.tree.command(name="log-channel", description="Set or disable the moderation log channel")
@app_commands.guild_only()
@app_commands.describe(channel="Text channel for logs; leave empty to disable")
async def log_channel_slash(interaction: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if channel is None:
        set_guild_value(interaction.guild.id, "log_channel_id", 0)
        await respond(interaction, embed=premium_embed("LOGGING DISABLED", "The moderation log channel has been cleared.", COLORS["warning"]), ephemeral=True)
        return
    me = interaction.guild.me
    perms = channel.permissions_for(me) if me else discord.Permissions.none()
    if not (perms.view_channel and perms.send_messages and perms.embed_links):
        await respond(interaction, embed=premium_embed("LOG CHANNEL NOT READY", "I need **View Channel**, **Send Messages**, and **Embed Links** there.", COLORS["danger"]), ephemeral=True)
        return
    set_guild_value(interaction.guild.id, "log_channel_id", channel.id)
    await respond(interaction, embed=premium_embed("✦ LOG CHANNEL SAVED", f"Logs will be sent to {channel.mention}.", COLORS["success"]), ephemeral=True)
    await send_log(interaction.guild, "LOGGING ONLINE", f"Log channel: {channel.mention}\nConfigured by: {interaction.user.mention}", COLORS["success"])


@bot.tree.command(name="purge", description="Delete recent messages from the current channel")
@app_commands.guild_only()
@app_commands.describe(amount="Number of messages to delete, 1-100")
async def purge_slash(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if not isinstance(interaction.channel, discord.TextChannel):
        await respond(interaction, embed=premium_embed("UNSUPPORTED CHANNEL", "Purge is supported for text channels.", COLORS["danger"]), ephemeral=True)
        return
    if not await require_bot_permission(interaction, "manage_messages", "Manage Messages"):
        return
    try:
        deleted = await interaction.channel.purge(limit=int(amount), reason=f"Purge by {interaction.user}")
    except discord.Forbidden:
        await respond(interaction, embed=premium_embed("PURGE FAILED", "Discord denied Manage Messages/Read Message History.", COLORS["danger"]), ephemeral=True)
        return
    except discord.HTTPException as exc:
        await respond(interaction, embed=premium_embed("PURGE FAILED", f"Discord rejected the request: `{exc}`", COLORS["danger"]), ephemeral=True)
        return
    await respond(interaction, embed=premium_embed("✦ PURGE COMPLETE", f"Deleted **{len(deleted)}** message(s) from {interaction.channel.mention}.", COLORS["success"]), delete_after=PURGE_REPLY_DELETE_AFTER)
    await send_log(interaction.guild, "PURGE", f"Channel: {interaction.channel.mention}\nCount: `{len(deleted)}`\nModerator: {interaction.user.mention}", COLORS["success"])


@bot.tree.command(name="ban", description="Ban a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to ban", reason="Reason")
async def ban_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if not await require_bot_permission(interaction, "ban_members", "Ban Members"):
        return
    me = interaction.guild.me
    if not me:
        await respond(interaction, embed=premium_embed("BAN BLOCKED", "Bot member information is unavailable.", COLORS["danger"]), ephemeral=True)
        return
    ok, problem = can_target(interaction.user, member, me)
    if not ok:
        await respond(interaction, embed=premium_embed("BAN BLOCKED", problem, COLORS["danger"]), ephemeral=True)
        return
    try:
        await member.ban(reason=f"{interaction.user}: {reason}", delete_message_seconds=0)
    except discord.Forbidden:
        await respond(interaction, embed=premium_embed("BAN FAILED", "Discord denied the ban. Check role hierarchy and Ban Members permission.", COLORS["danger"]), ephemeral=True)
        return
    except discord.HTTPException:
        await respond(interaction, embed=premium_embed("BAN FAILED", "Discord rejected the ban request.", COLORS["danger"]), ephemeral=True)
        return
    await respond(interaction, embed=premium_embed("🔨 MEMBER BANNED", f"{member.mention} was banned.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["danger"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("🔨 YOU WERE BANNED", f"You were banned from **{interaction.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {interaction.user.mention}", COLORS["danger"]))
    await send_log(interaction.guild, "MEMBER BANNED", f"Member: {member.mention}\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {interaction.user.mention}", COLORS["danger"])


@bot.tree.command(name="kick", description="Kick a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to kick", reason="Reason")
async def kick_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    me = interaction.guild.me
    if not me:
        await respond(interaction, embed=premium_embed("KICK BLOCKED", "Bot member information is unavailable.", COLORS["danger"]), ephemeral=True)
        return
    if not me.guild_permissions.kick_members:
        await respond(interaction, embed=premium_embed("BOT PERMISSION NEEDED", "I need **Kick Members** permission.", COLORS["danger"]), ephemeral=True)
        return
    ok, problem = can_target(interaction.user, member, me)
    if not ok:
        await respond(interaction, embed=premium_embed("KICK BLOCKED", problem, COLORS["danger"]), ephemeral=True)
        return
    try:
        await member.kick(reason=f"{interaction.user}: {reason}")
    except discord.Forbidden:
        await respond(interaction, embed=premium_embed("KICK FAILED", "Discord denied the kick. Check my role hierarchy and Kick Members permission.", COLORS["danger"]), ephemeral=True)
        return
    except discord.HTTPException:
        await respond(interaction, embed=premium_embed("KICK FAILED", "Discord rejected the kick request.", COLORS["danger"]), ephemeral=True)
        return
    await respond(interaction, embed=premium_embed("👢 MEMBER KICKED", f"{member.mention} was kicked.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["warning"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("👢 YOU WERE KICKED", f"You were kicked from **{interaction.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {interaction.user.mention}", COLORS["warning"]))
    await send_log(interaction.guild, "MEMBER KICKED", f"Member: {member.mention}\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {interaction.user.mention}", COLORS["warning"])


@bot.tree.command(name="timeout", description="Timeout a member")
@app_commands.guild_only()
@app_commands.describe(member="Member to timeout", duration="10s, 10m, 1h, 1d or 1w", reason="Reason")
async def timeout_slash(interaction: discord.Interaction, member: discord.Member, duration: str, reason: str = "No reason provided"):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    if not await require_bot_permission(interaction, "moderate_members", "Moderate Members"):
        return
    seconds = parse_duration(duration, 2_419_200)
    if seconds is None:
        await respond(interaction, embed=premium_embed("INVALID DURATION", "Use `10s`, `10m`, `1h`, `1d` or `1w` (maximum 28 days).", COLORS["danger"]), ephemeral=True)
        return
    me = interaction.guild.me
    if not me:
        await respond(interaction, embed=premium_embed("TIMEOUT BLOCKED", "Bot member information is unavailable.", COLORS["danger"]), ephemeral=True)
        return
    ok, problem = can_target(interaction.user, member, me)
    if not ok:
        await respond(interaction, embed=premium_embed("TIMEOUT BLOCKED", problem, COLORS["danger"]), ephemeral=True)
        return
    try:
        await member.timeout(discord.utils.utcnow() + timedelta(seconds=seconds), reason=f"{interaction.user}: {reason}")
    except discord.Forbidden:
        await respond(interaction, embed=premium_embed("TIMEOUT FAILED", "Discord denied the timeout. Check Moderate Members and role hierarchy.", COLORS["danger"]), ephemeral=True)
        return
    except discord.HTTPException:
        await respond(interaction, embed=premium_embed("TIMEOUT FAILED", "Discord rejected the timeout request.", COLORS["danger"]), ephemeral=True)
        return
    await respond(interaction, embed=premium_embed("⏳ MEMBER TIMED OUT", f"{member.mention} for **{human_duration(seconds)}**.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["warning"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("⏳ YOU WERE TIMED OUT", f"You were timed out in **{interaction.guild.name}** for **{human_duration(seconds)}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {interaction.user.mention}", COLORS["warning"]))
    await send_log(interaction.guild, "MEMBER TIMED OUT", f"Member: {member.mention}\nDuration: `{human_duration(seconds)}`\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {interaction.user.mention}", COLORS["warning"])


@bot.tree.command(name="mention", description="Configure protected mentions")
@app_commands.guild_only()
async def mention_slash(interaction: discord.Interaction):
    if not await claim_interaction(interaction.id):
        return
    if not await require_admin(interaction):
        return
    await respond(interaction, embed=mention_embed(interaction.guild), view=MentionView())


@bot.tree.command(name="help", description="Show the BLASTMC command center")
@app_commands.guild_only()
async def help_slash(interaction: discord.Interaction):
    if not await claim_interaction(interaction.id):
        return
    await respond(interaction, embed=help_embed())

# ============================================================
# HELP
# ============================================================

def help_embed() -> discord.Embed:
    embed = premium_embed(
        "✦ BLASTMC COMMAND CENTER",
        "Clean utilities, automation and moderation — powered by the Premium Core.",
        COLORS["main"],
    )
    embed.add_field(name="AFK", value="`/afk` `afklist` • `$` / `!`", inline=False)
    embed.add_field(name="AUTOMATION", value="`/autoresponder` *(slash only)* `autorole` • `$` / `!`", inline=False)
    embed.add_field(name="SERVER", value="`lockdown` `announce` `say` `slowmode` `log-channel` • `$` / `!`", inline=False)
    embed.add_field(name="MEMBERS", value="`userinfo` `membercount` • `$` / `!`", inline=False)
    embed.add_field(name="MODERATION", value="`warn` `warnings` `warnings-clear` `purge` `ban` `kick` `timeout` • `$` / `!`", inline=False)
    embed.add_field(name="MENTION GUARD", value="`mention` — the only dropdown/menu.", inline=False)
    embed.add_field(name="PREFIXES", value="`$` and `!`", inline=False)
    return embed

# ============================================================
# PREFIX COMMANDS — EXACTLY ONE EXECUTION
# ============================================================

@bot.command(name="afk")
async def afk_prefix(ctx: commands.Context, *, reason: str = "AFK"):
    if not ctx.guild:
        return
    row = afk_set(ctx.guild.id, ctx.author.id, reason)
    await safe_send(ctx.channel, embed=afk_embed(row["reason"], row["since"]))


@bot.command(name="afklist")
async def afklist_prefix(ctx: commands.Context):
    if not ctx.guild:
        return
    rows = afk_list(ctx.guild.id)
    if not rows:
        text = "No members are currently AFK."
    else:
        lines = []
        for row in rows[:20]:
            member = ctx.guild.get_member(row["user_id"])
            who = member.mention if member else f"<@{row['user_id']}>"
            lines.append(f"{who} • `{shorten(row['reason'], 55)}` • {fmt_since(row['since'])}")
        if len(rows) > 20:
            lines.append(f"…and {len(rows) - 20} more.")
        text = "\n".join(lines)
    await safe_send(ctx.channel, embed=premium_embed("💤 AFK LIST", text, COLORS["main"]), delete_after=20)


@bot.command(name="autorole")
async def autorole_prefix(ctx: commands.Context, role: Optional[discord.Role] = None):
    if not await require_admin_ctx(ctx):
        return
    if not await require_bot_permission_ctx(ctx, "manage_roles", "Manage Roles"):
        return
    if role is None:
        set_guild_value(ctx.guild.id, "autorole_id", 0)
        await safe_send(ctx.channel, embed=premium_embed("AUTO ROLE DISABLED", "Automatic role assignment is now off.", COLORS["warning"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    me = ctx.guild.me
    if role.is_default() or role.managed or not me or role.position >= me.top_role.position:
        await safe_send(ctx.channel, embed=premium_embed("ROLE NOT USABLE", "Choose a normal role below my bot role.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    set_guild_value(ctx.guild.id, "autorole_id", role.id)
    await safe_send(ctx.channel, embed=premium_embed("AUTO ROLE ENABLED", f"New members receive {role.mention}.", COLORS["success"]), delete_after=ACTION_REPLY_DELETE_AFTER)
    await send_log(ctx.guild, "AUTO ROLE UPDATED", f"Role: {role.mention}\nBy: {ctx.author.mention}", COLORS["success"])


@bot.command(name="lockdown")
async def lockdown_prefix(ctx: commands.Context, action: str = "lock"):
    if not await require_admin_ctx(ctx):
        return
    if not isinstance(ctx.channel, discord.TextChannel):
        return
    action = action.strip().lower()
    if action not in {"lock", "unlock"}:
        await safe_send(ctx.channel, embed=premium_embed("LOCKDOWN FORMAT", "Use `lock` or `unlock`.", COLORS["warning"]), delete_after=10)
        return
    await lockdown_action(ctx.guild, ctx.channel, ctx.author, action, ctx=ctx)


@bot.command(name="announce")
async def announce_prefix(ctx: commands.Context, channel: discord.TextChannel, *, message: str):
    if not await require_admin_ctx(ctx):
        return
    await announce_action(ctx.guild, channel, message, ctx.author, ctx=ctx)


@bot.command(name="say")
async def say_prefix(ctx: commands.Context, *, message: str = ""):
    if not await require_admin_ctx(ctx):
        return
    message = message.strip()
    if not message:
        await safe_send(ctx.channel, embed=premium_embed("SAY FORMAT", "Use `$say your message` or `!say your message`.", COLORS["warning"]), delete_after=8)
        return
    try:
        await safe_send(
            ctx.channel,
            content=message,
            allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
            dedupe_key=f"say:{ctx.message.id}",
        )
    except discord.Forbidden:
        await safe_send(ctx.channel, embed=premium_embed("SEND FAILED", "I need **Send Messages** here.", COLORS["danger"]), delete_after=8)


@bot.command(name="userinfo")
async def userinfo_prefix(ctx: commands.Context, member: Optional[discord.Member] = None):
    if not ctx.guild:
        return
    member = member or ctx.author
    embed = premium_embed(f"👤 {member.display_name}", member.mention, COLORS["main"])
    embed.set_thumbnail(url=member.display_avatar.url)
    embed.add_field(name="USER ID", value=f"`{member.id}`", inline=False)
    embed.add_field(name="CREATED", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    embed.add_field(name="JOINED", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "Unknown", inline=True)
    embed.add_field(name="ROLES", value=str(max(0, len(member.roles) - 1)), inline=True)
    embed.add_field(name="BOT", value="Yes" if member.bot else "No", inline=True)
    embed.add_field(name="TOP ROLE", value=member.top_role.mention if member.top_role else "None", inline=True)
    await safe_send(ctx.channel, embed=embed)


@bot.command(name="membercount")
async def membercount_prefix(ctx: commands.Context):
    if not ctx.guild:
        return
    total = ctx.guild.member_count or len(ctx.guild.members)
    humans = sum(1 for m in ctx.guild.members if not m.bot)
    bots = sum(1 for m in ctx.guild.members if m.bot)
    await safe_send(ctx.channel, embed=premium_embed("✦ MEMBER COUNT", f"**Total members:** `{total:,}`\n\n**Humans:** `{humans:,}`\n**Bots:** `{bots:,}`", COLORS["pink"]))


@bot.command(name="slowmode")
async def slowmode_prefix(ctx: commands.Context, seconds: str = ""):
    if not await require_admin_ctx(ctx):
        return
    if not seconds:
        await safe_send(ctx.channel, embed=premium_embed("SLOWMODE FORMAT", "Use `$slowmode 5` or `$slowmode 0`.", COLORS["warning"]), delete_after=10)
        return
    try:
        value = int(seconds)
    except ValueError:
        await safe_send(ctx.channel, embed=premium_embed("INVALID VALUE", "Use a number from `0` to `21600` seconds.", COLORS["danger"]), delete_after=10)
        return
    if not 0 <= value <= 21600 or not isinstance(ctx.channel, discord.TextChannel):
        await safe_send(ctx.channel, embed=premium_embed("INVALID VALUE", "Use a text channel and `0` to `21600` seconds.", COLORS["danger"]), delete_after=10)
        return
    await slowmode_action(ctx.guild, ctx.channel, ctx.author, value, ctx=ctx)


@bot.command(name="log-channel")
async def log_channel_prefix(ctx: commands.Context, channel: Optional[discord.TextChannel] = None):
    if not await require_admin_ctx(ctx):
        return
    if channel is None:
        set_guild_value(ctx.guild.id, "log_channel_id", 0)
        await safe_send(ctx.channel, embed=premium_embed("LOGGING DISABLED", "The moderation log channel has been cleared.", COLORS["warning"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    perms = channel.permissions_for(ctx.guild.me)
    if not (perms.view_channel and perms.send_messages and perms.embed_links):
        await safe_send(ctx.channel, embed=premium_embed("LOG CHANNEL NOT READY", "I need **View Channel**, **Send Messages**, and **Embed Links** there.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    set_guild_value(ctx.guild.id, "log_channel_id", channel.id)
    await safe_send(ctx.channel, embed=premium_embed("✦ LOG CHANNEL SAVED", f"Logs will be sent to {channel.mention}.", COLORS["success"]), delete_after=ACTION_REPLY_DELETE_AFTER)
    await send_log(ctx.guild, "LOGGING ONLINE", f"Log channel: {channel.mention}\nConfigured by: {ctx.author.mention}", COLORS["success"])


@bot.command(name="warn")
async def warn_prefix(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx):
        return
    me = ctx.guild.me
    if not me:
        return
    ok, problem = can_target(ctx.author, member, me)
    if not ok:
        await safe_send(ctx.channel, embed=premium_embed("WARN BLOCKED", problem, COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    warning_id = warning_add(ctx.guild.id, member.id, ctx.author.id, reason)
    total = len(warning_list(ctx.guild.id, member.id))
    embed = premium_embed("⚠️ WARNING ISSUED", f"{member.mention} has received a moderation warning.", COLORS["warning"])
    embed.add_field(name="REASON", value=shorten(discord.utils.escape_markdown(reason), 900), inline=False)
    embed.add_field(name="WARNING", value=f"`#{warning_id}`", inline=True)
    embed.add_field(name="TOTAL", value=f"`{total}`", inline=True)
    embed.add_field(name="MODERATOR", value=ctx.author.mention, inline=True)
    await safe_send(ctx.channel, embed=embed, delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("⚠️ WARNING ISSUED", f"You have received a moderation warning in **{ctx.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Warning:** `#{warning_id}`\n**Moderator:** {ctx.author.mention}", COLORS["warning"]))
    await send_log(ctx.guild, "WARNING ISSUED", f"Member: {member.mention}\nWarning: `#{warning_id}`\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {ctx.author.mention}", COLORS["warning"])


@bot.command(name="warnings")
async def warnings_prefix(ctx: commands.Context, member: discord.Member):
    if not await require_admin_ctx(ctx):
        return
    rows = warning_list(ctx.guild.id, member.id)
    if not rows:
        text = f"{member.mention} has **0 warnings**."
    else:
        lines = []
        for row in rows[:15]:
            mod = ctx.guild.get_member(row["moderator_id"])
            mod_text = mod.mention if mod else f"<@{row['moderator_id']}>"
            created = datetime.fromisoformat(row["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            lines.append(f"`#{row['id']}` • {discord.utils.format_dt(created, 'R')}\n**Reason:** {shorten(row['reason'], 150)} • **By:** {mod_text}")
        text = f"{member.mention} has **{len(rows)} warning(s)**.\n\n" + "\n\n".join(lines)
        if len(rows) > 15:
            text += f"\n\n…and {len(rows) - 15} more."
    await safe_send(ctx.channel, embed=premium_embed("⚠️ WARNINGS", text, COLORS["warning"]), delete_after=30)


@bot.command(name="warnings-clear")
async def warnings_clear_prefix(ctx: commands.Context, member: discord.Member):
    if not await require_admin_ctx(ctx):
        return
    count = warning_clear(ctx.guild.id, member.id)
    await safe_send(ctx.channel, embed=premium_embed("WARNINGS CLEARED", f"Cleared `{count}` warning(s) for {member.mention}.", COLORS["success"]), delete_after=ACTION_REPLY_DELETE_AFTER)
    await send_log(ctx.guild, "WARNINGS CLEARED", f"Member: {member.mention}\nModerator: {ctx.author.mention}\nCount: `{count}`", COLORS["success"])


@bot.command(name="purge")
async def purge_prefix(ctx: commands.Context, amount: int):
    if not await require_admin_ctx(ctx):
        return
    if not isinstance(ctx.channel, discord.TextChannel):
        return
    if not await require_bot_permission_ctx(ctx, "manage_messages", "Manage Messages"):
        return
    if not 1 <= amount <= 100:
        await safe_send(ctx.channel, embed=premium_embed("INVALID AMOUNT", "Choose a number from `1` to `100`.", COLORS["danger"]), delete_after=10)
        return
    try:
        deleted = await ctx.channel.purge(limit=amount, reason=f"Purge by {ctx.author}")
    except discord.Forbidden:
        await safe_send(ctx.channel, embed=premium_embed("PURGE FAILED", "Discord denied Manage Messages/Read Message History.", COLORS["danger"]), delete_after=10)
        return
    await safe_send(ctx.channel, embed=premium_embed("✦ PURGE COMPLETE", f"Deleted **{len(deleted)}** message(s).", COLORS["success"]), delete_after=PURGE_REPLY_DELETE_AFTER)
    await send_log(ctx.guild, "PURGE", f"Channel: {ctx.channel.mention}\nCount: `{len(deleted)}`\nModerator: {ctx.author.mention}", COLORS["success"])


@bot.command(name="ban")
async def ban_prefix(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx):
        return
    if not await require_bot_permission_ctx(ctx, "ban_members", "Ban Members"):
        return
    me = ctx.guild.me
    if not me:
        return
    ok, problem = can_target(ctx.author, member, me)
    if not ok:
        await safe_send(ctx.channel, embed=premium_embed("BAN BLOCKED", problem, COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    try:
        await member.ban(reason=f"{ctx.author}: {reason}", delete_message_seconds=0)
    except discord.Forbidden:
        await safe_send(ctx.channel, embed=premium_embed("BAN FAILED", "Check Ban Members permission and role hierarchy.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    except discord.HTTPException:
        await safe_send(ctx.channel, embed=premium_embed("BAN FAILED", "Discord rejected the ban request.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    await safe_send(ctx.channel, embed=premium_embed("🔨 MEMBER BANNED", f"{member.mention} was banned.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["danger"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("🔨 YOU WERE BANNED", f"You were banned from **{ctx.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {ctx.author.mention}", COLORS["danger"]))
    await send_log(ctx.guild, "MEMBER BANNED", f"Member: {member.mention}\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {ctx.author.mention}", COLORS["danger"])


@bot.command(name="kick")
async def kick_prefix(ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx):
        return
    ok, problem = await kick_member(ctx.guild, member, ctx.author)
    if not ok:
        await safe_send(ctx.channel, embed=premium_embed("KICK FAILED", problem, COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    await safe_send(ctx.channel, embed=premium_embed("👢 MEMBER KICKED", f"{member.mention} was kicked.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["warning"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("👢 YOU WERE KICKED", f"You were kicked from **{ctx.guild.name}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {ctx.author.mention}", COLORS["warning"]))
    await send_log(ctx.guild, "MEMBER KICKED", f"Member: {member.mention}\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {ctx.author.mention}", COLORS["warning"])


@bot.command(name="timeout")
async def timeout_prefix(ctx: commands.Context, member: discord.Member, duration: str, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx):
        return
    if not await require_bot_permission_ctx(ctx, "moderate_members", "Moderate Members"):
        return
    seconds = parse_duration(duration, 2_419_200)
    if seconds is None:
        await safe_send(ctx.channel, embed=premium_embed("INVALID DURATION", "Use `10s`, `10m`, `1h`, `1d` or `1w` (max 28 days).", COLORS["danger"]), delete_after=10)
        return
    me = ctx.guild.me
    if not me:
        return
    ok, problem = can_target(ctx.author, member, me)
    if not ok:
        await safe_send(ctx.channel, embed=premium_embed("TIMEOUT BLOCKED", problem, COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    try:
        await member.timeout(discord.utils.utcnow() + timedelta(seconds=seconds), reason=f"{ctx.author}: {reason}")
    except discord.Forbidden:
        await safe_send(ctx.channel, embed=premium_embed("TIMEOUT FAILED", "Check Moderate Members permission and role hierarchy.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    except discord.HTTPException:
        await safe_send(ctx.channel, embed=premium_embed("TIMEOUT FAILED", "Discord rejected the timeout request.", COLORS["danger"]), delete_after=ACTION_REPLY_DELETE_AFTER)
        return
    await safe_send(ctx.channel, embed=premium_embed("⏳ MEMBER TIMED OUT", f"{member.mention} for **{human_duration(seconds)}**.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["warning"]), delete_after=MODERATION_REPLY_DELETE_AFTER)
    await send_user_dm(member, embed=premium_embed("⏳ YOU WERE TIMED OUT", f"You were timed out in **{ctx.guild.name}** for **{human_duration(seconds)}**.\n\n**Reason:** {discord.utils.escape_markdown(reason)}\n**Moderator:** {ctx.author.mention}", COLORS["warning"]))
    await send_log(ctx.guild, "MEMBER TIMED OUT", f"Member: {member.mention}\nDuration: `{human_duration(seconds)}`\nReason: {discord.utils.escape_markdown(reason)}\nModerator: {ctx.author.mention}", COLORS["warning"])


@bot.command(name="mention")
async def mention_prefix(ctx: commands.Context):
    if not await require_admin_ctx(ctx):
        return
    await safe_send(ctx.channel, embed=mention_embed(ctx.guild), view=MentionView())


@bot.command(name="help")
async def help_prefix(ctx: commands.Context):
    await safe_send(ctx.channel, embed=help_embed())

# ============================================================
# MEMBER JOIN — AUTOROLE ONLY
# ============================================================

@bot.event
async def on_member_join(member: discord.Member):
    ensure_guild(member.guild.id)
    row = guild_row(member.guild.id)
    role_id = int(row["autorole_id"] or 0)
    if not role_id:
        return

    role = member.guild.get_role(role_id)
    me = member.guild.me
    if not role or not me:
        return

    if role.is_default() or role.managed:
        log.warning("AutoRole disabled/invalid in %s: role=%s", member.guild.name, role_id)
        return
    if not me.guild_permissions.manage_roles:
        log.warning("AutoRole needs Manage Roles in %s", member.guild.name)
        return
    if role.position >= me.top_role.position:
        log.warning("AutoRole role is too high in %s: role=%s bot_top=%s", member.guild.name, role.position, me.top_role.position)
        return

    try:
        await member.add_roles(role, reason="BLASTMC Auto Role")
        log.info("AutoRole applied: %s -> %s in %s", member, role.name, member.guild.name)
        await send_log(member.guild, "AUTO ROLE APPLIED", f"Member: {member.mention}\nRole: {role.mention}", COLORS["success"])
    except discord.Forbidden:
        log.warning("AutoRole permission failure in %s", member.guild.name)
    except discord.HTTPException:
        log.exception("AutoRole failed in %s", member.guild.name)

# ============================================================
# MESSAGE PIPELINE
# ============================================================

ar_cooldowns: dict[tuple[int, int], float] = {}


async def handle_protected_mention(message: discord.Message, targets: list[str]):
    # Delete the user's message FIRST, then show one warning for 30 seconds.
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

    unique_targets = list(dict.fromkeys(targets))
    embed = premium_embed(
        "🚫 DONT PING HIGH STAFF",
        f"👤 **Who pinged:** You\n🎯 **Target:** {', '.join(unique_targets)}\n\nYour message was removed because protected staff were pinged.",
        COLORS["danger"],
    )
    # Mention Guard is intentionally private: no warning message is posted in chat.
    await send_user_dm(message.author, embed=embed)
    await send_log(
        message.guild,
        "PROTECTED MENTION BLOCKED",
        f"Who: {message.author.mention}\nTarget: {', '.join(unique_targets)}",
        COLORS["danger"],
    )


_recent_bot_outputs: dict[tuple[int, str], float] = {}
_bot_output_lock = asyncio.Lock()


def _message_output_fingerprint(message: discord.Message) -> str:
    parts = [message.content or ""]
    for embed in message.embeds:
        parts.append(_embed_fingerprint(embed))
    return "|".join(parts)


async def _claim_bot_output_message(message: discord.Message) -> bool:
    # If two copies of the bot/process accidentally publish the same output,
    # keep the first and remove the later copy. This is the final safety net.
    key = (message.channel.id, _message_output_fingerprint(message))
    now = time.time()
    async with _bot_output_lock:
        old = _recent_bot_outputs.get(key)
        if old is not None and now - old < 6.0:
            try:
                await message.delete()
            except (discord.NotFound, discord.Forbidden, discord.HTTPException):
                pass
            return False
        _recent_bot_outputs[key] = now
        if len(_recent_bot_outputs) > 5000:
            cutoff = now - 30.0
            for k, ts in list(_recent_bot_outputs.items()):
                if ts < cutoff:
                    _recent_bot_outputs.pop(k, None)
        return True


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        if bot.user and message.author.id == bot.user.id:
            await _claim_bot_output_message(message)
        return
    if not await claim_message(message.id):
        return

    if message.guild is None:
        await bot.process_commands(message)
        return

    content = message.content.strip()
    lower_content = content.casefold()
    is_prefix_command = content.startswith(PREFIXES)
    is_afk_command = lower_content == "$afk" or lower_content == "!afk" or lower_content.startswith("$afk ") or lower_content.startswith("!afk ")

    # 1) Protected mention has highest priority.
    targets: list[str] = []
    for member in message.mentions:
        if protected_user(message.guild.id, member.id):
            targets.append(member.mention)
    for role in message.role_mentions:
        if protected_role(message.guild.id, role.id):
            targets.append(role.mention)
    if targets:
        await handle_protected_mention(message, targets)
        return

    # 2) AFK replies.
    for member in message.mentions:
        if member.bot:
            continue
        row = afk_get(message.guild.id, member.id)
        if row:
            embed = premium_embed(
                "💤 AFK",
                f"{member.mention} is currently AFK.\n**Reason:** {discord.utils.escape_markdown(row['reason'])}\n**Since:** {fmt_since(row['since'])}",
                COLORS["main"],
            )
            await safe_send(message.channel, embed=embed, delete_after=AFK_REPLY_DELETE_AFTER)

    # AFK is removed only by a normal message, not by $afk/!afk itself.
    own_afk = afk_get(message.guild.id, message.author.id)
    if own_afk and not is_afk_command:
        afk_remove(message.guild.id, message.author.id)
        await safe_send(message.channel, content=f"👋 {message.author.mention} is no longer AFK.", delete_after=8)

    # 3) AutoResponder only on normal text, never on prefix commands.
    if content and not is_prefix_command:
        now = asyncio.get_running_loop().time()
        seen_triggers: set[str] = set()
        for row in ar_list(message.guild.id):
            trigger = str(row["trigger"]).strip()
            if not trigger:
                continue
            trigger_key = trigger.casefold()
            if trigger_key in seen_triggers:
                continue
            seen_triggers.add(trigger_key)
            matched = lower_content == trigger_key if row["mode"] == "exact" else trigger_key in lower_content
            if not matched:
                continue

            key = (message.guild.id, int(row["id"]))
            if now - ar_cooldowns.get(key, 0.0) < 2.0:
                break
            ar_cooldowns[key] = now

            reply = (
                str(row["reply"])
                .replace("{user}", message.author.mention)
                .replace("{server}", message.guild.name)
                .replace("{membercount}", f"{message.guild.member_count or len(message.guild.members):,}")
            )
            await safe_send(
                message.channel,
                content=reply,
                allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False),
            )
            # One responder max per message.
            break

    # 4) Prefix commands are processed exactly once, then the invocation is removed.
    if is_prefix_command:
        await bot.process_commands(message)
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

# ============================================================
# ERROR HANDLING
# ============================================================

@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandNotFound):
        return
    original = getattr(error, "original", error)

    if isinstance(original, commands.MissingRequiredArgument):
        await safe_send(ctx.channel, embed=premium_embed("MISSING INPUT", "Check the command format and try again.", COLORS["warning"]), delete_after=10)
        return
    if isinstance(original, (commands.BadArgument, commands.MessageNotFound, commands.MemberNotFound, commands.RoleNotFound, commands.ChannelNotFound)):
        await safe_send(ctx.channel, embed=premium_embed("INVALID INPUT", "I could not find or understand one of the arguments.", COLORS["danger"]), delete_after=10)
        return

    log.exception("Prefix command error: %s", original)
    await safe_send(ctx.channel, embed=premium_embed("COMMAND ERROR", "The command failed. Check Render Logs for the exact error.", COLORS["danger"]), delete_after=12)


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    original = getattr(error, "original", error)
    if isinstance(original, app_commands.errors.TransformerError):
        text = "One of the inputs is invalid or points to an unavailable Discord object."
    elif isinstance(original, app_commands.errors.CheckFailure):
        text = "You cannot use this command here."
    else:
        text = "The command failed. Check Render Logs for the exact error."
        log.exception("Slash command error: %s", original)
    await respond(interaction, embed=premium_embed("COMMAND ERROR", text, COLORS["danger"]), ephemeral=True)

# ============================================================
# SLASH SYNC
# ============================================================

_sync_lock = asyncio.Lock()
_synced_once = False


async def clear_old_guild_commands(guild: discord.Guild):
    """Remove old guild-scoped commands left by previous versions."""
    try:
        bot.tree.clear_commands(guild=guild)
        await bot.tree.sync(guild=guild)
        log.info("Cleared old guild-specific slash commands in %s", guild.name)
    except Exception:
        log.exception("Could not clear old guild slash commands in %s", guild.name)


@bot.event
async def on_guild_join(guild: discord.Guild):
    ensure_guild(guild.id)
    await clear_old_guild_commands(guild)


@bot.event
async def on_ready():
    global _synced_once
    db_init()

    async with _sync_lock:
        if not _synced_once:
            # Remove old guild-scoped copies first.
            for guild in bot.guilds:
                ensure_guild(guild.id)
                await clear_old_guild_commands(guild)

            # Register the current command list once, globally.
            try:
                synced = await bot.tree.sync()
                log.info("Global slash sync: %s current command(s)", len(synced))
            except Exception:
                log.exception("Global slash sync failed")
            _synced_once = True

    for guild in bot.guilds:
        me = guild.me
        if me:
            missing = [
                label
                for label, value in {
                    "View Channel": me.guild_permissions.view_channel,
                    "Send Messages": me.guild_permissions.send_messages,
                    "Embed Links": me.guild_permissions.embed_links,
                    "Read Message History": me.guild_permissions.read_message_history,
                    "Manage Messages": me.guild_permissions.manage_messages,
                    "Manage Channels": me.guild_permissions.manage_channels,
                    "Manage Roles": me.guild_permissions.manage_roles,
                    "Kick Members": me.guild_permissions.kick_members,
                    "Ban Members": me.guild_permissions.ban_members,
                    "Moderate Members": me.guild_permissions.moderate_members,
                }.items()
                if not value
            ]
            if missing:
                log.warning("[%s] Missing bot permissions: %s", guild.name, ", ".join(missing))

    log.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "unknown")
    log.info("Serving %s guild(s)", len(bot.guilds))
    log.info("Intents: message_content=%s members=%s", bot.intents.message_content, bot.intents.members)

# ============================================================
# RENDER HEALTH SERVER
# ============================================================

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"OK - BLASTMC CORE")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()

    def log_message(self, *_):
        return


def start_health_server():
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
        log.info("Health server listening on 0.0.0.0:%s", PORT)
        server.serve_forever()
    except Exception:
        log.exception("Health server failed")

# ============================================================
# START
# ============================================================

db_init()
threading.Thread(target=start_health_server, daemon=True, name="render-health").start()
bot.run(TOKEN)
