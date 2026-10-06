import os
import re
import sqlite3
import asyncio
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import discord
from discord.ext import commands
from discord import app_commands

# ============================================================
# CONFIG
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")
PREFIXES = ("!", "$")
DB_FILE = "bot.db"
PORT = int(os.getenv("PORT", "10000"))
BOT_COLOR = discord.Color.blurple()
BOT_WARNING_SECONDS = 60
MENTION_MESSAGE_DELETE_SECONDS = 10
COMMAND_ANIMATION_DELAY = 0.35

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN environment variable is missing.")

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s:%(name)s: %(message)s"
)
log = logging.getLogger("security-bot")

# ============================================================
# DATABASE
# ============================================================

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.row_factory = sqlite3.Row


def db_init():
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS guilds (
            guild_id INTEGER PRIMARY KEY,
            log_channel INTEGER DEFAULT 0,
            automod INTEGER DEFAULT 1,
            antispam INTEGER DEFAULT 1,
            antilinks INTEGER DEFAULT 0,
            antiinvite INTEGER DEFAULT 1,
            badwords INTEGER DEFAULT 0,
            anticaps INTEGER DEFAULT 0,
            antimention INTEGER DEFAULT 1,
            duplicate INTEGER DEFAULT 0,
            spam_limit INTEGER DEFAULT 6,
            mention_limit INTEGER DEFAULT 5,
            punishment TEXT DEFAULT 'delete'
        );

        CREATE TABLE IF NOT EXISTS protected_users (
            guild_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (guild_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS protected_roles (
            guild_id INTEGER,
            role_id INTEGER,
            PRIMARY KEY (guild_id, role_id)
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            guild_id INTEGER,
            user_id INTEGER,
            PRIMARY KEY (guild_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS antinuke (
            guild_id INTEGER PRIMARY KEY,
            enabled INTEGER DEFAULT 1,
            ban_protection INTEGER DEFAULT 1,
            kick_protection INTEGER DEFAULT 1,
            channel_delete INTEGER DEFAULT 1,
            channel_create INTEGER DEFAULT 0,
            role_delete INTEGER DEFAULT 1,
            role_create INTEGER DEFAULT 0,
            webhook_protection INTEGER DEFAULT 1,
            bot_protection INTEGER DEFAULT 1,
            punishment TEXT DEFAULT 'ban'
        );

        CREATE TABLE IF NOT EXISTS afk (
            guild_id INTEGER,
            user_id INTEGER,
            reason TEXT NOT NULL,
            since TEXT NOT NULL,
            PRIMARY KEY (guild_id, user_id)
        );
        """
    )
    db.commit()


def ensure_guild(guild_id: int):
    db.execute("INSERT OR IGNORE INTO guilds (guild_id) VALUES (?)", (guild_id,))
    db.execute("INSERT OR IGNORE INTO antinuke (guild_id) VALUES (?)", (guild_id,))
    db.commit()


def guild_settings(guild_id: int):
    ensure_guild(guild_id)
    return db.execute(
        "SELECT * FROM guilds WHERE guild_id=?", (guild_id,)
    ).fetchone()


def nukesettings(guild_id: int):
    ensure_guild(guild_id)
    return db.execute(
        "SELECT * FROM antinuke WHERE guild_id=?", (guild_id,)
    ).fetchone()


def set_guild(guild_id: int, column: str, value):
    allowed = {
        "log_channel", "automod", "antispam", "antilinks", "antiinvite",
        "badwords", "anticaps", "antimention", "duplicate", "spam_limit",
        "mention_limit", "punishment"
    }
    if column not in allowed:
        return
    ensure_guild(guild_id)
    db.execute(f"UPDATE guilds SET {column}=? WHERE guild_id=?", (value, guild_id))
    db.commit()


def set_nuke(guild_id: int, column: str, value):
    allowed = {
        "enabled", "ban_protection", "kick_protection", "channel_delete",
        "channel_create", "role_delete", "role_create", "webhook_protection",
        "bot_protection", "punishment"
    }
    if column not in allowed:
        return
    ensure_guild(guild_id)
    db.execute(f"UPDATE antinuke SET {column}=? WHERE guild_id=?", (value, guild_id))
    db.commit()


def is_whitelisted(guild_id: int, user_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM whitelist WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    ).fetchone() is not None


def protected_user(guild_id: int, user_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM protected_users WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    ).fetchone() is not None


def protected_role(guild_id: int, role_id: int) -> bool:
    return db.execute(
        "SELECT 1 FROM protected_roles WHERE guild_id=? AND role_id=?",
        (guild_id, role_id)
    ).fetchone() is not None


def add_protected_user(guild_id: int, user_id: int):
    db.execute(
        "INSERT OR IGNORE INTO protected_users VALUES (?,?)",
        (guild_id, user_id)
    )
    db.commit()


def remove_protected_user(guild_id: int, user_id: int):
    db.execute(
        "DELETE FROM protected_users WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    )
    db.commit()


def add_protected_role(guild_id: int, role_id: int):
    db.execute(
        "INSERT OR IGNORE INTO protected_roles VALUES (?,?)",
        (guild_id, role_id)
    )
    db.commit()


def remove_protected_role(guild_id: int, role_id: int):
    db.execute(
        "DELETE FROM protected_roles WHERE guild_id=? AND role_id=?",
        (guild_id, role_id)
    )
    db.commit()


def get_afk(guild_id: int, user_id: int):
    return db.execute(
        "SELECT * FROM afk WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    ).fetchone()


def set_afk(guild_id: int, user_id: int, reason: str):
    since = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO afk(guild_id,user_id,reason,since) VALUES (?,?,?,?) "
        "ON CONFLICT(guild_id,user_id) DO UPDATE SET reason=excluded.reason, since=excluded.since",
        (guild_id, user_id, reason, since)
    )
    db.commit()


def remove_afk(guild_id: int, user_id: int):
    db.execute(
        "DELETE FROM afk WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    )
    db.commit()

# ============================================================
# BOT
# ============================================================

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
intents.message_content = True
intents.moderation = True

bot = commands.Bot(
    command_prefix=PREFIXES,
    intents=intents,
    help_command=None,
    case_insensitive=True
)

spam_cache = defaultdict(lambda: defaultdict(deque))
duplicate_cache = defaultdict(lambda: defaultdict(deque))

LINK_RE = re.compile(r"(https?://|www\.)\S+", re.I)
INVITE_RE = re.compile(
    r"(discord\.gg/|discord\.com/invite/|discordapp\.com/invite/)\S+",
    re.I
)

BAD_WORDS = {
    "nigger", "nigga", "fuck", "fucker", "motherfucker", "bitch", "cunt"
}

# ============================================================
# GENERAL HELPERS
# ============================================================

def now():
    return datetime.now(timezone.utc)


def make_embed(title: str, description: str = "", color=BOT_COLOR):
    return discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=now()
    )


def is_admin(member) -> bool:
    return bool(
        member.guild_permissions.administrator
        or member.guild_permissions.manage_guild
    )


async def safe_delete(message):
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def delete_later(message, seconds: int):
    await asyncio.sleep(seconds)
    await safe_delete(message)


async def send_log(guild: discord.Guild, title: str, description: str, color=BOT_COLOR):
    settings = guild_settings(guild.id)
    channel_id = settings["log_channel"]
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if not channel:
        return
    try:
        await channel.send(embed=make_embed(title, description, color))
    except (discord.Forbidden, discord.HTTPException):
        pass


async def punishment(member: discord.Member, mode: str, reason: str):
    try:
        if mode == "timeout":
            await member.timeout(timedelta(minutes=10), reason=reason)
        elif mode == "kick":
            await member.kick(reason=reason)
        elif mode == "ban":
            await member.ban(reason=reason, delete_message_seconds=86400)
    except (discord.Forbidden, discord.HTTPException):
        pass


async def temp_interaction(interaction, title: str, description: str = "", color=BOT_COLOR):
    await interaction.response.send_message(
        embed=make_embed(title, description, color),
        ephemeral=True
    )


async def animated_interaction(interaction, final_embed, view=None):
    first = make_embed("⏳ Security Core", "`Loading` ▰▱▱▱▱ 20%")
    await interaction.response.send_message(embed=first)
    message = await interaction.original_response()

    await asyncio.sleep(COMMAND_ANIMATION_DELAY)
    second = make_embed("⚡ Security Core", "`Syncing modules` ▰▰▰▱▱ 60%")
    await message.edit(embed=second)

    await asyncio.sleep(COMMAND_ANIMATION_DELAY)
    await message.edit(embed=final_embed, view=view)


async def animated_prefix(ctx, final_embed, view=None):
    first = make_embed("⏳ Security Core", "`Loading` ▰▱▱▱▱ 20%")
    message = await ctx.send(embed=first)

    await asyncio.sleep(COMMAND_ANIMATION_DELAY)
    second = make_embed("⚡ Security Core", "`Syncing modules` ▰▰▰▱▱ 60%")
    await message.edit(embed=second)

    await asyncio.sleep(COMMAND_ANIMATION_DELAY)
    await message.edit(embed=final_embed, view=view)
    return message


def fmt_since(iso_value: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_value)
        return f"<t:{int(dt.timestamp())}:R>"
    except (TypeError, ValueError):
        return "just now"

# ============================================================
# EMBEDS
# ============================================================

def status_embed(guild):
    s = guild_settings(guild.id)
    n = nukesettings(guild.id)
    user_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_users WHERE guild_id=?", (guild.id,)
    ).fetchone()["c"]
    role_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_roles WHERE guild_id=?", (guild.id,)
    ).fetchone()["c"]
    afk_count = db.execute(
        "SELECT COUNT(*) AS c FROM afk WHERE guild_id=?", (guild.id,)
    ).fetchone()["c"]

    return make_embed(
        "🔐 Security Dashboard",
        f"**🛡️ AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**☢️ Anti-Nuke:** {'🟢 ON' if n['enabled'] else '🔴 OFF'}\n"
        f"**📢 Mention Protection:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**🔗 Anti-Link:** {'🟢 ON' if s['antilinks'] else '🔴 OFF'}\n"
        f"**📨 Anti-Invite:** {'🟢 ON' if s['antiinvite'] else '🔴 OFF'}\n"
        f"**💤 AFK System:** 🟢 ON\n\n"
        f"**👤 Protected Users:** `{user_count}`\n"
        f"**🎭 Protected Roles:** `{role_count}`\n"
        f"**💤 AFK Users:** `{afk_count}`\n"
        f"**📊 Log Channel:** "
        + (f"<#{s['log_channel']}>" if s["log_channel"] else "Not configured")
        + "\n\n"
        "Use the dropdown to open a security module."
    )


def automod_embed(guild):
    s = guild_settings(guild.id)
    return make_embed(
        "🛡️ AutoMod Control Panel",
        f"**Master AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**Anti Spam:** {'🟢 ON' if s['antispam'] else '🔴 OFF'}\n"
        f"**Anti Links:** {'🟢 ON' if s['antilinks'] else '🔴 OFF'}\n"
        f"**Anti Invite:** {'🟢 ON' if s['antiinvite'] else '🔴 OFF'}\n"
        f"**Bad Words:** {'🟢 ON' if s['badwords'] else '🔴 OFF'}\n"
        f"**Anti Caps:** {'🟢 ON' if s['anticaps'] else '🔴 OFF'}\n"
        f"**Anti Mention:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**Duplicate:** {'🟢 ON' if s['duplicate'] else '🔴 OFF'}\n\n"
        f"Spam limit: `{s['spam_limit']}` messages / 8 sec\n"
        f"Mention limit: `{s['mention_limit']}` mentions\n"
        f"Punishment: `{s['punishment']}`"
    )


def antinuke_embed(guild):
    s = nukesettings(guild.id)
    return make_embed(
        "☢️ Anti-Nuke Control Panel",
        f"**Master Anti-Nuke:** {'🟢 ON' if s['enabled'] else '🔴 OFF'}\n"
        f"**Ban Protection:** {'🟢' if s['ban_protection'] else '🔴'}\n"
        f"**Kick Protection:** {'🟢' if s['kick_protection'] else '🔴'}\n"
        f"**Channel Delete:** {'🟢' if s['channel_delete'] else '🔴'}\n"
        f"**Channel Create:** {'🟢' if s['channel_create'] else '🔴'}\n"
        f"**Role Delete:** {'🟢' if s['role_delete'] else '🔴'}\n"
        f"**Role Create:** {'🟢' if s['role_create'] else '🔴'}\n"
        f"**Webhook Protection:** {'🟢' if s['webhook_protection'] else '🔴'}\n"
        f"**Bot Add Protection:** {'🟢' if s['bot_protection'] else '🔴'}\n\n"
        f"Punishment: `{s['punishment']}`"
    )


def help_embed(guild):
    s = guild_settings(guild.id)
    n = nukesettings(guild.id)
    protected_users_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_users WHERE guild_id=?", (guild.id,)
    ).fetchone()["c"]
    protected_roles_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_roles WHERE guild_id=?", (guild.id,)
    ).fetchone()["c"]

    return make_embed(
        "🌐 Global Security Status",
        f"**🛡️ AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**☢️ Anti-Nuke:** {'🟢 ON' if n['enabled'] else '🔴 OFF'}\n"
        f"**📢 Mention Protection:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**💤 AFK System:** 🟢 ON\n"
        f"**👤 Protected Users:** `{protected_users_count}`\n"
        f"**🎭 Protected Roles:** `{protected_roles_count}`\n\n"
        "**Prefix Commands**\n"
        "`$help` / `!help` — Global security status\n"
        "`$security` / `!security` — Security dashboard\n"
        "`$automod` / `!automod` — AutoMod panel\n"
        "`$antinuke` / `!antinuke` — Anti-Nuke panel\n"
        "`$mention` / `!mention` — Mention Protection panel\n"
        "`$setlog #channel` / `!setlog #channel` — Set logs\n"
        "`$whitelist @user` / `!whitelist @user` — Whitelist\n"
        "`$unwhitelist @user` / `!unwhitelist @user` — Remove whitelist\n"
        "`$afk reason` / `!afk reason` — Set AFK\n\n"
        "**Slash Commands**\n"
        "`/help` · `/security` · `/automod` · `/antinuke`\n"
        "`/mention` · `/setlog` · `/whitelist` · `/unwhitelist` · `/afk`\n\n"
        "✨ **Prefixes:** `$` and `!`"
    )


def mention_embed(guild):
    users = db.execute(
        "SELECT user_id FROM protected_users WHERE guild_id=?", (guild.id,)
    ).fetchall()
    roles = db.execute(
        "SELECT role_id FROM protected_roles WHERE guild_id=?", (guild.id,)
    ).fetchall()

    user_text = []
    for row in users:
        member = guild.get_member(row["user_id"])
        user_text.append(member.mention if member else f"<@{row['user_id']}>")

    role_text = []
    for row in roles:
        role = guild.get_role(row["role_id"])
        role_text.append(role.mention if role else f"<@&{row['role_id']}>")

    return make_embed(
        "📢 Mention Protection",
        "**Protected Users:**\n"
        + ("\n".join(user_text) if user_text else "None")
        + "\n\n**Protected Roles:**\n"
        + ("\n".join(role_text) if role_text else "None")
        + "\n\n"
        "When somebody pings a protected target:\n"
        "• Their message is deleted after **10 seconds**.\n"
        "• The bot warning stays for **1 minute** and then disappears."
    )

# ============================================================
# GLOBAL DROPDOWN UI
# ============================================================

class GlobalPanelSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(
                label="Security Dashboard", value="status", emoji="🔐",
                description="View complete security status"
            ),
            discord.SelectOption(
                label="AutoMod", value="automod", emoji="🛡️",
                description="Message protection settings"
            ),
            discord.SelectOption(
                label="Anti-Nuke", value="antinuke", emoji="☢️",
                description="Server destruction protection"
            ),
            discord.SelectOption(
                label="Mention Protection", value="mention", emoji="📢",
                description="Protect high staff users and roles"
            ),
            discord.SelectOption(
                label="Help", value="help", emoji="📖",
                description="Commands and live status"
            )
        ]
        super().__init__(
            placeholder="✨ Select a security module...",
            options=options,
            custom_id="global_security_menu"
        )

    async def callback(self, interaction):
        if not interaction.guild:
            return await temp_interaction(interaction, "❌ Server Only")
        if not is_admin(interaction.user):
            return await temp_interaction(
                interaction,
                "⛔ No Permission",
                "You need **Administrator** or **Manage Server** permission.",
                discord.Color.red()
            )

        selected = self.values[0]
        if selected == "status":
            await interaction.response.edit_message(
                embed=status_embed(interaction.guild), view=MainPanelView()
            )
        elif selected == "automod":
            await interaction.response.edit_message(
                embed=automod_embed(interaction.guild), view=AutoModView()
            )
        elif selected == "antinuke":
            await interaction.response.edit_message(
                embed=antinuke_embed(interaction.guild), view=AntiNukeView()
            )
        elif selected == "mention":
            # Mention panel intentionally has no animation, as requested.
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild), view=MentionView()
            )
        else:
            await interaction.response.edit_message(
                embed=help_embed(interaction.guild), view=MainPanelView()
            )


class MainPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)
        self.add_item(GlobalPanelSelect())

    @discord.ui.button(label="Refresh", emoji="🔄", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild), view=MainPanelView()
        )

# ============================================================
# AUTOMOD UI
# ============================================================

class AutoModSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="Master AutoMod", value="automod", emoji="🛡️"),
            discord.SelectOption(label="Anti Spam", value="antispam", emoji="🚫"),
            discord.SelectOption(label="Anti Links", value="antilinks", emoji="🔗"),
            discord.SelectOption(label="Anti Invite", value="antiinvite", emoji="📨"),
            discord.SelectOption(label="Bad Words", value="badwords", emoji="🤬"),
            discord.SelectOption(label="Anti Caps", value="anticaps", emoji="🔠"),
            discord.SelectOption(label="Anti Mention", value="antimention", emoji="📢"),
            discord.SelectOption(label="Duplicate Messages", value="duplicate", emoji="♻️")
        ]
        super().__init__(
            placeholder="🛡️ Choose AutoMod protection...",
            options=options,
            custom_id="automod_select"
        )

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        key = self.values[0]
        settings = guild_settings(interaction.guild.id)
        new_value = 0 if settings[key] else 1
        set_guild(interaction.guild.id, key, new_value)
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild), view=AutoModView()
        )


class AutoModView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)
        self.add_item(AutoModSelect())

    @discord.ui.button(label="Delete Only", emoji="🗑️", style=discord.ButtonStyle.secondary)
    async def delete_only(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        set_guild(interaction.guild.id, "punishment", "delete")
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild), view=AutoModView()
        )

    @discord.ui.button(label="Timeout", emoji="⏱️", style=discord.ButtonStyle.primary)
    async def timeout_mode(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        set_guild(interaction.guild.id, "punishment", "timeout")
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild), view=AutoModView()
        )

    @discord.ui.button(label="Back", emoji="↩️", style=discord.ButtonStyle.secondary)
    async def back(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild), view=MainPanelView()
        )

# ============================================================
# ANTI-NUKE UI
# ============================================================

class AntiNukeSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="Master Anti-Nuke", value="enabled", emoji="☢️"),
            discord.SelectOption(label="Ban Protection", value="ban_protection", emoji="🔨"),
            discord.SelectOption(label="Kick Protection", value="kick_protection", emoji="👢"),
            discord.SelectOption(label="Channel Delete", value="channel_delete", emoji="🗑️"),
            discord.SelectOption(label="Channel Create", value="channel_create", emoji="📁"),
            discord.SelectOption(label="Role Delete", value="role_delete", emoji="🎭"),
            discord.SelectOption(label="Role Create", value="role_create", emoji="➕"),
            discord.SelectOption(label="Webhook Protection", value="webhook_protection", emoji="🔌"),
            discord.SelectOption(label="Bot Add Protection", value="bot_protection", emoji="🤖")
        ]
        super().__init__(
            placeholder="☢️ Choose Anti-Nuke protection...",
            options=options,
            custom_id="antinuke_select"
        )

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        key = self.values[0]
        settings = nukesettings(interaction.guild.id)
        new_value = 0 if settings[key] else 1
        set_nuke(interaction.guild.id, key, new_value)
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild), view=AntiNukeView()
        )


class AntiNukeView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)
        self.add_item(AntiNukeSelect())

    @discord.ui.button(label="Ban", emoji="🔨", style=discord.ButtonStyle.danger)
    async def ban_mode(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        set_nuke(interaction.guild.id, "punishment", "ban")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild), view=AntiNukeView()
        )

    @discord.ui.button(label="Kick", emoji="👢", style=discord.ButtonStyle.primary)
    async def kick_mode(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        set_nuke(interaction.guild.id, "punishment", "kick")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild), view=AntiNukeView()
        )

    @discord.ui.button(label="Timeout", emoji="⏱️", style=discord.ButtonStyle.secondary)
    async def timeout_mode(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        set_nuke(interaction.guild.id, "punishment", "timeout")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild), view=AntiNukeView()
        )

    @discord.ui.button(label="Back", emoji="↩️", style=discord.ButtonStyle.secondary)
    async def back(self, interaction, button):
        if not is_admin(interaction.user):
            return await temp_interaction(interaction, "⛔ No Permission")
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild), view=MainPanelView()
        )

# ============================================================
# MENTION UI - NO COMMAND ANIMATION HERE
# ============================================================

class MentionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)

        add_user_button = discord.ui.Button(
            label="Add User", emoji="👤", style=discord.ButtonStyle.primary
        )
        add_role_button = discord.ui.Button(
            label="Add Role", emoji="🎭", style=discord.ButtonStyle.primary
        )
        remove_user_button = discord.ui.Button(
            label="Remove User", emoji="🗑️", style=discord.ButtonStyle.danger
        )
        remove_role_button = discord.ui.Button(
            label="Remove Role", emoji="🗑️", style=discord.ButtonStyle.danger
        )
        back_button = discord.ui.Button(
            label="Back", emoji="↩️", style=discord.ButtonStyle.secondary
        )

        async def add_user_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_interaction(interaction, "⛔ No Permission")
            await interaction.response.send_modal(AddUserModal())

        async def add_role_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_interaction(interaction, "⛔ No Permission")
            await interaction.response.send_modal(AddRoleModal())

        async def remove_user_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_interaction(interaction, "⛔ No Permission")
            await interaction.response.send_modal(RemoveUserModal())

        async def remove_role_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_interaction(interaction, "⛔ No Permission")
            await interaction.response.send_modal(RemoveRoleModal())

        async def back_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_interaction(interaction, "⛔ No Permission")
            await interaction.response.edit_message(
                embed=status_embed(interaction.guild), view=MainPanelView()
            )

        add_user_button.callback = add_user_callback
        add_role_button.callback = add_role_callback
        remove_user_button.callback = remove_user_callback
        remove_role_button.callback = remove_role_callback
        back_button.callback = back_callback

        self.add_item(add_user_button)
        self.add_item(add_role_button)
        self.add_item(remove_user_button)
        self.add_item(remove_role_button)
        self.add_item(back_button)


class AddUserModal(discord.ui.Modal, title="Add Protected User"):
    user_id = discord.ui.TextInput(
        label="User ID",
        placeholder="Enter Discord user ID",
        required=True,
        max_length=25
    )

    async def on_submit(self, interaction):
        try:
            uid = int(self.user_id.value.strip())
            member = interaction.guild.get_member(uid)
            if not member:
                return await temp_interaction(
                    interaction, "❌ User Not Found",
                    "Make sure the user is in this server."
                )
            add_protected_user(interaction.guild.id, uid)
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild), view=MentionView()
            )
        except ValueError:
            await temp_interaction(
                interaction, "❌ Invalid ID", "Enter a numeric Discord user ID."
            )


class AddRoleModal(discord.ui.Modal, title="Add Protected Role"):
    role_id = discord.ui.TextInput(
        label="Role ID",
        placeholder="Enter Discord role ID",
        required=True,
        max_length=25
    )

    async def on_submit(self, interaction):
        try:
            rid = int(self.role_id.value.strip())
            role = interaction.guild.get_role(rid)
            if not role:
                return await temp_interaction(
                    interaction, "❌ Role Not Found",
                    "Make sure the role is in this server."
                )
            add_protected_role(interaction.guild.id, rid)
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild), view=MentionView()
            )
        except ValueError:
            await temp_interaction(
                interaction, "❌ Invalid ID", "Enter a numeric Discord role ID."
            )


class RemoveUserModal(discord.ui.Modal, title="Remove Protected User"):
    user_id = discord.ui.TextInput(
        label="User ID",
        placeholder="Enter Discord user ID",
        required=True,
        max_length=25
    )

    async def on_submit(self, interaction):
        try:
            remove_protected_user(interaction.guild.id, int(self.user_id.value.strip()))
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild), view=MentionView()
            )
        except ValueError:
            await temp_interaction(
                interaction, "❌ Invalid ID", "Enter a numeric Discord user ID."
            )


class RemoveRoleModal(discord.ui.Modal, title="Remove Protected Role"):
    role_id = discord.ui.TextInput(
        label="Role ID",
        placeholder="Enter Discord role ID",
        required=True,
        max_length=25
    )

    async def on_submit(self, interaction):
        try:
            remove_protected_role(interaction.guild.id, int(self.role_id.value.strip()))
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild), view=MentionView()
            )
        except ValueError:
            await temp_interaction(
                interaction, "❌ Invalid ID", "Enter a numeric Discord role ID."
            )

# ============================================================
# COMMANDS - SLASH + PREFIX
# ============================================================

@bot.tree.command(name="help", description="Show global security status and commands")
async def help_slash(interaction):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")
    await animated_interaction(interaction, help_embed(interaction.guild), MainPanelView())


@bot.command(name="help")
@commands.guild_only()
async def help_prefix(ctx):
    await animated_prefix(ctx, help_embed(ctx.guild), MainPanelView())


@bot.tree.command(name="security", description="Open the security dashboard")
@app_commands.default_permissions(manage_guild=True)
async def security_slash(interaction):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")
    ensure_guild(interaction.guild.id)
    await animated_interaction(interaction, status_embed(interaction.guild), MainPanelView())


@bot.command(name="security")
@commands.guild_only()
@commands.has_guild_permissions(manage_guild=True)
async def security_prefix(ctx):
    ensure_guild(ctx.guild.id)
    await animated_prefix(ctx, status_embed(ctx.guild), MainPanelView())


@bot.tree.command(name="automod", description="Open AutoMod settings")
@app_commands.default_permissions(manage_guild=True)
async def automod_slash(interaction):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")
    await animated_interaction(interaction, automod_embed(interaction.guild), AutoModView())


@bot.command(name="automod")
@commands.guild_only()
@commands.has_guild_permissions(manage_guild=True)
async def automod_prefix(ctx):
    await animated_prefix(ctx, automod_embed(ctx.guild), AutoModView())


@bot.tree.command(name="antinuke", description="Open Anti-Nuke settings")
@app_commands.default_permissions(administrator=True)
async def antinuke_slash(interaction):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")
    await animated_interaction(interaction, antinuke_embed(interaction.guild), AntiNukeView())


@bot.command(name="antinuke")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def antinuke_prefix(ctx):
    await animated_prefix(ctx, antinuke_embed(ctx.guild), AntiNukeView())


@bot.tree.command(name="mention", description="Open Mention Protection settings")
@app_commands.default_permissions(manage_guild=True)
async def mention_slash(interaction):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")
    # Intentionally no animation for mention command.
    await interaction.response.send_message(
        embed=mention_embed(interaction.guild), view=MentionView()
    )


@bot.command(name="mention")
@commands.guild_only()
@commands.has_guild_permissions(manage_guild=True)
async def mention_prefix(ctx):
    # Intentionally no animation for mention command.
    await ctx.send(embed=mention_embed(ctx.guild), view=MentionView())


@bot.tree.command(name="setlog", description="Set the security log channel")
@app_commands.describe(channel="Channel where security logs should be sent")
@app_commands.default_permissions(manage_guild=True)
async def setlog_slash(interaction, channel: discord.TextChannel):
    set_guild(interaction.guild.id, "log_channel", channel.id)
    await animated_interaction(
        interaction,
        make_embed(
            "✅ Log Channel Updated",
            f"Security logs will be sent to {channel.mention}."
        ),
        MainPanelView()
    )


@bot.command(name="setlog")
@commands.guild_only()
@commands.has_guild_permissions(manage_guild=True)
async def setlog_prefix(ctx, channel: discord.TextChannel):
    set_guild(ctx.guild.id, "log_channel", channel.id)
    await animated_prefix(
        ctx,
        make_embed(
            "✅ Log Channel Updated",
            f"Security logs will be sent to {channel.mention}."
        ),
        MainPanelView()
    )


@bot.tree.command(name="whitelist", description="Whitelist a member from Anti-Nuke")
@app_commands.describe(member="Member to whitelist")
@app_commands.default_permissions(administrator=True)
async def whitelist_slash(interaction, member: discord.Member):
    db.execute(
        "INSERT OR IGNORE INTO whitelist VALUES (?,?)",
        (interaction.guild.id, member.id)
    )
    db.commit()
    await animated_interaction(
        interaction,
        make_embed("✅ Whitelisted", f"{member.mention} is now protected from Anti-Nuke actions."),
        MainPanelView()
    )


@bot.command(name="whitelist")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def whitelist_prefix(ctx, member: discord.Member):
    db.execute(
        "INSERT OR IGNORE INTO whitelist VALUES (?,?)",
        (ctx.guild.id, member.id)
    )
    db.commit()
    await animated_prefix(
        ctx,
        make_embed("✅ Whitelisted", f"{member.mention} is now protected from Anti-Nuke actions."),
        MainPanelView()
    )


@bot.tree.command(name="unwhitelist", description="Remove a member from Anti-Nuke whitelist")
@app_commands.describe(member="Member to remove from whitelist")
@app_commands.default_permissions(administrator=True)
async def unwhitelist_slash(interaction, member: discord.Member):
    db.execute(
        "DELETE FROM whitelist WHERE guild_id=? AND user_id=?",
        (interaction.guild.id, member.id)
    )
    db.commit()
    await animated_interaction(
        interaction,
        make_embed("✅ Whitelist Removed", f"{member.mention} was removed from the Anti-Nuke whitelist."),
        MainPanelView()
    )


@bot.command(name="unwhitelist")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def unwhitelist_prefix(ctx, member: discord.Member):
    db.execute(
        "DELETE FROM whitelist WHERE guild_id=? AND user_id=?",
        (ctx.guild.id, member.id)
    )
    db.commit()
    await animated_prefix(
        ctx,
        make_embed("✅ Whitelist Removed", f"{member.mention} was removed from the Anti-Nuke whitelist."),
        MainPanelView()
    )


@bot.tree.command(name="afk", description="Set your AFK reason")
@app_commands.describe(reason="Why you are AFK")
async def afk_slash(interaction, reason: str):
    if not interaction.guild:
        return await temp_interaction(interaction, "❌ Server Only")

    clean_reason = reason.strip()
    if not clean_reason:
        return await temp_interaction(interaction, "❌ Missing Reason", "Give a reason like `sona jaa rha`.")
    if len(clean_reason) > 200:
        return await temp_interaction(interaction, "❌ Reason Too Long", "Keep the AFK reason under 200 characters.")

    set_afk(interaction.guild.id, interaction.user.id, clean_reason)
    await animated_interaction(
        interaction,
        make_embed(
            "💤 AFK Enabled",
            f"**Reason:** {discord.utils.escape_mentions(discord.utils.escape_markdown(clean_reason))}\n"
            f"**Since:** <t:{int(now().timestamp())}:R>\n\n"
            "Anyone who pings you will get your AFK status."
        ),
        MainPanelView()
    )


@bot.command(name="afk")
@commands.guild_only()
async def afk_prefix(ctx, *, reason: str = None):
    if not reason or not reason.strip():
        message = await ctx.send("❌ Usage: `$afk sona jaa rha`")
        asyncio.create_task(delete_later(message, 10))
        return

    clean_reason = reason.strip()
    if len(clean_reason) > 200:
        message = await ctx.send("❌ AFK reason must be 200 characters or less.")
        asyncio.create_task(delete_later(message, 10))
        return

    set_afk(ctx.guild.id, ctx.author.id, clean_reason)
    await animated_prefix(
        ctx,
        make_embed(
            "💤 AFK Enabled",
            f"**Reason:** {discord.utils.escape_mentions(discord.utils.escape_markdown(clean_reason))}\n"
            f"**Since:** <t:{int(now().timestamp())}:R>\n\n"
            "Anyone who pings you will get your AFK status."
        ),
        MainPanelView()
    )

# ============================================================
# AFK MESSAGE HANDLER
# ============================================================

async def process_afk(message):
    if not message.guild or message.author.bot:
        return

    # Sending a normal message removes the author's AFK.
    own_afk = get_afk(message.guild.id, message.author.id)
    if own_afk:
        remove_afk(message.guild.id, message.author.id)
        comeback = await message.channel.send(
            embed=make_embed(
                "👋 Welcome Back",
                f"{message.author.mention}, your AFK has been removed."
            )
        )
        asyncio.create_task(delete_later(comeback, 10))

    mentioned_afk = []
    seen = set()
    for member in message.mentions:
        if member.id in seen or member.id == message.author.id:
            continue
        row = get_afk(message.guild.id, member.id)
        if row:
            mentioned_afk.append((member, row))
            seen.add(member.id)

    if not mentioned_afk:
        return

    lines = []
    for member, row in mentioned_afk:
        reason = discord.utils.escape_mentions(discord.utils.escape_markdown(row["reason"]))
        lines.append(
            f"💤 {member.mention} is AFK\n"
            f"📝 **Reason:** {reason}\n"
            f"🕐 **Since:** {fmt_since(row['since'])}"
        )

    response = await message.channel.send(
        embed=make_embed("💤 AFK Notice", "\n\n".join(lines), discord.Color.orange())
    )
    asyncio.create_task(delete_later(response, 20))

# ============================================================
# MENTION PROTECTION
# ============================================================

def mention_targets(message):
    targets = []
    for member in message.mentions:
        if member.id != message.author.id and protected_user(message.guild.id, member.id):
            targets.append(("user", member))

    for role in message.role_mentions:
        if protected_role(message.guild.id, role.id):
            targets.append(("role", role))

    return targets


async def process_protected_mentions(message):
    if not message.guild or message.author.bot:
        return False

    settings = guild_settings(message.guild.id)
    if not settings["antimention"]:
        return False

    if is_admin(message.author) or is_whitelisted(message.guild.id, message.author.id):
        return False

    targets = mention_targets(message)
    if not targets:
        return False

    # Keep the offending message visible briefly, then delete it.
    asyncio.create_task(delete_later(message, MENTION_MESSAGE_DELETE_SECONDS))

    target_text = " ".join(target.mention for _, target in targets)
    warning = None
    try:
        warning = await message.channel.send(
            embed=make_embed(
                "🚫 DONT PING HIGH STAFF",
                f"👤 **Who pinged:** {message.author.mention}\n"
                f"🎯 **Target:** {target_text}",
                discord.Color.red()
            )
        )
        asyncio.create_task(delete_later(warning, BOT_WARNING_SECONDS))
    except (discord.Forbidden, discord.HTTPException):
        pass

    await send_log(
        message.guild,
        "🚫 Protected Mention Blocked",
        f"**Who pinged:** {message.author.mention}\n"
        f"**Target:** {target_text}\n"
        f"**Channel:** {message.channel.mention}\n"
        f"**Message delete:** `{MENTION_MESSAGE_DELETE_SECONDS}s`",
        discord.Color.red()
    )

    return True

# ============================================================
# AUTOMOD MESSAGE HANDLER
# ============================================================

async def process_automod(message):
    if not message.guild or message.author.bot:
        return False

    settings = guild_settings(message.guild.id)
    member = message.author

    if is_admin(member) or is_whitelisted(message.guild.id, member.id):
        return False

    if not settings["automod"]:
        return False

    reason = None
    content = message.content or ""
    lower = content.lower()

    if settings["antiinvite"] and INVITE_RE.search(content):
        reason = "Discord invite detected"

    elif settings["antilinks"] and LINK_RE.search(content):
        reason = "Link detected"

    elif settings["badwords"] and any(word in lower.split() for word in BAD_WORDS):
        reason = "Blocked word detected"

    elif settings["anticaps"] and len(content) >= 10:
        letters = [c for c in content if c.isalpha()]
        if letters and sum(c.isupper() for c in letters) / len(letters) >= 0.75:
            reason = "Excessive caps detected"

    if settings["antispam"] and not reason:
        q = spam_cache[message.guild.id][member.id]
        current = now()
        q.append(current)
        while q and (current - q[0]).total_seconds() > 8:
            q.popleft()
        if len(q) >= settings["spam_limit"]:
            reason = "Spam detected"
            q.clear()

    if settings["duplicate"] and not reason:
        q = duplicate_cache[message.guild.id][member.id]
        current = now()
        q.append((current, content[:500]))
        while q and (current - q[0][0]).total_seconds() > 10:
            q.popleft()
        same_count = sum(1 for _, text in q if text == content[:500] and text)
        if content.strip() and same_count >= 3:
            reason = "Duplicate messages detected"
            q.clear()

    if settings["antimention"] and not reason:
        mention_count = len(message.mentions) + len(message.role_mentions)
        if mention_count >= settings["mention_limit"]:
            reason = "Mass mention detected"

    if not reason:
        return False

    await safe_delete(message)
    mode = settings["punishment"]
    if mode != "delete":
        await punishment(member, mode, reason)

    await send_log(
        message.guild,
        "🛡️ AutoMod Action",
        f"**User:** {member.mention}\n"
        f"**Channel:** {message.channel.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Action:** `{mode}`",
        discord.Color.orange()
    )

    try:
        warning = await message.channel.send(
            embed=make_embed(
                "🛡️ AutoMod",
                f"{member.mention}, your message was removed.\n"
                f"**Reason:** {reason}",
                discord.Color.orange()
            )
        )
        asyncio.create_task(delete_later(warning, BOT_WARNING_SECONDS))
    except (discord.Forbidden, discord.HTTPException):
        pass

    return True

# ============================================================
# ANTI-NUKE AUDIT LOG HELPERS
# ============================================================

async def recent_audit_executor(guild, action, target_id=None):
    try:
        async for entry in guild.audit_logs(limit=8, action=action):
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            age = (now() - entry.created_at).total_seconds()
            if 0 <= age <= 15:
                return entry.user
    except (discord.Forbidden, discord.HTTPException):
        pass
    return None


async def punish_nuker(guild, user, reason):
    if not user or user.bot:
        return
    if bot.user and user.id == bot.user.id:
        return
    if is_whitelisted(guild.id, user.id):
        return
    if user.id == guild.owner_id:
        return

    settings = nukesettings(guild.id)
    if not settings["enabled"]:
        return

    try:
        member = guild.get_member(user.id) or await guild.fetch_member(user.id)
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        return

    await punishment(member, settings["punishment"], reason)
    await send_log(
        guild,
        "☢️ ANTI-NUKE ACTION",
        f"**User:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Action:** `{settings['punishment']}`",
        discord.Color.red()
    )

# ============================================================
# ANTI-NUKE EVENT LISTENERS
# ============================================================

@bot.event
async def on_guild_channel_delete(channel):
    settings = nukesettings(channel.guild.id)
    if not settings["enabled"] or not settings["channel_delete"]:
        return
    user = await recent_audit_executor(
        channel.guild, discord.AuditLogAction.channel_delete, channel.id
    )
    await punish_nuker(channel.guild, user, f"Deleted channel `{channel.name}`")


@bot.event
async def on_guild_channel_create(channel):
    settings = nukesettings(channel.guild.id)
    if not settings["enabled"] or not settings["channel_create"]:
        return
    user = await recent_audit_executor(
        channel.guild, discord.AuditLogAction.channel_create, channel.id
    )
    await punish_nuker(channel.guild, user, f"Created channel `{channel.name}`")


@bot.event
async def on_guild_role_delete(role):
    settings = nukesettings(role.guild.id)
    if not settings["enabled"] or not settings["role_delete"]:
        return
    user = await recent_audit_executor(
        role.guild, discord.AuditLogAction.role_delete, role.id
    )
    await punish_nuker(role.guild, user, f"Deleted role `{role.name}`")


@bot.event
async def on_guild_role_create(role):
    settings = nukesettings(role.guild.id)
    if not settings["enabled"] or not settings["role_create"]:
        return
    user = await recent_audit_executor(
        role.guild, discord.AuditLogAction.role_create, role.id
    )
    await punish_nuker(role.guild, user, f"Created role `{role.name}`")


@bot.event
async def on_member_ban(guild, user):
    settings = nukesettings(guild.id)
    if not settings["enabled"] or not settings["ban_protection"]:
        return
    executor = await recent_audit_executor(
        guild, discord.AuditLogAction.ban, user.id
    )
    await punish_nuker(guild, executor, f"Banned `{user}`")


@bot.event
async def on_member_remove(member):
    settings = nukesettings(member.guild.id)
    if not settings["enabled"] or not settings["kick_protection"]:
        return

    executor = await recent_audit_executor(
        member.guild, discord.AuditLogAction.kick, member.id
    )
    if executor:
        await punish_nuker(member.guild, executor, f"Kicked `{member}`")


@bot.event
async def on_member_join(member):
    settings = nukesettings(member.guild.id)
    if not settings["enabled"] or not settings["bot_protection"]:
        return

    if member.bot:
        executor = await recent_audit_executor(
            member.guild, discord.AuditLogAction.bot_add, member.id
        )
        await punish_nuker(member.guild, executor, f"Added bot `{member}`")


@bot.event
async def on_webhooks_update(channel):
    settings = nukesettings(channel.guild.id)
    if not settings["enabled"] or not settings["webhook_protection"]:
        return

    # Webhook audit entries do not identify the exact changed webhook here
    # reliably enough across create/delete/update, so inspect recent entries.
    try:
        async for entry in channel.guild.audit_logs(limit=10):
            if entry.action in {
                discord.AuditLogAction.webhook_create,
                discord.AuditLogAction.webhook_delete,
                discord.AuditLogAction.webhook_update,
            }:
                if (now() - entry.created_at).total_seconds() <= 15:
                    await punish_nuker(
                        channel.guild,
                        entry.user,
                        f"Changed webhook in `{channel.name}`"
                    )
                    return
    except (discord.Forbidden, discord.HTTPException):
        return

# ============================================================
# MESSAGE EVENT
# ============================================================

@bot.event
async def on_message(message):
    if message.guild:
        ensure_guild(message.guild.id)

        if not message.author.bot:
            await process_afk(message)
            blocked = await process_protected_mentions(message)
            if not blocked:
                await process_automod(message)

    await bot.process_commands(message)

# ============================================================
# COMMAND ERRORS
# ============================================================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return

    if isinstance(error, commands.MissingPermissions):
        try:
            await ctx.send(
                "⛔ You don't have permission to use this command.",
                delete_after=10
            )
        except discord.HTTPException:
            pass
        return

    if isinstance(error, commands.MissingRequiredArgument):
        try:
            await ctx.send(
                f"❌ Missing argument: `{error.param.name}`",
                delete_after=10
            )
        except discord.HTTPException:
            pass
        return

    if isinstance(error, commands.MissingRequiredArgument):
        return

    if isinstance(error, commands.BadArgument):
        try:
            await ctx.send(
                "❌ Invalid argument. Mention the member/channel correctly.",
                delete_after=10
            )
        except discord.HTTPException:
            pass
        return

    log.exception("Prefix command error: %s", error)


@bot.tree.error
async def on_app_command_error(interaction, error):
    original = getattr(error, "original", error)
    if isinstance(original, app_commands.errors.MissingPermissions):
        message = "⛔ You don't have permission to use this command."
    else:
        log.exception("Slash command error: %s", original)
        message = "❌ Something went wrong while running that command."

    try:
        if interaction.response.is_done():
            await interaction.followup.send(message, ephemeral=True)
        else:
            await interaction.response.send_message(message, ephemeral=True)
    except discord.HTTPException:
        pass

# ============================================================
# READY
# ============================================================

@bot.event
async def on_ready():
    db_init()
    for guild in bot.guilds:
        ensure_guild(guild.id)

    try:
        synced = await bot.tree.sync()
        log.info("Synced %s slash commands.", len(synced))
    except Exception:
        log.exception("Slash command sync failed")

    log.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "unknown")
    log.info("Serving %s guild(s).", len(bot.guilds))

# ============================================================
# RENDER HEALTH SERVER
# ============================================================

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"OK - Discord Security Bot is running")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, format, *args):
        return


def start_health_server():
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), HealthHandler)
        log.info("Render health server listening on 0.0.0.0:%s", PORT)
        server.serve_forever()
    except Exception:
        log.exception("Render health server failed")

# ============================================================
# RUN
# ============================================================

db_init()
threading.Thread(
    target=start_health_server,
    daemon=True,
    name="render-health"
).start()

bot.run(TOKEN)
