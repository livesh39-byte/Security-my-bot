import os
import re
import sqlite3
import asyncio
import logging
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
BOT_COLOR = discord.Color.blurple()
DELETE_AFTER = 60

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN environment variable is missing.")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("security-bot")

# ============================================================
# DATABASE
# ============================================================

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = asyncio.Lock()

def db_init():
    db.executescript("""
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
    """)
    db.commit()

def ensure_guild(guild_id):
    db.execute(
        "INSERT OR IGNORE INTO guilds (guild_id) VALUES (?)",
        (guild_id,)
    )
    db.execute(
        "INSERT OR IGNORE INTO antinuke (guild_id) VALUES (?)",
        (guild_id,)
    )
    db.commit()

def guild_settings(guild_id):
    ensure_guild(guild_id)
    return db.execute(
        "SELECT * FROM guilds WHERE guild_id=?", (guild_id,)
    ).fetchone()

def nukesettings(guild_id):
    ensure_guild(guild_id)
    return db.execute(
        "SELECT * FROM antinuke WHERE guild_id=?", (guild_id,)
    ).fetchone()

def set_guild(guild_id, column, value):
    allowed = {
        "log_channel", "automod", "antispam", "antilinks",
        "antiinvite", "badwords", "anticaps", "antimention",
        "duplicate", "spam_limit", "mention_limit", "punishment"
    }
    if column not in allowed:
        return
    ensure_guild(guild_id)
    db.execute(f"UPDATE guilds SET {column}=? WHERE guild_id=?", (value, guild_id))
    db.commit()

def set_nuke(guild_id, column, value):
    allowed = {
        "enabled", "ban_protection", "kick_protection",
        "channel_delete", "channel_create", "role_delete",
        "role_create", "webhook_protection", "bot_protection",
        "punishment"
    }
    if column not in allowed:
        return
    ensure_guild(guild_id)
    db.execute(f"UPDATE antinuke SET {column}=? WHERE guild_id=?", (value, guild_id))
    db.commit()

def is_whitelisted(guild_id, user_id):
    return db.execute(
        "SELECT 1 FROM whitelist WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    ).fetchone() is not None

def protected_user(guild_id, user_id):
    return db.execute(
        "SELECT 1 FROM protected_users WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    ).fetchone() is not None

def protected_role(guild_id, role_id):
    return db.execute(
        "SELECT 1 FROM protected_roles WHERE guild_id=? AND role_id=?",
        (guild_id, role_id)
    ).fetchone() is not None

def add_protected_user(guild_id, user_id):
    db.execute(
        "INSERT OR IGNORE INTO protected_users VALUES (?,?)",
        (guild_id, user_id)
    )
    db.commit()

def remove_protected_user(guild_id, user_id):
    db.execute(
        "DELETE FROM protected_users WHERE guild_id=? AND user_id=?",
        (guild_id, user_id)
    )
    db.commit()

def add_protected_role(guild_id, role_id):
    db.execute(
        "INSERT OR IGNORE INTO protected_roles VALUES (?,?)",
        (guild_id, role_id)
    )
    db.commit()

def remove_protected_role(guild_id, role_id):
    db.execute(
        "DELETE FROM protected_roles WHERE guild_id=? AND role_id=?",
        (guild_id, role_id)
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
    help_command=None
)

spam_cache = defaultdict(lambda: defaultdict(deque))
duplicate_cache = defaultdict(lambda: defaultdict(deque))
action_cache = defaultdict(lambda: deque(maxlen=20))

LINK_RE = re.compile(r"(https?://|www\.)\S+", re.I)
INVITE_RE = re.compile(
    r"(discord\.gg/|discord\.com/invite/|discordapp\.com/invite/)\S+",
    re.I
)

BAD_WORDS = {
    "nigger", "nigga", "fuck", "fucker", "motherfucker",
    "bitch", "cunt"
}

# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.now(timezone.utc)

def embed(title, description="", color=BOT_COLOR):
    return discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=now()
    )

def is_admin(member):
    return member.guild_permissions.administrator or member.guild_permissions.manage_guild

async def temp_reply(interaction, title, description, color=BOT_COLOR):
    e = embed(title, description, color)
    await interaction.response.send_message(e, ephemeral=True)

async def delete_later(message, seconds=DELETE_AFTER):
    await asyncio.sleep(seconds)
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass

async def send_log(guild, title, description, color=BOT_COLOR):
    settings = guild_settings(guild.id)
    channel_id = settings["log_channel"]
    if not channel_id:
        return
    channel = guild.get_channel(channel_id)
    if not channel:
        return
    try:
        await channel.send(embed=embed(title, description, color))
    except discord.HTTPException:
        pass

async def punishment(member, mode, reason):
    try:
        if mode == "timeout":
            await member.timeout(timedelta(minutes=10), reason=reason)
        elif mode == "kick":
            await member.kick(reason=reason)
        elif mode == "ban":
            await member.ban(reason=reason, delete_message_days=1)
    except (discord.Forbidden, discord.HTTPException):
        pass

def mention_targets(message):
    targets = []

    for member in message.mentions:
        if protected_user(message.guild.id, member.id):
            targets.append(("user", member))

    for role in message.role_mentions:
        if protected_role(message.guild.id, role.id):
            targets.append(("role", role))

    return targets

# ============================================================
# UI: MAIN PANEL
# ============================================================

class MainPanelSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(
                label="AutoMod",
                value="automod",
                emoji="🛡️",
                description="Configure message protection"
            ),
            discord.SelectOption(
                label="Anti-Nuke",
                value="antinuke",
                emoji="☢️",
                description="Configure server protection"
            ),
            discord.SelectOption(
                label="Mention Protection",
                value="mention",
                emoji="📢",
                description="Protect selected users and roles"
            ),
            discord.SelectOption(
                label="Status",
                value="status",
                emoji="📊",
                description="View current security status"
            )
        ]
        super().__init__(
            placeholder="Select a security panel...",
            options=options,
            custom_id="main_security_select"
        )

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await temp_reply(
                interaction,
                "⛔ No Permission",
                "You need **Administrator** or **Manage Server** permission."
            )

        if self.values[0] == "automod":
            await interaction.response.edit_message(
                embed=automod_embed(interaction.guild),
                view=AutoModView()
            )
        elif self.values[0] == "antinuke":
            await interaction.response.edit_message(
                embed=antinuke_embed(interaction.guild),
                view=AntiNukeView()
            )
        elif self.values[0] == "mention":
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild),
                view=MentionView()
            )
        else:
            await interaction.response.edit_message(
                embed=status_embed(interaction.guild),
                view=MainPanelView()
            )

class MainPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(MainPanelSelect())

    @discord.ui.button(label="Refresh", emoji="🔄", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction, button):
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild),
            view=MainPanelView()
        )

# ============================================================
# AUTOMOD UI
# ============================================================

def automod_embed(guild):
    s = guild_settings(guild.id)
    return embed(
        "🛡️ AutoMod Control Panel",
        f"**AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**Anti Spam:** {'🟢 ON' if s['antispam'] else '🔴 OFF'}\n"
        f"**Anti Links:** {'🟢 ON' if s['antilinks'] else '🔴 OFF'}\n"
        f"**Anti Invite:** {'🟢 ON' if s['antiinvite'] else '🔴 OFF'}\n"
        f"**Bad Words:** {'🟢 ON' if s['badwords'] else '🔴 OFF'}\n"
        f"**Anti Caps:** {'🟢 ON' if s['anticaps'] else '🔴 OFF'}\n"
        f"**Anti Mention:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**Duplicate:** {'🟢 ON' if s['duplicate'] else '🔴 OFF'}\n\n"
        f"Spam limit: `{s['spam_limit']}` messages / 8 sec\n"
        f"Mention limit: `{s['mention_limit']}` mentions"
    )

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
            discord.SelectOption(label="Duplicate Messages", value="duplicate", emoji="♻️"),
        ]
        super().__init__(
            placeholder="Choose AutoMod protection...",
            options=options,
            custom_id="automod_select"
        )

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await temp_reply(interaction, "⛔ No Permission")
        key = self.values[0]
        s = guild_settings(interaction.guild.id)
        new_value = 0 if s[key] else 1
        set_guild(interaction.guild.id, key, new_value)
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild),
            view=AutoModView()
        )

class AutoModView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(AutoModSelect())

    @discord.ui.button(label="Delete Only", emoji="🗑️", style=discord.ButtonStyle.secondary)
    async def delete_only(self, interaction, button):
        set_guild(interaction.guild.id, "punishment", "delete")
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild),
            view=AutoModView()
        )

    @discord.ui.button(label="Timeout", emoji="⏱️", style=discord.ButtonStyle.primary)
    async def timeout(self, interaction, button):
        set_guild(interaction.guild.id, "punishment", "timeout")
        await interaction.response.edit_message(
            embed=automod_embed(interaction.guild),
            view=AutoModView()
        )

    @discord.ui.button(label="Back", emoji="↩️", style=discord.ButtonStyle.secondary)
    async def back(self, interaction, button):
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild),
            view=MainPanelView()
        )

# ============================================================
# ANTINUKE UI
# ============================================================

def antinuke_embed(guild):
    s = nukesettings(guild.id)
    return embed(
        "☢️ Anti-Nuke Control Panel",
        f"**Anti-Nuke:** {'🟢 ON' if s['enabled'] else '🔴 OFF'}\n"
        f"**Ban Protection:** {'🟢' if s['ban_protection'] else '🔴'}\n"
        f"**Kick Protection:** {'🟢' if s['kick_protection'] else '🔴'}\n"
        f"**Channel Delete:** {'🟢' if s['channel_delete'] else '🔴'}\n"
        f"**Channel Create:** {'🟢' if s['channel_create'] else '🔴'}\n"
        f"**Role Delete:** {'🟢' if s['role_delete'] else '🔴'}\n"
        f"**Role Create:** {'🟢' if s['role_create'] else '🔴'}\n"
        f"**Webhook:** {'🟢' if s['webhook_protection'] else '🔴'}\n"
        f"**Bot Add:** {'🟢' if s['bot_protection'] else '🔴'}\n\n"
        f"Punishment: `{s['punishment']}`"
    )

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
            discord.SelectOption(label="Bot Add Protection", value="bot_protection", emoji="🤖"),
        ]
        super().__init__(
            placeholder="Choose Anti-Nuke protection...",
            options=options,
            custom_id="antinuke_select"
        )

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await temp_reply(interaction, "⛔ No Permission")
        key = self.values[0]
        s = nukesettings(interaction.guild.id)
        new_value = 0 if s[key] else 1
        set_nuke(interaction.guild.id, key, new_value)
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild),
            view=AntiNukeView()
        )

class AntiNukeView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(AntiNukeSelect())

    @discord.ui.button(label="Ban", emoji="🔨", style=discord.ButtonStyle.danger)
    async def ban_mode(self, interaction, button):
        set_nuke(interaction.guild.id, "punishment", "ban")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild),
            view=AntiNukeView()
        )

    @discord.ui.button(label="Kick", emoji="👢", style=discord.ButtonStyle.primary)
    async def kick_mode(self, interaction, button):
        set_nuke(interaction.guild.id, "punishment", "kick")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild),
            view=AntiNukeView()
        )

    @discord.ui.button(label="Timeout", emoji="⏱️", style=discord.ButtonStyle.secondary)
    async def timeout_mode(self, interaction, button):
        set_nuke(interaction.guild.id, "punishment", "timeout")
        await interaction.response.edit_message(
            embed=antinuke_embed(interaction.guild),
            view=AntiNukeView()
        )

    @discord.ui.button(label="Back", emoji="↩️", style=discord.ButtonStyle.secondary)
    async def back(self, interaction, button):
        await interaction.response.edit_message(
            embed=status_embed(interaction.guild),
            view=MainPanelView()
        )

# ============================================================
# MENTION UI
# ============================================================

def mention_embed(guild):
    users = db.execute(
        "SELECT user_id FROM protected_users WHERE guild_id=?",
        (guild.id,)
    ).fetchall()
    roles = db.execute(
        "SELECT role_id FROM protected_roles WHERE guild_id=?",
        (guild.id,)
    ).fetchall()

    user_text = []
    for row in users:
        member = guild.get_member(row["user_id"])
        user_text.append(member.mention if member else f"<@{row['user_id']}>")

    role_text = []
    for row in roles:
        role = guild.get_role(row["role_id"])
        role_text.append(role.mention if role else f"<@&{row['role_id']}>")

    return embed(
        "📢 Mention Protection",
        "**Protected Users:**\n" +
        ("\n".join(user_text) if user_text else "None") +
        "\n\n**Protected Roles:**\n" +
        ("\n".join(role_text) if role_text else "None") +
        "\n\nWhen somebody pings a protected target, the offending message is deleted and the bot sends:\n"
        "`🚫 DONT PING HIGH STAFF`\n"
        "`👤 Who pinged: @User`\n"
        "`🎯 Target: @High Staff`\n\n"
        "The bot response is automatically removed after **1 minute**."
    )

class MentionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)

    @discord.ui.button(label="Add User", emoji="👤", style=discord.ButtonStyle.primary)
    async def add_user(self, interaction, button):
        await interaction.response.send_modal(AddUserModal())

    @discord.ui.button(label="Add Role", emoji="🎭", style=discord.ButtonStyle.primary)
    async def add_role(self, interaction, button):
        await interaction.response.send_modal(AddRoleModal())

    @discord.ui.button(label="Remove User", emoji="🗑️", style=discord.ButtonStyle.
