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

        add_user_button = discord.ui.Button(label="Add User", emoji="👤", style=discord.ButtonStyle.primary)
        add_role_button = discord.ui.Button(label="Add Role", emoji="🎭", style=discord.ButtonStyle.primary)
        remove_user_button = discord.ui.Button(label="Remove User", emoji="🗑️", style=discord.ButtonStyle.danger)
        remove_role_button = discord.ui.Button(label="Remove Role", emoji="🗑️", style=discord.ButtonStyle.danger)
        back_button = discord.ui.Button(label="Back", emoji="↩️", style=discord.ButtonStyle.secondary)

        async def add_user_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_reply(interaction, "⛔ No Permission")
            await interaction.response.send_modal(AddUserModal())

        async def add_role_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_reply(interaction, "⛔ No Permission")
            await interaction.response.send_modal(AddRoleModal())

        async def remove_user_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_reply(interaction, "⛔ No Permission")
            await interaction.response.send_modal(RemoveUserModal())

        async def remove_role_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_reply(interaction, "⛔ No Permission")
            await interaction.response.send_modal(RemoveRoleModal())

        async def back_callback(interaction):
            if not is_admin(interaction.user):
                return await temp_reply(interaction, "⛔ No Permission")
            await interaction.response.edit_message(
                embed=status_embed(interaction.guild),
                view=MainPanelView()
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
                return await temp_reply(
                    interaction, "❌ User Not Found",
                    "Make sure the user is in this server."
                )
            add_protected_user(interaction.guild.id, uid)
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild),
                view=MentionView()
            )
        except ValueError:
            await temp_reply(interaction, "❌ Invalid ID", "Enter a numeric Discord user ID.")

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
                return await temp_reply(
                    interaction, "❌ Role Not Found",
                    "Make sure the role is in this server."
                )
            add_protected_role(interaction.guild.id, rid)
            await interaction.response.edit_message(
                embed=mention_embed(interaction.guild),
                view=MentionView()
            )
        except ValueError:
            await temp_reply(interaction, "❌ Invalid ID", "Enter a numeric Discord role ID.")

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
                embed=mention_embed(interaction.guild),
                view=MentionView()
            )
        except ValueError:
            await temp_reply(interaction, "❌ Invalid ID")

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
                embed=mention_embed(interaction.guild),
                view=MentionView()
            )
        except ValueError:
            await temp_reply(interaction, "❌ Invalid ID")

# ============================================================
# STATUS
# ============================================================

def status_embed(guild):
    s = guild_settings(guild.id)
    n = nukesettings(guild.id)
    return embed(
        "🔐 Security Dashboard",
        f"**🛡️ AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**☢️ Anti-Nuke:** {'🟢 ON' if n['enabled'] else '🔴 OFF'}\n"
        f"**📢 Anti-Mention:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**🔗 Anti-Link:** {'🟢 ON' if s['antilinks'] else '🔴 OFF'}\n"
        f"**📨 Anti-Invite:** {'🟢 ON' if s['antiinvite'] else '🔴 OFF'}\n"
        f"**📊 Log Channel:** "
        + (f"<#{s['log_channel']}>" if s["log_channel"] else "Not configured") +
        "\n\nUse the dropdown below to configure everything."
    )

# ============================================================
# COMMANDS
# ============================================================


@bot.command(name="help")
async def help_prefix(ctx):
    """Show global security status and available prefix commands."""
    if not ctx.guild:
        return

    s = guild_settings(ctx.guild.id)
    n = nukesettings(ctx.guild.id)

    protected_users_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_users WHERE guild_id=?",
        (ctx.guild.id,)
    ).fetchone()["c"]

    protected_roles_count = db.execute(
        "SELECT COUNT(*) AS c FROM protected_roles WHERE guild_id=?",
        (ctx.guild.id,)
    ).fetchone()["c"]

    e = embed(
        "🌐 Global Security Status",
        f"**🛡️ AutoMod:** {'🟢 ON' if s['automod'] else '🔴 OFF'}\n"
        f"**☢️ Anti-Nuke:** {'🟢 ON' if n['enabled'] else '🔴 OFF'}\n"
        f"**📢 Mention Protection:** {'🟢 ON' if s['antimention'] else '🔴 OFF'}\n"
        f"**🔗 Anti Links:** {'🟢 ON' if s['antilinks'] else '🔴 OFF'}\n"
        f"**📨 Anti Invite:** {'🟢 ON' if s['antiinvite'] else '🔴 OFF'}\n"
        f"**🚫 Anti Spam:** {'🟢 ON' if s['antispam'] else '🔴 OFF'}\n"
        f"**👤 Protected Users:** `{protected_users_count}`\n"
        f"**🎭 Protected Roles:** `{protected_roles_count}`\n\n"
        "**Prefix Commands**\n"
        "`$help` — Global security status\n"
        "`$security` — Security dashboard\n"
        "`$automod` — AutoMod panel\n"
        "`$antinuke` — Anti-Nuke panel\n"
        "`$mention` — Mention Protection panel\n"
        "`$setlog #channel` — Set security logs\n"
        "`$whitelist @user` — Whitelist a user\n\n"
        "**Slash Commands**\n"
        "`/security` · `/automod` · `/antinuke` · `/mention`\n\n"
        "✨ Prefixes: `$` and `!`"
    )

    await ctx.send(embed=e)

@bot.tree.command(name="security", description="Open the security dashboard")
@app_commands.default_permissions(manage_guild=True)
async def security_slash(interaction):
    if not interaction.guild:
        return await temp_reply(interaction, "❌ Server Only")
    ensure_guild(interaction.guild.id)
    await interaction.response.send_message(
        embed=status_embed(interaction.guild),
        view=MainPanelView()
    )

@bot.command(name="security")
@commands.has_guild_permissions(manage_guild=True)
async def security_prefix(ctx):
    ensure_guild(ctx.guild.id)
    await ctx.send(embed=status_embed(ctx.guild), view=MainPanelView())

@bot.tree.command(name="automod", description="Open AutoMod settings")
@app_commands.default_permissions(manage_guild=True)
async def automod_slash(interaction):
    await interaction.response.send_message(
        embed=automod_embed(interaction.guild),
        view=AutoModView()
    )

@bot.command(name="automod")
@commands.has_guild_permissions(manage_guild=True)
async def automod_prefix(ctx):
    await ctx.send(embed=automod_embed(ctx.guild), view=AutoModView())

@bot.tree.command(name="antinuke", description="Open Anti-Nuke settings")
@app_commands.default_permissions(administrator=True)
async def antinuke_slash(interaction):
    await interaction.response.send_message(
        embed=antinuke_embed(interaction.guild),
        view=AntiNukeView()
    )

@bot.command(name="antinuke")
@commands.has_guild_permissions(administrator=True)
async def antinuke_prefix(ctx):
    await ctx.send(embed=antinuke_embed(ctx.guild), view=AntiNukeView())

@bot.tree.command(name="mention", description="Open Mention Protection settings")
@app_commands.default_permissions(manage_guild=True)
async def mention_slash(interaction):
    await interaction.response.send_message(
        embed=mention_embed(interaction.guild),
        view=MentionView()
    )

@bot.command(name="mention")
@commands.has_guild_permissions(manage_guild=True)
async def mention_prefix(ctx):
    await ctx.send(embed=mention_embed(ctx.guild), view=MentionView())

@bot.tree.command(name="setlog", description="Set the security log channel")
@app_commands.describe(channel="Channel where security logs should be sent")
@app_commands.default_permissions(manage_guild=True)
async def setlog(interaction, channel: discord.TextChannel):
    set_guild(interaction.guild.id, "log_channel", channel.id)
    await temp_reply(
        interaction,
        "✅ Log Channel Updated",
        f"Security logs will be sent to {channel.mention}."
    )

@bot.command(name="setlog")
@commands.has_guild_permissions(manage_guild=True)
async def setlog_prefix(ctx, channel: discord.TextChannel):
    set_guild(ctx.guild.id, "log_channel", channel.id)
    await ctx.send(f"✅ Security log channel set to {channel.mention}")

@bot.tree.command(name="whitelist", description="Whitelist a member from Anti-Nuke")
@app_commands.describe(member="Member to whitelist")
@app_commands.default_permissions(administrator=True)
async def whitelist_slash(interaction, member: discord.Member):
    db.execute(
        "INSERT OR IGNORE INTO whitelist VALUES (?,?)",
        (interaction.guild.id, member.id)
    )
    db.commit()
    await temp_reply(
        interaction,
        "✅ Whitelisted",
        f"{member.mention} is now protected from Anti-Nuke actions."
    )

@bot.tree.command(name="unwhitelist", description="Remove a member from Anti-Nuke whitelist")
@app_commands.default_permissions(administrator=True)
async def unwhitelist_slash(interaction, member: discord.Member):
    db.execute(
        "DELETE FROM whitelist WHERE guild_id=? AND user_id=?",
        (interaction.guild.id, member.id)
    )
    db.commit()
    await temp_reply(interaction, "✅ Removed", f"{member.mention} was removed from whitelist.")

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

    reason = None

    if settings["automod"]:
        content = message.content or ""

        if settings["antiinvite"] and INVITE_RE.search(content):
            reason = "Discord invite detected"

        elif settings["antilinks"] and LINK_RE.search(content):
            reason = "Link detected"

        elif settings["badwords"]:
            lower = content.lower()
            if any(word in lower.split() for word in BAD_WORDS):
                reason = "Blocked word detected"

        elif settings["anticaps"] and len(content) >= 10:
            letters = [c for c in content if c.isalpha()]
            if letters and sum(c.isupper() for c in letters) / len(letters) >= 0.75:
                reason = "Excessive caps detected"

        if settings["antispam"]:
            q = spam_cache[message.guild.id][member.id]
            current = now()
            q.append(current)
            while q and (current - q[0]).total_seconds() > 8:
                q.popleft()
            if len(q) >= settings["spam_limit"]:
                reason = "Spam detected"
                q.clear()

        if settings["duplicate"]:
            q = duplicate_cache[message.guild.id][member.id]
            q.append(message.content[:500])
            while len(q) > 5:
                q.popleft()
            if len(q) >= 3 and len(set(q)) == 1:
                reason = "Duplicate messages detected"
                q.clear()

        if settings["antimention"]:
            if len(message.mentions) + len(message.role_mentions) >= settings["mention_limit"]:
                reason = "Mass mention detected"

    if reason:
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            return True

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
                embed=embed(
                    "🛡️ AutoMod",
                    f"{member.mention}, your message was removed.\n"
                    f"**Reason:** {reason}",
                    discord.Color.orange()
                )
            )
            asyncio.create_task(delete_later(warning))
        except discord.HTTPException:
            pass

        return True

    return False

# ============================================================
# MENTION PROTECTION
# ============================================================

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

    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        return True

    for target_type, target in targets:
        target_name = target.mention
        target_label = "HIGH STAFF" if target_type == "role" else "PROTECTED USER"

        warning = await message.channel.send(
            embed=embed(
                "🚫 DONT PING HIGH STAFF",
                f"👤 **Who pinged:** {message.author.mention}\n"
                f"🎯 **Target:** {target_name}\n"
                f"⚠️ **Reason:** Protected {target_label.lower()} was mentioned.",
                discord.Color.red()
            )
        )
        asyncio.create_task(delete_later(warning))

        await send_log(
            message.guild,
            "🚫 Protected Mention Blocked",
            f"**Who pinged:** {message.author.mention}\n"
            f"**Target:** {target_name}\n"
            f"**Channel:** {message.channel.mention}",
            discord.Color.red()
        )

    return True

# ============================================================
# ANTI-NUKE AUDIT LOG HELPERS
# ============================================================

async def recent_audit_executor(guild, action, target_id=None):
    try:
        async for entry in guild.audit_logs(limit=5, action=action):
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            if (now() - entry.created_at).total_seconds() <= 15:
                return entry.user
    except (discord.Forbidden, discord.HTTPException):
        pass
    return None

async def punish_nuker(guild, user, reason):
    if not user or user.bot:
        return
    if is_whitelisted(guild.id, user.id):
        return
    if user.id == guild.owner_id:
        return

    s = nukesettings(guild.id)
    if not s["enabled"]:
        return

    try:
        member = guild.get_member(user.id) or await guild.fetch_member(user.id)
    except (discord.NotFound, discord.HTTPException):
        return

    await punishment(member, s["punishment"], reason)

    await send_log(
        guild,
        "☢️ ANTI-NUKE ACTION",
        f"**User:** {member.mention}\n"
        f"**Reason:** {reason}\n"
        f"**Action:** `{s['punishment']}`",
        discord.Color.red()
    )

# ============================================================
# AUDIT EVENT LISTENERS
# ============================================================

@bot.event
async def on_guild_channel_delete(channel):
    guild = channel.guild
    s = nukesettings(guild.id)
    if not s["enabled"] or not s["channel_delete"]:
        return

    user = await recent_audit_executor(guild, discord.AuditLogAction.channel_delete, channel.id)
    await punish_nuker(guild, user, f"Deleted channel `{channel.name}`")

@bot.event
async def on_guild_channel_create(channel):
    guild = channel.guild
    s = nukesettings(guild.id)
    if not s["enabled"] or not s["channel_create"]:
        return

    user = await recent_audit_executor(guild, discord.AuditLogAction.channel_create, channel.id)
    await punish_nuker(guild, user, f"Created channel `{channel.name}`")

@bot.event
async def on_guild_role_delete(role):
    guild = role.guild
    s = nukesettings(guild.id)
    if not s["enabled"] or not s["role_delete"]:
        return

    user = await recent_audit_executor(guild, discord.AuditLogAction.role_delete, role.id)
    await punish_nuker(guild, user, f"Deleted role `{role.name}`")

@bot.event
async def on_guild_role_create(role):
    guild = role.guild
    s = nukesettings(guild.id)
    if not s["enabled"] or not s["role_create"]:
        return

    user = await recent_audit_executor(guild, discord.AuditLogAction.role_create, role.id)
    await punish_nuker(guild, user, f"Created role `{role.name}`")

@bot.event
async def on_member_ban(guild, user):
    s = nukesettings(guild.id)
    if not s["enabled"] or not s["ban_protection"]:
        return

    executor = await recent_audit_executor(guild, discord.AuditLogAction.ban, user.id)
    await punish_nuker(guild, executor, f"Banned `{user}`")

@bot.event
async def on_member_remove(member):
    s = nukesettings(member.guild.id)
    if not s["enabled"] or not s["kick_protection"]:
        return

    executor = await recent_audit_executor(
        member.guild,
        discord.AuditLogAction.kick,
        member.id
    )
    if executor:
        await punish_nuker(
            member.guild,
            executor,
            f"Kicked `{member}`"
        )

@bot.event
async def on_member_join(member):
    s = nukesettings(member.guild.id)
    if not s["enabled"] or not s["bot_protection"]:
        return

    if member.bot:
        executor = await recent_audit_executor(
            member.guild,
            discord.AuditLogAction.bot_add,
            member.id
        )
        await punish_nuker(
            member.guild,
            executor,
            f"Added bot `{member}`"
        )

# ============================================================
# MESSAGE EVENT
# ============================================================

@bot.event
async def on_message(message):
    if message.guild:
        ensure_guild(message.guild.id)

        if not message.author.bot:
            blocked = await process_protected_mentions(message)
            if not blocked:
                await process_automod(message)

    await bot.process_commands(message)

# ============================================================
# ERRORS
# ============================================================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        try:
            await ctx.send("⛔ You don't have permission to use this command.", delete_after=10)
        except discord.HTTPException:
            pass
    elif isinstance(error, commands.MissingRequiredArgument):
        try:
            await ctx.send(f"❌ Missing argument: `{error.param.name}`", delete_after=10)
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
    except Exception as e:
        log.exception("Slash command sync failed: %s", e)

    log.info("Logged in as %s (%s)", bot.user, bot.user.id)
    log.info("Serving %s guild(s).", len(bot.guilds))

# ============================================================
# RUN
# ============================================================

db_init()
bot.run(TOKEN)
