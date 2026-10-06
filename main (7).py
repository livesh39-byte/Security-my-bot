import os
import re
import sqlite3
import asyncio
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections import defaultdict, deque
from datetime import datetime, timezone

import discord
from discord.ext import commands
from discord import app_commands

# ============================================================
# BLASTMC SECURITY CORE — PREMIUM BUILD
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")
DB_FILE = "bot.db"
PORT = int(os.getenv("PORT", "10000"))
PREFIXES = ("!", "$")
COLOR = discord.Color.from_rgb(99, 102, 241)
GREEN = discord.Color.from_rgb(34, 197, 94)
RED = discord.Color.from_rgb(239, 68, 68)
ORANGE = discord.Color.from_rgb(245, 158, 11)
CYAN = discord.Color.from_rgb(34, 211, 238)
AFK_DELETE_AFTER = 60
MENTION_DELETE_AFTER = 10
COMMAND_ANIMATION = 0.22

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN environment variable is missing.")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s:%(name)s: %(message)s")
log = logging.getLogger("blastmc-security")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.messages = True
intents.moderation = True

bot = commands.Bot(command_prefix=PREFIXES, intents=intents, help_command=None)

# ============================================================
# DATABASE
# ============================================================

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = threading.RLock()


def db_exec(sql, params=(), fetch=False, many=False):
    with db_lock:
        cur = db.cursor()
        if many:
            cur.executemany(sql, params)
        else:
            cur.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        db.commit()
        return rows


def db_init():
    with db_lock:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS guilds (
            guild_id INTEGER PRIMARY KEY,
            log_channel INTEGER DEFAULT 0,
            automod INTEGER DEFAULT 1,
            antilinks INTEGER DEFAULT 1,
            antiinvite INTEGER DEFAULT 1,
            antispam INTEGER DEFAULT 1,
            badwords INTEGER DEFAULT 0,
            anticaps INTEGER DEFAULT 0,
            antimention INTEGER DEFAULT 1,
            duplicate INTEGER DEFAULT 0,
            spam_limit INTEGER DEFAULT 6,
            mention_limit INTEGER DEFAULT 5,
            punishment TEXT DEFAULT 'timeout',
            antinuke INTEGER DEFAULT 1,
            nuke_ban INTEGER DEFAULT 1,
            nuke_kick INTEGER DEFAULT 1,
            nuke_channel_delete INTEGER DEFAULT 1,
            nuke_channel_create INTEGER DEFAULT 0,
            nuke_role_delete INTEGER DEFAULT 1,
            nuke_role_create INTEGER DEFAULT 0,
            nuke_webhook INTEGER DEFAULT 1,
            nuke_bot_add INTEGER DEFAULT 1,
            nuke_punishment TEXT DEFAULT 'ban'
        );
        CREATE TABLE IF NOT EXISTS protected_users (
            guild_id INTEGER, user_id INTEGER,
            PRIMARY KEY(guild_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS protected_roles (
            guild_id INTEGER, role_id INTEGER,
            PRIMARY KEY(guild_id, role_id)
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            guild_id INTEGER, user_id INTEGER,
            PRIMARY KEY(guild_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS afk (
            guild_id INTEGER, user_id INTEGER PRIMARY KEY,
            reason TEXT NOT NULL, since TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS autoresponders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guild_id INTEGER NOT NULL,
            trigger TEXT NOT NULL,
            reply TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'exact',
            enabled INTEGER NOT NULL DEFAULT 1,
            UNIQUE(guild_id, trigger)
        );
        """)

        # Lightweight migrations for older bot.db files.
        existing = {r[1] for r in db.execute("PRAGMA table_info(guilds)").fetchall()}
        defaults = {
            "antinuke": "INTEGER DEFAULT 1", "nuke_ban": "INTEGER DEFAULT 1",
            "nuke_kick": "INTEGER DEFAULT 1", "nuke_channel_delete": "INTEGER DEFAULT 1",
            "nuke_channel_create": "INTEGER DEFAULT 0", "nuke_role_delete": "INTEGER DEFAULT 1",
            "nuke_role_create": "INTEGER DEFAULT 0", "nuke_webhook": "INTEGER DEFAULT 1",
            "nuke_bot_add": "INTEGER DEFAULT 1", "nuke_punishment": "TEXT DEFAULT 'ban'",
        }
        for col, definition in defaults.items():
            if col not in existing:
                db.execute(f"ALTER TABLE guilds ADD COLUMN {col} {definition}")
        db.commit()


def ensure_guild(guild_id):
    db_exec("INSERT OR IGNORE INTO guilds(guild_id) VALUES(?)", (guild_id,))


def settings(guild_id):
    ensure_guild(guild_id)
    return db_exec("SELECT * FROM guilds WHERE guild_id=?", (guild_id,), True)[0]


def set_setting(guild_id, key, value):
    allowed = {
        "log_channel", "automod", "antilinks", "antiinvite", "antispam", "badwords",
        "anticaps", "antimention", "duplicate", "spam_limit", "mention_limit", "punishment",
        "antinuke", "nuke_ban", "nuke_kick", "nuke_channel_delete", "nuke_channel_create",
        "nuke_role_delete", "nuke_role_create", "nuke_webhook", "nuke_bot_add", "nuke_punishment"
    }
    if key not in allowed:
        raise ValueError("Invalid setting")
    db_exec(f"UPDATE guilds SET {key}=? WHERE guild_id=?", (value, guild_id))


def bool_setting(guild_id, key):
    return bool(settings(guild_id)[key])


def is_admin(member):
    return isinstance(member, discord.Member) and member.guild_permissions.administrator


def protected_user(guild_id, user_id):
    return bool(db_exec("SELECT 1 FROM protected_users WHERE guild_id=? AND user_id=?", (guild_id, user_id), True))


def protected_role(guild_id, role_id):
    return bool(db_exec("SELECT 1 FROM protected_roles WHERE guild_id=? AND role_id=?", (guild_id, role_id), True))


def whitelist(guild_id, user_id):
    return bool(db_exec("SELECT 1 FROM whitelist WHERE guild_id=? AND user_id=?", (guild_id, user_id), True))


def afk_get(guild_id, user_id):
    rows = db_exec("SELECT * FROM afk WHERE guild_id=? AND user_id=?", (guild_id, user_id), True)
    return rows[0] if rows else None


def afk_set(guild_id, user_id, reason):
    db_exec("INSERT OR REPLACE INTO afk(guild_id,user_id,reason,since) VALUES(?,?,?,?)",
            (guild_id, user_id, reason[:500], datetime.now(timezone.utc).isoformat()))


def afk_remove(guild_id, user_id):
    db_exec("DELETE FROM afk WHERE guild_id=? AND user_id=?", (guild_id, user_id))


def ar_list(guild_id):
    return db_exec("SELECT * FROM autoresponders WHERE guild_id=? ORDER BY id", (guild_id,), True)

# ============================================================
# UI / HELPERS
# ============================================================


def status_dot(value):
    return "🟢 ON" if value else "⚫ OFF"


def fmt_since(iso):
    try:
        dt = datetime.fromisoformat(iso)
        return discord.utils.format_dt(dt, style="R")
    except Exception:
        return "unknown"


def premium_embed(title, description="", color=COLOR):
    e = discord.Embed(title=title, description=description, color=color, timestamp=datetime.now(timezone.utc))
    e.set_footer(text="BLASTMC • SECURITY CORE", icon_url=bot.user.display_avatar.url if bot.user else discord.Embed.Empty)
    return e


def compact_status(guild):
    s = settings(guild.id)
    protected_u = len(db_exec("SELECT user_id FROM protected_users WHERE guild_id=?", (guild.id,), True))
    protected_r = len(db_exec("SELECT role_id FROM protected_roles WHERE guild_id=?", (guild.id,), True))
    responders = len(ar_list(guild.id))
    return s, protected_u, protected_r, responders


def dashboard_embed(guild):
    s, pu, pr, ar = compact_status(guild)
    e = premium_embed("✦ SECURITY CORE", "**Administrator control center**\nFast controls. Instant enforcement. Persistent settings.")
    e.add_field(name="🛡️ AUTOMOD", value=f"{status_dot(s['automod'])}\n🔗 Links {status_dot(s['antilinks'])}\n✉️ Invites {status_dot(s['antiinvite'])}\n💬 Spam {status_dot(s['antispam'])}\n🔠 Caps {status_dot(s['anticaps'])}", inline=True)
    e.add_field(name="☢️ ANTI-NUKE", value=f"{status_dot(s['antinuke'])}\n🔨 Ban {status_dot(s['nuke_ban'])}\n🥾 Kick {status_dot(s['nuke_kick'])}\n🗑️ Channels {status_dot(s['nuke_channel_delete'])}\n🎭 Roles {status_dot(s['nuke_role_delete'])}", inline=True)
    e.add_field(name="🎯 PROTECTION", value=f"👤 Users **{pu}**\n🎭 Roles **{pr}**\n💬 Responders **{ar}**\n📜 Logs {'set' if s['log_channel'] else 'not set'}", inline=True)
    e.add_field(name="⚡ ENFORCEMENT", value=f"Punishment: **{s['punishment'].upper()}**\nNuke: **{s['nuke_punishment'].upper()}**\nSpam limit: **{s['spam_limit']} msgs**", inline=False)
    return e


def automod_embed(guild):
    s = settings(guild.id)
    e = premium_embed("🛡️ AUTOMOD", "Real-time moderation. Offending messages are removed before they can spread.")
    e.add_field(name="CORE", value=f"Master {status_dot(s['automod'])}\n🔗 Links {status_dot(s['antilinks'])}\n✉️ Invites {status_dot(s['antiinvite'])}\n💬 Spam {status_dot(s['antispam'])}", inline=True)
    e.add_field(name="FILTERS", value=f"🤬 Bad words {status_dot(s['badwords'])}\n🔠 Caps {status_dot(s['anticaps'])}\n📢 Mentions {status_dot(s['antimention'])}\n♻️ Duplicate {status_dot(s['duplicate'])}", inline=True)
    e.add_field(name="ACTION", value=f"**{s['punishment'].upper()}** after detection\nLinks/invites: **instant delete + punishment**", inline=False)
    return e


def antinuke_embed(guild):
    s = settings(guild.id)
    e = premium_embed("☢️ ANTI-NUKE", "Audit-log protection against destructive server actions.")
    e.add_field(name="CORE", value=f"Master {status_dot(s['antinuke'])}\n🔨 Ban {status_dot(s['nuke_ban'])}\n🥾 Kick {status_dot(s['nuke_kick'])}\n🤖 Bot Add {status_dot(s['nuke_bot_add'])}", inline=True)
    e.add_field(name="STRUCTURE", value=f"🗑️ Channel Delete {status_dot(s['nuke_channel_delete'])}\n➕ Channel Create {status_dot(s['nuke_channel_create'])}\n🗑️ Role Delete {status_dot(s['nuke_role_delete'])}\n➕ Role Create {status_dot(s['nuke_role_create'])}", inline=True)
    e.add_field(name="OTHER", value=f"🔗 Webhook {status_dot(s['nuke_webhook'])}\nPunishment: **{s['nuke_punishment'].upper()}**", inline=False)
    return e


def mention_embed(guild):
    s = settings(guild.id)
    pu = len(db_exec("SELECT user_id FROM protected_users WHERE guild_id=?", (guild.id,), True))
    pr = len(db_exec("SELECT role_id FROM protected_roles WHERE guild_id=?", (guild.id,), True))
    e = premium_embed("🎯 MENTION GUARD", "Protected staff mentions are blocked automatically.")
    e.add_field(name="STATUS", value=f"Master {status_dot(s['antimention'])}\n👤 Protected users **{pu}**\n🎭 Protected roles **{pr}**", inline=True)
    e.add_field(name="RESPONSE", value="Offender message → delete after **10s**\nBot warning → delete after **60s**", inline=True)
    return e


def autoresponder_embed(guild):
    rows = ar_list(guild.id)
    e = premium_embed("💠 AUTORESPONDER", "Exact-match automation with persistent triggers.")
    if not rows:
        e.description += "\n\nNo triggers configured yet."
    else:
        lines = []
        for r in rows[:15]:
            state = "🟢" if r["enabled"] else "⚫"
            lines.append(f"{state} `{r['trigger']}` → `{r['reply']}` • **{r['mode'].upper()}**")
        e.add_field(name=f"TRIGGERS • {len(rows)}", value="\n".join(lines), inline=False)
        if len(rows) > 15:
            e.set_footer(text=f"BLASTMC • SECURITY CORE • +{len(rows)-15} more")
    return e


async def delete_after(message, seconds):
    await asyncio.sleep(seconds)
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def animated_send(interaction, final_embed, view=None, ephemeral=False):
    if interaction.response.is_done():
        msg = await interaction.followup.send("⟡ **SYNCING SECURITY CORE...**", wait=True, ephemeral=ephemeral)
        await asyncio.sleep(COMMAND_ANIMATION)
        await msg.edit(content=None, embed=final_embed, view=view)
        return msg
    await interaction.response.send_message("⟡ **SYNCING SECURITY CORE...**", ephemeral=ephemeral)
    await asyncio.sleep(COMMAND_ANIMATION)
    msg = await interaction.original_response()
    await msg.edit(content=None, embed=final_embed, view=view)
    return msg


async def animated_ctx(ctx, embed, view=None):
    msg = await ctx.send("⟡ **SYNCING SECURITY CORE...**")
    await asyncio.sleep(COMMAND_ANIMATION)
    await msg.edit(content=None, embed=embed, view=view)
    return msg


async def deny(interaction):
    msg = "⛔ **Administrator access required.**"
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)


async def punishment(member, mode, reason):
    if not isinstance(member, discord.Member) or member.guild_permissions.administrator:
        return False
    try:
        if mode == "ban" and member.guild.me.guild_permissions.ban_members and member.top_role < member.guild.me.top_role:
            await member.ban(reason=reason, delete_message_seconds=0)
            return True
        if mode == "kick" and member.guild.me.guild_permissions.kick_members and member.top_role < member.guild.me.top_role:
            await member.kick(reason=reason)
            return True
        if mode == "timeout" and member.guild.me.guild_permissions.moderate_members:
            await member.timeout(discord.utils.utcnow() + __import__('datetime').timedelta(minutes=10), reason=reason)
            return True
    except discord.HTTPException:
        return False
    return False


async def send_log(guild, title, description, color=COLOR):
    s = settings(guild.id)
    channel_id = s["log_channel"]
    if not channel_id:
        return
    ch = guild.get_channel(channel_id)
    if not ch:
        return
    try:
        await ch.send(embed=premium_embed(title, description, color))
    except discord.HTTPException:
        pass


# ============================================================
# PREMIUM ADMIN BUTTON UI — NO DROPDOWNS
# ============================================================

class BackButton(discord.ui.Button):
    def __init__(self):
        super().__init__(label="Dashboard", emoji="⌂", style=discord.ButtonStyle.secondary, row=1)

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        await animated_send(interaction, dashboard_embed(interaction.guild), DashboardView(), ephemeral=False)


class DashboardView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(PanelButton("AutoMod", "🛡️", 0, "automod"))
        self.add_item(PanelButton("Anti-Nuke", "☢️", 0, "antinuke"))
        self.add_item(PanelButton("Mention Guard", "🎯", 0, "mention"))
        self.add_item(PanelButton("AutoResponder", "💠", 0, "autoresponder"))
        self.add_item(PanelButton("Status", "✦", 1, "status"))


class PanelButton(discord.ui.Button):
    def __init__(self, label, emoji, row, target):
        super().__init__(label=label, emoji=emoji, style=discord.ButtonStyle.primary if target != "status" else discord.ButtonStyle.secondary, row=row)
        self.target = target

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        guild = interaction.guild
        if self.target == "automod":
            await animated_send(interaction, automod_embed(guild), AutoModView(), ephemeral=False)
        elif self.target == "antinuke":
            await animated_send(interaction, antinuke_embed(guild), AntiNukeView(), ephemeral=False)
        elif self.target == "mention":
            await animated_send(interaction, mention_embed(guild), MentionView(), ephemeral=False)
        elif self.target == "autoresponder":
            await animated_send(interaction, autoresponder_embed(guild), AutoResponderView(), ephemeral=False)
        else:
            await animated_send(interaction, dashboard_embed(guild), DashboardView(), ephemeral=False)


class ToggleButton(discord.ui.Button):
    def __init__(self, label, key, row=0):
        super().__init__(label=label, style=discord.ButtonStyle.success, row=row)
        self.key = key

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        current = bool_setting(interaction.guild.id, self.key)
        set_setting(interaction.guild.id, self.key, 0 if current else 1)
        await animated_send(interaction, automod_embed(interaction.guild), AutoModView(), ephemeral=False)


class AutoModView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(ToggleButton("Master", "automod", 0))
        self.add_item(ToggleButton("Links", "antilinks", 0))
        self.add_item(ToggleButton("Invites", "antiinvite", 0))
        self.add_item(ToggleButton("Spam", "antispam", 0))
        self.add_item(ToggleButton("Caps", "anticaps", 1))
        self.add_item(ToggleButton("Mentions", "antimention", 1))
        self.add_item(ToggleButton("Duplicate", "duplicate", 1))
        self.add_item(ToggleButton("Bad Words", "badwords", 1))
        self.add_item(BackButton())


class NukeToggleButton(discord.ui.Button):
    def __init__(self, label, key, row=0):
        super().__init__(label=label, style=discord.ButtonStyle.danger, row=row)
        self.key = key

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        current = bool_setting(interaction.guild.id, self.key)
        set_setting(interaction.guild.id, self.key, 0 if current else 1)
        await animated_send(interaction, antinuke_embed(interaction.guild), AntiNukeView(), ephemeral=False)


class AntiNukeView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(NukeToggleButton("Master", "antinuke", 0))
        self.add_item(NukeToggleButton("Ban", "nuke_ban", 0))
        self.add_item(NukeToggleButton("Kick", "nuke_kick", 0))
        self.add_item(NukeToggleButton("Ch Delete", "nuke_channel_delete", 1))
        self.add_item(NukeToggleButton("Ch Create", "nuke_channel_create", 1))
        self.add_item(NukeToggleButton("Role Delete", "nuke_role_delete", 1))
        self.add_item(NukeToggleButton("Role Create", "nuke_role_create", 2))
        self.add_item(NukeToggleButton("Webhook", "nuke_webhook", 2))
        self.add_item(NukeToggleButton("Bot Add", "nuke_bot_add", 2))
        self.add_item(BackButton())


class MentionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(MentionButton("Add User", "add_user", 0))
        self.add_item(MentionButton("Remove User", "remove_user", 0))
        self.add_item(MentionButton("Add Role", "add_role", 1))
        self.add_item(MentionButton("Remove Role", "remove_role", 1))
        self.add_item(MentionButton("Toggle Guard", "toggle", 1))
        self.add_item(BackButton())


class MentionButton(discord.ui.Button):
    def __init__(self, label, action, row):
        super().__init__(label=label, emoji="🎯", style=discord.ButtonStyle.primary, row=row)
        self.action = action

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        if self.action == "toggle":
            cur = bool_setting(interaction.guild.id, "antimention")
            set_setting(interaction.guild.id, "antimention", 0 if cur else 1)
            return await animated_send(interaction, mention_embed(interaction.guild), MentionView(), ephemeral=False)
        title = "Add protected user" if self.action == "add_user" else "Remove protected user" if self.action == "remove_user" else "Add protected role" if self.action == "add_role" else "Remove protected role"
        await interaction.response.send_modal(IDModal(self.action, title))


class IDModal(discord.ui.Modal):
    def __init__(self, action, title):
        super().__init__(title=title[:45])
        self.action = action
        self.value = discord.ui.TextInput(label="Discord ID", placeholder="123456789012345678", min_length=17, max_length=20)
        self.add_item(self.value)

    async def on_submit(self, interaction):
        try:
            ident = int(self.value.value.strip())
        except ValueError:
            return await interaction.response.send_message("❌ Invalid Discord ID.", ephemeral=True)
        gid = interaction.guild.id
        if self.action == "add_user":
            db_exec("INSERT OR IGNORE INTO protected_users VALUES(?,?)", (gid, ident))
        elif self.action == "remove_user":
            db_exec("DELETE FROM protected_users WHERE guild_id=? AND user_id=?", (gid, ident))
        elif self.action == "add_role":
            db_exec("INSERT OR IGNORE INTO protected_roles VALUES(?,?)", (gid, ident))
        else:
            db_exec("DELETE FROM protected_roles WHERE guild_id=? AND role_id=?", (gid, ident))
        await animated_send(interaction, mention_embed(interaction.guild), MentionView(), ephemeral=False)


class AutoResponderView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        self.add_item(ARButton("Add Trigger", "add", 0))
        self.add_item(ARButton("Remove Trigger", "remove", 0))
        self.add_item(ARButton("List", "list", 0))
        self.add_item(BackButton())


class ARButton(discord.ui.Button):
    def __init__(self, label, action, row):
        super().__init__(label=label, emoji="💠", style=discord.ButtonStyle.primary, row=row)
        self.action = action

    async def callback(self, interaction):
        if not is_admin(interaction.user):
            return await deny(interaction)
        if self.action == "add":
            await interaction.response.send_modal(AutoResponderModal())
        elif self.action == "remove":
            await interaction.response.send_modal(ARRemoveModal())
        else:
            await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView(), ephemeral=False)


class AutoResponderModal(discord.ui.Modal, title="Create AutoResponder"):
    trigger = discord.ui.TextInput(label="Trigger", placeholder="ip", max_length=100)
    reply = discord.ui.TextInput(label="Exact reply", placeholder="ip port", max_length=1000)
    mode = discord.ui.TextInput(label="Mode: exact / contains", placeholder="exact", default="exact", max_length=20)

    async def on_submit(self, interaction):
        mode = self.mode.value.strip().lower()
        if mode not in ("exact", "contains"):
            return await interaction.response.send_message("❌ Mode must be `exact` or `contains`.", ephemeral=True)
        try:
            db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES(?,?,?,?)",
                    (interaction.guild.id, self.trigger.value.strip(), self.reply.value, mode))
        except sqlite3.IntegrityError:
            return await interaction.response.send_message("⚠️ That trigger already exists.", ephemeral=True)
        await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView(), ephemeral=False)


class ARRemoveModal(discord.ui.Modal, title="Remove AutoResponder"):
    trigger = discord.ui.TextInput(label="Trigger", placeholder="ip", max_length=100)

    async def on_submit(self, interaction):
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND trigger=?", (interaction.guild.id, self.trigger.value.strip()))
        await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView(), ephemeral=False)

# ============================================================
# COMMANDS
# ============================================================

@bot.tree.command(name="security", description="Open the premium security dashboard")
@app_commands.default_permissions(administrator=True)
async def security_slash(interaction):
    if not is_admin(interaction.user):
        return await deny(interaction)
    await animated_send(interaction, dashboard_embed(interaction.guild), DashboardView())


@bot.command(name="security")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def security_prefix(ctx):
    await animated_ctx(ctx, dashboard_embed(ctx.guild), DashboardView())


@bot.tree.command(name="automod", description="Open AutoMod controls")
@app_commands.default_permissions(administrator=True)
async def automod_slash(interaction):
    if not is_admin(interaction.user): return await deny(interaction)
    await animated_send(interaction, automod_embed(interaction.guild), AutoModView())


@bot.command(name="automod")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def automod_prefix(ctx):
    await animated_ctx(ctx, automod_embed(ctx.guild), AutoModView())


@bot.tree.command(name="antinuke", description="Open Anti-Nuke controls")
@app_commands.default_permissions(administrator=True)
async def antinuke_slash(interaction):
    if not is_admin(interaction.user): return await deny(interaction)
    await animated_send(interaction, antinuke_embed(interaction.guild), AntiNukeView())


@bot.command(name="antinuke")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def antinuke_prefix(ctx):
    await animated_ctx(ctx, antinuke_embed(ctx.guild), AntiNukeView())


@bot.tree.command(name="mention", description="Open Mention Guard controls")
@app_commands.default_permissions(administrator=True)
async def mention_slash(interaction):
    if not is_admin(interaction.user): return await deny(interaction)
    await animated_send(interaction, mention_embed(interaction.guild), MentionView())


@bot.command(name="mention")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def mention_prefix(ctx):
    await animated_ctx(ctx, mention_embed(ctx.guild), MentionView())


@bot.tree.command(name="setlog", description="Set security log channel")
@app_commands.describe(channel="Security log channel")
@app_commands.default_permissions(administrator=True)
async def setlog_slash(interaction, channel: discord.TextChannel):
    if not is_admin(interaction.user): return await deny(interaction)
    set_setting(interaction.guild.id, "log_channel", channel.id)
    await interaction.response.send_message(f"📜 Security logs → {channel.mention}", ephemeral=True)


@bot.command(name="setlog")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def setlog_prefix(ctx, channel: discord.TextChannel):
    set_setting(ctx.guild.id, "log_channel", channel.id)
    await ctx.send(f"📜 Security logs → {channel.mention}", delete_after=5)


@bot.tree.command(name="whitelist", description="Whitelist a member from Anti-Nuke")
@app_commands.describe(member="Member to whitelist")
@app_commands.default_permissions(administrator=True)
async def whitelist_slash(interaction, member: discord.Member):
    if not is_admin(interaction.user): return await deny(interaction)
    db_exec("INSERT OR IGNORE INTO whitelist VALUES(?,?)", (interaction.guild.id, member.id))
    await interaction.response.send_message(f"🟢 {member.mention} is now whitelisted.", ephemeral=True)


@bot.command(name="whitelist")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def whitelist_prefix(ctx, member: discord.Member):
    db_exec("INSERT OR IGNORE INTO whitelist VALUES(?,?)", (ctx.guild.id, member.id))
    await ctx.send(f"🟢 {member.mention} is now whitelisted.", delete_after=5)


@bot.tree.command(name="unwhitelist", description="Remove a member from Anti-Nuke whitelist")
@app_commands.describe(member="Member to remove")
@app_commands.default_permissions(administrator=True)
async def unwhitelist_slash(interaction, member: discord.Member):
    if not is_admin(interaction.user): return await deny(interaction)
    db_exec("DELETE FROM whitelist WHERE guild_id=? AND user_id=?", (interaction.guild.id, member.id))
    await interaction.response.send_message(f"⚫ {member.mention} removed from whitelist.", ephemeral=True)


@bot.command(name="unwhitelist")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def unwhitelist_prefix(ctx, member: discord.Member):
    db_exec("DELETE FROM whitelist WHERE guild_id=? AND user_id=?", (ctx.guild.id, member.id))
    await ctx.send(f"⚫ {member.mention} removed from whitelist.", delete_after=5)


# -------------------- AFK --------------------

@bot.tree.command(name="afk", description="Set your AFK status")
@app_commands.describe(reason="Why you are AFK")
async def afk_slash(interaction, reason: str):
    afk_set(interaction.guild.id, interaction.user.id, reason)
    e = premium_embed("💤 AFK Enabled", f"**Reason:** {reason}\n**Since:** {discord.utils.format_dt(discord.utils.utcnow(), 'R')}", CYAN)
    await interaction.response.send_message(embed=e)
    # No dashboard/menu attached.


@bot.command(name="afk")
@commands.guild_only()
async def afk_prefix(ctx, *, reason: str = "AFK"):
    afk_set(ctx.guild.id, ctx.author.id, reason)
    try:
        await ctx.message.delete()
    except discord.HTTPException:
        pass
    e = premium_embed("💤 AFK Enabled", f"**Reason:** {reason}\n**Since:** {discord.utils.format_dt(discord.utils.utcnow(), 'R')}", CYAN)
    await ctx.send(embed=e, delete_after=AFK_DELETE_AFTER)


# -------------------- AUTORESPONDER --------------------

@bot.tree.command(name="autoresponder", description="Manage exact-match automatic replies")
@app_commands.describe(action="Action", trigger="Trigger text", reply="Reply text", mode="Match mode")
@app_commands.choices(action=[app_commands.Choice(name="add", value="add"), app_commands.Choice(name="remove", value="remove"), app_commands.Choice(name="list", value="list")])
@app_commands.choices(mode=[app_commands.Choice(name="EXACT", value="exact"), app_commands.Choice(name="CONTAINS", value="contains")])
@app_commands.default_permissions(administrator=True)
async def autoresponder_slash(interaction, action: app_commands.Choice[str], trigger: str = None, reply: str = None, mode: app_commands.Choice[str] = None):
    if not is_admin(interaction.user): return await deny(interaction)
    action = action.value
    if action == "list":
        return await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView())
    if not trigger:
        return await interaction.response.send_message("❌ Trigger is required.", ephemeral=True)
    if action == "remove":
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND trigger=?", (interaction.guild.id, trigger.strip()))
        return await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView())
    if not reply:
        return await interaction.response.send_message("❌ Reply is required.", ephemeral=True)
    match_mode = mode.value if mode else "exact"
    try:
        db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES(?,?,?,?)", (interaction.guild.id, trigger.strip(), reply, match_mode))
    except sqlite3.IntegrityError:
        return await interaction.response.send_message("⚠️ Trigger already exists. Remove it first.", ephemeral=True)
    await animated_send(interaction, autoresponder_embed(interaction.guild), AutoResponderView())


@bot.command(name="ar")
@commands.guild_only()
@commands.has_guild_permissions(administrator=True)
async def ar_prefix(ctx, *, raw: str = None):
    """$ar add ip | ip port | exact  /  $ar remove ip  /  $ar list"""
    if not raw:
        return await ctx.send("💠 `$ar add trigger | reply | exact`\n💠 `$ar remove trigger`\n💠 `$ar list`", delete_after=10)
    parts = [p.strip() for p in raw.split("|")]
    action = parts[0].lower()
    if action == "list":
        return await animated_ctx(ctx, autoresponder_embed(ctx.guild), AutoResponderView())
    if action == "remove" and len(parts) >= 2:
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND trigger=?", (ctx.guild.id, parts[1]))
        return await animated_ctx(ctx, autoresponder_embed(ctx.guild), AutoResponderView())
    if action == "add" and len(parts) >= 3:
        trigger, reply = parts[1], parts[2]
        mode = parts[3].lower() if len(parts) >= 4 else "exact"
        if mode not in ("exact", "contains"):
            return await ctx.send("❌ Mode must be `exact` or `contains`.", delete_after=6)
        try:
            db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES(?,?,?,?)", (ctx.guild.id, trigger, reply, mode))
        except sqlite3.IntegrityError:
            return await ctx.send("⚠️ Trigger already exists.", delete_after=6)
        return await animated_ctx(ctx, autoresponder_embed(ctx.guild), AutoResponderView())
    await ctx.send("❌ Format: `$ar add trigger | reply | exact`", delete_after=8)


# -------------------- HELP / STATUS --------------------

@bot.tree.command(name="help", description="Show Security Core commands")
async def help_slash(interaction):
    e = premium_embed("✦ SECURITY CORE • COMMANDS", "**Admin controls** require the Discord **Administrator** permission.")
    e.add_field(name="ADMIN", value="`/security` · `/automod` · `/antinuke` · `/mention`\n`/setlog` · `/whitelist` · `/unwhitelist`\n`/autoresponder`", inline=False)
    e.add_field(name="MEMBERS", value="`/afk reason`", inline=False)
    e.add_field(name="PREFIX", value="`$` and `!` work. Example: `$afk sona jaa rha`", inline=False)
    await animated_send(interaction, e, None)


@bot.command(name="help")
@commands.guild_only()
async def help_prefix(ctx):
    e = premium_embed("✦ SECURITY CORE • COMMANDS", "**Admin controls** require the Discord **Administrator** permission.")
    e.add_field(name="ADMIN", value="`$security` · `$automod` · `$antinuke` · `$mention`\n`$setlog` · `$whitelist` · `$unwhitelist`\n`$ar add trigger | reply | exact`", inline=False)
    e.add_field(name="MEMBERS", value="`$afk reason`", inline=False)
    await animated_ctx(ctx, e)

# ============================================================
# MESSAGE PROTECTION
# ============================================================

URL_RE = re.compile(r"(?:https?://|www\.|discord\.gg/|discord\.com/invite/|discordapp\.com/invite/)[^\s]+", re.I)
INVITE_RE = re.compile(r"(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite)/[A-Za-z0-9-]+", re.I)
DEFAULT_BADWORDS = {"fuck", "fucker", "motherfucker"}

spam_cache = defaultdict(lambda: deque(maxlen=12))
duplicate_cache = defaultdict(lambda: deque(maxlen=6))
mention_cache = defaultdict(lambda: deque(maxlen=8))


async def process_afk(message):
    if message.author.bot or not message.guild:
        return False
    # Any normal message removes the sender's AFK.
    own = afk_get(message.guild.id, message.author.id)
    if own:
        afk_remove(message.guild.id, message.author.id)
        notice = await message.channel.send(f"👋 {message.author.mention} **AFK removed.** Welcome back.", delete_after=5)
        return False

    # Tell the sender about every AFK user they mention.
    mentioned = []
    for member in message.mentions:
        row = afk_get(message.guild.id, member.id)
        if row:
            mentioned.append((member, row))
    if mentioned:
        lines = []
        for member, row in mentioned[:5]:
            lines.append(f"💤 {member.mention} is AFK — **{row['reason']}** • {fmt_since(row['since'])}")
        try:
            await message.channel.send("\n".join(lines), delete_after=20)
        except discord.HTTPException:
            pass
    return False


def protected_mention_targets(message):
    targets = []
    for m in message.mentions:
        if protected_user(message.guild.id, m.id):
            targets.append(m.mention)
    role_ids = {r.id for r in message.role_mentions}
    for rid in role_ids:
        if protected_role(message.guild.id, rid):
            role = message.guild.get_role(rid)
            targets.append(role.mention if role else f"<@&{rid}>")
    return targets


async def process_mentions(message):
    if not bool_setting(message.guild.id, "antimention") or not message.mentions and not message.role_mentions:
        return False
    targets = protected_mention_targets(message)
    if not targets:
        return False
    if is_admin(message.author):
        return False
    warning = await message.channel.send(embed=premium_embed("🚫 DONT PING HIGH STAFF", f"👤 **Who pinged:** {message.author.mention}\n🎯 **Target:** {', '.join(targets[:5])}", RED))
    asyncio.create_task(delete_after(warning, 60))
    asyncio.create_task(delete_after(message, MENTION_DELETE_AFTER))
    await send_log(message.guild, "🎯 Protected mention blocked", f"{message.author.mention} → {', '.join(targets[:5])}", RED)
    return True


async def process_automod(message):
    if message.author.bot or not message.guild:
        return False
    s = settings(message.guild.id)
    if not s["automod"] or is_admin(message.author):
        return False

    content = message.content or ""
    reason = None
    instant = False

    # Links are intentionally instant: delete + punishment in the same event.
    if s["antilinks"] and URL_RE.search(content):
        reason = "Link protection"
        instant = True
    if s["antiinvite"] and INVITE_RE.search(content):
        reason = "Discord invite protection"
        instant = True
    if s["badwords"] and any(re.search(rf"\b{re.escape(w)}\b", content, re.I) for w in DEFAULT_BADWORDS):
        reason = "Bad word filter"
    if s["anticaps"]:
        letters = [c for c in content if c.isalpha()]
        if len(letters) >= 10 and sum(c.isupper() for c in letters) / len(letters) >= 0.75:
            reason = "Excessive caps"
    if s["antimention"] and len(message.mentions) + len(message.role_mentions) >= s["mention_limit"]:
        reason = "Mass mention protection"
    if s["duplicate"]:
        key = (message.guild.id, message.author.id)
        normalized = re.sub(r"\s+", " ", content.strip().lower())
        if normalized and normalized in duplicate_cache[key]:
            reason = "Duplicate message"
        duplicate_cache[key].append(normalized)
    if s["antispam"]:
        key = (message.guild.id, message.author.id)
        now = asyncio.get_running_loop().time()
        spam_cache[key].append(now)
        while spam_cache[key] and now - spam_cache[key][0] > 8:
            spam_cache[key].popleft()
        if len(spam_cache[key]) >= s["spam_limit"]:
            reason = "Spam protection"

    if not reason:
        return False

    try:
        await message.delete()
    except discord.HTTPException:
        pass

    mode = s["punishment"]
    await punishment(message.author, mode, f"AutoMod: {reason}")
    warning = await message.channel.send(embed=premium_embed("🛡️ AUTOMOD ACTION", f"👤 {message.author.mention}\n⚠️ **{reason}**\n⚡ **Action:** {mode.upper()}", ORANGE))
    asyncio.create_task(delete_after(warning, 30))
    await send_log(message.guild, "🛡️ AutoMod action", f"{message.author.mention}\nReason: **{reason}**\nAction: **{mode.upper()}**", ORANGE)
    return True


async def process_autoresponder(message):
    if message.author.bot or not message.guild or not message.content:
        return
    rows = ar_list(message.guild.id)
    if not rows:
        return
    text = message.content.strip()
    low = text.casefold()
    for row in rows:
        trigger = row["trigger"].strip().casefold()
        matched = low == trigger if row["mode"] == "exact" else trigger in low
        if matched and row["enabled"]:
            try:
                await message.channel.send(row["reply"])
            except discord.HTTPException:
                pass
            break

# ============================================================
# ANTI-NUKE AUDIT LOG
# ============================================================

async def audit_executor(guild, action, target_id=None):
    try:
        async for entry in guild.audit_logs(limit=6, action=action):
            if (datetime.now(timezone.utc) - entry.created_at).total_seconds() > 12:
                continue
            if target_id is not None and getattr(entry.target, "id", None) != target_id:
                continue
            return entry.user
    except (discord.Forbidden, discord.HTTPException):
        return None
    return None


async def nuke_action(guild, executor, reason):
    if not executor or executor.bot or whitelist(guild.id, executor.id) or is_admin(executor):
        return
    s = settings(guild.id)
    mode = s["nuke_punishment"]
    ok = await punishment(executor, mode, reason)
    await send_log(guild, "☢️ ANTI-NUKE ACTION", f"👤 Executor: {executor.mention}\n⚠️ {reason}\n⚡ Punishment: **{mode.upper()}**\n{'✅ Applied' if ok else '⚠️ Could not apply'}", RED)


@bot.event
async def on_guild_channel_delete(channel):
    if not bool_setting(channel.guild.id, "antinuke") or not bool_setting(channel.guild.id, "nuke_channel_delete"):
        return
    executor = await audit_executor(channel.guild, discord.AuditLogAction.channel_delete, channel.id)
    await nuke_action(channel.guild, executor, f"Channel deleted: **{channel.name}**")


@bot.event
async def on_guild_channel_create(channel):
    if not bool_setting(channel.guild.id, "antinuke") or not bool_setting(channel.guild.id, "nuke_channel_create"):
        return
    executor = await audit_executor(channel.guild, discord.AuditLogAction.channel_create, channel.id)
    await nuke_action(channel.guild, executor, f"Channel created: **{channel.name}**")


@bot.event
async def on_guild_role_delete(role):
    if not bool_setting(role.guild.id, "antinuke") or not bool_setting(role.guild.id, "nuke_role_delete"):
        return
    executor = await audit_executor(role.guild, discord.AuditLogAction.role_delete, role.id)
    await nuke_action(role.guild, executor, f"Role deleted: **{role.name}**")


@bot.event
async def on_guild_role_create(role):
    if not bool_setting(role.guild.id, "antinuke") or not bool_setting(role.guild.id, "nuke_role_create"):
        return
    executor = await audit_executor(role.guild, discord.AuditLogAction.role_create, role.id)
    await nuke_action(role.guild, executor, f"Role created: **{role.name}**")


@bot.event
async def on_member_ban(guild, user):
    if not bool_setting(guild.id, "antinuke") or not bool_setting(guild.id, "nuke_ban"):
        return
    executor = await audit_executor(guild, discord.AuditLogAction.ban, user.id)
    await nuke_action(guild, executor, f"Member banned: **{user}**")


@bot.event
async def on_member_remove(member):
    if not bool_setting(member.guild.id, "antinuke") or not bool_setting(member.guild.id, "nuke_kick"):
        return
    executor = await audit_executor(member.guild, discord.AuditLogAction.kick, member.id)
    if executor:
        await nuke_action(member.guild, executor, f"Member kicked: **{member}**")


@bot.event
async def on_member_join(member):
    if not member.bot or not bool_setting(member.guild.id, "antinuke") or not bool_setting(member.guild.id, "nuke_bot_add"):
        return
    executor = await audit_executor(member.guild, discord.AuditLogAction.bot_add, member.id)
    await nuke_action(member.guild, executor, f"Bot added: **{member}**")


@bot.event
async def on_webhooks_update(channel):
    if not bool_setting(channel.guild.id, "antinuke") or not bool_setting(channel.guild.id, "nuke_webhook"):
        return
    # Discord doesn't expose whether this was create/delete/update in the event;
    # audit-log lookup still identifies the latest webhook executor.
    executor = await audit_executor(channel.guild, discord.AuditLogAction.webhook_create)
    if not executor:
        executor = await audit_executor(channel.guild, discord.AuditLogAction.webhook_delete)
    await nuke_action(channel.guild, executor, f"Webhook change detected in **{channel.name}**")

# ============================================================
# MESSAGE EVENT
# ============================================================

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    if message.guild:
        ensure_guild(message.guild.id)
        await process_afk(message)
        if await process_mentions(message):
            await bot.process_commands(message)
            return
        if await process_automod(message):
            await bot.process_commands(message)
            return
        await process_autoresponder(message)
    await bot.process_commands(message)

# ============================================================
# ERROR HANDLERS
# ============================================================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        return await ctx.send("⛔ **Administrator permission required.**", delete_after=5)
    if isinstance(error, commands.MissingRequiredArgument):
        return await ctx.send("❌ Missing required argument.", delete_after=5)
    if isinstance(error, commands.MemberNotFound):
        return await ctx.send("❌ Member not found.", delete_after=5)
    log.exception("Prefix command error", exc_info=error)


@bot.tree.error
async def on_app_command_error(interaction, error):
    original = getattr(error, "original", error)
    if isinstance(original, app_commands.errors.MissingPermissions):
        msg = "⛔ **Administrator permission required.**"
    else:
        log.exception("Slash command error: %s", original)
        msg = "❌ **Command failed. Check bot permissions and try again.**"
    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except discord.HTTPException:
        pass

# ============================================================
# READY / RENDER
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
        log.exception("Slash sync failed")
    log.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "unknown")
    log.info("Serving %s guild(s).", len(bot.guilds))


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"OK - BLASTMC SECURITY CORE")

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


db_init()
threading.Thread(target=start_health_server, daemon=True, name="render-health").start()
bot.run(TOKEN)
