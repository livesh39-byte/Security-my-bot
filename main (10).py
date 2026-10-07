import os
import re
import sqlite3
import asyncio
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

import discord
from discord.ext import commands
from discord import app_commands

# ============================================================
# BLASTMC • PREMIUM COMMUNITY BOT
# Features: AFK, AutoResponder, Auto Role, Lockdown, Announce,
# UserInfo, MemberCount + Mention Guard (only module with menu)
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")
DB_FILE = "bot.db"
PORT = int(os.getenv("PORT", "10000"))
PREFIXES = ("!", "$")
AFK_DELETE_AFTER = 60
MENTION_DELETE_AFTER = 10
BOT_MESSAGE_DELETE_AFTER = 60

COLORS = {
    "main": discord.Color.from_rgb(99, 102, 241),
    "success": discord.Color.from_rgb(34, 197, 94),
    "danger": discord.Color.from_rgb(239, 68, 68),
    "gold": discord.Color.from_rgb(245, 158, 11),
    "cyan": discord.Color.from_rgb(34, 211, 238),
    "pink": discord.Color.from_rgb(236, 72, 153),
}

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN environment variable is missing.")

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s:%(name)s: %(message)s")
log = logging.getLogger("blastmc-premium")

intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.message_content = True
intents.messages = True

bot = commands.Bot(command_prefix=PREFIXES, intents=intents, help_command=None)

# ============================================================
# DATABASE
# ============================================================

db = sqlite3.connect(DB_FILE, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = threading.RLock()


def db_exec(sql, params=(), fetch=False):
    with db_lock:
        cur = db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        db.commit()
        return rows


def db_init():
    with db_lock:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS guilds (
            guild_id INTEGER PRIMARY KEY,
            autorole_id INTEGER DEFAULT 0,
            lockdown INTEGER DEFAULT 0,
            welcome_channel_id INTEGER DEFAULT 0,
            welcome_text TEXT DEFAULT '',
            welcome_dm TEXT DEFAULT '',
            welcome_enabled INTEGER DEFAULT 0
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
        """)
        # Safe migration for older bot.db files.
        cols = {r[1] for r in db.execute("PRAGMA table_info(guilds)").fetchall()}
        if "autorole_id" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN autorole_id INTEGER DEFAULT 0")
        if "lockdown" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN lockdown INTEGER DEFAULT 0")
        if "welcome_channel_id" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN welcome_channel_id INTEGER DEFAULT 0")
        if "welcome_text" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN welcome_text TEXT DEFAULT ''")
        if "welcome_dm" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN welcome_dm TEXT DEFAULT ''")
        if "welcome_enabled" not in cols:
            db.execute("ALTER TABLE guilds ADD COLUMN welcome_enabled INTEGER DEFAULT 0")
        db.commit()


def ensure_guild(guild_id):
    db_exec("INSERT OR IGNORE INTO guilds(guild_id) VALUES (?)", (guild_id,))


def guild_row(guild_id):
    ensure_guild(guild_id)
    return db_exec("SELECT * FROM guilds WHERE guild_id=?", (guild_id,), True)[0]


def set_guild_value(guild_id, column, value):
    if column not in {"autorole_id", "lockdown", "welcome_channel_id", "welcome_text", "welcome_dm", "welcome_enabled"}:
        raise ValueError("invalid guild setting")
    ensure_guild(guild_id)
    db_exec(f"UPDATE guilds SET {column}=? WHERE guild_id=?", (value, guild_id))


def afk_get(guild_id, user_id):
    rows = db_exec("SELECT * FROM afk WHERE guild_id=? AND user_id=?", (guild_id, user_id), True)
    return rows[0] if rows else None


def afk_set(guild_id, user_id, reason):
    since = datetime.now(timezone.utc).isoformat()
    db_exec("INSERT OR REPLACE INTO afk(guild_id,user_id,reason,since) VALUES (?,?,?,?)",
            (guild_id, user_id, reason, since))


def afk_remove(guild_id, user_id):
    db_exec("DELETE FROM afk WHERE guild_id=? AND user_id=?", (guild_id, user_id))


def ar_list(guild_id):
    return db_exec("SELECT * FROM autoresponders WHERE guild_id=? ORDER BY id", (guild_id,), True)


def protected_user(guild_id, user_id):
    return bool(db_exec("SELECT 1 FROM protected_users WHERE guild_id=? AND user_id=?", (guild_id, user_id), True))


def protected_role(guild_id, role_id):
    return bool(db_exec("SELECT 1 FROM protected_roles WHERE guild_id=? AND role_id=?", (guild_id, role_id), True))


def is_admin(member):
    return bool(member and isinstance(member, discord.Member) and member.guild_permissions.administrator)


def fmt_since(iso):
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        seconds = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        if seconds < 60:
            return f"{seconds} second{'s' if seconds != 1 else ''} ago"
        minutes = seconds // 60
        if minutes < 60:
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        days = hours // 24
        return f"{days} day{'s' if days != 1 else ''} ago"
    except Exception:
        return "just now"


def parse_duration(value):
    """Parse 10s, 5m, 2h, 1d or plain seconds into seconds."""
    value = str(value).strip().lower()
    m = re.fullmatch(r"(\d{1,5})(s|m|h|d)?", value)
    if not m:
        return None
    amount = int(m.group(1))
    unit = m.group(2) or "s"
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    seconds = amount * mult
    return seconds if 1 <= seconds <= 2419200 else None

def welcome_render(template, member):
    return (template or "Welcome {user} to **{server}**! 🎉")\
        .replace("{user}", member.mention)\
        .replace("{server}", member.guild.name)\
        .replace("{membercount}", f"{member.guild.member_count:,}")

def premium_embed(title, description="", color=None):
    e = discord.Embed(title=title, description=description, color=color or COLORS["main"])
    e.set_footer(text="BLASTMC • PREMIUM")
    e.timestamp = datetime.now(timezone.utc)
    return e


def bot_can(member, permission):
    return bool(member and getattr(member.guild_permissions, permission, False))


async def safe_delete(message, delay):
    await asyncio.sleep(delay)
    try:
        await message.delete()
    except (discord.NotFound, discord.Forbidden, discord.HTTPException):
        pass


async def safe_send(channel, content=None, embed=None, delete_after=None):
    try:
        msg = await channel.send(content=content, embed=embed)
        if delete_after:
            asyncio.create_task(safe_delete(msg, delete_after))
        return msg
    except discord.HTTPException:
        return None


async def send_prefix(ctx, embed=None, content=None, delete_after=None):
    # No fake "syncing" message. One clean response only.
    return await safe_send(ctx.channel, content=content, embed=embed, delete_after=delete_after)


async def send_slash(interaction, embed=None, content=None, ephemeral=False):
    try:
        if not interaction.response.is_done():
            await interaction.response.send_message(content=content, embed=embed, ephemeral=ephemeral)
        else:
            await interaction.followup.send(content=content, embed=embed, ephemeral=ephemeral)
    except discord.HTTPException:
        pass


async def require_admin(interaction):
    if not is_admin(interaction.user):
        await send_slash(interaction, embed=premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"]), ephemeral=True)
        return False
    return True


async def require_admin_ctx(ctx):
    if not is_admin(ctx.author):
        await send_prefix(ctx, embed=premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"]), delete_after=8)
        return False
    return True

# ============================================================
# EMBEDS
# ============================================================

def afk_embed(member, reason, since):
    return premium_embed(
        "💤 AFK Enabled",
        f"**Reason:** {discord.utils.escape_markdown(reason)}\n**Since:** {fmt_since(since)}",
        COLORS["main"],
    )


def autoresponder_embed(guild):
    rows = ar_list(guild.id)
    e = premium_embed("✦ AUTORESPONDER", "Exact-match and contains-match replies.")
    if not rows:
        e.add_field(name="STATUS", value="No responders configured.", inline=False)
    else:
        lines = []
        for r in rows[:15]:
            lines.append(f"`{r['trigger']}` → `{r['reply']}` • **{r['mode'].upper()}**")
        if len(rows) > 15:
            lines.append(f"…and {len(rows)-15} more")
        e.add_field(name=f"RESPONDERS • {len(rows)}", value="\n".join(lines), inline=False)
    return e


def mention_embed(guild):
    users = db_exec("SELECT user_id FROM protected_users WHERE guild_id=?", (guild.id,), True)
    roles = db_exec("SELECT role_id FROM protected_roles WHERE guild_id=?", (guild.id,), True)
    return premium_embed(
        "🎯 MENTION GUARD",
        f"Protected users: **{len(users)}**\nProtected roles: **{len(roles)}**\n\nPing protection is active.",
        COLORS["danger"],
    )

# ============================================================
# MENTION MENU — ONLY DROPDOWN IN THE BOT
# ============================================================

class MentionSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="Add Protected User", value="add_user", emoji="👤"),
            discord.SelectOption(label="Remove Protected User", value="remove_user", emoji="🗑️"),
            discord.SelectOption(label="Add Protected Role", value="add_role", emoji="🛡️"),
            discord.SelectOption(label="Remove Protected Role", value="remove_role", emoji="🗑️"),
            discord.SelectOption(label="View Protected List", value="list", emoji="📋"),
        ]
        super().__init__(placeholder="Choose a mention action…", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        if not await require_admin(interaction):
            return
        action = self.values[0]
        if action == "list":
            users = db_exec("SELECT user_id FROM protected_users WHERE guild_id=?", (interaction.guild.id,), True)
            roles = db_exec("SELECT role_id FROM protected_roles WHERE guild_id=?", (interaction.guild.id,), True)
            text = []
            text.append("**Users**\n" + ("\n".join(f"• <@{r['user_id']}>" for r in users) if users else "• None"))
            text.append("**Roles**\n" + ("\n".join(f"• <@&{r['role_id']}>" for r in roles) if roles else "• None"))
            await send_slash(interaction, embed=premium_embed("🎯 PROTECTED LIST", "\n\n".join(text)), ephemeral=True)
            return
        await interaction.response.send_modal(ProtectedIDModal(action))


class MentionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)
        self.add_item(MentionSelect())


class ProtectedIDModal(discord.ui.Modal):
    def __init__(self, action):
        self.action = action
        super().__init__(title="Mention Guard")
        self.target = discord.ui.TextInput(label="Discord ID", placeholder="Paste the user/role ID", min_length=2, max_length=30)
        self.add_item(self.target)

    async def on_submit(self, interaction: discord.Interaction):
        if not await require_admin(interaction):
            return
        try:
            target_id = int(str(self.target.value).strip())
        except ValueError:
            await send_slash(interaction, embed=premium_embed("INVALID ID", "Please enter a numeric Discord ID.", COLORS["danger"]), ephemeral=True)
            return
        if self.action.endswith("user"):
            if self.action == "add_user":
                db_exec("INSERT OR IGNORE INTO protected_users(guild_id,user_id) VALUES (?,?)", (interaction.guild.id, target_id))
                text = f"Protected user added: <@{target_id}>"
            else:
                db_exec("DELETE FROM protected_users WHERE guild_id=? AND user_id=?", (interaction.guild.id, target_id))
                text = f"Protected user removed: <@{target_id}>"
        else:
            if self.action == "add_role":
                db_exec("INSERT OR IGNORE INTO protected_roles(guild_id,role_id) VALUES (?,?)", (interaction.guild.id, target_id))
                text = f"Protected role added: <@&{target_id}>"
            else:
                db_exec("DELETE FROM protected_roles WHERE guild_id=? AND role_id=?", (interaction.guild.id, target_id))
                text = f"Protected role removed: <@&{target_id}>"
        await send_slash(interaction, embed=premium_embed("MENTION GUARD UPDATED", text, COLORS["success"]), ephemeral=True)

# ============================================================
# AUTORESPONDER MODAL (NO DROPDOWN)
# ============================================================

class AutoResponderModal(discord.ui.Modal):
    def __init__(self, guild_id):
        self.guild_id = guild_id
        super().__init__(title="Create AutoResponder")
        self.trigger = discord.ui.TextInput(label="Trigger", placeholder="ip", max_length=200)
        self.reply = discord.ui.TextInput(label="Reply", placeholder="ip port", style=discord.TextStyle.paragraph, max_length=1500)
        self.mode = discord.ui.TextInput(label="Mode", placeholder="exact or contains", default="exact", max_length=10)
        self.add_item(self.trigger)
        self.add_item(self.reply)
        self.add_item(self.mode)

    async def on_submit(self, interaction: discord.Interaction):
        if not await require_admin(interaction):
            return
        trigger = str(self.trigger.value).strip()
        reply = str(self.reply.value).strip()
        mode = str(self.mode.value).strip().lower()
        if not trigger or not reply or mode not in {"exact", "contains"}:
            await send_slash(interaction, embed=premium_embed("INVALID AUTORESPONDER", "Mode must be `exact` or `contains`.", COLORS["danger"]), ephemeral=True)
            return
        db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES (?,?,?,?)", (self.guild_id, trigger, reply, mode))
        await send_slash(interaction, embed=premium_embed("AUTORESPONDER SAVED", f"`{trigger}` → `{reply}`\nMode: **{mode.upper()}**", COLORS["success"]), ephemeral=True)

# ============================================================
# ADMIN PANEL — BUTTONS ONLY; MENTION HAS THE ONLY MENU
# ============================================================

# ============================================================
# SLASH COMMANDS — clean embeds; Mention is the only dropdown menu
# ============================================================

@bot.tree.command(name="afk", description="Set your AFK status")
@app_commands.describe(reason="Why you are AFK")
async def afk_slash(interaction: discord.Interaction, reason: str):
    old = afk_get(interaction.guild.id, interaction.user.id)
    afk_set(interaction.guild.id, interaction.user.id, reason)
    await send_slash(interaction, embed=afk_embed(interaction.user, reason, afk_get(interaction.guild.id, interaction.user.id)["since"]))


@bot.tree.command(name="autoresponder", description="Create, remove, or list automatic replies")
@app_commands.describe(action="add, remove, or list", trigger="Trigger text", reply="Reply text", mode="exact or contains")
@app_commands.choices(action=[app_commands.Choice(name="add", value="add"), app_commands.Choice(name="remove", value="remove"), app_commands.Choice(name="list", value="list")], mode=[app_commands.Choice(name="exact", value="exact"), app_commands.Choice(name="contains", value="contains")])
async def autoresponder_slash(interaction: discord.Interaction, action: app_commands.Choice[str], trigger: str | None = None, reply: str | None = None, mode: app_commands.Choice[str] | None = None):
    if not await require_admin(interaction): return
    act = action.value
    if act == "list":
        await send_slash(interaction, embed=autoresponder_embed(interaction.guild), ephemeral=True)
        return
    if not trigger:
        await send_slash(interaction, embed=premium_embed("MISSING TRIGGER", "Provide the trigger text.", COLORS["danger"]), ephemeral=True)
        return
    if act == "remove":
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND lower(trigger)=lower(?)", (interaction.guild.id, trigger.strip()))
        await send_slash(interaction, embed=premium_embed("AUTORESPONDER REMOVED", f"Trigger: `{trigger}`", COLORS["success"]), ephemeral=True)
        return
    if not reply:
        await send_slash(interaction, embed=premium_embed("MISSING REPLY", "Provide the reply text.", COLORS["danger"]), ephemeral=True)
        return
    selected_mode = mode.value if mode else "exact"
    db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES (?,?,?,?)", (interaction.guild.id, trigger.strip(), reply, selected_mode))
    await send_slash(interaction, embed=premium_embed("AUTORESPONDER SAVED", f"`{trigger}` → `{reply}`\nMode: **{selected_mode.upper()}**", COLORS["success"]), ephemeral=True)


@bot.tree.command(name="autorole", description="Configure the role given to new members")
@app_commands.describe(role="Role to give automatically; leave empty to disable")
async def autorole_slash(interaction: discord.Interaction, role: discord.Role | None = None):
    if not await require_admin(interaction): return
    if role is None:
        set_guild_value(interaction.guild.id, "autorole_id", 0)
        await send_slash(interaction, embed=premium_embed("AUTO ROLE DISABLED", "New members will no longer receive an automatic role.", COLORS["danger"]), ephemeral=True)
        return
    if role >= interaction.guild.me.top_role:
        await send_slash(interaction, embed=premium_embed("ROLE TOO HIGH", "Move the bot role above the Auto Role target first.", COLORS["danger"]), ephemeral=True)
        return
    set_guild_value(interaction.guild.id, "autorole_id", role.id)
    await send_slash(interaction, embed=premium_embed("AUTO ROLE ENABLED", f"New members will receive {role.mention}.", COLORS["success"]), ephemeral=True)


@bot.tree.command(name="lockdown", description="Lock or unlock the current channel")
@app_commands.describe(action="lock or unlock")
@app_commands.choices(action=[app_commands.Choice(name="lock", value="lock"), app_commands.Choice(name="unlock", value="unlock")])
async def lockdown_slash(interaction: discord.Interaction, action: app_commands.Choice[str]):
    if not await require_admin(interaction): return
    await do_lockdown(interaction.guild, interaction.user, interaction=interaction, force=action.value)


@bot.tree.command(name="announce", description="Send a premium announcement to a channel")
@app_commands.describe(channel="Target channel", message="Announcement content")
async def announce_slash(interaction: discord.Interaction, channel: discord.TextChannel, message: str):
    if not await require_admin(interaction): return
    if not channel.permissions_for(interaction.guild.me).send_messages:
        await send_slash(interaction, embed=premium_embed("NO CHANNEL ACCESS", "I cannot send messages in that channel.", COLORS["danger"]), ephemeral=True)
        return
    e = premium_embed("📣 ANNOUNCEMENT", message, COLORS["cyan"])
    await channel.send(embed=e)
    await send_slash(interaction, embed=premium_embed("ANNOUNCEMENT SENT", f"Published in {channel.mention}.", COLORS["success"]), ephemeral=True)


@bot.tree.command(name="userinfo", description="Show information about a member")
@app_commands.describe(member="Member to inspect")
async def userinfo_slash(interaction: discord.Interaction, member: discord.Member | None = None):
    member = member or interaction.user
    e = premium_embed(f"👤 {member.display_name}", f"{member.mention}")
    e.set_thumbnail(url=member.display_avatar.url)
    e.add_field(name="User ID", value=f"`{member.id}`", inline=False)
    e.add_field(name="Joined", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "Unknown", inline=True)
    e.add_field(name="Created", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    e.add_field(name="Roles", value=str(max(0, len(member.roles)-1)), inline=True)
    await send_slash(interaction, embed=e)


@bot.tree.command(name="membercount", description="Show current server member count")
async def membercount_slash(interaction: discord.Interaction):
    g = interaction.guild
    humans = sum(1 for m in g.members if not m.bot)
    bots = sum(1 for m in g.members if m.bot)
    e = premium_embed("✦ MEMBER COUNT", f"**Total:** {g.member_count:,}\n**Humans:** {humans:,}\n**Bots:** {bots:,}", COLORS["pink"])
    await send_slash(interaction, embed=e)


@bot.tree.command(name="say", description="Make the bot send a message")
@app_commands.describe(message="What the bot should say")
async def say_slash(interaction: discord.Interaction, message: str):
    if not await require_admin(interaction):
        return
    try:
        await interaction.channel.send(message)
        await send_slash(interaction, embed=premium_embed("✦ MESSAGE SENT", "Your message has been published.", COLORS["success"]), ephemeral=True)
    except discord.Forbidden:
        await send_slash(interaction, embed=premium_embed("SEND FAILED", "I need **Send Messages** permission in this channel.", COLORS["danger"]), ephemeral=True)
    except discord.HTTPException as exc:
        log.exception("Slash /say failed")
        await send_slash(interaction, embed=premium_embed("SEND FAILED", f"Discord rejected the message: `{exc}`", COLORS["danger"]), ephemeral=True)


@bot.tree.command(name="welcome", description="Configure the welcome channel, text, DM, or disable welcomes")
@app_commands.describe(action="channel, text, dm, or off", channel="Welcome channel", message="Welcome text or DM text")
@app_commands.choices(action=[app_commands.Choice(name="channel", value="channel"), app_commands.Choice(name="text", value="text"), app_commands.Choice(name="dm", value="dm"), app_commands.Choice(name="off", value="off")])
async def welcome_slash(interaction: discord.Interaction, action: app_commands.Choice[str], channel: discord.TextChannel | None = None, message: str | None = None):
    if not await require_admin(interaction): return
    act = action.value
    if act == "channel":
        if channel is None:
            await send_slash(interaction, embed=premium_embed("WELCOME CHANNEL", "Select a channel first.", COLORS["danger"]), ephemeral=True); return
        set_guild_value(interaction.guild.id, "welcome_channel_id", channel.id)
        set_guild_value(interaction.guild.id, "welcome_enabled", 1)
        await send_slash(interaction, embed=premium_embed("✦ WELCOME CHANNEL", f"Welcome messages will be sent in {channel.mention}.", COLORS["success"]), ephemeral=True); return
    if act == "text":
        if not message:
            await send_slash(interaction, embed=premium_embed("WELCOME TEXT", "Provide the welcome message.", COLORS["danger"]), ephemeral=True); return
        set_guild_value(interaction.guild.id, "welcome_text", message)
        await send_slash(interaction, embed=premium_embed("✦ WELCOME TEXT SAVED", "Use `{user}`, `{server}`, and `{membercount}` placeholders.", COLORS["success"]), ephemeral=True); return
    if act == "dm":
        if not message:
            await send_slash(interaction, embed=premium_embed("WELCOME DM", "Provide the DM message, or use `off` to disable it.", COLORS["danger"]), ephemeral=True); return
        set_guild_value(interaction.guild.id, "welcome_dm", message)
        await send_slash(interaction, embed=premium_embed("✦ WELCOME DM SAVED", "New members will receive the configured DM.", COLORS["success"]), ephemeral=True); return
    set_guild_value(interaction.guild.id, "welcome_enabled", 0)
    await send_slash(interaction, embed=premium_embed("WELCOME DISABLED", "Welcome messages are now off.", COLORS["danger"]), ephemeral=True)

@bot.tree.command(name="welcometest", description="Send a test welcome message for yourself")
async def welcometest_slash(interaction: discord.Interaction):
    if not await require_admin(interaction): return
    row = guild_row(interaction.guild.id)
    channel = interaction.guild.get_channel(row["welcome_channel_id"]) if row["welcome_channel_id"] else None
    if not channel:
        await send_slash(interaction, embed=premium_embed("WELCOME NOT CONFIGURED", "Set a welcome channel first.", COLORS["danger"]), ephemeral=True); return
    await channel.send(embed=premium_embed("✦ WELCOME", welcome_render(row["welcome_text"], interaction.user), COLORS["main"]))
    await send_slash(interaction, embed=premium_embed("WELCOME TEST SENT", f"Test sent in {channel.mention}.", COLORS["success"]), ephemeral=True)

@bot.tree.command(name="purge", description="Delete recent messages from this channel")
@app_commands.describe(amount="Number of messages to delete (1-100)")
async def purge_slash(interaction: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    if not await require_admin(interaction): return
    if not interaction.channel.permissions_for(interaction.guild.me).manage_messages:
        await send_slash(interaction, embed=premium_embed("MISSING PERMISSION", "I need **Manage Messages**.", COLORS["danger"]), ephemeral=True); return
    deleted = await interaction.channel.purge(limit=amount)
    await send_slash(interaction, embed=premium_embed("✦ PURGE COMPLETE", f"Deleted **{len(deleted)}** message(s).", COLORS["success"]), ephemeral=True)

@bot.tree.command(name="ban", description="Ban a member")
@app_commands.describe(member="Member to ban", reason="Reason")
async def ban_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await require_admin(interaction): return
    if member == interaction.user or member.top_role >= interaction.user.top_role:
        await send_slash(interaction, embed=premium_embed("BAN BLOCKED", "You cannot ban that member.", COLORS["danger"]), ephemeral=True); return
    try:
        await member.ban(reason=f"{interaction.user}: {reason}")
        await send_slash(interaction, embed=premium_embed("🔨 MEMBER BANNED", f"{member.mention} was banned.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["danger"]))
    except discord.Forbidden:
        await send_slash(interaction, embed=premium_embed("BAN FAILED", "I need **Ban Members** and a higher role.", COLORS["danger"]), ephemeral=True)

@bot.tree.command(name="kick", description="Kick a member")
@app_commands.describe(member="Member to kick", reason="Reason")
async def kick_slash(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
    if not await require_admin(interaction): return
    if member == interaction.user or member.top_role >= interaction.user.top_role:
        await send_slash(interaction, embed=premium_embed("KICK BLOCKED", "You cannot kick that member.", COLORS["danger"]), ephemeral=True); return
    try:
        await member.kick(reason=f"{interaction.user}: {reason}")
        await send_slash(interaction, embed=premium_embed("👢 MEMBER KICKED", f"{member.mention} was kicked.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["gold"]))
    except discord.Forbidden:
        await send_slash(interaction, embed=premium_embed("KICK FAILED", "I need **Kick Members** and a higher role.", COLORS["danger"]), ephemeral=True)

@bot.tree.command(name="timeout", description="Timeout a member")
@app_commands.describe(member="Member to timeout", duration="Examples: 10m, 1h, 1d", reason="Reason")
async def timeout_slash(interaction: discord.Interaction, member: discord.Member, duration: str, reason: str = "No reason provided"):
    if not await require_admin(interaction): return
    seconds = parse_duration(duration)
    if seconds is None:
        await send_slash(interaction, embed=premium_embed("INVALID DURATION", "Use `10s`, `10m`, `2h`, or `1d` (max 28 days).", COLORS["danger"]), ephemeral=True); return
    if member == interaction.user or member.top_role >= interaction.user.top_role:
        await send_slash(interaction, embed=premium_embed("TIMEOUT BLOCKED", "You cannot timeout that member.", COLORS["danger"]), ephemeral=True); return
    try:
        await member.timeout(datetime.now(timezone.utc) + __import__("datetime").timedelta(seconds=seconds), reason=f"{interaction.user}: {reason}")
        await send_slash(interaction, embed=premium_embed("⏳ MEMBER TIMED OUT", f"{member.mention} for **{duration}**.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["gold"]))
    except discord.Forbidden:
        await send_slash(interaction, embed=premium_embed("TIMEOUT FAILED", "I need **Moderate Members** and a higher role.", COLORS["danger"]), ephemeral=True)

@bot.tree.command(name="mention", description="Configure protected mentions")
async def mention_slash(interaction: discord.Interaction):
    if not await require_admin(interaction): return
    await send_slash(interaction, embed=mention_embed(interaction.guild), view=MentionView())

# ============================================================
# PREFIX COMMANDS — $ AND !
# ============================================================

@bot.command(name="afk")
async def afk_prefix(ctx, *, reason: str = "AFK"):
    afk_set(ctx.guild.id, ctx.author.id, reason)
    row = afk_get(ctx.guild.id, ctx.author.id)
    await send_prefix(ctx, embed=afk_embed(ctx.author, reason, row["since"]))


@bot.command(name="say")
async def say_prefix(ctx, *, message: str = ""):
    if not await require_admin_ctx(ctx):
        return
    if not message.strip():
        await send_prefix(ctx, embed=premium_embed("SAY FORMAT", "Use `$say your message` or `!say your message`.", COLORS["gold"]), delete_after=8)
        return
    try:
        await ctx.send(message)
        try:
            await ctx.message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
    except discord.Forbidden:
        await send_prefix(ctx, embed=premium_embed("SEND FAILED", "I need **Send Messages** permission in this channel.", COLORS["danger"]), delete_after=8)
    except discord.HTTPException as exc:
        log.exception("Prefix say failed")
        await send_prefix(ctx, embed=premium_embed("SEND FAILED", f"Discord rejected the message: `{exc}`", COLORS["danger"]), delete_after=8)


@bot.command(name="autorole")
async def autorole_prefix(ctx, role: discord.Role | None = None):
    if not await require_admin_ctx(ctx): return
    if role is None:
        set_guild_value(ctx.guild.id, "autorole_id", 0)
        await send_prefix(ctx, embed=premium_embed("AUTO ROLE DISABLED", "Auto Role is now off.", COLORS["danger"]), delete_after=10)
        return
    if role >= ctx.guild.me.top_role:
        await send_prefix(ctx, embed=premium_embed("ROLE TOO HIGH", "Move the bot role above the selected role.", COLORS["danger"]), delete_after=10)
        return
    set_guild_value(ctx.guild.id, "autorole_id", role.id)
    await send_prefix(ctx, embed=premium_embed("AUTO ROLE ENABLED", f"New members receive {role.mention}.", COLORS["success"]), delete_after=10)


@bot.command(name="lockdown")
async def lockdown_prefix(ctx, action: str = "lock"):
    if not await require_admin_ctx(ctx): return
    await do_lockdown(ctx.guild, ctx.author, channel=ctx.channel, force=action.lower())


@bot.command(name="announce")
async def announce_prefix(ctx, channel: discord.TextChannel | None = None, *, message: str = ""):
    if not await require_admin_ctx(ctx): return
    if not message:
        await send_prefix(ctx, embed=premium_embed("ANNOUNCE FORMAT", "`$announce #channel message`", COLORS["gold"]), delete_after=10)
        return
    channel = channel or ctx.channel
    e = premium_embed("📣 ANNOUNCEMENT", message, COLORS["cyan"])
    await channel.send(embed=e)
    await send_prefix(ctx, embed=premium_embed("ANNOUNCEMENT SENT", f"Published in {channel.mention}.", COLORS["success"]), delete_after=8)


@bot.command(name="userinfo")
async def userinfo_prefix(ctx, member: discord.Member | None = None):
    member = member or ctx.author
    e = premium_embed(f"👤 {member.display_name}", member.mention)
    e.set_thumbnail(url=member.display_avatar.url)
    e.add_field(name="User ID", value=f"`{member.id}`", inline=False)
    e.add_field(name="Joined", value=discord.utils.format_dt(member.joined_at, "R") if member.joined_at else "Unknown", inline=True)
    e.add_field(name="Created", value=discord.utils.format_dt(member.created_at, "R"), inline=True)
    e.add_field(name="Roles", value=str(max(0, len(member.roles)-1)), inline=True)
    await send_prefix(ctx, embed=e)


@bot.command(name="membercount")
async def membercount_prefix(ctx):
    g = ctx.guild
    humans = sum(1 for m in g.members if not m.bot)
    bots = sum(1 for m in g.members if m.bot)
    await send_prefix(ctx, embed=premium_embed("✦ MEMBER COUNT", f"**Total:** {g.member_count:,}\n**Humans:** {humans:,}\n**Bots:** {bots:,}", COLORS["pink"]))


@bot.command(name="autoresponder")
async def autoresponder_prefix(ctx, action: str = "list", trigger: str = "", *, rest: str = ""):
    if not await require_admin_ctx(ctx): return
    act = action.lower()
    if act == "list":
        await send_prefix(ctx, embed=autoresponder_embed(ctx.guild), delete_after=15); return
    if act == "remove":
        db_exec("DELETE FROM autoresponders WHERE guild_id=? AND lower(trigger)=lower(?)", (ctx.guild.id, trigger.strip()))
        await send_prefix(ctx, embed=premium_embed("AUTORESPONDER REMOVED", f"Trigger: `{trigger}`", COLORS["success"]), delete_after=8); return
    if act == "add":
        parts = [x.strip() for x in rest.split("|", 1)]
        if not trigger or len(parts) < 1 or not parts[0]:
            await send_prefix(ctx, embed=premium_embed("AUTORESPONDER FORMAT", "`$autoresponder add trigger | reply | exact`", COLORS["gold"]), delete_after=10); return
        reply = parts[0]; mode = (parts[1].lower() if len(parts) > 1 else "exact")
        if mode not in {"exact", "contains"}: mode = "exact"
        db_exec("INSERT INTO autoresponders(guild_id,trigger,reply,mode) VALUES (?,?,?,?)", (ctx.guild.id, trigger.strip(), reply, mode))
        await send_prefix(ctx, embed=premium_embed("AUTORESPONDER SAVED", f"`{trigger}` → `{reply}`\nMode: **{mode.upper()}**", COLORS["success"]), delete_after=10); return
    await send_prefix(ctx, embed=premium_embed("AUTORESPONDER", "Use `add`, `remove`, or `list`.", COLORS["gold"]), delete_after=10)

@bot.command(name="welcome")
async def welcome_prefix(ctx, action: str = "", *, value: str = ""):
    if not await require_admin_ctx(ctx): return
    act = action.lower()
    if act == "channel":
        channel = ctx.message.channel_mentions[0] if ctx.message.channel_mentions else None
        if not channel:
            await send_prefix(ctx, embed=premium_embed("WELCOME CHANNEL", "Use `$welcome channel #channel`.", COLORS["danger"]), delete_after=10); return
        set_guild_value(ctx.guild.id, "welcome_channel_id", channel.id); set_guild_value(ctx.guild.id, "welcome_enabled", 1)
        await send_prefix(ctx, embed=premium_embed("✦ WELCOME CHANNEL", f"Set to {channel.mention}.", COLORS["success"]), delete_after=8); return
    if act in {"text", "dm"}:
        if not value:
            await send_prefix(ctx, embed=premium_embed("WELCOME", "Provide a message.", COLORS["danger"]), delete_after=10); return
        set_guild_value(ctx.guild.id, "welcome_text" if act == "text" else "welcome_dm", value)
        await send_prefix(ctx, embed=premium_embed("✦ WELCOME UPDATED", "Saved. Placeholders: `{user}`, `{server}`, `{membercount}`.", COLORS["success"]), delete_after=8); return
    if act == "off":
        set_guild_value(ctx.guild.id, "welcome_enabled", 0)
        await send_prefix(ctx, embed=premium_embed("WELCOME DISABLED", "Welcome messages are off.", COLORS["danger"]), delete_after=8); return
    await send_prefix(ctx, embed=premium_embed("WELCOME SETUP", "`$welcome channel #channel`\n`$welcome text Welcome {user}!`\n`$welcome dm Welcome to {server}!`\n`$welcome off`", COLORS["gold"]), delete_after=15)

@bot.command(name="welcometest")
async def welcometest_prefix(ctx):
    if not await require_admin_ctx(ctx): return
    row = guild_row(ctx.guild.id); channel = ctx.guild.get_channel(row["welcome_channel_id"]) if row["welcome_channel_id"] else None
    if not channel:
        await send_prefix(ctx, embed=premium_embed("WELCOME NOT CONFIGURED", "Set a welcome channel first.", COLORS["danger"]), delete_after=10); return
    await channel.send(embed=premium_embed("✦ WELCOME", welcome_render(row["welcome_text"], ctx.author), COLORS["main"]))
    await send_prefix(ctx, embed=premium_embed("WELCOME TEST SENT", f"Sent in {channel.mention}.", COLORS["success"]), delete_after=8)

@bot.command(name="purge")
async def purge_prefix(ctx, amount: int = 0):
    if not await require_admin_ctx(ctx): return
    if not 1 <= amount <= 100:
        await send_prefix(ctx, embed=premium_embed("PURGE FORMAT", "Use `$purge 1-100`.", COLORS["gold"]), delete_after=8); return
    try:
        deleted = await ctx.channel.purge(limit=amount + 1)
        msg = await ctx.channel.send(embed=premium_embed("✦ PURGE COMPLETE", f"Deleted **{max(0, len(deleted)-1)}** message(s).", COLORS["success"]))
        asyncio.create_task(safe_delete(msg, 6))
    except discord.Forbidden:
        await send_prefix(ctx, embed=premium_embed("PURGE FAILED", "I need **Manage Messages**.", COLORS["danger"]), delete_after=8)

@bot.command(name="ban")
async def ban_prefix(ctx, member: discord.Member | None = None, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx): return
    if not member or member == ctx.author or member.top_role >= ctx.author.top_role:
        await send_prefix(ctx, embed=premium_embed("BAN BLOCKED", "Mention a member you can moderate.", COLORS["danger"]), delete_after=8); return
    try:
        await member.ban(reason=f"{ctx.author}: {reason}")
        await send_prefix(ctx, embed=premium_embed("🔨 MEMBER BANNED", f"{member.mention} was banned.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["danger"]))
    except discord.Forbidden:
        await send_prefix(ctx, embed=premium_embed("BAN FAILED", "I need **Ban Members** and a higher role.", COLORS["danger"]), delete_after=8)

@bot.command(name="kick")
async def kick_prefix(ctx, member: discord.Member | None = None, *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx): return
    if not member or member == ctx.author or member.top_role >= ctx.author.top_role:
        await send_prefix(ctx, embed=premium_embed("KICK BLOCKED", "Mention a member you can moderate.", COLORS["danger"]), delete_after=8); return
    try:
        await member.kick(reason=f"{ctx.author}: {reason}")
        await send_prefix(ctx, embed=premium_embed("👢 MEMBER KICKED", f"{member.mention} was kicked.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["gold"]))
    except discord.Forbidden:
        await send_prefix(ctx, embed=premium_embed("KICK FAILED", "I need **Kick Members** and a higher role.", COLORS["danger"]), delete_after=8)

@bot.command(name="timeout")
async def timeout_prefix(ctx, member: discord.Member | None = None, duration: str = "", *, reason: str = "No reason provided"):
    if not await require_admin_ctx(ctx): return
    seconds = parse_duration(duration)
    if not member or seconds is None or member == ctx.author or member.top_role >= ctx.author.top_role:
        await send_prefix(ctx, embed=premium_embed("TIMEOUT FORMAT", "Use `$timeout @user 10m reason` (max 28 days).", COLORS["gold"]), delete_after=10); return
    try:
        await member.timeout(datetime.now(timezone.utc) + __import__("datetime").timedelta(seconds=seconds), reason=f"{ctx.author}: {reason}")
        await send_prefix(ctx, embed=premium_embed("⏳ MEMBER TIMED OUT", f"{member.mention} for **{duration}**.\n**Reason:** {discord.utils.escape_markdown(reason)}", COLORS["gold"]))
    except discord.Forbidden:
        await send_prefix(ctx, embed=premium_embed("TIMEOUT FAILED", "I need **Moderate Members** and a higher role.", COLORS["danger"]), delete_after=8)

@bot.command(name="mention")
async def mention_prefix(ctx):
    if not await require_admin_ctx(ctx): return
    # Prefix commands cannot open an interaction select menu directly, so show
    # the same clean mention panel with a button that opens the menu.
    await send_prefix(ctx, embed=mention_embed(ctx.guild), view=MentionPrefixView())


class MentionPrefixView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=180)

    @discord.ui.button(label="Open Mention Menu", style=discord.ButtonStyle.danger, emoji="🎯")
    async def open_menu(self, interaction, button):
        if not await require_admin(interaction): return
        await interaction.response.send_message(embed=mention_embed(interaction.guild), view=MentionView(), ephemeral=True)

# ============================================================
# LOCKDOWN / EVENTS
# ============================================================

async def do_lockdown(guild, actor, interaction=None, channel=None, force=None):
    channel = channel or guild.system_channel
    if channel is None:
        if interaction:
            await send_slash(interaction, embed=premium_embed("NO CHANNEL", "Select/use a text channel for lockdown.", COLORS["danger"]), ephemeral=True)
        return
    current = bool(guild_row(guild.id)["lockdown"])
    should_lock = (force == "lock") if force in {"lock", "unlock"} else not current
    me = guild.me
    if not me or not channel.permissions_for(me).manage_channels:
        msg = premium_embed("MISSING PERMISSION", "I need **Manage Channels** to change this channel.", COLORS["danger"])
        if interaction: await send_slash(interaction, embed=msg, ephemeral=True)
        else: await send_prefix(actor, embed=msg, delete_after=10)
        return
    try:
        overwrite = channel.overwrites_for(guild.default_role)
        overwrite.send_messages = False if should_lock else None
        await channel.set_permissions(guild.default_role, overwrite=overwrite, reason=f"Lockdown by {actor}")
        set_guild_value(guild.id, "lockdown", 1 if should_lock else 0)
        msg = premium_embed("🔒 CHANNEL LOCKED" if should_lock else "🔓 CHANNEL UNLOCKED", f"{channel.mention} is now **{'locked' if should_lock else 'unlocked'}**.", COLORS["danger"] if should_lock else COLORS["success"])
    except discord.HTTPException as exc:
        log.exception("Lockdown failed")
        msg = premium_embed("LOCKDOWN FAILED", f"Discord rejected the change: `{exc}`", COLORS["danger"])
    if interaction: await send_slash(interaction, embed=msg, ephemeral=True)
    else: await send_prefix(actor, embed=msg, delete_after=10)


@bot.event
async def on_member_join(member):
    ensure_guild(member.guild.id)
    row = guild_row(member.guild.id)
    role_id = row["autorole_id"]
    if role_id:
        role = member.guild.get_role(role_id)
        if role and member.guild.me and role < member.guild.me.top_role:
            try:
                await member.add_roles(role, reason="Premium Auto Role")
            except discord.HTTPException:
                log.exception("Auto Role failed in %s", member.guild.name)
    if row["welcome_enabled"] and row["welcome_channel_id"]:
        channel = member.guild.get_channel(row["welcome_channel_id"])
        if channel and channel.permissions_for(member.guild.me).send_messages:
            try:
                await channel.send(embed=premium_embed("✦ WELCOME", welcome_render(row["welcome_text"], member), COLORS["main"]))
            except discord.HTTPException:
                log.exception("Welcome channel message failed in %s", member.guild.name)
    if row["welcome_dm"]:
        try:
            await member.send(embed=premium_embed("✦ WELCOME", welcome_render(row["welcome_dm"], member), COLORS["cyan"]))
        except discord.HTTPException:
            log.info("Welcome DM unavailable for %s", member.id)


@bot.event
async def on_message(message):
    if message.author.bot:
        return
    if not message.guild:
        await bot.process_commands(message)
        return

    # AFK: tell the person who pinged an AFK member.
    for member in message.mentions:
        if member.bot:
            continue
        row = afk_get(message.guild.id, member.id)
        if row:
            e = premium_embed("💤 AFK", f"{member.mention} is currently AFK.\n**Reason:** {discord.utils.escape_markdown(row['reason'])}\n**Since:** {fmt_since(row['since'])}", COLORS["main"])
            await safe_send(message.channel, embed=e, delete_after=15)

    # AFK is removed when the AFK member speaks again.
    own_afk = afk_get(message.guild.id, message.author.id)
    is_prefix_command = content.startswith(PREFIXES) if (content := message.content.strip()) else False
    if own_afk and not is_prefix_command:
        afk_remove(message.guild.id, message.author.id)
        await safe_send(message.channel, content=f"👋 {message.author.mention} is no longer AFK.", delete_after=8)

    # Mention Guard. This is the only moderation-style feature retained.
    targets = set()
    for member in message.mentions:
        if protected_user(message.guild.id, member.id):
            targets.add(member.mention)
    for role in message.role_mentions:
        if protected_role(message.guild.id, role.id):
            targets.add(role.mention)
    if targets:
        try:
            await asyncio.sleep(MENTION_DELETE_AFTER)
            await message.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
        target_text = ", ".join(targets)
        e = premium_embed("🚫 DONT PING HIGH STAFF", f"👤 **Who pinged:** {message.author.mention}\n🎯 **Target:** {target_text}", COLORS["danger"])
        await safe_send(message.channel, embed=e, delete_after=BOT_MESSAGE_DELETE_AFTER)
        return

    # AutoResponder: exact or contains.
    if content:
        for row in ar_list(message.guild.id):
            trigger = row["trigger"].strip()
            matched = content.casefold() == trigger.casefold() if row["mode"] == "exact" else trigger.casefold() in content.casefold()
            if matched:
                reply = row["reply"]
                reply = reply.replace("{user}", message.author.mention).replace("{server}", message.guild.name)
                await safe_send(message.channel, content=reply)
                break

    await bot.process_commands(message)

# ============================================================
# ERRORS / READY / RENDER
# ============================================================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingPermissions):
        await send_prefix(ctx, embed=premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"]), delete_after=8)
        return
    if isinstance(error, (commands.BadArgument, commands.MissingRequiredArgument)):
        await send_prefix(ctx, embed=premium_embed("INVALID COMMAND", "Check the command format and try again.", COLORS["danger"]), delete_after=10)
        return
    log.error("Prefix command error: %r", error, exc_info=(type(error), error, error.__traceback__))
    await send_prefix(ctx, embed=premium_embed("COMMAND ERROR", "Something went wrong. Check the Render log for the exact error.", COLORS["danger"]), delete_after=10)


@bot.tree.error
async def on_app_command_error(interaction, error):
    original = getattr(error, "original", error)
    if isinstance(original, app_commands.errors.MissingPermissions):
        msg = premium_embed("ACCESS DENIED", "Administrator permission is required.", COLORS["danger"])
    else:
        log.error("Slash command error: %r", original, exc_info=(type(original), original, original.__traceback__))
        msg = premium_embed("COMMAND ERROR", "Something went wrong. Check the Render log for the exact traceback.", COLORS["danger"])
    await send_slash(interaction, embed=msg, ephemeral=True)


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
        self.wfile.write(b"OK - BLASTMC PREMIUM BOT")

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
