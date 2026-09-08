#!/usr/bin/env python3
"""
lwIP-CE Discord Relay Server
============================
Bridges TI-84+CE calculators to Discord channels via a bot.

Line protocol (newline-terminated UTF-8):

  Calc → Relay:
    AUTH <username> <pin>
    SEND <text>              -- send to currently active channel
    CHAN <#name>             -- switch active channel

  Relay → Calc:
    OK
    DENIED
    RELAY_CHAN <#ch1>,<#ch2>,...   -- channel list, sent right after OK
    RELAY_ACTIVE <#name>           -- confirms channel switch
    MSG <author>: <text>           -- message received in active channel
    SYS <text>                     -- system/status message

Setup
-----
1. pip install discord.py
2. Generate TLS cert (runs on any host, internet-accessible port):
     openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
       -keyout relay_key.pem -out relay_cert.pem -days 3650 -nodes \
       -subj "/CN=lwip-relay"
3. Copy users.json.example → users.json and edit usernames/PINs
4. Set env vars (see below) and run:
     DISCORD_TOKEN=Bot.xxx DISCORD_CHANNEL_ID=123 python3 relay.py

Environment variables
---------------------
  DISCORD_TOKEN        Bot token (required)
  DISCORD_CHANNEL_ID   Default channel snowflake (required)
  RELAY_HOST           Bind address (default 0.0.0.0)
  RELAY_PORT           TCP port (default 8443)
  RELAY_CERT           TLS cert PEM (default relay_cert.pem)
  RELAY_KEY            TLS key PEM  (default relay_key.pem)
  USERS_FILE           users JSON path (default users.json)
  DISCORD_DISPLAY_FMT  Format for calc→Discord messages:
                       {user} and {text} are substituted
                       (default "[{user}] {text}")
"""

import asyncio
import json
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import discord

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DISCORD_TOKEN      = os.environ.get("DISCORD_TOKEN", "")
DISCORD_CHANNEL_ID = int(os.environ.get("DISCORD_CHANNEL_ID", "0"))
RELAY_HOST         = os.environ.get("RELAY_HOST", "0.0.0.0")
RELAY_PORT         = int(os.environ.get("RELAY_PORT", "8443"))
RELAY_CERT         = os.environ.get("RELAY_CERT", "relay_cert.pem")
RELAY_KEY          = os.environ.get("RELAY_KEY",  "relay_key.pem")
USERS_FILE         = os.environ.get("USERS_FILE", "users.json")
DISPLAY_FMT        = os.environ.get("DISCORD_DISPLAY_FMT", "[{user}] {text}")

MAX_MESSAGE_LEN    = 200
MAX_LINE_LEN       = 512
READ_TIMEOUT       = 30.0   # seconds to wait for AUTH before dropping

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("relay")


# ---------------------------------------------------------------------------
# User database
# ---------------------------------------------------------------------------

def load_users(path: str) -> Dict[str, str]:
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:
        log.warning("Cannot load %s: %s", path, exc)
    return {}


# ---------------------------------------------------------------------------
# Connected client state
# ---------------------------------------------------------------------------

class CalcClient:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader   = reader
        self.writer   = writer
        self.authed   = False
        self.username: Optional[str] = None
        self.active_channel_id: Optional[int] = None
        peer = writer.get_extra_info("peername", ("?", 0))
        self.addr = f"{peer[0]}:{peer[1]}"

    async def send_line(self, line: str) -> None:
        try:
            self.writer.write((line + "\n").encode("utf-8", errors="replace"))
            await self.writer.drain()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self.writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Relay server
# ---------------------------------------------------------------------------

class RelayServer:
    def __init__(self) -> None:
        self.clients: Dict[str, CalcClient] = {}
        self.users:   Dict[str, str]        = {}
        self.bridge:  Optional["DiscordBridge"] = None

    def reload_users(self) -> None:
        self.users = load_users(USERS_FILE)
        log.info("Loaded %d user(s) from %s", len(self.users), USERS_FILE)

    async def broadcast_channel(self, channel_id: int, line: str,
                                skip_addr: Optional[str] = None) -> None:
        """Send a line to all authenticated calcs watching a specific channel."""
        dead = []
        for addr, client in self.clients.items():
            if not client.authed:
                continue
            if addr == skip_addr:
                continue
            if client.active_channel_id != channel_id:
                continue
            try:
                await client.send_line(line)
            except Exception:
                dead.append(addr)
        for addr in dead:
            self._remove(addr)

    async def broadcast_all(self, line: str,
                            skip_addr: Optional[str] = None) -> None:
        """Send a line to all authenticated calcs regardless of channel."""
        dead = []
        for addr, client in self.clients.items():
            if not client.authed:
                continue
            if addr == skip_addr:
                continue
            try:
                await client.send_line(line)
            except Exception:
                dead.append(addr)
        for addr in dead:
            self._remove(addr)

    def _remove(self, addr: str) -> None:
        client = self.clients.pop(addr, None)
        if client:
            client.close()
            name = client.username or "(unauthenticated)"
            log.info("Disconnected: %s (%s)", name, addr)

    async def handle_client(self,
                            reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        client = CalcClient(reader, writer)
        self.clients[client.addr] = client
        log.info("Connection from %s", client.addr)
        try:
            await self._client_loop(client)
        except Exception as exc:
            log.debug("Client %s error: %s", client.addr, exc)
        finally:
            self._remove(client.addr)

    async def _client_loop(self, client: CalcClient) -> None:
        while True:
            timeout = None if client.authed else READ_TIMEOUT
            try:
                raw = await asyncio.wait_for(
                    client.reader.readline(), timeout=timeout
                )
            except asyncio.TimeoutError:
                log.info("Auth timeout: %s", client.addr)
                await client.send_line("SYS timeout")
                return
            except Exception:
                return

            if not raw:
                return

            if len(raw) > MAX_LINE_LEN:
                log.warning("Oversized line from %s, closing", client.addr)
                return

            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                continue

            if not client.authed:
                await self._handle_auth(client, line)
            else:
                await self._handle_authed(client, line)

    async def _handle_auth(self, client: CalcClient, line: str) -> None:
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[0] != "AUTH":
            await client.send_line("DENIED")
            return

        username = parts[1]
        pin      = parts[2]

        expected = self.users.get(username)
        if expected is None or expected != pin:
            log.info("Auth failed for %r from %s", username, client.addr)
            await client.send_line("DENIED")
            return

        client.authed           = True
        client.username         = username
        client.active_channel_id = DISCORD_CHANNEL_ID
        log.info("Auth OK: %s (%s)", username, client.addr)

        await client.send_line("OK")

        # Send channel list
        if self.bridge:
            chan_list = self.bridge.channel_list_str()
            if chan_list:
                await client.send_line(f"RELAY_CHAN {chan_list}")
            # Confirm default active channel
            default_name = self.bridge.channel_name(DISCORD_CHANNEL_ID)
            if default_name:
                await client.send_line(f"RELAY_ACTIVE #{default_name}")

        # Announce join to Discord and other calcs
        if self.bridge:
            await self.bridge.send_system(f"**{username}** joined the relay")
        await self.broadcast_all(f"SYS {username} joined", skip_addr=client.addr)

    async def _handle_authed(self, client: CalcClient, line: str) -> None:
        if line.startswith("SEND "):
            text = line[5:MAX_MESSAGE_LEN + 5]
            log.info("SEND from %s on %s: %s",
                     client.username, client.active_channel_id, text)

            if self.bridge and client.active_channel_id:
                discord_text = DISPLAY_FMT.format(user=client.username, text=text)
                await self.bridge.send_to_channel(client.active_channel_id,
                                                  discord_text)

            # Echo to other calcs watching the same channel
            if client.active_channel_id:
                await self.broadcast_channel(
                    client.active_channel_id,
                    f"MSG {client.username}: {text}",
                    skip_addr=client.addr,
                )

        elif line.startswith("CHAN "):
            # Client wants to switch channel: "CHAN #general"
            raw_name = line[5:].strip().lstrip("#")
            if self.bridge:
                ch = self.bridge.find_channel_by_name(raw_name)
                if ch:
                    client.active_channel_id = ch.id
                    await client.send_line(f"RELAY_ACTIVE #{ch.name}")
                    log.info("%s switched to #%s", client.username, ch.name)
                else:
                    await client.send_line(f"SYS unknown channel #{raw_name}")


# ---------------------------------------------------------------------------
# Discord bot bridge
# ---------------------------------------------------------------------------

class DiscordBridge(discord.Client):
    def __init__(self, relay: RelayServer) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        super().__init__(intents=intents)
        self.relay = relay
        relay.bridge = self
        # Cached text channels visible to the bot, keyed by channel id
        self._channels: Dict[int, discord.TextChannel] = {}

    # -----------------------------------------------------------------------
    # discord.py events
    # -----------------------------------------------------------------------

    async def on_ready(self) -> None:
        log.info("Discord bot ready: %s", self.user)
        self._refresh_channels()
        names = [f"#{c.name}" for c in self._channels.values()]
        log.info("Bridging channels: %s", ", ".join(names) or "(none)")

    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        self._refresh_channels()

    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        self._refresh_channels()

    async def on_message(self, message: discord.Message) -> None:
        if message.author == self.user:
            return
        if not isinstance(message.channel, discord.TextChannel):
            return
        if message.channel.id not in self._channels:
            return

        content = message.content
        if not content:
            return

        author = message.author.display_name
        relay_line = f"MSG {author}: {content}"
        await self.relay.broadcast_channel(message.channel.id, relay_line)

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _refresh_channels(self) -> None:
        """Rebuild the cached channel map from all guilds."""
        self._channels = {}
        for guild in self.guilds:
            for ch in guild.text_channels:
                # Only include channels the bot can read
                perms = ch.permissions_for(guild.me)
                if perms.read_messages and perms.send_messages:
                    self._channels[ch.id] = ch

    def channel_list_str(self) -> str:
        """Return comma-separated #name list, max 200 chars for the line."""
        names = sorted(f"#{c.name}" for c in self._channels.values())
        result = ",".join(names)
        if len(result) > 200:
            result = result[:200]
        return result

    def channel_name(self, channel_id: int) -> Optional[str]:
        ch = self._channels.get(channel_id)
        return ch.name if ch else None

    def find_channel_by_name(self, name: str) -> Optional[discord.TextChannel]:
        name_lower = name.lower()
        for ch in self._channels.values():
            if ch.name.lower() == name_lower:
                return ch
        return None

    async def send_to_channel(self, channel_id: int, text: str) -> None:
        ch = self._channels.get(channel_id)
        if ch is None:
            log.warning("Channel %d not in cache, dropping: %s", channel_id, text)
            return
        try:
            await ch.send(text)
        except Exception as exc:
            log.warning("Discord send to #%s failed: %s", ch.name, exc)

    async def send_system(self, text: str) -> None:
        # Post system messages to the default channel
        await self.send_to_channel(DISCORD_CHANNEL_ID, f"*{text}*")


# ---------------------------------------------------------------------------
# TLS context
# ---------------------------------------------------------------------------

def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=RELAY_CERT, keyfile=RELAY_KEY)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # Protection model:
    #   • TLS 1.3 ECDHE encrypts the channel (server cert, no client cert)
    #   • Application-level AUTH username+PIN is the identity gate
    return ctx


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    if not DISCORD_TOKEN:
        log.error("DISCORD_TOKEN is not set.")
        sys.exit(1)
    if DISCORD_CHANNEL_ID == 0:
        log.error("DISCORD_CHANNEL_ID is not set (or is 0).")
        sys.exit(1)
    if not Path(RELAY_CERT).exists() or not Path(RELAY_KEY).exists():
        log.error(
            "TLS cert/key not found (%s / %s).\n"
            "Generate with:\n"
            "  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \\\n"
            "    -keyout relay_key.pem -out relay_cert.pem -days 3650 -nodes \\\n"
            "    -subj '/CN=lwip-relay'",
            RELAY_CERT, RELAY_KEY,
        )
        sys.exit(1)

    relay  = RelayServer()
    relay.reload_users()

    ssl_ctx = make_ssl_context()
    server  = await asyncio.start_server(
        relay.handle_client,
        host=RELAY_HOST,
        port=RELAY_PORT,
        ssl=ssl_ctx,
    )
    log.info("Relay listening on %s:%d (TLS 1.3)", RELAY_HOST, RELAY_PORT)

    bridge = DiscordBridge(relay)

    async with server:
        try:
            await asyncio.gather(
                server.serve_forever(),
                bridge.start(DISCORD_TOKEN),
            )
        except KeyboardInterrupt:
            log.info("Shutting down")
        finally:
            await bridge.close()


if __name__ == "__main__":
    asyncio.run(main())
