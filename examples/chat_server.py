#!/usr/bin/env python3
"""Dual TCP/TLS chat server for lwIP-CE live demos."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(eq=False)
class Client:
    ident: int
    writer: asyncio.StreamWriter
    tls: bool
    peer: str

    @property
    def name(self) -> str:
        proto = "tls" if self.tls else "tcp"
        return f"{proto}{self.ident}"


class ChatServer:
    def __init__(
        self,
        max_line: int,
        idle_timeout: float,
        tls_debug: bool,
        close_timeout: float,
    ) -> None:
        self.clients: set[Client] = set()
        self.next_ident = 1
        self.max_line = max_line
        self.idle_timeout = idle_timeout
        self.tls_debug = tls_debug
        self.close_timeout = close_timeout

    async def broadcast(self, text: str) -> None:
        if not text.endswith("\n"):
            text += "\n"
        data = text.encode("utf-8", errors="replace")
        stale: list[Client] = []
        for client in list(self.clients):
            try:
                client.writer.write(data)
                await asyncio.wait_for(client.writer.drain(), timeout=5.0)
            except Exception as exc:  # nonfatal: drop only that peer
                print(f"[warn] broadcast to {client.name} failed: {exc}", file=sys.stderr)
                stale.append(client)
        for client in stale:
            await self.remove_client(client, announce=False)

    async def remove_client(self, client: Client, announce: bool = True) -> None:
        if client not in self.clients:
            return
        self.clients.remove(client)
        try:
            client.writer.close()
            await asyncio.wait_for(
                client.writer.wait_closed(), timeout=self.close_timeout
            )
        except asyncio.TimeoutError:
            print(f"[warn] close timeout for {client.name}", file=sys.stderr)
        except Exception as exc:
            print(f"[warn] close failed for {client.name}: {exc}", file=sys.stderr)
        if announce:
            await self.broadcast(f"* {client.name} disconnected")

    def configure_socket(self, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if not sock:
            return
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError as exc:
            print(f"[warn] could not enable keepalive: {exc}", file=sys.stderr)

    def log_tls_connection(self, writer: asyncio.StreamWriter, client: Client) -> None:
        if not self.tls_debug:
            return

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            print(f"[tls] {client.name}: no ssl object", file=sys.stderr)
            return

        cipher = ssl_obj.cipher()
        cipher_name = cipher[0] if cipher else "unknown"
        cipher_proto = cipher[1] if cipher else "unknown"
        cipher_bits = cipher[2] if cipher else 0
        print(
            f"[tls] {client.name}: version={ssl_obj.version()} "
            f"cipher={cipher_name}/{cipher_proto}/{cipher_bits} "
            f"alpn={ssl_obj.selected_alpn_protocol()}",
            file=sys.stderr,
        )

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        tls: bool,
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = str(peer_info) if peer_info is not None else "unknown"
        client = Client(self.next_ident, writer, tls, peer)
        self.next_ident += 1
        self.clients.add(client)
        self.configure_socket(writer)

        print(f"[info] {client.name} connected from {peer}")
        if tls:
            self.log_tls_connection(writer, client)
        await self.broadcast(f"* {client.name} connected")

        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=self.idle_timeout
                    )
                except asyncio.TimeoutError:
                    continue
                except (ConnectionResetError, BrokenPipeError) as exc:
                    print(f"[info] {client.name} reset: {exc}")
                    break
                except Exception as exc:
                    await self.broadcast(f"* {client.name} read error: {exc}")
                    print(f"[warn] {client.name} read error: {exc}", file=sys.stderr)
                    break

                if line == b"":
                    break
                if len(line) > self.max_line:
                    await self.broadcast(f"* {client.name} sent an oversized line")
                    continue

                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not text:
                    continue
                print(f"[chat] {client.name}: {text}")
                await self.broadcast(f"{client.name}: {text}")
        finally:
            print(f"[info] {client.name} disconnected")
            await self.remove_client(client)


async def console_loop(chat: ChatServer, stop: asyncio.Event) -> None:
    if not sys.stdin.isatty():
        return

    loop = asyncio.get_running_loop()
    lines: asyncio.Queue[str] = asyncio.Queue()

    def on_stdin() -> None:
        line = sys.stdin.readline()
        if line == "":
            stop.set()
            return
        lines.put_nowait(line)

    try:
        loop.add_reader(sys.stdin.fileno(), on_stdin)
    except (NotImplementedError, OSError):
        print("[warn] interactive console input unavailable", file=sys.stderr)
        return

    print("[info] type chat lines here; /quit exits")
    try:
        while not stop.is_set():
            line = await lines.get()
            text = line.rstrip("\r\n")
            if text in ("/quit", "/exit"):
                stop.set()
                return
            if not text:
                continue
            print(f"[chat] server: {text}")
            await chat.broadcast(f"server: {text}")
    finally:
        with contextlib.suppress(Exception):
            loop.remove_reader(sys.stdin.fileno())


def run_openssl(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def generate_demo_cert(tmpdir: Path) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("openssl not found; pass --cert and --key for TLS")

    cert = tmpdir / "lwip-chat.crt"
    key = tmpdir / "lwip-chat.key"
    base_cmd = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "7",
        "-subj",
        "/CN=lwip-ce-chat",
        "-keyout",
        str(key),
        "-out",
        str(cert),
    ]
    try:
        run_openssl(
            base_cmd
            + ["-addext", "subjectAltName=DNS:lwip-ce-chat,IP:127.0.0.1"]
        )
    except subprocess.CalledProcessError:
        run_openssl(base_cmd)
    return cert, key


def cert_sha256_fingerprint(cert: Path) -> str:
    pem = cert.read_text(encoding="utf-8")
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def install_tls_exception_logger(loop: asyncio.AbstractEventLoop) -> None:
    previous = loop.get_exception_handler()

    def handle_exception(
        loop: asyncio.AbstractEventLoop, context: dict[str, object]
    ) -> None:
        message = str(context.get("message", ""))
        exc = context.get("exception")
        transport = context.get("transport")
        peer = None
        if transport is not None and hasattr(transport, "get_extra_info"):
            peer = transport.get_extra_info("peername")

        if isinstance(exc, ssl.SSLError) or "ssl" in message.lower():
            print(
                f"[tls] handshake/transport error peer={peer}: {message}: {exc}",
                file=sys.stderr,
            )
            return

        if previous is not None:
            previous(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handle_exception)


def build_tls_context(
    cert: Path,
    key: Path,
    *,
    tls13_only: bool,
    no_tls_tickets: bool,
    tls_debug: bool,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.verify_mode = ssl.CERT_NONE
    if hasattr(ctx, "num_tickets"):
        ctx.num_tickets = 0 if no_tls_tickets else 2
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    def log_sni(ssl_obj: ssl.SSLObject, server_name: str | None,
                ssl_ctx: ssl.SSLContext) -> None:
        (void_ssl_obj, void_ssl_ctx) = (ssl_obj, ssl_ctx)
        del void_ssl_obj, void_ssl_ctx
        if tls_debug:
            print(f"[tls] sni={server_name}", file=sys.stderr)

    ctx.set_servername_callback(log_sni)
    return ctx


async def run(args: argparse.Namespace) -> None:
    chat = ChatServer(
        max_line=args.max_line,
        idle_timeout=args.idle_timeout,
        tls_debug=args.tls_debug,
        close_timeout=args.close_timeout,
    )
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    console_task: asyncio.Task[None] | None = None

    try:
        if args.cert and args.key:
            cert = Path(args.cert)
            key = Path(args.key)
        else:
            temp_dir = tempfile.TemporaryDirectory(prefix="lwip-chat-")
            cert, key = generate_demo_cert(Path(temp_dir.name))
            print(f"[info] generated temporary RSA cert: {cert}")
        print(f"[tls] cert sha256={cert_sha256_fingerprint(cert)}", file=sys.stderr)

        tls_ctx = build_tls_context(
            cert,
            key,
            tls13_only=args.tls13_only,
            no_tls_tickets=args.no_tls_tickets,
            tls_debug=args.tls_debug,
        )
        print(
            f"[tls] min={tls_ctx.minimum_version.name} "
            f"max={tls_ctx.maximum_version.name} "
            f"tickets={getattr(tls_ctx, 'num_tickets', 'n/a')}",
            file=sys.stderr,
        )

        tcp_server = await asyncio.start_server(
            lambda r, w: chat.handle_client(r, w, tls=False),
            host=args.host,
            port=args.tcp_port,
            limit=args.max_line + 2,
        )
        tls_server = await asyncio.start_server(
            lambda r, w: chat.handle_client(r, w, tls=True),
            host=args.host,
            port=args.tls_port,
            ssl=tls_ctx,
            limit=args.max_line + 2,
        )

        sockets = list(tcp_server.sockets or []) + list(tls_server.sockets or [])
        for sock in sockets:
            print(f"[info] listening on {sock.getsockname()}")
        print("[info] tcp and tls chat listeners ready")

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        install_tls_exception_logger(loop)
        console_task = asyncio.create_task(console_loop(chat, stop))
        for signame in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signame):
                with contextlib.suppress(NotImplementedError):
                    loop.add_signal_handler(getattr(signal, signame), stop.set)

        async with tcp_server, tls_server:
            await stop.wait()
    finally:
        if console_task is not None:
            console_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await console_task
        if chat.clients:
            await chat.broadcast("* server shutting down")
            for client in list(chat.clients):
                await chat.remove_client(client, announce=False)
        if temp_dir is not None:
            temp_dir.cleanup()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--tcp-port", type=int, default=4242)
    parser.add_argument("--tls-port", type=int, default=4243)
    parser.add_argument("--cert", help="TLS certificate PEM")
    parser.add_argument("--key", help="TLS private key PEM")
    parser.add_argument("--max-line", type=int, default=512)
    parser.add_argument("--idle-timeout", type=float, default=30.0)
    parser.add_argument("--close-timeout", type=float, default=5.0)
    parser.add_argument(
        "--tls13-only",
        action="store_true",
        help="only allow TLS 1.3 on the TLS listener",
    )
    parser.add_argument(
        "--no-tls-tickets",
        action="store_true",
        help="disable OpenSSL TLS 1.3 post-handshake session tickets",
    )
    parser.add_argument(
        "--tls-debug",
        action="store_true",
        help="print TLS handshake details to the server terminal",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
