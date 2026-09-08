#!/usr/bin/env python3
"""
Minimal RFC 6455 WebSocket echo server for testing lwIP-CE ws_echo.

Run:
    python3 ws_echo_server.py          # listens on 0.0.0.0:8080
    python3 ws_echo_server.py 9000     # custom port

Point ws_echo at:
    WS_HOST  = "<your-machine-ip>"
    WS_PORT  = 8080
    WS_PATH  = "/"
"""

import asyncio
import base64
import hashlib
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept_key(client_key: str) -> str:
    combined = (client_key.strip() + WS_MAGIC).encode()
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()


def parse_frame(data: bytes) -> tuple[int, bytes, int] | None:
    """Return (opcode, payload, total_bytes) or None if incomplete."""
    if len(data) < 2:
        return None
    b0, b1 = data[0], data[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    payload_len = b1 & 0x7F

    offset = 2
    if payload_len == 126:
        if len(data) < 4:
            return None
        payload_len = struct.unpack_from("!H", data, 2)[0]
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            return None
        payload_len = struct.unpack_from("!Q", data, 2)[0]
        offset = 10

    if masked:
        if len(data) < offset + 4 + payload_len:
            return None
        mask = data[offset:offset + 4]
        offset += 4
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data[offset:offset + payload_len]))
    else:
        if len(data) < offset + payload_len:
            return None
        payload = data[offset:offset + payload_len]

    return opcode, payload, offset + payload_len


def make_frame(opcode: int, payload: bytes) -> bytes:
    """Server frames are never masked (RFC 6455 §5.1)."""
    length = len(payload)
    header = bytes([0x80 | opcode])
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + struct.pack("!H", length)
    else:
        header += bytes([127]) + struct.pack("!Q", length)
    return header + payload


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    addr = writer.get_extra_info("peername")
    print(f"[+] {addr}")

    # HTTP upgrade handshake
    headers_raw = b""
    while b"\r\n\r\n" not in headers_raw:
        chunk = await reader.read(1024)
        if not chunk:
            writer.close()
            return
        headers_raw += chunk

    client_key = ""
    for line in headers_raw.decode(errors="replace").splitlines():
        if line.lower().startswith("sec-websocket-key:"):
            client_key = line.split(":", 1)[1].strip()

    if not client_key:
        writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    accept = ws_accept_key(client_key)
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    )
    writer.write(response.encode())
    await writer.drain()
    print(f"    handshake OK")

    buf = b""
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk

            while buf:
                result = parse_frame(buf)
                if result is None:
                    break
                opcode, payload, consumed = result
                buf = buf[consumed:]

                if opcode == 0x08:  # CLOSE
                    writer.write(make_frame(0x08, payload[:2] if len(payload) >= 2 else b""))
                    await writer.drain()
                    return
                elif opcode == 0x09:  # PING
                    writer.write(make_frame(0x0A, payload))
                    await writer.drain()
                elif opcode in (0x01, 0x02):  # TEXT or BINARY — echo it
                    text = payload.decode(errors="replace") if opcode == 0x01 else repr(payload)
                    print(f"    rx: {text[:60]}")
                    writer.write(make_frame(opcode, payload))
                    await writer.drain()
    except Exception as e:
        print(f"    error: {e}")
    finally:
        print(f"[-] {addr}")
        try:
            writer.close()
        except Exception:
            pass


async def main() -> None:
    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    print(f"WS echo server listening on ws://0.0.0.0:{PORT}/")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
