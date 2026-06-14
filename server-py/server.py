from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
from pathlib import Path
import ssl
import struct
import time
from typing import Callable, cast

from database import DatabaseManager, init_db
from protocol import MsgType, SVPCodec, SVPFlags, SVPFormatError, SVPFrame, SVPHmacError


HOST: str = "0.0.0.0"
PORT: int = 7443
DB_PATH: str = "secvault.db"
DEFAULT_CERT_PATH: str = "certs/server.crt"
DEFAULT_KEY_PATH: str = "certs/server.key"
TLS13_CIPHERSUITES: str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
DUMMY_MAC_KEY: bytes = b"\x00" * 32
MAX_CLOCK_SKEW_MS: int = 5 * 60 * 1000
SESSION_TTL_MS: int = 24 * 60 * 60 * 1000
ERR_AUTH_FAILED: int = 0x06

LOGGER: logging.Logger = logging.getLogger("secvault.server")


def configure_logging() -> None:
    """Configure console logging for server events."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def get_ssl_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """Build a TLS 1.3-only SSL context with the required cipher suites."""
    cert_file: Path = Path(cert_path)
    key_file: Path = Path(key_path)

    if not cert_file.is_file():
        raise FileNotFoundError(f"TLS certificate file not found: {cert_path}")
    if not key_file.is_file():
        raise FileNotFoundError(f"TLS private key file not found: {key_path}")

    context: ssl.SSLContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))

    '''         #### WINDOWDS TESTING PURPOSE ###
    set_ciphersuites = getattr(context, "set_ciphersuites", None)
    if set_ciphersuites is None:
        raise RuntimeError(
            "This Python/OpenSSL build does not support configuring TLS 1.3 cipher suites."
        )

    try:
        cast(Callable[[str], None], set_ciphersuites)(TLS13_CIPHERSUITES)
    except ssl.SSLError as exc:
        raise RuntimeError("Failed to configure required TLS 1.3 cipher suites.") from exc
    '''
    return context


def _now_ms() -> int:
    return int(time.time() * 1000)


async def _read_frame(reader: asyncio.StreamReader, mac_key: bytes) -> SVPFrame:
    header: bytes = await reader.readexactly(SVPCodec.HEADER_LEN)
    try:
        _, _, _, _, payload_len = SVPCodec.HEADER_STRUCT.unpack(header)
    except struct.error as exc:
        raise SVPFormatError("invalid SVP header") from exc

    if payload_len > SVPCodec.MAX_PAYLOAD_LEN:
        raise SVPFormatError("payload_len exceeds maximum allowed size")

    body_and_hmac: bytes = await reader.readexactly(payload_len + SVPCodec.HMAC_LEN)
    frame_data: bytes = header + body_and_hmac
    return SVPCodec.decode(frame_data, mac_key)


async def _send_frame(
    writer: asyncio.StreamWriter,
    msg_type: MsgType,
    payload: bytes,
    seq_id: int,
    mac_key: bytes,
) -> None:
    frame: SVPFrame = SVPFrame(
        version=1,
        msg_type=msg_type,
        flags=SVPFlags.NONE,
        seq_id=seq_id,
        payload_len=len(payload),
        payload=payload,
        hmac=b"",
    )
    writer.write(SVPCodec.encode(frame, mac_key))
    await writer.drain()


def _parse_hello_payload(payload: bytes) -> tuple[bytes, bytes, int]:
    expected_len: int = 32 + 16 + 8
    if len(payload) != expected_len:
        raise SVPFormatError("HELLO payload has invalid length")

    nonce_c, client_id, timestamp_ms = struct.unpack("<32s16sQ", payload)
    if abs(_now_ms() - int(timestamp_ms)) > MAX_CLOCK_SKEW_MS:
        raise SVPFormatError("HELLO timestamp exceeds allowed clock skew")

    return nonce_c, client_id, int(timestamp_ms)


def _parse_auth_payload(payload: bytes) -> tuple[str, bytes]:
    if len(payload) < 1 + 32:
        raise SVPFormatError("AUTH payload is too short")

    username_len: int = payload[0]
    username_start: int = 1
    username_end: int = username_start + username_len
    hmac_end: int = username_end + 32

    if username_len == 0 or username_len > 64:
        raise SVPFormatError("AUTH username length is invalid")

    if len(payload) != hmac_end:
        raise SVPFormatError("AUTH payload has invalid length")

    username_bytes: bytes = payload[username_start:username_end]
    hmac_resp: bytes = payload[username_end:hmac_end]
    try:
        username: str = username_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SVPFormatError("AUTH username is not valid UTF-8") from exc

    return username, hmac_resp


def _build_auth_ok_payload(session_token: bytes, expiry_ms: int, vault_version: int) -> bytes:
    return (
        struct.pack("<H", len(session_token))
        + session_token
        + struct.pack("<Q", expiry_ms)
        + struct.pack("<Q", vault_version)
    )


def _build_auth_fail_payload() -> bytes:
    return struct.pack("<BI", ERR_AUTH_FAILED, 0)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Handle one TLS client and perform SVP greeting/authentication handshake."""
    peername = writer.get_extra_info("peername")
    client_ip: str = "unknown"
    client_port: int = 0
    if isinstance(peername, tuple) and len(peername) >= 2:
        client_ip = str(peername[0])
        client_port = int(peername[1])

    LOGGER.info("Accepted TLS connection from %s:%d", client_ip, client_port)

    state: str = "GREETING"
    outbound_seq: int = 0
    nonce_c: bytes | None = None
    nonce_s: bytes | None = None
    client_id: bytes | None = None

    try:
        async with DatabaseManager(DB_PATH) as db:
            while True:
                if state in {"GREETING", "AUTHENTICATING"}:
                    mac_key: bytes = DUMMY_MAC_KEY
                else:
                    mac_key = DUMMY_MAC_KEY

                frame: SVPFrame = await _read_frame(reader, mac_key)

                if state == "GREETING":
                    if frame.msg_type != MsgType.HELLO:
                        raise SVPFormatError("Expected HELLO in GREETING state")

                    nonce_c, client_id, _ = _parse_hello_payload(frame.payload)
                    nonce_s = os.urandom(32)
                    challenge_payload: bytes = nonce_s + struct.pack("<Q", _now_ms())

                    await _send_frame(
                        writer=writer,
                        msg_type=MsgType.CHALLENGE,
                        payload=challenge_payload,
                        seq_id=outbound_seq,
                        mac_key=DUMMY_MAC_KEY,
                    )
                    outbound_seq += 1
                    state = "AUTHENTICATING"
                    continue

                if state == "AUTHENTICATING":
                    if frame.msg_type != MsgType.AUTH:
                        raise SVPFormatError("Expected AUTH in AUTHENTICATING state")

                    if nonce_c is None or nonce_s is None or client_id is None:
                        raise SVPFormatError("Authentication state is incomplete")

                    username, hmac_resp = _parse_auth_payload(frame.payload)
                    user = await db.get_user_by_username(username)

                    auth_valid: bool = False
                    if user is not None and user.get("k_auth") is not None:
                        k_auth: bytes = bytes(user["k_auth"])
                        expected_hmac: bytes = hmac.new(
                            k_auth,
                            nonce_c + nonce_s + username.encode("utf-8"),
                            hashlib.sha256,
                        ).digest()
                        auth_valid = hmac.compare_digest(hmac_resp, expected_hmac)

                    if not auth_valid:
                        await _send_frame(
                            writer=writer,
                            msg_type=MsgType.AUTH_FAIL,
                            payload=_build_auth_fail_payload(),
                            seq_id=outbound_seq,
                            mac_key=DUMMY_MAC_KEY,
                        )
                        outbound_seq += 1
                        LOGGER.info("Authentication failed for %s:%d", client_ip, client_port)
                        return

                    session_token: bytes = os.urandom(32)
                    expiry: int = _now_ms() + SESSION_TTL_MS
                    await db.create_session(
                        token=session_token,
                        user_id=int(user["id"]),
                        expiry=expiry,
                        client_id=client_id,
                    )

                    auth_ok_payload: bytes = _build_auth_ok_payload(
                        session_token=session_token,
                        expiry_ms=expiry,
                        vault_version=0,
                    )
                    await _send_frame(
                        writer=writer,
                        msg_type=MsgType.AUTH_OK,
                        payload=auth_ok_payload,
                        seq_id=outbound_seq,
                        mac_key=DUMMY_MAC_KEY,
                    )
                    outbound_seq += 1
                    state = "ESTABLISHED"
                    LOGGER.info(
                        "Client %s:%d authenticated as '%s'",
                        client_ip,
                        client_port,
                        username,
                    )
                    continue

                if state == "ESTABLISHED":
                    LOGGER.info(
                        "Received %s in ESTABLISHED (not implemented yet); closing",
                        frame.msg_type.name,
                    )
                    return

                raise SVPFormatError(f"Unknown server state: {state}")
    except asyncio.IncompleteReadError:
        LOGGER.info("Client %s:%d disconnected", client_ip, client_port)
    except SVPHmacError:
        LOGGER.warning("HMAC validation failed for %s:%d", client_ip, client_port)
    except SVPFormatError as exc:
        LOGGER.warning("Protocol format error from %s:%d: %s", client_ip, client_port, exc)
    except ConnectionError:
        LOGGER.info("Connection from %s:%d closed abruptly", client_ip, client_port)
    else:
        LOGGER.info("Connection from %s:%d closed", client_ip, client_port)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def main() -> None:
    """Start the asynchronous TLS server and serve until cancelled."""
    configure_logging()
    await init_db(DB_PATH)
    LOGGER.info("Database initialized at %s", DB_PATH)

    ssl_context: ssl.SSLContext = get_ssl_context(DEFAULT_CERT_PATH, DEFAULT_KEY_PATH)
    server: asyncio.base_events.Server = await asyncio.start_server(
        handle_client,
        host=HOST,
        port=PORT,
        ssl=ssl_context,
        ssl_handshake_timeout=10.0,
    )

    sockets = server.sockets or []
    bound_addresses: str = ", ".join(str(sock.getsockname()) for sock in sockets)
    LOGGER.info("SVP TLS server listening on %s", bound_addresses or f"{HOST}:{PORT}")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        LOGGER.info("Server task cancelled, shutting down")
        server.close()
        await server.wait_closed()
        raise
    finally:
        LOGGER.info("Server stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOGGER.info("Keyboard interrupt received, shutting down")
