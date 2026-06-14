from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import ssl
import struct
import sys
import time
from typing import AsyncIterator

import aiosqlite
import pyotp
import pytest
import pytest_asyncio


SERVER_DIR: Path = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import server as svp_server
from database import DatabaseManager, init_db
from protocol import MsgType, SVPCodec, SVPFlags, SVPFrame


DUMMY_MAC_KEY: bytes = b"\x00" * 32
ALICE_USERNAME: str = "alice"
ALICE_K_AUTH: bytes = b"test_k_auth_32_bytes_long_string!"
BOB_USERNAME: str = "bob"
BOB_K_AUTH: bytes = b"bob_k_auth_32_bytes_long_string!"


@dataclass(frozen=True)
class MockDbInfo:
    path: Path
    bob_totp_secret: str


@pytest_asyncio.fixture
async def test_db_info(tmp_path: Path) -> AsyncIterator[MockDbInfo]:
    db_path: Path = tmp_path / "secvault_test.db"
    await init_db(str(db_path))

    async with DatabaseManager(str(db_path)) as db:
        await db.create_user(ALICE_USERNAME, ALICE_K_AUTH)
        await db.create_user(BOB_USERNAME, BOB_K_AUTH)

    bob_totp_secret: str = pyotp.random_base32()
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute(
            "UPDATE users SET totp_secret = ? WHERE username = ?",
            (bob_totp_secret, BOB_USERNAME),
        )
        await conn.commit()

    yield MockDbInfo(path=db_path, bob_totp_secret=bob_totp_secret)


@pytest_asyncio.fixture
async def running_server(
    test_db_info: MockDbInfo,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[str, int]]:
    monkeypatch.setattr(svp_server, "DB_PATH", str(test_db_info.path))

    cert_path: Path = SERVER_DIR / "certs" / "server.crt"
    key_path: Path = SERVER_DIR / "certs" / "server.key"
    ssl_context: ssl.SSLContext = svp_server.get_ssl_context(str(cert_path), str(key_path))

    host: str = "127.0.0.1"
    server: asyncio.base_events.Server = await asyncio.start_server(
        svp_server.handle_client,
        host=host,
        port=0,
        ssl=ssl_context,
        ssl_handshake_timeout=10.0,
    )

    sockets = server.sockets or []
    if not sockets:
        server.close()
        await server.wait_closed()
        raise RuntimeError("Server did not bind any socket")

    port: int = int(sockets[0].getsockname()[1])

    try:
        yield host, port
    finally:
        server.close()
        await server.wait_closed()


def _client_ssl_context() -> ssl.SSLContext:
    context: ssl.SSLContext = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _read_frame(reader: asyncio.StreamReader, mac_key: bytes) -> SVPFrame:
    header: bytes = await reader.readexactly(SVPCodec.HEADER_LEN)
    _, _, _, _, payload_len = SVPCodec.HEADER_STRUCT.unpack(header)
    trailer: bytes = await reader.readexactly(payload_len + SVPCodec.HMAC_LEN)
    return SVPCodec.decode(header + trailer, mac_key)


async def _send_frame(
    writer: asyncio.StreamWriter,
    msg_type: MsgType,
    payload: bytes,
    seq_id: int,
    mac_key: bytes,
    flags: SVPFlags = SVPFlags.NONE,
) -> None:
    frame: SVPFrame = SVPFrame(
        version=1,
        msg_type=msg_type,
        flags=flags,
        seq_id=seq_id,
        payload_len=len(payload),
        payload=payload,
        hmac=b"",
    )
    writer.write(SVPCodec.encode(frame, mac_key))
    await writer.drain()


def _build_auth_payload(
    username: str,
    nonce_c: bytes,
    nonce_s: bytes,
    k_auth: bytes,
    *,
    include_totp: bool,
    totp_code: int = 0,
) -> bytes:
    username_bytes: bytes = username.encode("utf-8")
    hmac_resp: bytes = hmac.new(
        k_auth,
        nonce_c + nonce_s + username_bytes,
        hashlib.sha256,
    ).digest()

    payload: bytes = bytes([len(username_bytes)]) + username_bytes + hmac_resp + b"\x00"
    if include_totp:
        payload += b"\x01" + struct.pack("<I", totp_code)
    return payload


async def perform_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    username: str,
    k_auth: bytes,
    include_totp: bool,
    totp_code: int = 0,
) -> SVPFrame:
    nonce_c: bytes = os.urandom(32)
    client_id: bytes = os.urandom(16)
    hello_payload: bytes = struct.pack("<32s16sQ", nonce_c, client_id, int(time.time() * 1000))

    await _send_frame(
        writer=writer,
        msg_type=MsgType.HELLO,
        payload=hello_payload,
        seq_id=0,
        mac_key=DUMMY_MAC_KEY,
    )

    challenge: SVPFrame = await _read_frame(reader, DUMMY_MAC_KEY)
    assert challenge.msg_type == MsgType.CHALLENGE
    assert len(challenge.payload) >= 32
    nonce_s: bytes = challenge.payload[:32]

    auth_payload: bytes = _build_auth_payload(
        username,
        nonce_c,
        nonce_s,
        k_auth,
        include_totp=include_totp,
        totp_code=totp_code,
    )
    await _send_frame(
        writer=writer,
        msg_type=MsgType.AUTH,
        payload=auth_payload,
        seq_id=1,
        mac_key=DUMMY_MAC_KEY,
    )

    return await _read_frame(reader, DUMMY_MAC_KEY)


@pytest.mark.asyncio
async def test_totp_success(
    running_server: tuple[str, int],
    test_db_info: MockDbInfo,
) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        current_code: int = int(pyotp.TOTP(test_db_info.bob_totp_secret).now())
        response: SVPFrame = await perform_handshake(
            reader,
            writer,
            username=BOB_USERNAME,
            k_auth=BOB_K_AUTH,
            include_totp=True,
            totp_code=current_code,
        )
        assert response.msg_type == MsgType.AUTH_OK
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_totp_missing(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        response: SVPFrame = await perform_handshake(
            reader,
            writer,
            username=BOB_USERNAME,
            k_auth=BOB_K_AUTH,
            include_totp=False,
        )
        assert response.msg_type == MsgType.AUTH_FAIL
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_totp_invalid(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        wrong_code: int = 111111
        response: SVPFrame = await perform_handshake(
            reader,
            writer,
            username=BOB_USERNAME,
            k_auth=BOB_K_AUTH,
            include_totp=True,
            totp_code=wrong_code,
        )
        assert response.msg_type == MsgType.AUTH_FAIL
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_totp_alice_ignored(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        response: SVPFrame = await perform_handshake(
            reader,
            writer,
            username=ALICE_USERNAME,
            k_auth=ALICE_K_AUTH,
            include_totp=True,
            totp_code=123456,
        )
        assert response.msg_type == MsgType.AUTH_OK
    finally:
        writer.close()
        await writer.wait_closed()
