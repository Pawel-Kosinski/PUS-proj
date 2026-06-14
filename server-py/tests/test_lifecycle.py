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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pytest
import pytest_asyncio


SERVER_DIR: Path = Path(__file__).resolve().parents[1]
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import server as svp_server
from database import DatabaseManager, init_db
from protocol import MsgType, SVPCodec, SVPFlags, SVPFrame


DUMMY_MAC_KEY: bytes = b"\x00" * 32
TEST_USERNAME: str = "alice"
TEST_K_AUTH: bytes = b"test_k_auth_32_bytes_long_string!"


@dataclass(frozen=True)
class MockDbInfo:
    path: Path
    user_id: int


@dataclass(frozen=True)
class MockHandshakeResult:
    mac_key: bytes
    session_token: bytes
    client_id: bytes


@pytest_asyncio.fixture
async def test_db_info(tmp_path: Path) -> AsyncIterator[MockDbInfo]:
    db_path: Path = tmp_path / "secvault_test.db"
    await init_db(str(db_path))

    async with DatabaseManager(str(db_path)) as db:
        user_id: int = await db.create_user(TEST_USERNAME, TEST_K_AUTH)

    yield MockDbInfo(path=db_path, user_id=user_id)


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


def _derive_mac_key(session_token: bytes, nonce_c: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_c,
        info=b"svp-mac",
    )
    return hkdf.derive(session_token)


async def perform_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    client_id: bytes | None = None,
) -> MockHandshakeResult:
    handshake_client_id: bytes = client_id if client_id is not None else os.urandom(16)
    nonce_c: bytes = os.urandom(32)
    hello_payload: bytes = struct.pack(
        "<32s16sQ",
        nonce_c,
        handshake_client_id,
        int(time.time() * 1000),
    )

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

    username_bytes: bytes = TEST_USERNAME.encode("utf-8")
    hmac_resp: bytes = hmac.new(
        TEST_K_AUTH,
        nonce_c + nonce_s + username_bytes,
        hashlib.sha256,
    ).digest()

    auth_payload: bytes = bytes([len(username_bytes)]) + username_bytes + hmac_resp
    await _send_frame(
        writer=writer,
        msg_type=MsgType.AUTH,
        payload=auth_payload,
        seq_id=1,
        mac_key=DUMMY_MAC_KEY,
    )

    auth_ok: SVPFrame = await _read_frame(reader, DUMMY_MAC_KEY)
    assert auth_ok.msg_type == MsgType.AUTH_OK

    token_len: int = struct.unpack_from("<H", auth_ok.payload, 0)[0]
    token_start: int = 2
    token_end: int = token_start + token_len
    assert len(auth_ok.payload) >= token_end + 16

    session_token: bytes = auth_ok.payload[token_start:token_end]
    expiry, vault_version = struct.unpack_from("<QQ", auth_ok.payload, token_end)

    assert len(session_token) == 32
    assert expiry > int(time.time() * 1000)
    assert vault_version == 0

    return MockHandshakeResult(
        mac_key=_derive_mac_key(session_token, nonce_c),
        session_token=session_token,
        client_id=handshake_client_id,
    )


@pytest.mark.asyncio
async def test_ping_pong(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        handshake = await perform_handshake(reader, writer)
        ping_ts: int = 1_717_000_000_123
        ping_payload: bytes = struct.pack("<q", ping_ts)

        await _send_frame(
            writer=writer,
            msg_type=MsgType.PING,
            payload=ping_payload,
            seq_id=2,
            mac_key=handshake.mac_key,
        )

        pong: SVPFrame = await _read_frame(reader, handshake.mac_key)
        assert pong.msg_type == MsgType.PONG
        assert pong.payload == ping_payload
        assert struct.unpack("<q", pong.payload)[0] == ping_ts
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_bye_graceful_close(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        handshake = await perform_handshake(reader, writer)

        await _send_frame(
            writer=writer,
            msg_type=MsgType.BYE,
            payload=b"\x00",
            seq_id=2,
            mac_key=handshake.mac_key,
        )

        bye: SVPFrame = await _read_frame(reader, handshake.mac_key)
        assert bye.msg_type == MsgType.BYE
        assert bye.payload == b"\x00"

        try:
            tail = await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
            assert tail == b""
        except asyncio.IncompleteReadError:
            pass
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_session_resumption_success(running_server: tuple[str, int]) -> None:
    host, port = running_server

    reader1, writer1 = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )
    try:
        first_handshake = await perform_handshake(reader1, writer1)
        previous_token: bytes = first_handshake.session_token
        resume_client_id: bytes = first_handshake.client_id
    finally:
        writer1.close()
        await writer1.wait_closed()

    reader2, writer2 = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )
    try:
        nonce_c2: bytes = os.urandom(32)
        hello_payload2: bytes = struct.pack(
            "<32s16sQ",
            nonce_c2,
            resume_client_id,
            int(time.time() * 1000),
        )
        await _send_frame(
            writer=writer2,
            msg_type=MsgType.HELLO,
            payload=hello_payload2,
            seq_id=0,
            mac_key=DUMMY_MAC_KEY,
        )

        challenge2: SVPFrame = await _read_frame(reader2, DUMMY_MAC_KEY)
        assert challenge2.msg_type == MsgType.CHALLENGE

        username_bytes: bytes = TEST_USERNAME.encode("utf-8")
        auth_refresh_payload: bytes = (
            bytes([len(username_bytes)])
            + username_bytes
            + (b"\x00" * 32)
            + b"\x01"
            + previous_token
        )
        await _send_frame(
            writer=writer2,
            msg_type=MsgType.AUTH,
            payload=auth_refresh_payload,
            seq_id=1,
            mac_key=DUMMY_MAC_KEY,
        )

        auth_ok2: SVPFrame = await _read_frame(reader2, DUMMY_MAC_KEY)
        assert auth_ok2.msg_type == MsgType.AUTH_OK

        token_len2: int = struct.unpack_from("<H", auth_ok2.payload, 0)[0]
        token_start2: int = 2
        token_end2: int = token_start2 + token_len2
        assert len(auth_ok2.payload) >= token_end2 + 16

        new_session_token: bytes = auth_ok2.payload[token_start2:token_end2]
        assert len(new_session_token) == 32
        assert new_session_token != previous_token
    finally:
        writer2.close()
        await writer2.wait_closed()
