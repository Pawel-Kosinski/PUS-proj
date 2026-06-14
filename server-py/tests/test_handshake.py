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
class TestDbInfo:
    path: Path
    user_id: int


@pytest_asyncio.fixture
async def test_db_info(tmp_path: Path) -> AsyncIterator[TestDbInfo]:
    db_path: Path = tmp_path / "secvault_test.db"
    await init_db(str(db_path))

    async with DatabaseManager(str(db_path)) as db:
        user_id: int = await db.create_user(TEST_USERNAME, TEST_K_AUTH)

    yield TestDbInfo(path=db_path, user_id=user_id)


@pytest_asyncio.fixture
async def running_server(
    test_db_info: TestDbInfo,
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


@pytest.mark.asyncio
async def test_successful_handshake(
    running_server: tuple[str, int],
    test_db_info: TestDbInfo,
) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        nonce_c: bytes = os.urandom(32)
        client_id: bytes = os.urandom(16)
        hello_payload: bytes = struct.pack("<32s16sQ", nonce_c, client_id, int(time.time() * 1000))

        await _send_frame(writer, MsgType.HELLO, hello_payload, seq_id=0, mac_key=DUMMY_MAC_KEY)

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
        await _send_frame(writer, MsgType.AUTH, auth_payload, seq_id=1, mac_key=DUMMY_MAC_KEY)

        auth_ok: SVPFrame = await _read_frame(reader, DUMMY_MAC_KEY)
        assert auth_ok.msg_type == MsgType.AUTH_OK

        token_len: int = struct.unpack_from("<H", auth_ok.payload, 0)[0]
        token_start: int = 2
        token_end: int = token_start + token_len
        session_token: bytes = auth_ok.payload[token_start:token_end]
        expiry, vault_version = struct.unpack_from("<QQ", auth_ok.payload, token_end)

        assert len(session_token) == 32
        assert expiry > int(time.time() * 1000)
        assert vault_version == 0

        async with DatabaseManager(str(test_db_info.path)) as db:
            session = await db.get_session(session_token)
        assert session is not None
        assert int(session["user_id"]) == test_db_info.user_id
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_failed_handshake_wrong_password(
    running_server: tuple[str, int],
) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        nonce_c: bytes = os.urandom(32)
        client_id: bytes = os.urandom(16)
        hello_payload: bytes = struct.pack("<32s16sQ", nonce_c, client_id, int(time.time() * 1000))

        await _send_frame(writer, MsgType.HELLO, hello_payload, seq_id=0, mac_key=DUMMY_MAC_KEY)

        challenge: SVPFrame = await _read_frame(reader, DUMMY_MAC_KEY)
        assert challenge.msg_type == MsgType.CHALLENGE
        nonce_s: bytes = challenge.payload[:32]

        username_bytes: bytes = TEST_USERNAME.encode("utf-8")
        wrong_k_auth: bytes = b"wrong_k_auth_32_bytes_long_string!!"
        hmac_resp: bytes = hmac.new(
            wrong_k_auth,
            nonce_c + nonce_s + username_bytes,
            hashlib.sha256,
        ).digest()

        auth_payload: bytes = bytes([len(username_bytes)]) + username_bytes + hmac_resp
        await _send_frame(writer, MsgType.AUTH, auth_payload, seq_id=1, mac_key=DUMMY_MAC_KEY)

        try:
            response: SVPFrame = await asyncio.wait_for(_read_frame(reader, DUMMY_MAC_KEY), timeout=2.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        assert response.msg_type == MsgType.AUTH_FAIL
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_bad_hmac_disconnects(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        nonce_c: bytes = os.urandom(32)
        client_id: bytes = os.urandom(16)
        hello_payload: bytes = struct.pack("<32s16sQ", nonce_c, client_id, int(time.time() * 1000))

        hello_frame = SVPFrame(
            version=1,
            msg_type=MsgType.HELLO,
            flags=SVPFlags.NONE,
            seq_id=0,
            payload_len=len(hello_payload),
            payload=hello_payload,
            hmac=b"",
        )
        corrupted: bytearray = bytearray(SVPCodec.encode(hello_frame, DUMMY_MAC_KEY))
        corrupted[-1] ^= 0xFF

        writer.write(bytes(corrupted))
        await writer.drain()

        with pytest.raises(asyncio.IncompleteReadError):
            await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
    finally:
        writer.close()
        await writer.wait_closed()
