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
ERR_CONFLICT: int = 0x0A
MAX_PAYLOAD: int = 1_048_576


@dataclass(frozen=True)
class DbInfo:
    path: Path
    user_id: int


@pytest_asyncio.fixture
async def test_db_info(tmp_path: Path) -> AsyncIterator[DbInfo]:
    db_path: Path = tmp_path / "secvault_test.db"
    await init_db(str(db_path))

    async with DatabaseManager(str(db_path)) as db:
        user_id: int = await db.create_user(TEST_USERNAME, TEST_K_AUTH)

    yield DbInfo(path=db_path, user_id=user_id)


@pytest_asyncio.fixture
async def running_server(
    test_db_info: DbInfo,
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
) -> bytes:
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

    if len(auth_ok.payload) < 2 + 8 + 8:
        raise AssertionError("AUTH_OK payload too short")

    token_len: int = struct.unpack_from("<H", auth_ok.payload, 0)[0]
    token_start: int = 2
    token_end: int = token_start + token_len
    if len(auth_ok.payload) < token_end + 16:
        raise AssertionError("AUTH_OK payload malformed")

    session_token: bytes = auth_ok.payload[token_start:token_end]
    expiry, vault_version = struct.unpack_from("<QQ", auth_ok.payload, token_end)

    assert len(session_token) == 32
    assert expiry > int(time.time() * 1000)
    assert vault_version == 0

    return _derive_mac_key(session_token, nonce_c)


@pytest.mark.asyncio
async def test_vault_put_and_get(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        mac_key: bytes = await perform_handshake(reader, writer)
        seq: int = 2

        vault_id: bytes = os.urandom(16)
        blob: bytes = b"vault-blob-small"
        put_payload: bytes = vault_id + struct.pack("<Q", 0) + struct.pack("<I", len(blob)) + blob

        await _send_frame(writer, MsgType.VAULT_PUT, put_payload, seq, mac_key)
        seq += 1

        ack: SVPFrame = await _read_frame(reader, mac_key)
        assert ack.msg_type == MsgType.VAULT_ACK
        assert len(ack.payload) == 24
        ack_vault_id: bytes = ack.payload[:16]
        new_version: int = struct.unpack_from("<Q", ack.payload, 16)[0]
        assert ack_vault_id == vault_id
        assert new_version == 1

        get_payload: bytes = struct.pack("<16sQ", vault_id, 1)
        await _send_frame(writer, MsgType.VAULT_GET, get_payload, seq, mac_key)

        vault_data: SVPFrame = await _read_frame(reader, mac_key)
        assert vault_data.msg_type == MsgType.VAULT_DATA
        assert len(vault_data.payload) >= 24

        recv_vault_id: bytes = vault_data.payload[:16]
        recv_version: int = struct.unpack_from("<Q", vault_data.payload, 16)[0]
        recv_blob: bytes = vault_data.payload[24:]

        assert recv_vault_id == vault_id
        assert recv_version == 1
        assert recv_blob == blob
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_vault_put_conflict_cas(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        mac_key: bytes = await perform_handshake(reader, writer)
        seq: int = 2

        vault_id: bytes = os.urandom(16)
        blob_v1: bytes = b"blob-version-1"
        put_v1: bytes = vault_id + struct.pack("<Q", 0) + struct.pack("<I", len(blob_v1)) + blob_v1

        await _send_frame(writer, MsgType.VAULT_PUT, put_v1, seq, mac_key)
        seq += 1

        ack_v1: SVPFrame = await _read_frame(reader, mac_key)
        assert ack_v1.msg_type == MsgType.VAULT_ACK
        assert struct.unpack_from("<Q", ack_v1.payload, 16)[0] == 1

        blob_stale: bytes = b"blob-stale-client"
        put_stale: bytes = (
            vault_id
            + struct.pack("<Q", 0)
            + struct.pack("<I", len(blob_stale))
            + blob_stale
        )
        await _send_frame(writer, MsgType.VAULT_PUT, put_stale, seq, mac_key)

        error_frame: SVPFrame = await _read_frame(reader, mac_key)
        assert error_frame.msg_type == MsgType.ERROR
        assert len(error_frame.payload) >= 1
        assert error_frame.payload[0] == ERR_CONFLICT
    finally:
        writer.close()
        await writer.wait_closed()


@pytest.mark.asyncio
async def test_inbound_fragmentation(running_server: tuple[str, int]) -> None:
    host, port = running_server
    reader, writer = await asyncio.open_connection(
        host=host,
        port=port,
        ssl=_client_ssl_context(),
        server_hostname="localhost",
    )

    try:
        mac_key: bytes = await perform_handshake(reader, writer)
        seq: int = 2

        vault_id: bytes = os.urandom(16)
        blob: bytes = os.urandom(int(1.5 * 1024 * 1024))
        full_payload: bytes = vault_id + struct.pack("<Q", 0) + struct.pack("<I", len(blob)) + blob

        first_chunk: bytes = full_payload[:MAX_PAYLOAD]
        second_chunk: bytes = full_payload[MAX_PAYLOAD:]
        assert len(first_chunk) == MAX_PAYLOAD
        assert len(second_chunk) > 0

        await _send_frame(
            writer=writer,
            msg_type=MsgType.VAULT_PUT,
            payload=first_chunk,
            seq_id=seq,
            mac_key=mac_key,
            flags=SVPFlags.FRAGMENTED,
        )
        seq += 1

        await _send_frame(
            writer=writer,
            msg_type=MsgType.VAULT_PUT,
            payload=second_chunk,
            seq_id=seq,
            mac_key=mac_key,
            flags=SVPFlags.FRAGMENTED | SVPFlags.LAST_FRAG,
        )

        ack: SVPFrame = await _read_frame(reader, mac_key)
        assert ack.msg_type == MsgType.VAULT_ACK
        assert ack.payload[:16] == vault_id
        assert struct.unpack_from("<Q", ack.payload, 16)[0] == 1
    finally:
        writer.close()
        await writer.wait_closed()
