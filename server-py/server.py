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

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import pyotp

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
ERR_NOT_FOUND: int = 0x08
ERR_CONFLICT: int = 0x0A
FRAGMENT_TIMEOUT_SECONDS: float = 30.0
IDLE_TIMEOUT_SECONDS: float = 90.0
BYE_REASON_NORMAL: int = 0x00

HELLO_STRUCT: struct.Struct = struct.Struct("<32s16sQ")
VAULT_GET_STRUCT: struct.Struct = struct.Struct("<16sQ")
VAULT_PUT_HEADER_STRUCT: struct.Struct = struct.Struct("<16sQI")
AUTH_OK_TRAILER_STRUCT: struct.Struct = struct.Struct("<QQ")
AUTH_FAIL_STRUCT: struct.Struct = struct.Struct("<BI")
MAX_VAULT_BLOB_BYTES: int = 50 * 1024 * 1024
MAX_FRAGMENTED_VAULT_PUT_BYTES: int = MAX_VAULT_BLOB_BYTES + VAULT_PUT_HEADER_STRUCT.size
SESSION_TOKEN_LEN: int = 32

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
        set_ciphersuites(TLS13_CIPHERSUITES)
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


async def _send_fragmented_payload(
    writer: asyncio.StreamWriter,
    msg_type: MsgType,
    payload: bytes,
    seq_id: int,
    mac_key: bytes,
) -> int:
    if len(payload) <= SVPCodec.MAX_PAYLOAD_LEN:
        await _send_frame(
            writer=writer,
            msg_type=msg_type,
            payload=payload,
            seq_id=seq_id,
            mac_key=mac_key,
            flags=SVPFlags.NONE,
        )
        return seq_id + 1

    next_seq: int = seq_id
    chunk_size: int = SVPCodec.MAX_PAYLOAD_LEN
    offset: int = 0
    while offset < len(payload):
        chunk: bytes = payload[offset : offset + chunk_size]
        flags: SVPFlags = SVPFlags.FRAGMENTED
        if offset + len(chunk) >= len(payload):
            flags |= SVPFlags.LAST_FRAG

        await _send_frame(
            writer=writer,
            msg_type=msg_type,
            payload=chunk,
            seq_id=next_seq,
            mac_key=mac_key,
            flags=flags,
        )
        next_seq += 1
        offset += len(chunk)

    return next_seq


def _parse_hello_payload(payload: bytes) -> tuple[bytes, bytes, int]:
    if len(payload) != HELLO_STRUCT.size:
        raise SVPFormatError("HELLO payload has invalid length")

    nonce_c, client_id, timestamp_ms = HELLO_STRUCT.unpack(payload)
    if abs(_now_ms() - int(timestamp_ms)) > MAX_CLOCK_SKEW_MS:
        raise SVPFormatError("HELLO timestamp exceeds allowed clock skew")

    return nonce_c, client_id, int(timestamp_ms)


def _parse_auth_payload(
    payload: bytes,
) -> tuple[str, bytes, int, bytes | None, int, int | None]:
    if len(payload) < 1 + 32:
        raise SVPFormatError("AUTH payload is too short")

    username_len: int = payload[0]
    username_start: int = 1
    username_end: int = username_start + username_len
    hmac_end: int = username_end + 32

    if username_len == 0 or username_len > 64:
        raise SVPFormatError("AUTH username length is invalid")

    if len(payload) < hmac_end:
        raise SVPFormatError("AUTH payload has invalid length")

    username_bytes: bytes = payload[username_start:username_end]
    hmac_resp: bytes = payload[username_end:hmac_end]
    try:
        username: str = username_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SVPFormatError("AUTH username is not valid UTF-8") from exc

    if len(payload) == hmac_end:
        return username, hmac_resp, 0, None, 0, None

    token_refresh: int = payload[hmac_end]
    idx: int = hmac_end + 1
    refresh_token: bytes | None = None
    if token_refresh == 0:
        pass
    elif token_refresh == 1:
        remaining_len: int = len(payload) - idx
        if remaining_len < SESSION_TOKEN_LEN:
            raise SVPFormatError("AUTH token refresh requires a full session token")
        refresh_token = payload[idx:idx + SESSION_TOKEN_LEN]
        idx += SESSION_TOKEN_LEN
    else:
        raise SVPFormatError("AUTH token_refresh must be 0x00 or 0x01")

    if idx == len(payload):
        return username, hmac_resp, token_refresh, refresh_token, 0, None

    totp_present: int = payload[idx]
    idx += 1
    if totp_present == 0:
        if idx != len(payload):
            raise SVPFormatError("AUTH payload has trailing bytes after totp_present=0x00")
        return username, hmac_resp, token_refresh, refresh_token, totp_present, None

    if totp_present == 1:
        if len(payload) - idx != 4:
            raise SVPFormatError("AUTH payload must include 4-byte TOTP code")
        totp_code: int = struct.unpack_from("<I", payload, idx)[0]
        return username, hmac_resp, token_refresh, refresh_token, totp_present, totp_code

    raise SVPFormatError("AUTH totp_present must be 0x00 or 0x01")


def _build_auth_ok_payload(session_token: bytes, expiry_ms: int, vault_version: int) -> bytes:
    return (
        struct.pack("<H", len(session_token))
        + session_token
        + AUTH_OK_TRAILER_STRUCT.pack(expiry_ms, vault_version)
    )


def _build_auth_fail_payload() -> bytes:
    return AUTH_FAIL_STRUCT.pack(ERR_AUTH_FAILED, 0)


def _build_error_payload(error_code: int) -> bytes:
    return struct.pack("<B", error_code)


def _build_vault_data_payload(vault_id: bytes, version: int, blob: bytes) -> bytes:
    return vault_id + struct.pack("<Q", version) + blob


def _build_vault_ack_payload(vault_id: bytes, new_version: int) -> bytes:
    return vault_id + struct.pack("<Q", new_version)


def _parse_vault_get_payload(payload: bytes) -> tuple[bytes, int]:
    if len(payload) != VAULT_GET_STRUCT.size:
        raise SVPFormatError("VAULT_GET payload has invalid length")
    return VAULT_GET_STRUCT.unpack(payload)


def _parse_vault_put_payload(payload: bytes) -> tuple[bytes, int, bytes]:
    if len(payload) < VAULT_PUT_HEADER_STRUCT.size:
        raise SVPFormatError("VAULT_PUT payload is too short")

    vault_id, base_version, blob_len = VAULT_PUT_HEADER_STRUCT.unpack_from(payload, 0)
    if blob_len > MAX_VAULT_BLOB_BYTES:
        raise SVPFormatError("VAULT_PUT blob exceeds server size limit")

    expected_len: int = VAULT_PUT_HEADER_STRUCT.size + blob_len
    if len(payload) != expected_len:
        raise SVPFormatError("VAULT_PUT payload length does not match blob_len")

    blob: bytes = payload[VAULT_PUT_HEADER_STRUCT.size:expected_len]
    return vault_id, base_version, blob


def _derive_mac_key(session_token: bytes, nonce_c: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_c,
        info=b"svp-mac",
    )
    return hkdf.derive(session_token)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Handle one TLS client and run the SVP session state machine."""
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
    authenticated_user_id: int | None = None
    session_mac_key: bytes | None = None
    fragmented_put_buffer: bytearray | None = None
    fragment_started_at: float | None = None

    try:
        async with DatabaseManager(DB_PATH) as db:
            while True:
                if state in {"GREETING", "AUTHENTICATING"}:
                    active_mac_key: bytes = DUMMY_MAC_KEY
                else:
                    if session_mac_key is None:
                        raise SVPFormatError("missing session MAC key in ESTABLISHED state")
                    active_mac_key = session_mac_key
                read_timeout: float = IDLE_TIMEOUT_SECONDS
                if state == "ESTABLISHED" and fragmented_put_buffer is not None:
                    if fragment_started_at is None:
                        fragmented_put_buffer = None
                        fragment_started_at = None
                    else:
                        remaining_fragment_timeout: float = FRAGMENT_TIMEOUT_SECONDS - (
                            time.monotonic() - fragment_started_at
                        )
                        if remaining_fragment_timeout <= 0:
                            LOGGER.warning(
                                "Dropping incomplete fragmented VAULT_PUT from %s:%d (timeout)",
                                client_ip,
                                client_port,
                            )
                            fragmented_put_buffer = None
                            fragment_started_at = None
                            continue
                        read_timeout = min(read_timeout, remaining_fragment_timeout)

                try:
                    frame = await asyncio.wait_for(
                        _read_frame(reader, active_mac_key),
                        timeout=read_timeout,
                    )
                except asyncio.TimeoutError:
                    if state == "ESTABLISHED" and fragmented_put_buffer is not None:
                        if fragment_started_at is not None and (
                            time.monotonic() - fragment_started_at
                        ) >= FRAGMENT_TIMEOUT_SECONDS:
                            LOGGER.warning(
                                "Dropping incomplete fragmented VAULT_PUT from %s:%d (timeout)",
                                client_ip,
                                client_port,
                            )
                            fragmented_put_buffer = None
                            fragment_started_at = None
                            continue

                    LOGGER.info(
                        "Session timed out after %.0f seconds for %s:%d",
                        IDLE_TIMEOUT_SECONDS,
                        client_ip,
                        client_port,
                    )
                    break

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

                    (
                        username,
                        hmac_resp,
                        token_refresh,
                        refresh_token,
                        totp_present,
                        totp_code,
                    ) = _parse_auth_payload(frame.payload)
                    user = await db.get_user_by_username(username)

                    auth_valid: bool = False
                    auth_user_id: int | None = None
                    if token_refresh == 1:
                        if user is not None and refresh_token is not None:
                            session_row = await db.get_session(refresh_token)
                            if session_row is not None:
                                session_expiry: int = int(session_row.get("expiry") or 0)
                                session_user_id: int = int(session_row.get("user_id") or 0)
                                session_client_id_value = session_row.get("client_id")
                                session_client_id: bytes = (
                                    bytes(session_client_id_value)
                                    if session_client_id_value is not None
                                    else b""
                                )
                                if (
                                    session_expiry > _now_ms()
                                    and session_user_id == int(user["id"])
                                    and session_client_id == client_id
                                ):
                                    auth_valid = True
                                    auth_user_id = session_user_id
                    else:
                        if user is not None and user.get("k_auth") is not None:
                            k_auth: bytes = bytes(user["k_auth"])
                            expected_hmac: bytes = hmac.new(
                                k_auth,
                                nonce_c + nonce_s + username.encode("utf-8"),
                                hashlib.sha256,
                            ).digest()
                            auth_valid = hmac.compare_digest(hmac_resp, expected_hmac)
                            if auth_valid:
                                auth_user_id = int(user["id"])

                                totp_secret_value = user.get("totp_secret")
                                if totp_secret_value is not None:
                                    if totp_present != 1 or totp_code is None:
                                        auth_valid = False
                                    else:
                                        totp_secret: str = str(totp_secret_value)
                                        totp = pyotp.TOTP(totp_secret)
                                        is_totp_valid: bool = totp.verify(
                                            str(totp_code).zfill(6)
                                        )
                                        if not is_totp_valid:
                                            auth_valid = False

                    if not auth_valid or auth_user_id is None:
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
                    authenticated_user_id = auth_user_id
                    await db.create_session(
                        token=session_token,
                        user_id=authenticated_user_id,
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
                    session_mac_key = _derive_mac_key(session_token, nonce_c)
                    state = "ESTABLISHED"
                    LOGGER.info(
                        "Client %s:%d authenticated as '%s'",
                        client_ip,
                        client_port,
                        username,
                    )
                    continue

                if state == "ESTABLISHED":
                    if authenticated_user_id is None:
                        raise SVPFormatError("missing authenticated user in ESTABLISHED state")

                    if fragmented_put_buffer is not None and frame.msg_type != MsgType.VAULT_PUT:
                        raise SVPFormatError(
                            "fragmented VAULT_PUT interrupted by another message type"
                        )

                    if frame.msg_type == MsgType.PING:
                        if len(frame.payload) != 8:
                            raise SVPFormatError("PING payload must be exactly 8 bytes")
                        ping_timestamp: int = struct.unpack("<q", frame.payload)[0]
                        await _send_frame(
                            writer=writer,
                            msg_type=MsgType.PONG,
                            payload=struct.pack("<q", ping_timestamp),
                            seq_id=outbound_seq,
                            mac_key=active_mac_key,
                        )
                        outbound_seq += 1
                        continue

                    if frame.msg_type == MsgType.BYE:
                        if len(frame.payload) != 1:
                            raise SVPFormatError("BYE payload must be exactly 1 byte")
                        _reason_code: int = frame.payload[0]
                        await _send_frame(
                            writer=writer,
                            msg_type=MsgType.BYE,
                            payload=bytes([BYE_REASON_NORMAL]),
                            seq_id=outbound_seq,
                            mac_key=active_mac_key,
                        )
                        outbound_seq += 1
                        break

                    if frame.msg_type == MsgType.VAULT_GET:
                        vault_id, _known_version = _parse_vault_get_payload(frame.payload)
                        vault_row = await db.get_vault(vault_id)
                        if vault_row is None:
                            await _send_frame(
                                writer=writer,
                                msg_type=MsgType.ERROR,
                                payload=_build_error_payload(ERR_NOT_FOUND),
                                seq_id=outbound_seq,
                                mac_key=active_mac_key,
                            )
                            outbound_seq += 1
                            continue

                        row_user_id = vault_row.get("user_id")
                        if row_user_id is not None and int(row_user_id) != authenticated_user_id:
                            await _send_frame(
                                writer=writer,
                                msg_type=MsgType.ERROR,
                                payload=_build_error_payload(ERR_NOT_FOUND),
                                seq_id=outbound_seq,
                                mac_key=active_mac_key,
                            )
                            outbound_seq += 1
                            continue

                        version: int = int(vault_row.get("version") or 0)
                        blob_value = vault_row.get("blob")
                        blob: bytes = bytes(blob_value) if blob_value is not None else b""
                        vault_payload: bytes = _build_vault_data_payload(vault_id, version, blob)

                        outbound_seq = await _send_fragmented_payload(
                            writer=writer,
                            msg_type=MsgType.VAULT_DATA,
                            payload=vault_payload,
                            seq_id=outbound_seq,
                            mac_key=active_mac_key,
                        )
                        continue

                    if frame.msg_type == MsgType.VAULT_PUT:
                        is_fragmented: bool = bool(frame.flags & SVPFlags.FRAGMENTED)
                        is_last_fragment: bool = bool(frame.flags & SVPFlags.LAST_FRAG)
                        if is_last_fragment and not is_fragmented:
                            raise SVPFormatError("LAST_FRAG set without FRAGMENTED")

                        payload_to_process: bytes | None = None
                        if is_fragmented:
                            if fragmented_put_buffer is None:
                                fragmented_put_buffer = bytearray()
                                fragment_started_at = time.monotonic()

                            fragmented_put_buffer.extend(frame.payload)
                            if len(fragmented_put_buffer) > MAX_FRAGMENTED_VAULT_PUT_BYTES:
                                fragmented_put_buffer = None
                                fragment_started_at = None
                                raise SVPFormatError(
                                    "fragmented VAULT_PUT exceeds maximum allowed size"
                                )

                            if not is_last_fragment:
                                continue

                            payload_to_process = bytes(fragmented_put_buffer)
                            fragmented_put_buffer = None
                            fragment_started_at = None
                        else:
                            payload_to_process = frame.payload

                        vault_id, base_version, blob = _parse_vault_put_payload(payload_to_process)

                        current_vault = await db.get_vault(vault_id)
                        current_version: int = 0
                        if current_vault is not None:
                            row_user_id = current_vault.get("user_id")
                            if row_user_id is not None and int(row_user_id) != authenticated_user_id:
                                await _send_frame(
                                    writer=writer,
                                    msg_type=MsgType.ERROR,
                                    payload=_build_error_payload(ERR_NOT_FOUND),
                                    seq_id=outbound_seq,
                                    mac_key=active_mac_key,
                                )
                                outbound_seq += 1
                                continue
                            current_version = int(current_vault.get("version") or 0)

                        if base_version != current_version:
                            await _send_frame(
                                writer=writer,
                                msg_type=MsgType.ERROR,
                                payload=_build_error_payload(ERR_CONFLICT),
                                seq_id=outbound_seq,
                                mac_key=active_mac_key,
                            )
                            outbound_seq += 1
                            continue

                        new_version: int = current_version + 1
                        updated: bool = await db.update_vault(
                            vault_id=vault_id,
                            user_id=authenticated_user_id,
                            version=new_version,
                            blob=blob,
                            ts=_now_ms(),
                        )
                        if not updated:
                            await _send_frame(
                                writer=writer,
                                msg_type=MsgType.ERROR,
                                payload=_build_error_payload(ERR_CONFLICT),
                                seq_id=outbound_seq,
                                mac_key=active_mac_key,
                            )
                            outbound_seq += 1
                            continue

                        ack_payload: bytes = _build_vault_ack_payload(vault_id, new_version)
                        await _send_frame(
                            writer=writer,
                            msg_type=MsgType.VAULT_ACK,
                            payload=ack_payload,
                            seq_id=outbound_seq,
                            mac_key=active_mac_key,
                        )
                        outbound_seq += 1
                        continue

                    raise SVPFormatError(
                        f"unsupported message in ESTABLISHED: {frame.msg_type.name}"
                    )

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
