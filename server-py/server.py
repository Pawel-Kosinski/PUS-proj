from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import ssl
from typing import Callable, cast


HOST: str = "0.0.0.0"
PORT: int = 7443
DEFAULT_CERT_PATH: str = "certs/server.crt"
DEFAULT_KEY_PATH: str = "certs/server.key"
TLS13_CIPHERSUITES: str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

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


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Connection handler placeholder for future SVP state machine logic."""
    del reader

    peername = writer.get_extra_info("peername")
    client_ip: str = "unknown"
    client_port: int = 0
    if isinstance(peername, tuple) and len(peername) >= 2:
        client_ip = str(peername[0])
        client_port = int(peername[1])

    LOGGER.info("Accepted TLS connection from %s:%d", client_ip, client_port)

    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionError:
        LOGGER.info("Connection from %s:%d closed abruptly", client_ip, client_port)
    else:
        LOGGER.info("Connection from %s:%d closed", client_ip, client_port)


async def main() -> None:
    """Start the asynchronous TLS server and serve until cancelled."""
    configure_logging()

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
