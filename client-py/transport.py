"""transport.py - warstwa transportu: gniazdo TCP opakowane w TLS 1.3.

Styl oparty na przykładach referencyjnych (moduł socket + ssl, klasa SecureClient).
Klient zawsze inicjuje połączenie; operacje są blokujące (model request-response).
"""
import socket
import ssl
import sys

import framing
import protocol
import svpcrypto as crypto


class TlsError(Exception):
    pass


class TlsConnection:
    """Pojedyncze połączenie TLS do serwera SVP; wysyła i odbiera całe ramki SVP."""

    def __init__(self, host, port, ca_file=None, insecure=False, debug=False):
        self.debug = debug
        # Kontekst TLS klienta (weryfikacja tożsamości serwera).
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # wymuszenie TLS 1.3
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif ca_file:
            ctx.load_verify_locations(cafile=ca_file)

        # Tworzenie gniazda TCP i owinięcie warstwą TLS (jak w przykładzie 4.0/client.py).
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock = ctx.wrap_socket(raw, server_hostname=host)
        try:
            self._sock.connect((host, port))
        except (ssl.SSLError, OSError) as e:
            raise TlsError(f"połączenie/handshake nieudane: {e}")

        cert = self._sock.getpeercert()
        self.peer_cn = ""
        if cert:
            for rdn in cert.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        self.peer_cn = v
        if self.debug:
            print(f"[tls] połączono, {self._sock.version()}, peer CN={self.peer_cn}",
                  file=sys.stderr)

    # --- niskopoziomowe I/O ---
    def _read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise TlsError("połączenie zamknięte przez serwer (EOF)")
            buf += chunk
        return bytes(buf)

    # --- ramki SVP ---
    def send_frame(self, frame: framing.Frame, k_mac):
        raw = framing.serialize(frame, k_mac)
        if self.debug:
            print(f"[tx] {protocol.msg_name(frame.type):<11} seq={frame.seq} "
                  f"flags=0x{frame.flags:02x} len={len(frame.payload)}", file=sys.stderr)
        try:
            self._sock.sendall(raw)
        except (ssl.SSLError, OSError) as e:
            raise TlsError(f"zapis nieudany (zerwane połączenie): {e}")

    def recv_frame(self, k_mac) -> framing.Frame:
        hdr = self._read_exact(protocol.HEADER_LEN)
        version, typ, flags, seq, plen = framing.parse_header(hdr)
        if version != protocol.SVP_VERSION:
            raise framing.FrameError("nieobsługiwana wersja protokołu")
        if plen > protocol.MAX_PAYLOAD:
            raise framing.FrameError("PAYLOAD_LEN przekracza limit")
        payload = self._read_exact(plen) if plen else b""
        mac = self._read_exact(protocol.HMAC_LEN)

        if k_mac is not None:
            expect = crypto.hmac_sha256(k_mac, hdr + payload)
            if not crypto.const_time_eq(expect, mac):
                raise framing.FrameError("zła suma HMAC ramki (ERR_BAD_HMAC)")

        if self.debug:
            print(f"[rx] {protocol.msg_name(typ):<11} seq={seq} "
                  f"flags=0x{flags:02x} len={len(payload)}", file=sys.stderr)
        return framing.Frame(type=typ, flags=flags, seq=seq, payload=payload, version=version)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass
