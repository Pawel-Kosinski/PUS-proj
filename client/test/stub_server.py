#!/usr/bin/env python3
"""Minimalny serwer-zaślepka SVP do testów klienta C++ (NIE jest to docelowy serwer).
Implementuje tyle protokołu, ile potrzeba do przejścia ścieżki:
REGISTER/AUTH -> VAULT_GET/PUT, w tym weryfikacja HMAC ramek i CAS (ERR_CONFLICT).
"""
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys
import threading
import time

HDR = struct.Struct("<BBBII")  # VERSION, TYPE, FLAGS, SEQ, PAYLOAD_LEN
VER = 0x01
(HELLO, CHALLENGE, AUTH, AUTH_OK, AUTH_FAIL, REGISTER, REGISTER_OK) = (
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
(VGET, VDATA, VPUT, VACK, VSYNC) = (0x10, 0x11, 0x12, 0x13, 0x14)
(PING, PONG, BYE, ERROR) = (0x20, 0x21, 0x2E, 0x2F)
F_TOTP, F_REFRESH = 0x08, 0x10
ERR_CONFLICT, ERR_NOT_FOUND, ERR_SESSION_EXPIRED = 0x04, 0x05, 0x07

USERS = {}    # login -> K_auth (32B)
VAULTS = {}   # login -> (vault_id 16B, version, blob)
SECRET = b"server-token-signing-key"


def hkdf(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def rstr(b, o):
    (n,) = struct.unpack_from("<H", b, o); o += 2
    return b[o:o+n], o+n


def wstr(b):
    return struct.pack("<H", len(b)) + b


class Conn:
    def __init__(self, s):
        self.s = s
        self.nonce_c = b""
        self.login = None
        self.kmac = None

    def recv_n(self, n):
        buf = b""
        while len(buf) < n:
            c = self.s.recv(n - len(buf))
            if not c:
                raise ConnectionError("EOF")
            buf += c
        return buf

    def recv_frame(self):
        hdr = self.recv_n(HDR.size)
        ver, typ, flags, seq, plen = HDR.unpack(hdr)
        payload = self.recv_n(plen) if plen else b""
        mac = self.recv_n(32)
        if self.kmac:
            exp = hmac.new(self.kmac, hdr + payload, hashlib.sha256).digest()
            if not hmac.compare_digest(exp, mac):
                raise ConnectionError("zła suma HMAC ramki")
        return typ, flags, seq, payload

    def send(self, typ, payload=b"", flags=0):
        hdr = HDR.pack(VER, typ, flags, 0, len(payload))
        mac = (hmac.new(self.kmac, hdr + payload, hashlib.sha256).digest()
               if self.kmac else b"\x00" * 32)
        self.s.sendall(hdr + payload + mac)

    def err(self, code, msg=b""):
        self.send(ERROR, bytes([code]) + (wstr(msg) if msg else b""))


def handle(raw):
    c = Conn(raw)
    try:
        while True:
            typ, flags, seq, p = c.recv_frame()
            if typ == HELLO:
                client_id, nonce_c, ts = p[:16], p[16:32], struct.unpack_from("<Q", p, 32)[0]
                c.nonce_c = nonce_c
                c.send(CHALLENGE, os.urandom(16) and (NONCE_S := os.urandom(16)) and NONCE_S
                       + struct.pack("<Q", int(time.time())))
                # zapamiętaj wysłany nonce_s do weryfikacji AUTH:
                c.nonce_s = c._last = None
            elif typ == REGISTER:
                login, o = rstr(p, 0)
                kauth = p[o:o+32]
                login = login.decode()
                USERS[login] = kauth
                vid = os.urandom(16)
                VAULTS.setdefault(login, (vid, 0, b""))
                c.send(REGISTER_OK, VAULTS[login][0])
            elif typ == AUTH:
                login, o = rstr(p, 0)
                login = login.decode()
                if flags & F_REFRESH:
                    pass  # akceptuj token bez weryfikacji (zaślepka)
                else:
                    hmac_resp = p[o:o+32]
                    # serwer nie zna nonce_s w tej uproszczonej wersji -> akceptuje dowolny
                if login not in USERS:
                    c.err(ERR_SESSION_EXPIRED); continue
                c.login = login
                token = hmac.new(SECRET, login.encode(), hashlib.sha256).digest()
                c.kmac_pending = hkdf(token, c.nonce_c, b"svp-mac")
                vid, ver, _ = VAULTS.get(login, (os.urandom(16), 0, b""))
                VAULTS.setdefault(login, (vid, ver, b""))
                body = wstr(token) + struct.pack("<Q", int(time.time()) + 86400) + vid + struct.pack("<I", ver)
                c.send(AUTH_OK, body)
                c.kmac = c.kmac_pending  # od tej ramki weryfikujemy HMAC
            elif typ == VGET:
                vid, ver, blob = VAULTS[c.login]
                if not blob:
                    c.err(ERR_NOT_FOUND); continue
                c.send(VDATA, vid + struct.pack("<I", ver) + struct.pack("<I", len(blob)) + blob)
            elif typ == VPUT:
                vid = p[:16]
                base = struct.unpack_from("<I", p, 16)[0]
                blen = struct.unpack_from("<I", p, 20)[0]
                blob = p[24:24+blen]
                cur_vid, cur_ver, _ = VAULTS[c.login]
                if base != cur_ver:
                    c.err(ERR_CONFLICT); continue
                newver = cur_ver + 1
                VAULTS[c.login] = (cur_vid, newver, blob)
                c.send(VACK, cur_vid + struct.pack("<I", newver))
            elif typ == PING:
                c.send(PONG)
            elif typ == BYE:
                break
            else:
                c.err(0x09)
    except (ConnectionError, ssl.SSLError, OSError) as e:
        print(f"[server] rozłączenie: {e}", file=sys.stderr)
    finally:
        raw.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7443
    here = os.path.dirname(os.path.abspath(__file__))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(here, "cert.pem"), os.path.join(here, "key.pem"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)
    print(f"[server] SVP stub nasłuchuje na 127.0.0.1:{port}", file=sys.stderr)
    while True:
        cli, addr = srv.accept()
        try:
            tls = ctx.wrap_socket(cli, server_side=True)
        except ssl.SSLError as e:
            print(f"[server] błąd TLS: {e}", file=sys.stderr); continue
        threading.Thread(target=handle, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
