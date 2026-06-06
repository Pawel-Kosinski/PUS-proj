"""svpclient.py - menedżer protokołu SVP po stronie klienta.

Realizuje: logowanie challenge-response (UC-01), rejestrację, pobranie/zapis sejfu
(UC-02/03), wznowienie sesji tokenem (UC-05). Logika jest portem client/src/client.cpp.
"""
import time

import protocol
import svpcrypto as crypto
from framing import ByteReader, ByteWriter, Frame
from transport import TlsConnection


class ProtocolError(Exception):
    """Błąd zwrócony przez serwer w ramce AUTH_FAIL lub ERROR."""

    def __init__(self, code, message=""):
        super().__init__(message)
        self.code = code


class ClientConfig:
    def __init__(self, host="127.0.0.1", port=protocol.SVP_PORT, ca_file=None,
                 insecure=False, debug=False):
        self.host = host
        self.port = port
        self.ca_file = ca_file
        self.insecure = insecure
        self.debug = debug


class Client:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.conn = None
        self.login_name = ""
        self.k_auth = b""        # PBKDF2(password, SHA256(login)) - weryfikator
        self.k_vault = b""       # PBKDF2(password, SHA256("vault:"+login)) - serwer go nie zna
        self.client_id = crypto.random_bytes(protocol.CLIENT_ID_LEN)
        self.nonce_c = b""       # nonce klienta z bieżącego handshake
        self.session_token = b""
        self.k_mac = None        # klucz HMAC ramek po ESTABLISHED (None = faza przed sesją)
        self.vault_id = b""
        self.vault_version = 0
        self.token_expiry = 0
        self._seq = 0

    # --- niskopoziomowe ---
    def _next_seq(self):
        s = self._seq
        self._seq += 1
        return s

    def _send(self, type, flags, payload, authed):
        f = Frame(type=type, flags=flags, seq=self._next_seq(), payload=payload)
        self.conn.send_frame(f, self.k_mac if authed else None)

    def _recv(self, authed):
        """Odbiera ramkę; odpowiada na PING; rzuca ProtocolError na ERROR."""
        while True:
            f = self.conn.recv_frame(self.k_mac if authed else None)
            if f.type == protocol.MSG_PING:
                self._send(protocol.MSG_PONG, protocol.FLAG_NONE, b"", authed)
                continue
            if f.type == protocol.MSG_ERROR:
                r = ByteReader(f.payload)
                code = r.u8()
                msg = r.lpstr() if r.remaining() else ""
                text = protocol.err_name(code) + (": " + msg if msg else "")
                raise ProtocolError(code, text)
            return f

    def _expect(self, type, authed):
        f = self._recv(authed)
        if f.type != type:
            raise ProtocolError(protocol.ERR_INTERNAL,
                                f"oczekiwano {protocol.msg_name(type)}, "
                                f"otrzymano {protocol.msg_name(f.type)}")
        return f

    def _do_challenge(self) -> bytes:
        """HELLO -> CHALLENGE; zwraca nonce_s."""
        self.nonce_c = crypto.random_bytes(protocol.NONCE_LEN)
        w = ByteWriter()
        w.raw(self.client_id)
        w.raw(self.nonce_c)
        w.u64(int(time.time()))
        self._send(protocol.MSG_HELLO, protocol.FLAG_NONE, w.take(), authed=False)

        ch = self._expect(protocol.MSG_CHALLENGE, authed=False)
        r = ByteReader(ch.payload)
        return r.raw(protocol.NONCE_LEN)

    def _compute_kmac(self):
        self.k_mac = crypto.hkdf_sha256(self.session_token, self.nonce_c, b"svp-mac",
                                        protocol.KEY_LEN)

    # --- API publiczne ---
    def connect(self):
        self.conn = TlsConnection(self.cfg.host, self.cfg.port, self.cfg.ca_file,
                                  self.cfg.insecure, self.cfg.debug)
        self.k_mac = None  # nowe połączenie - brak ustalonego K_mac

    def connected(self):
        return self.conn is not None

    def has_keys(self):
        return bool(self.k_auth)

    def derive_keys(self, login, password):
        self.login_name = login
        salt_auth = crypto.sha256(login.encode("utf-8"))
        self.k_auth = crypto.pbkdf2_sha256(password, salt_auth, protocol.PBKDF2_ITERS,
                                           protocol.KEY_LEN)
        # Niezależna sól => serwer (znający K_auth) nie wyprowadzi K_vault.
        salt_vault = crypto.sha256(("secvault-vault:" + login).encode("utf-8"))
        self.k_vault = crypto.pbkdf2_sha256(password, salt_vault, protocol.PBKDF2_ITERS,
                                            protocol.KEY_LEN)

    def login(self, totp_code=None):
        nonce_s = self._do_challenge()
        # hmac_resp = HMAC-SHA256(K_auth, nonce_c || nonce_s || login)
        msg = self.nonce_c + nonce_s + self.login_name.encode("utf-8")
        hmac_resp = crypto.hmac_sha256(self.k_auth, msg)

        flags = protocol.FLAG_NONE
        w = ByteWriter()
        w.lpstr(self.login_name)
        w.raw(hmac_resp)
        if totp_code:
            flags |= protocol.FLAG_TOTP_PRESENT
            w.lpstr(totp_code)
        self._send(protocol.MSG_AUTH, flags, w.take(), authed=False)

        ok = self._expect(protocol.MSG_AUTH_OK, authed=False)
        r = ByteReader(ok.payload)
        self.session_token = r.lpbytes()
        self.token_expiry = r.u64()
        self.vault_id = r.raw(protocol.VAULT_ID_LEN)
        self.vault_version = r.u32()
        self._compute_kmac()

    def register_account(self):
        w = ByteWriter()
        w.lpstr(self.login_name)
        w.raw(self.k_auth)  # serwer zapisuje K_auth jako weryfikator (przez tunel TLS)
        self._send(protocol.MSG_REGISTER, protocol.FLAG_NONE, w.take(), authed=False)

        ok = self._expect(protocol.MSG_REGISTER_OK, authed=False)
        r = ByteReader(ok.payload)
        self.vault_id = r.raw(protocol.VAULT_ID_LEN)
        self.vault_version = 0

    def refresh_session(self):
        self._do_challenge()  # przy odświeżaniu tokenem nie liczymy hmac_resp
        w = ByteWriter()
        w.lpstr(self.login_name)
        w.lpbytes(self.session_token)
        self._send(protocol.MSG_AUTH, protocol.FLAG_TOKEN_REFRESH, w.take(), authed=False)

        ok = self._expect(protocol.MSG_AUTH_OK, authed=False)
        r = ByteReader(ok.payload)
        self.session_token = r.lpbytes()
        self.token_expiry = r.u64()
        self.vault_id = r.raw(protocol.VAULT_ID_LEN)
        self.vault_version = r.u32()
        self._compute_kmac()

    def fetch_vault(self):
        """VAULT_GET -> VAULT_DATA. Zwraca (True, blob) albo (False, b'') przy ERR_NOT_FOUND."""
        w = ByteWriter()
        w.raw(self.vault_id)
        w.u32(self.vault_version)
        self._send(protocol.MSG_VAULT_GET, protocol.FLAG_NONE, w.take(), authed=True)
        try:
            data = self._expect(protocol.MSG_VAULT_DATA, authed=True)
        except ProtocolError as e:
            if e.code == protocol.ERR_NOT_FOUND:
                return False, b""
            raise
        r = ByteReader(data.payload)
        r.raw(protocol.VAULT_ID_LEN)  # vault_id (pomijamy - znamy własny)
        self.vault_version = r.u32()
        return True, r.lpblob()

    def put_vault(self, blob, base_version):
        """VAULT_PUT -> VAULT_ACK. Rzuca ProtocolError(ERR_CONFLICT) przy konflikcie."""
        w = ByteWriter()
        w.raw(self.vault_id)
        w.u32(base_version)
        w.lpblob(blob)
        self._send(protocol.MSG_VAULT_PUT, protocol.FLAG_NONE, w.take(), authed=True)

        ack = self._expect(protocol.MSG_VAULT_ACK, authed=True)
        r = ByteReader(ack.payload)
        r.raw(protocol.VAULT_ID_LEN)
        self.vault_version = r.u32()
        return self.vault_version

    def ping(self):
        self._send(protocol.MSG_PING, protocol.FLAG_NONE, b"", authed=True)
        self._expect(protocol.MSG_PONG, authed=True)

    def bye(self, reason=protocol.BYE_NORMAL):
        if not self.conn:
            return
        try:
            w = ByteWriter()
            w.u8(reason)
            self._send(protocol.MSG_BYE, protocol.FLAG_NONE, w.take(),
                       authed=self.k_mac is not None)
        except Exception:
            pass  # grzeczne zamknięcie - ignorujemy błędy zapisu
        self.conn.close()
        self.conn = None

    def ensure_session(self):
        """Gwarantuje aktywną sesję; po zerwaniu łączy ponownie i odświeża token (UC-05)."""
        if self.conn:
            try:
                self.ping()  # szybki test żywotności
                return
            except Exception:
                self.conn = None  # połączenie martwe - odbudujemy poniżej
        self.connect()
        try:
            self.refresh_session()
        except ProtocolError as e:
            if e.code == protocol.ERR_SESSION_EXPIRED and self.has_keys():
                self.login()  # token nieważny, ale mamy klucze z hasła w pamięci sesji
            else:
                raise
