#!/usr/bin/env python3
"""secvault.py - interfejs CLI (REPL) klienta SecVault.

Sejf żyje w pamięci RAM przez czas sesji; hasło główne nigdy nie jest zapisywane.
Uruchomienie:  python3 secvault.py --host 127.0.0.1 --port 7443 [--insecure]
Self-test krypto (bez serwera):  python3 secvault.py --selftest
"""
import argparse
import getpass
import sys

import protocol
import svpcrypto as crypto
from framing import ByteReader, ByteWriter, FrameError
from svpclient import Client, ClientConfig, ProtocolError
from vault import Vault

_CACHE_MAGIC = b"SVCACHE1"


# ---- wejście użytkownika ----
def read_line(prompt):
    try:
        return input(prompt)
    except EOFError:
        raise


def read_password(prompt):
    # getpass wyłącza echo; przy stdin z potoku czyta linię i ostrzega na stderr.
    try:
        return getpass.getpass(prompt)
    except EOFError:
        return ""


# ---- lokalna pamięć podręczna (offline) ----
def save_cache(path, login, vault_id, version, blob):
    w = ByteWriter()
    w.raw(_CACHE_MAGIC)
    w.lpstr(login)
    w.raw(vault_id)
    w.u32(version)
    w.lpblob(blob)
    with open(path, "wb") as f:
        f.write(w.take())


def load_cache(path):
    """Zwraca (login, vault_id, version, blob) lub None."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    try:
        r = ByteReader(raw)
        if r.raw(len(_CACHE_MAGIC)) != _CACHE_MAGIC:
            return None
        login = r.lpstr()
        vault_id = r.raw(protocol.VAULT_ID_LEN)
        version = r.u32()
        blob = r.lpblob()
        return login, vault_id, version, blob
    except (FrameError, ValueError):
        return None


def print_entry(e, show_password):
    print(f"  id:       {e.id}")
    print(f"  serwis:   {e.service}")
    print(f"  login:    {e.username}")
    print(f"  hasło:    {e.password if show_password else '********'}")
    if e.notes:
        print(f"  notatka:  {e.notes}")


def print_help():
    print(
        "Dostępne komendy:\n"
        "  ls                 - lista wpisów\n"
        "  get <serwis|id>    - pokaż wpis wraz z hasłem\n"
        "  add                - dodaj nowy wpis\n"
        "  edit <serwis|id>   - edytuj wpis\n"
        "  rm  <serwis|id>    - usuń wpis\n"
        "  sync               - wyślij zmiany na serwer (z obsługą konfliktu)\n"
        "  pull               - pobierz i scal wersję z serwera\n"
        "  ping               - test połączenia (keep-alive)\n"
        "  help               - ta pomoc\n"
        "  quit / exit        - synchronizuj i zakończ"
    )


# ---- synchronizacja z obsługą konfliktu (UC-03/UC-04) ----
def do_sync(cli: Client, vault: Vault):
    cli.ensure_session()
    for _ in range(3):
        blob = vault.encrypt(cli.k_vault)
        try:
            v = cli.put_vault(blob, cli.vault_version)
            print(f"Zsynchronizowano. Nowa wersja sejfu: {v}")
            return True
        except ProtocolError as e:
            if e.code == protocol.ERR_CONFLICT:
                print("Konflikt wersji - pobieram wersję serwera i scalam...")
                ok, srv_blob = cli.fetch_vault()
                if ok:
                    srv = Vault.decrypt(srv_blob, cli.k_vault)
                    for c in vault.merge_from(srv):
                        print(f"  konflikt wpisu: {c} (wybrano nowszy)")
                continue  # ponów PUT z nową base_version
            raise
    print("Nie udało się zsynchronizować po 3 próbach.")
    return False


# ---- self-test kryptografii (KAT + roundtrip) ----
def selftest():
    fails = 0

    def check(name, ok):
        nonlocal fails
        print(("[ OK ] " if ok else "[FAIL] ") + name)
        if not ok:
            fails += 1

    check('SHA256("abc")',
          crypto.to_hex(crypto.sha256(b"abc")) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    check("HMAC-SHA256 (RFC 4231 #1)",
          crypto.to_hex(crypto.hmac_sha256(b"\x0b" * 20, b"Hi There")) ==
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    vk, iv = crypto.random_bytes(32), crypto.random_bytes(12)
    pt = "tajne hasło 123".encode("utf-8")
    ct = crypto.aes256gcm_encrypt(vk, iv, pt)
    check("AES-256-GCM roundtrip", crypto.aes256gcm_decrypt(vk, iv, ct) == pt)
    detected = False
    bad = bytearray(ct)
    bad[0] ^= 0x01
    try:
        crypto.aes256gcm_decrypt(vk, iv, bytes(bad))
    except crypto.CryptoError:
        detected = True
    check("AES-256-GCM wykrywa modyfikację", detected)

    a = crypto.pbkdf2_sha256("pass", crypto.sha256(b"user"), 1000, 32)
    b = crypto.pbkdf2_sha256("pass", crypto.sha256(b"user"), 1000, 32)
    check("PBKDF2 determinizm", a == b)
    check("HKDF determinizm",
          crypto.hkdf_sha256(a, iv, b"svp-mac", 32) == crypto.hkdf_sha256(a, iv, b"svp-mac", 32))
    check("HKDF różne info -> różny klucz",
          crypto.hkdf_sha256(a, iv, b"x", 32) != crypto.hkdf_sha256(a, iv, b"y", 32))

    v = Vault()
    v.add("github.com", "alice", "s3cr3t", "konto firmowe")
    v2 = Vault.decrypt(v.encrypt(vk), vk)
    check("Vault encrypt/decrypt", len(v2) == 1 and v2.entries[0].password == "s3cr3t")

    print(f"\n{'NIEPOWODZENIE' if fails else 'Wszystkie testy OK'} ({fails} błędów)")
    return 1 if fails else 0


def parse_args():
    p = argparse.ArgumentParser(description="Klient SecVault (SVP) - Python")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=protocol.SVP_PORT)
    p.add_argument("--ca", dest="ca_file", default=None, help="plik CA do weryfikacji serwera")
    p.add_argument("--insecure", action="store_true", help="wyłącz weryfikację certyfikatu")
    p.add_argument("--cache", default=".svp_cache", help="plik lokalnej kopii sejfu")
    p.add_argument("--offline", action="store_true", help="praca na lokalnej kopii (tylko odczyt)")
    p.add_argument("--debug", action="store_true", help="hex/metadane ramek na stderr")
    p.add_argument("--selftest", action="store_true", help="self-test kryptografii i wyjście")
    return p.parse_args()


def main():
    args = parse_args()
    if args.selftest:
        return selftest()

    cfg = ClientConfig(host=args.host, port=args.port, ca_file=args.ca_file,
                       insecure=args.insecure, debug=args.debug)
    cli = Client(cfg)
    vault = Vault()
    dirty = False
    online = False

    try:
        login = read_line("Użytkownik: ")
    except EOFError:
        return 1
    password = read_password("Hasło główne: ")
    if not login:
        print("Brak nazwy użytkownika.", file=sys.stderr)
        return 1
    cli.derive_keys(login, password)

    if not args.offline:
        try:
            cli.connect()
            mode = read_line("Zaloguj (l) czy zarejestruj nowe konto (r)? [l] ")
            if mode in ("r", "R"):
                cli.register_account()
                print("Konto utworzone.")
                cli.login()
            else:
                cli.login()
            print(f"Zalogowano. Wersja sejfu na serwerze: {cli.vault_version}")

            ok, blob = cli.fetch_vault()
            if ok:
                vault = Vault.decrypt(blob, cli.k_vault)
                save_cache(args.cache, login, cli.vault_id, cli.vault_version, blob)
                print(f"Pobrano sejf ({len(vault)} wpisów).")
            else:
                print("Serwer nie ma jeszcze sejfu - zaczynamy pusty.")
            online = True
        except ProtocolError as e:
            print(f"Błąd protokołu: {e}", file=sys.stderr)
            if e.code == protocol.ERR_AUTH_FAILED:
                print("Sprawdź login i hasło.", file=sys.stderr)
            return 1
        except Exception as e:
            print(f"Brak połączenia z serwerem ({e}).", file=sys.stderr)
            print("Przechodzę w tryb offline (tylko odczyt z lokalnej kopii).", file=sys.stderr)

    if not online:
        cached = load_cache(args.cache)
        if not cached:
            print(f"Brak lokalnej kopii sejfu ({args.cache}).", file=sys.stderr)
            return 1
        _, _, c_ver, c_blob = cached
        try:
            vault = Vault.decrypt(c_blob, cli.k_vault)
            print(f"Tryb offline: wczytano lokalną kopię (wersja {c_ver}, {len(vault)} wpisów).")
        except Exception:
            print("Nie udało się odszyfrować lokalnej kopii (złe hasło?).", file=sys.stderr)
            return 1

    print("Wpisz 'help' aby zobaczyć komendy.")

    while True:
        try:
            line = read_line("secvault> ")
        except EOFError:
            print()
            break
        parts = line.split(maxsplit=1)
        if not parts:
            continue
        cmd = parts[0]
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "help":
            print_help()
        elif cmd == "ls":
            if len(vault) == 0:
                print("(sejf pusty)")
            for e in vault.entries:
                print(f"  {e.id}  {e.service}  ({e.username})")
        elif cmd == "get":
            e = vault.find(arg)
            if e:
                print_entry(e, True)
            else:
                print(f"Nie znaleziono wpisu: {arg}")
        elif cmd == "add":
            service = read_line("  serwis: ")
            username = read_line("  login: ")
            pw = read_password("  hasło: ")
            notes = read_line("  notatka (opcjonalnie): ")
            vault.add(service, username, pw, notes)
            dirty = True
            print("Dodano. Użyj 'sync' aby wysłać na serwer.")
        elif cmd == "edit":
            e = vault.find(arg)
            if not e:
                print(f"Nie znaleziono wpisu: {arg}")
                continue
            print("(Enter = bez zmian)")
            u = read_line(f"  login [{e.username}]: ")
            pw = read_password("  nowe hasło: ")
            n = read_line(f"  notatka [{e.notes}]: ")
            if u:
                e.username = u
            if pw:
                e.password = pw
            if n:
                e.notes = n
            e.updated_at = int(__import__("time").time())
            dirty = True
            print("Zmieniono. Użyj 'sync'.")
        elif cmd in ("rm", "delete"):
            if vault.remove(arg):
                dirty = True
                print("Usunięto.")
            else:
                print(f"Nie znaleziono wpisu: {arg}")
        elif cmd == "sync":
            if not online:
                print("Tryb offline - synchronizacja niedostępna.")
                continue
            try:
                if do_sync(cli, vault):
                    dirty = False
                    save_cache(args.cache, login, cli.vault_id, cli.vault_version,
                               vault.encrypt(cli.k_vault))
            except Exception as e:
                print(f"Błąd synchronizacji: {e}")
        elif cmd == "pull":
            if not online:
                print("Tryb offline.")
                continue
            try:
                cli.ensure_session()
                ok, blob = cli.fetch_vault()
                if ok:
                    srv = Vault.decrypt(blob, cli.k_vault)
                    vault.merge_from(srv)
                    print(f"Pobrano i scalono (wersja {cli.vault_version}).")
                else:
                    print("Serwer nie ma sejfu.")
            except Exception as e:
                print(f"Błąd: {e}")
        elif cmd == "ping":
            if not online:
                print("Tryb offline.")
                continue
            try:
                cli.ensure_session()
                print("PONG")
            except Exception as e:
                print(f"Brak odpowiedzi: {e}")
        elif cmd in ("quit", "exit"):
            break
        else:
            print(f"Nieznana komenda: {cmd} (help)")

    if online and dirty:
        print("Masz niezapisane zmiany - synchronizuję...")
        try:
            do_sync(cli, vault)
        except Exception as e:
            print(f"Nie udało się zsynchronizować: {e}")
    if online:
        cli.bye()
    print("Do widzenia.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
