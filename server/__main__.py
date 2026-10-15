"""
Narzędzie administracyjne serwera (uruchamiane na serwerze jako `sudo keystead-admin ...`):

    serve                             – uruchom serwer
    setup-token                       – jednorazowy token do założenia konta administratora w panelu WEB
    reset-admin                       – usuń konta administratorów (utrata telefonu z 2FA)
    add-user <login> [--name "..."]   – utwórz użytkownika i wypisz kod aktywacyjny
    enroll-code <login>               – nowy kod aktywacyjny dla urządzenia użytkownika
    list-users                        – lista użytkowników
    add-device <nazwa> [--user login] – token urządzenia bez kodu aktywacyjnego (tryb awaryjny)
    list-devices                      – lista urządzeń
    revoke-device <device_id>         – odetnij urządzenie
    status [--user login]             – stan sejfu
"""

import argparse
import logging
import sys

from server import SERVER_VERSION
from server.accounts import AdminStore, AuditLog, EnrollmentStore, UserStore
from server.config import ServerConfig
from server.devices import DeviceRegistry
from server.storage import VaultStore


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="keystead-admin", description="KeyStead Server – serwer synchronizacji")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="uruchom serwer HTTP")
    sub.add_parser("setup-token", help="token do pierwszej konfiguracji panelu WEB")
    sub.add_parser("reset-admin", help="usuń konta administratorów panelu")
    au = sub.add_parser("add-user", help="utwórz użytkownika")
    au.add_argument("username")
    au.add_argument("--name", default="")
    ec = sub.add_parser("enroll-code", help="nowy kod aktywacyjny")
    ec.add_argument("username")
    sub.add_parser("list-users", help="lista użytkowników")
    add = sub.add_parser("add-device", help="utwórz token dla urządzenia (bez kodu aktywacyjnego)")
    add.add_argument("name", help='nazwa urządzenia, np. "PC praca"')
    add.add_argument("--user", default="owner", help="login użytkownika")
    sub.add_parser("list-devices", help="lista urządzeń")
    rev = sub.add_parser("revoke-device", help="odwołaj token urządzenia")
    rev.add_argument("device_id")
    st = sub.add_parser("status", help="stan sejfu")
    st.add_argument("--user", default="owner")
    args = parser.parse_args(argv)

    config = ServerConfig.from_env()

    if args.cmd == "serve":
        import uvicorn
        from server.app import create_app
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        ssl_kwargs = {}
        if config.tls_cert and config.tls_key:
            ssl_kwargs = {"ssl_certfile": config.tls_cert, "ssl_keyfile": config.tls_key}
        uvicorn.run(
            create_app(config), host=config.host, port=config.port, server_header=False,
            proxy_headers=True, forwarded_allow_ips=",".join(config.trusted_proxies), **ssl_kwargs
        )
        return 0

    users = UserStore(config.data_dir)
    devices = DeviceRegistry(config.data_dir)
    audit = AuditLog(config.data_dir)

    if args.cmd == "setup-token":
        admins = AdminStore(config.data_dir)
        if admins.has_admin():
            print("Konto administratora już istnieje. Aby je zresetować: keystead-admin reset-admin")
            return 1
        token = admins.new_setup_token()
        print("Token konfiguracyjny panelu administratora (jednorazowy):\n")
        print(f"    {token}\n")
        print("Otwórz panel: <adres serwera>/admin i wpisz token, aby utworzyć konto administratora.")
        return 0

    if args.cmd == "reset-admin":
        AdminStore(config.data_dir).reset_all()
        audit.add("admin_reset", actor="terminal")
        print("Usunięto konta administratorów. Wygeneruj token: keystead-admin setup-token")
        return 0

    if args.cmd == "add-user":
        try:
            user = users.create(args.username, args.name, created_by="terminal")
        except ValueError as e:
            print(f"Błąd: {e}")
            return 1
        code, rec = EnrollmentStore(config.data_dir).create(user["user_id"], config.enrollment_ttl_hours, "terminal")
        audit.add("user_created", actor="terminal", user=user["user_id"])
        print(f"Utworzono użytkownika '{user['username']}'.")
        print(f"\nKod aktywacyjny (jednorazowy, ważny do {rec['expires_at']}):\n\n    {code}\n")
        return 0

    if args.cmd == "enroll-code":
        if not users.get(args.username.lower()):
            print("Nie ma takiego użytkownika.")
            return 1
        code, rec = EnrollmentStore(config.data_dir).create(args.username.lower(), config.enrollment_ttl_hours, "terminal")
        audit.add("enrollment_code_created", actor="terminal", user=args.username.lower(), hint=rec["hint"])
        print(f"Kod aktywacyjny (jednorazowy, ważny do {rec['expires_at']}):\n\n    {code}\n")
        return 0

    if args.cmd == "list-users":
        for u in users.list():
            state = "ZABLOKOWANY" if u.get("disabled") else "aktywny"
            n = len([d for d in devices.list_for_user(u["user_id"]) if not d.get("revoked")])
            print(f"{u['username']:<24} {state:<11} urządzeń: {n:<3} {u['display_name']}")
        return 0

    if args.cmd == "add-device":
        users.ensure(args.user, "Właściciel" if args.user == "owner" else args.user)
        if not users.get(args.user):
            print("Nieprawidłowy login użytkownika.")
            return 1
        token, rec = devices.create(args.name, args.user)
        audit.add("device_created", actor="terminal", user=args.user, device=rec["name"])
        print(f"Utworzono urządzenie '{rec['name']}' (id: {rec['device_id']}) dla użytkownika '{args.user}'.")
        print("\nTOKEN (pokazywany tylko raz – wklej go w aplikacji, zakładka 'Serwer'):\n")
        print(f"    {token}\n")
        return 0

    if args.cmd == "list-devices":
        rows = devices.list()
        if not rows:
            print("Brak urządzeń.")
        for d in rows:
            state = "ODWOŁANY" if d.get("revoked") else "aktywny"
            print(f"{d['device_id']}  {d.get('user_id', '-'):<16} {d['name']:<24} {state:<9} ostatnio: {d.get('last_seen') or '-'}")
        return 0

    if args.cmd == "revoke-device":
        ok = devices.revoke(args.device_id)
        if ok:
            audit.add("device_revoked", actor="terminal", device_id=args.device_id)
        print("Token odwołany." if ok else "Nie znaleziono aktywnego urządzenia o tym id.")
        return 0 if ok else 1

    if args.cmd == "status":
        store = VaultStore(config.data_dir, config.max_history)
        meta = store.get_meta(args.user)
        print(f"Serwer {SERVER_VERSION}, id instancji: {store.server_id}, dane: {config.data_dir}")
        if not meta:
            print(f"Użytkownik '{args.user}' nie wysłał jeszcze sejfu.")
        else:
            print(f"Wersja {meta['version']}, {meta['size']} B, zmieniono {meta['updated_at']} przez {meta['updated_by']}")
            print(f"Przechowywane wersje: {len(store.history(args.user))}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
