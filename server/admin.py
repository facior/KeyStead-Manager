"""
Panel WEB administratora serwera (/admin).

Zabezpieczenia:
- dostępny wyłącznie z sieci z listy KS_ADMIN_ALLOWED_NETWORKS (domyślnie sieci prywatne/VPN)
  i nigdy dla żądań przychodzących z internetu przez Tailscale Funnel / Cloudflare (odpowiedź 404),
- pierwsze konto administratora zakłada się jednorazowym tokenem wygenerowanym w terminalu serwera,
- logowanie: login + hasło (Argon2id) + obowiązkowy kod 2FA (TOTP), blokada po nieudanych próbach,
- sesja w ciasteczku HttpOnly + SameSite=Strict (+ Secure przy HTTPS), wygasa po 30 min bezczynności,
- każdy formularz chroniony tokenem CSRF, brak JavaScriptu, restrykcyjna polityka CSP.
"""

import hashlib
import hmac
import os
import secrets
import ssl
import time
from datetime import datetime
from typing import Any, Dict, Optional

import pyotp
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from server import SERVER_VERSION
from server.accounts import AdminStore, AuditLog, EnrollmentStore, UserStore, new_totp_secret, totp_uri
from server.config import ServerConfig
from server.devices import DeviceRegistry
from server.security import RateLimiter, client_ip, ip_allowed, is_public_edge_request, parse_networks
from server.storage import VaultStore

SESSION_COOKIE = "ks_admin"
SESSION_IDLE_SECONDS = 30 * 60
SESSION_MAX_SECONDS = 8 * 3600
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")

try:  # kod QR do konfiguracji 2FA (opcjonalnie – bez biblioteki pokazujemy klucz do ręcznego wpisania)
    import segno
except ImportError:  # pragma: no cover
    segno = None


def _fmt_time(value) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError):
        return str(value)


def _fmt_size(size) -> str:
    if not size:
        return "—"
    size = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def certificate_fingerprint(cert_path: str) -> str:
    """Odcisk SHA-256 certyfikatu TLS serwera – użytkownik porównuje go z odciskiem pokazanym w aplikacji."""
    try:
        with open(cert_path, "r", encoding="ascii") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
    except (OSError, ValueError):
        return ""
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def create_admin_router(config: ServerConfig, store: VaultStore, devices: DeviceRegistry,
                        users: UserStore, admins: AdminStore, enrollments: EnrollmentStore,
                        audit: AuditLog) -> APIRouter:
    router = APIRouter(prefix="/admin")
    templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
    templates.env.filters["dt"] = _fmt_time
    templates.env.filters["size"] = _fmt_size
    admin_networks = parse_networks(config.admin_allowed_networks)
    login_limiter = RateLimiter(max_failures=5, window_seconds=900, block_seconds=900)
    sessions: Dict[str, Dict[str, Any]] = {}
    pending_setup: Dict[str, Dict[str, Any]] = {}
    tls_fingerprint = certificate_fingerprint(config.tls_cert) if config.tls_cert else ""

    # ------------------------------------------------------------ pomocnicze
    def allowed(request: Request) -> bool:
        return ip_allowed(client_ip(request), admin_networks) and not is_public_edge_request(request)

    def not_found() -> Response:
        return Response("Not Found", status_code=404, media_type="text/plain")

    def get_session(request: Request) -> Optional[Dict[str, Any]]:
        sid = request.cookies.get(SESSION_COOKIE, "")
        sess = sessions.get(sid)
        now = time.time()
        if not sess or now - sess["last_seen"] > SESSION_IDLE_SECONDS or now - sess["created"] > SESSION_MAX_SECONDS:
            sessions.pop(sid, None)
            return None
        sess["last_seen"] = now
        return sess

    def render(request: Request, template: str, sess: Optional[Dict[str, Any]] = None, status: int = 200, **ctx) -> HTMLResponse:
        ctx.update({"request": request, "session": sess, "csrf": sess["csrf"] if sess else "",
                    "server_version": SERVER_VERSION, "public_url": config.public_url,
                    "tls_fingerprint": tls_fingerprint})
        if sess and sess.get("flash"):
            ctx["flash"] = sess.pop("flash")
        return templates.TemplateResponse(request, template, ctx, status_code=status)

    def redirect(url: str) -> RedirectResponse:
        return RedirectResponse(url, status_code=303)

    def csrf_ok(sess: Dict[str, Any], token: str) -> bool:
        return hmac.compare_digest(sess["csrf"], token or "")

    def set_session_cookie(request: Request, resp: Response, sid: str) -> None:
        resp.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", path="/admin", max_age=SESSION_MAX_SECONDS)

    def flash(sess: Dict[str, Any], kind: str, text: str, **extra) -> None:
        sess["flash"] = {"kind": kind, "text": text, **extra}

    def actor(sess: Dict[str, Any]) -> str:
        return f"admin:{sess['username']}"

    def guard(request: Request):
        """Zwraca (sesja, odpowiedź_błędu)."""
        if not allowed(request):
            return None, not_found()
        sess = get_session(request)
        if not sess:
            return None, redirect("/admin/setup" if not admins.has_admin() else "/admin/login")
        return sess, None

    def user_rows():
        rows = []
        for u in users.list():
            devs = devices.list_for_user(u["user_id"])
            active = [d for d in devs if not d.get("revoked")]
            meta = store.get_meta(u["user_id"])
            last_seen = max((d.get("last_seen") or "" for d in active), default="") or None
            rows.append({**u, "devices": len(active), "meta": meta, "last_seen": last_seen})
        return rows

    # ------------------------------------------------------------ pierwsza konfiguracja
    @router.get("/setup", response_class=HTMLResponse)
    async def setup_form(request: Request):
        if not allowed(request):
            return not_found()
        if admins.has_admin():
            return redirect("/admin/login")
        return render(request, "setup.html", step=1)

    @router.post("/setup", response_class=HTMLResponse)
    async def setup_submit(request: Request, setup_token: str = Form(""), username: str = Form(""),
                           password: str = Form(""), password2: str = Form("")):
        if not allowed(request):
            return not_found()
        if admins.has_admin():
            return redirect("/admin/login")
        ip = client_ip(request)
        blocked, wait = login_limiter.is_blocked(ip)
        if blocked:
            return render(request, "setup.html", step=1, error=f"Zbyt wiele prób. Spróbuj za {wait // 60 + 1} min.", status=429)
        if not admins.check_setup_token(setup_token):
            login_limiter.fail(ip)
            audit.add("admin_setup_failed", ip=ip)
            return render(request, "setup.html", step=1, username=username,
                          error="Nieprawidłowy token konfiguracyjny. Wygeneruj go na serwerze: sudo keystead-admin setup-token", status=403)
        if password != password2:
            return render(request, "setup.html", step=1, username=username, error="Hasła różnią się.")
        if len(password) < 12:
            return render(request, "setup.html", step=1, username=username, error="Hasło musi mieć co najmniej 12 znaków.")
        secret = new_totp_secret()
        pid = secrets.token_urlsafe(24)
        pending_setup[pid] = {"username": username.strip().lower(), "password": password, "secret": secret,
                              "token": setup_token, "created": time.time()}
        uri = totp_uri(secret, username.strip().lower())
        qr = segno.make(uri, error="m").svg_inline(scale=5, dark="#0f172a", light="#ffffff", border=2) if segno else ""
        return render(request, "setup.html", step=2, pid=pid, secret=secret, uri=uri, qr=qr)

    @router.post("/setup/confirm", response_class=HTMLResponse)
    async def setup_confirm(request: Request, pid: str = Form(""), code: str = Form("")):
        if not allowed(request):
            return not_found()
        pending = pending_setup.get(pid)
        if not pending or time.time() - pending["created"] > 900 or admins.has_admin():
            pending_setup.pop(pid, None)
            return redirect("/admin/setup")
        if not pyotp.TOTP(pending["secret"]).verify(code.strip().replace(" ", ""), valid_window=1):
            uri = totp_uri(pending["secret"], pending["username"])
            qr = segno.make(uri, error="m").svg_inline(scale=5, dark="#0f172a", light="#ffffff", border=2) if segno else ""
            return render(request, "setup.html", step=2, pid=pid, secret=pending["secret"], uri=uri, qr=qr,
                          error="Kod z aplikacji uwierzytelniającej jest nieprawidłowy. Sprawdź godzinę w telefonie.")
        if not admins.check_setup_token(pending["token"]):
            return redirect("/admin/setup")
        try:
            admins.create(pending["username"], pending["password"], pending["secret"])
        except ValueError as e:
            return render(request, "setup.html", step=1, error=str(e))
        pending_setup.pop(pid, None)
        audit.add("admin_created", actor=pending["username"], ip=client_ip(request))
        return render(request, "login.html", info="Konto administratora utworzone. Zaloguj się.")

    # ------------------------------------------------------------ logowanie
    @router.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request):
        if not allowed(request):
            return not_found()
        if not admins.has_admin():
            return redirect("/admin/setup")
        return render(request, "login.html")

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request, username: str = Form(""), password: str = Form(""), code: str = Form("")):
        if not allowed(request):
            return not_found()
        ip = client_ip(request)
        for key in (ip, f"user:{username.strip().lower()}"):
            blocked, wait = login_limiter.is_blocked(key)
            if blocked:
                audit.add("admin_login_blocked", actor=username, ip=ip)
                return render(request, "login.html", username=username,
                              error=f"Zbyt wiele nieudanych prób. Spróbuj ponownie za {wait // 60 + 1} min.", status=429)
        if not admins.verify(username, password, code):
            login_limiter.fail(ip)
            login_limiter.fail(f"user:{username.strip().lower()}")
            audit.add("admin_login_failed", actor=username, ip=ip)
            return render(request, "login.html", username=username, error="Nieprawidłowy login, hasło lub kod 2FA.", status=401)
        login_limiter.success(ip)
        login_limiter.success(f"user:{username.strip().lower()}")
        sid = secrets.token_urlsafe(32)
        now = time.time()
        sessions[sid] = {"username": username.strip().lower(), "csrf": secrets.token_urlsafe(24), "created": now, "last_seen": now}
        audit.add("admin_login", actor=username.strip().lower(), ip=ip)
        resp = redirect("/admin")
        set_session_cookie(request, resp, sid)
        return resp

    @router.post("/logout")
    async def logout(request: Request, csrf: str = Form("")):
        sess = get_session(request)
        if sess and csrf_ok(sess, csrf):
            sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        resp = redirect("/admin/login")
        resp.delete_cookie(SESSION_COOKIE, path="/admin")
        return resp

    # ------------------------------------------------------------ użytkownicy
    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        sess, err = guard(request)
        if err:
            return err
        rows = user_rows()
        stats = {
            "users": len(rows),
            "active_users": sum(1 for r in rows if not r["disabled"]),
            "devices": sum(r["devices"] for r in rows),
            "storage": sum((r["meta"] or {}).get("size", 0) for r in rows),
        }
        return render(request, "dashboard.html", sess, users=rows, stats=stats)

    @router.post("/users", response_class=HTMLResponse)
    async def create_user(request: Request, csrf: str = Form(""), username: str = Form(""), display_name: str = Form("")):
        sess, err = guard(request)
        if err:
            return err
        if not csrf_ok(sess, csrf):
            return Response("CSRF", status_code=403)
        try:
            user = users.create(username, display_name, created_by=sess["username"])
        except ValueError as e:
            flash(sess, "error", str(e))
            return redirect("/admin")
        code, rec = enrollments.create(user["user_id"], config.enrollment_ttl_hours, sess["username"])
        audit.add("user_created", actor=actor(sess), ip=client_ip(request), user=user["user_id"])
        audit.add("enrollment_code_created", actor=actor(sess), ip=client_ip(request), user=user["user_id"], hint=rec["hint"])
        flash(sess, "code", f"Utworzono konto „{user['display_name']}”.", code=code, expires=rec["expires_at"])
        return redirect(f"/admin/users/{user['user_id']}")

    @router.get("/users/{user_id}", response_class=HTMLResponse)
    async def user_detail(request: Request, user_id: str):
        sess, err = guard(request)
        if err:
            return err
        user = users.get(user_id)
        if not user:
            return redirect("/admin")
        return render(request, "user.html", sess, user=user,
                      devices=devices.list_for_user(user_id),
                      codes=enrollments.active_for(user_id),
                      meta=store.get_meta(user_id),
                      history=store.history(user_id)[:10])

    async def _user_action(request: Request, user_id: str, csrf: str):
        sess, err = guard(request)
        if err:
            return None, None, err
        if not csrf_ok(sess, csrf):
            return None, None, Response("CSRF", status_code=403)
        user = users.get(user_id)
        if not user:
            return None, None, redirect("/admin")
        return sess, user, None

    @router.post("/users/{user_id}/code")
    async def new_code(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = await _user_action(request, user_id, csrf)
        if err:
            return err
        code, rec = enrollments.create(user_id, config.enrollment_ttl_hours, sess["username"])
        audit.add("enrollment_code_created", actor=actor(sess), ip=client_ip(request), user=user_id, hint=rec["hint"])
        flash(sess, "code", "Nowy kod aktywacyjny dla urządzenia.", code=code, expires=rec["expires_at"])
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/codes/revoke")
    async def revoke_codes(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = await _user_action(request, user_id, csrf)
        if err:
            return err
        n = enrollments.revoke_for(user_id)
        audit.add("enrollment_codes_revoked", actor=actor(sess), ip=client_ip(request), user=user_id, count=n)
        flash(sess, "ok", f"Unieważniono kody aktywacyjne: {n}.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/disable")
    async def disable_user(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = await _user_action(request, user_id, csrf)
        if err:
            return err
        disabled = not user.get("disabled")
        users.set_disabled(user_id, disabled)
        audit.add("user_disabled" if disabled else "user_enabled", actor=actor(sess), ip=client_ip(request), user=user_id)
        flash(sess, "ok", "Konto zablokowane – wszystkie urządzenia utraciły dostęp." if disabled else "Konto odblokowane.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/delete")
    async def delete_user(request: Request, user_id: str, csrf: str = Form(""), confirm: str = Form("")):
        sess, user, err = await _user_action(request, user_id, csrf)
        if err:
            return err
        if confirm.strip().lower() != user["username"]:
            flash(sess, "error", "Aby usunąć konto, wpisz dokładnie jego login.")
            return redirect(f"/admin/users/{user_id}")
        enrollments.revoke_for(user_id)
        devices.delete_for_user(user_id)
        users.delete(user_id)
        audit.add("user_deleted", actor=actor(sess), ip=client_ip(request), user=user_id)
        flash(sess, "ok", f"Usunięto konto „{user['username']}” wraz z sejfem i historią wersji.")
        return redirect("/admin")

    @router.post("/devices/{device_id}/revoke")
    async def revoke_device(request: Request, device_id: str, csrf: str = Form("")):
        sess, err = guard(request)
        if err:
            return err
        if not csrf_ok(sess, csrf):
            return Response("CSRF", status_code=403)
        dev = devices.get(device_id)
        if dev and devices.revoke(device_id):
            audit.add("device_revoked", actor=actor(sess), ip=client_ip(request), user=dev["user_id"], device=dev["name"])
            flash(sess, "ok", f"Odcięto urządzenie „{dev['name']}”.")
        return redirect(f"/admin/users/{dev['user_id']}" if dev else "/admin")

    # ------------------------------------------------------------ dziennik i konto
    @router.get("/audit", response_class=HTMLResponse)
    async def audit_log(request: Request):
        sess, err = guard(request)
        if err:
            return err
        return render(request, "audit.html", sess, events=audit.recent(300))

    @router.get("/account", response_class=HTMLResponse)
    async def account(request: Request):
        sess, err = guard(request)
        if err:
            return err
        return render(request, "account.html", sess)

    @router.post("/account/password", response_class=HTMLResponse)
    async def change_password(request: Request, csrf: str = Form(""), current: str = Form(""),
                              code: str = Form(""), new: str = Form(""), new2: str = Form("")):
        sess, err = guard(request)
        if err:
            return err
        if not csrf_ok(sess, csrf):
            return Response("CSRF", status_code=403)
        if not admins.verify(sess["username"], current, code):
            audit.add("admin_password_change_failed", actor=actor(sess), ip=client_ip(request))
            flash(sess, "error", "Nieprawidłowe obecne hasło lub kod 2FA.")
        elif new != new2:
            flash(sess, "error", "Nowe hasła różnią się.")
        else:
            try:
                admins.change_password(sess["username"], new)
                audit.add("admin_password_changed", actor=actor(sess), ip=client_ip(request))
                flash(sess, "ok", "Hasło administratora zostało zmienione.")
            except ValueError as e:
                flash(sess, "error", str(e))
        return redirect("/admin/account")

    return router


def admin_security_headers(response: Response) -> None:
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
