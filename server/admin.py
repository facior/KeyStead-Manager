"""
Panel WEB administratora serwera (/admin).

Zabezpieczenia:
- dostępny wyłącznie z sieci z listy KS_ADMIN_ALLOWED_NETWORKS (domyślnie sieci prywatne/VPN)
  i nigdy dla żądań przychodzących z internetu przez Tailscale Funnel / Cloudflare (odpowiedź 404),
- pierwsze konto administratora zakłada się jednorazowym tokenem wygenerowanym w terminalu serwera,
  kolejne – jednorazowym zaproszeniem z przypisaną rolą,
- logowanie: login + hasło (Argon2id) + obowiązkowy kod 2FA (TOTP), blokada po nieudanych próbach,
- role: administrator (pełne uprawnienia) oraz pomoc techniczna (podgląd użytkowników i kody aktywacyjne),
- sesja w ciasteczku HttpOnly + SameSite=Strict (+ Secure przy HTTPS), wygasa po 30 min bezczynności,
- każdy formularz chroniony tokenem CSRF, brak JavaScriptu, restrykcyjna polityka CSP.
"""

import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import ssl
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pyotp
from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from server import SERVER_VERSION
from server.accounts import ROLES, new_totp_secret, totp_uri
from server.context import LOGO_MAX_BYTES, PNG_MAGIC, ServerContext
from server.ops import _version_tuple, data_size, disk_status
from server.security import RateLimiter, client_ip, ip_allowed, is_public_edge_request, parse_networks
from server.settings import EVENT_LABELS
from server.updater import STEPS, UpdateError

SESSION_COOKIE = "ks_admin"
SESSION_IDLE_SECONDS = 30 * 60
SESSION_MAX_SECONDS = 8 * 3600
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; "
       "frame-ancestors 'none'; base-uri 'none'")
STARTED_AT = time.time()

try:  # kod QR do konfiguracji 2FA (opcjonalnie – bez biblioteki pokazujemy klucz do ręcznego wpisania)
    import segno
except ImportError:  # pragma: no cover
    segno = None


def _fmt_time(value) -> str:
    if not value:
        return "—"
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%d.%m.%Y %H:%M")
        return datetime.fromisoformat(value).astimezone().strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError, OSError):
        return str(value)


def _fmt_size(size) -> str:
    if not size:
        return "—"
    size = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def certificate_fingerprint(cert_path: str) -> str:
    """Odcisk SHA-256 certyfikatu TLS serwera – użytkownik porównuje go z odciskiem pokazanym w aplikacji."""
    try:
        with open(cert_path, "r", encoding="ascii") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read())
    except (OSError, ValueError):
        return ""
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _qr(uri: str) -> str:
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#0f172a", light="#ffffff", border=2) if segno else ""


def _bar_chart(points: List[tuple]) -> str:
    """Prosty wykres słupkowy w SVG (bez JavaScriptu)."""
    width, height, pad = 640, 160, 24
    top = max([v for _, v in points] + [1])
    bw = (width - pad * 2) / max(len(points), 1)
    parts = [f'<svg viewBox="0 0 {width} {height + 24}" width="100%" role="img" aria-label="Synchronizacje dziennie">']
    for i, (day, value) in enumerate(points):
        h = (height - pad) * value / top
        x = pad + i * bw + 3
        y = height - h
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw - 6:.1f}" height="{h:.1f}" rx="3" fill="#4f46e5"><title>{day}: {value}</title></rect>')
        if value:
            parts.append(f'<text x="{x + (bw - 6) / 2:.1f}" y="{y - 4:.1f}" fill="#94a3b8" font-size="10" text-anchor="middle">{value}</text>')
        parts.append(f'<text x="{x + (bw - 6) / 2:.1f}" y="{height + 14}" fill="#94a3b8" font-size="10" text-anchor="middle">{day[8:10]}.{day[5:7]}</text>')
    parts.append("</svg>")
    return "".join(parts)


def create_admin_router(ctx: ServerContext) -> APIRouter:
    config, store, devices, users, admins = ctx.config, ctx.store, ctx.devices, ctx.users, ctx.admins
    enrollments, audit, settings = ctx.enrollments, ctx.audit, ctx.settings

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
        role = admins.role_of(sess["username"])
        if role is None:  # konto usunięte w trakcie sesji
            sessions.pop(sid, None)
            return None
        sess["role"] = role
        sess["last_seen"] = now
        return sess

    def render(request: Request, template: str, sess: Optional[Dict[str, Any]] = None, status: int = 200, **ctx_vars) -> HTMLResponse:
        branding = settings.section("branding")
        ops = ctx.ops_state.get()
        latest = ops.get("latest_release") or {}
        ctx_vars.update({
            "request": request, "session": sess, "csrf": sess["csrf"] if sess else "",
            "is_admin": bool(sess and sess.get("role") == "admin"), "roles": ROLES,
            "server_version": SERVER_VERSION, "public_url": ctx.public_url(), "tls_fingerprint": tls_fingerprint,
            "download_url": f"{ctx.public_url()}/download" if ctx.public_url() else "/download",
            "branding": branding,
            "update_available": latest if latest and _version_tuple(latest.get("version", "")) > _version_tuple(SERVER_VERSION) else None,
        })
        if sess and sess.get("flash"):
            ctx_vars["flash"] = sess.pop("flash")
        return templates.TemplateResponse(request, template, ctx_vars, status_code=status)

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

    def guard(request: Request, role: str = "admin", csrf: Optional[str] = None):
        """Zwraca (sesja, odpowiedź_błędu). role='any' dopuszcza też pomoc techniczną."""
        if not allowed(request):
            return None, not_found()
        sess = get_session(request)
        if not sess:
            return None, redirect("/admin/setup" if not admins.has_admin() else "/admin/login")
        if role == "admin" and sess["role"] != "admin":
            flash(sess, "error", "Ta operacja wymaga uprawnień administratora.")
            return None, redirect("/admin")
        if csrf is not None and not csrf_ok(sess, csrf):
            return None, Response("CSRF", status_code=403)
        return sess, None

    def user_rows():
        rows = []
        for u in users.list():
            devs = devices.list_for_user(u["user_id"])
            active = [d for d in devs if not d.get("revoked")]
            meta = store.get_meta(u["user_id"])
            last_seen = max((d.get("last_seen") or "" for d in active), default="") or None
            rows.append({**u, "devices": len(active), "meta": meta, "last_seen": last_seen,
                         "report": ctx.reports.get(u["user_id"]), "has_2fa": users.has_totp(u["user_id"])})
        return rows

    # ------------------------------------------------------------ logo w panelu
    @router.get("/logo")
    async def panel_logo(request: Request):
        if not allowed(request) or not os.path.isfile(ctx.logo_path):
            return not_found()
        return FileResponse(ctx.logo_path, media_type="image/png")

    # ------------------------------------------------------------ pierwsza konfiguracja i zaproszenia
    def _start_totp_step(request: Request, username: str, password: str, token: str, mode: str, role: str):
        secret = new_totp_secret()
        pid = secrets.token_urlsafe(24)
        pending_setup[pid] = {"username": username.strip().lower(), "password": password, "secret": secret,
                              "token": token, "mode": mode, "role": role, "created": time.time()}
        uri = totp_uri(secret, username.strip().lower(), ctx.server_name())
        return render(request, "setup.html", step=2, pid=pid, secret=secret, uri=uri, qr=_qr(uri), mode=mode)

    @router.get("/setup", response_class=HTMLResponse)
    async def setup_form(request: Request):
        if not allowed(request):
            return not_found()
        if admins.has_admin():
            return redirect("/admin/login")
        return render(request, "setup.html", step=1, mode="setup")

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
            return render(request, "setup.html", step=1, mode="setup", error=f"Zbyt wiele prób. Spróbuj za {wait // 60 + 1} min.", status=429)
        if not admins.check_setup_token(setup_token):
            login_limiter.fail(ip)
            audit.add("admin_setup_failed", ip=ip)
            return render(request, "setup.html", step=1, mode="setup", username=username,
                          error="Nieprawidłowy token konfiguracyjny. Wygeneruj go na serwerze: sudo keystead-admin setup-token", status=403)
        if password != password2:
            return render(request, "setup.html", step=1, mode="setup", username=username, error="Hasła różnią się.")
        if len(password) < 12:
            return render(request, "setup.html", step=1, mode="setup", username=username, error="Hasło musi mieć co najmniej 12 znaków.")
        return _start_totp_step(request, username, password, setup_token, "setup", "admin")

    @router.get("/invite/{token}", response_class=HTMLResponse)
    async def invite_form(request: Request, token: str):
        if not allowed(request):
            return not_found()
        role = admins.check_invite(token)
        if not role:
            return render(request, "login.html", error="Zaproszenie jest nieprawidłowe albo wygasło.", status=404)
        return render(request, "setup.html", step=1, mode="invite", invite_token=token, invite_role=ROLES[role])

    @router.post("/invite/{token}", response_class=HTMLResponse)
    async def invite_submit(request: Request, token: str, username: str = Form(""),
                            password: str = Form(""), password2: str = Form("")):
        if not allowed(request):
            return not_found()
        role = admins.check_invite(token)
        if not role:
            return render(request, "login.html", error="Zaproszenie jest nieprawidłowe albo wygasło.", status=404)
        if password != password2 or len(password) < 12:
            return render(request, "setup.html", step=1, mode="invite", invite_token=token, invite_role=ROLES[role],
                          username=username, error="Hasła muszą być identyczne i mieć co najmniej 12 znaków.")
        if admins.role_of(username.strip().lower()):
            return render(request, "setup.html", step=1, mode="invite", invite_token=token, invite_role=ROLES[role],
                          username=username, error="Taki login administratora już istnieje.")
        return _start_totp_step(request, username, password, token, "invite", role)

    @router.post("/setup/confirm", response_class=HTMLResponse)
    async def setup_confirm(request: Request, pid: str = Form(""), code: str = Form("")):
        if not allowed(request):
            return not_found()
        pending = pending_setup.get(pid)
        if not pending or time.time() - pending["created"] > 900:
            pending_setup.pop(pid, None)
            return redirect("/admin/login")
        mode = pending["mode"]
        if not pyotp.TOTP(pending["secret"]).verify(code.strip().replace(" ", ""), valid_window=1):
            uri = totp_uri(pending["secret"], pending["username"], ctx.server_name())
            return render(request, "setup.html", step=2, pid=pid, secret=pending["secret"], uri=uri, qr=_qr(uri), mode=mode,
                          error="Kod z aplikacji uwierzytelniającej jest nieprawidłowy. Sprawdź godzinę w telefonie.")
        if mode == "setup":
            if admins.has_admin() or not admins.check_setup_token(pending["token"]):
                return redirect("/admin/setup")
        elif admins.check_invite(pending["token"]) != pending["role"]:
            return render(request, "login.html", error="Zaproszenie wygasło – poproś o nowe.")
        try:
            admins.create(pending["username"], pending["password"], pending["secret"], role=pending["role"],
                          created_by="zaproszenie" if mode == "invite" else "konfiguracja")
        except ValueError as e:
            return render(request, "login.html", error=str(e))
        if mode == "invite":
            admins.consume_invite(pending["token"])
        pending_setup.pop(pid, None)
        audit.add("admin_created", actor=pending["username"], ip=client_ip(request), role=pending["role"])
        return render(request, "login.html", info="Konto utworzone. Zaloguj się.")

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
        uname = username.strip().lower()
        for key in (ip, f"user:{uname}"):
            blocked, wait = login_limiter.is_blocked(key)
            if blocked:
                audit.add("admin_login_blocked", actor=username, ip=ip)
                return render(request, "login.html", username=username,
                              error=f"Zbyt wiele nieudanych prób. Spróbuj ponownie za {wait // 60 + 1} min.", status=429)
        if not admins.verify(username, password, code):
            login_limiter.fail(ip)
            login_limiter.fail(f"user:{uname}")
            audit.add("admin_login_failed", actor=username, ip=ip)
            return render(request, "login.html", username=username, error="Nieprawidłowy login, hasło lub kod 2FA.", status=401)
        login_limiter.success(ip)
        login_limiter.success(f"user:{uname}")
        sid = secrets.token_urlsafe(32)
        now = time.time()
        sessions[sid] = {"username": uname, "role": admins.role_of(uname), "csrf": secrets.token_urlsafe(24),
                         "created": now, "last_seen": now}
        audit.add("admin_login", actor=uname, ip=ip)
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
        sess, err = guard(request, role="any")
        if err:
            return err
        rows = user_rows()
        scored = [r["report"]["score"] for r in rows if r.get("report")]
        stats = {
            "users": len(rows),
            "active_users": sum(1 for r in rows if not r["disabled"]),
            "devices": sum(r["devices"] for r in rows),
            "storage": sum((r["meta"] or {}).get("size", 0) for r in rows),
            "avg_score": round(sum(scored) / len(scored)) if scored else None,
        }
        last_backup = ctx.ops_state.get().get("last_backup")
        return render(request, "dashboard.html", sess, users=rows, stats=stats, last_backup=last_backup,
                      backups_enabled=settings.section("backups").get("enabled"))

    @router.post("/users", response_class=HTMLResponse)
    async def create_user(request: Request, csrf: str = Form(""), username: str = Form(""),
                          display_name: str = Form(""), email: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        try:
            user = users.create(username, display_name, created_by=sess["username"])
            if email.strip():
                users.update_profile(user["user_id"], user["display_name"], email)
        except ValueError as e:
            flash(sess, "error", str(e))
            return redirect("/admin")
        ttl = int(settings.section("general").get("enrollment_ttl_hours", 24))
        code, rec = enrollments.create(user["user_id"], ttl, sess["username"])
        audit.add("user_created", actor=actor(sess), ip=client_ip(request), user=user["user_id"])
        audit.add("enrollment_code_created", actor=actor(sess), ip=client_ip(request), user=user["user_id"], hint=rec["hint"])
        flash(sess, "code", f"Utworzono konto „{user['display_name']}”.", code=code, expires=rec["expires_at"])
        return redirect(f"/admin/users/{user['user_id']}")

    @router.get("/users/{user_id}", response_class=HTMLResponse)
    async def user_detail(request: Request, user_id: str):
        sess, err = guard(request, role="any")
        if err:
            return err
        user = users.get(user_id)
        if not user:
            return redirect("/admin")
        email_ready = bool(settings.section("notifications")["email"].get("smtp_host"))
        return render(request, "user.html", sess, user=user,
                      devices=devices.list_for_user(user_id),
                      codes=enrollments.active_for(user_id),
                      meta=store.get_meta(user_id),
                      history=store.history(user_id)[:15],
                      report=ctx.reports.get(user_id),
                      has_2fa=users.has_totp(user_id),
                      email_ready=email_ready,
                      policy=settings.section("policy"))

    def _user(sess_err, user_id):
        sess, err = sess_err
        if err:
            return None, None, err
        user = users.get(user_id)
        if not user:
            return None, None, redirect("/admin")
        return sess, user, None

    @router.post("/users/{user_id}/code")
    async def new_code(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = _user(guard(request, role="any", csrf=csrf), user_id)
        if err:
            return err
        ttl = int(settings.section("general").get("enrollment_ttl_hours", 24))
        code, rec = enrollments.create(user_id, ttl, sess["username"])
        audit.add("enrollment_code_created", actor=actor(sess), ip=client_ip(request), user=user_id, hint=rec["hint"])
        flash(sess, "code", "Nowy kod aktywacyjny dla urządzenia.", code=code, expires=rec["expires_at"])
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/code/email")
    async def email_code(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = _user(guard(request, role="any", csrf=csrf), user_id)
        if err:
            return err
        if not user.get("email"):
            flash(sess, "error", "Użytkownik nie ma adresu e-mail – uzupełnij go w danych konta.")
            return redirect(f"/admin/users/{user_id}")
        ttl = int(settings.section("general").get("enrollment_ttl_hours", 24))
        code, rec = enrollments.create(user_id, ttl, sess["username"])
        url = ctx.public_url() or "(adres poda administrator)"
        body = (f"Dzień dobry {user['display_name']},\n\n"
                f"administrator przygotował dla Ciebie dostęp do menedżera haseł KeyStead.\n\n"
                f"1. Pobierz, zainstaluj i uruchom aplikację KeyStead Manager: {ctx.download_link()}\n"
                f"2. Na ekranie logowania wybierz zakładkę „Serwer”.\n"
                f"3. Adres serwera: {url}\n"
                f"4. Kod aktywacyjny: {code}  (ważny do {_fmt_time(rec['expires_at'])}, jednorazowy)\n")
        if tls_fingerprint:
            body += f"\nJeśli aplikacja zapyta o certyfikat serwera, jego odcisk SHA-256 to:\n{tls_fingerprint}\n"
        body += "\nWiadomość wygenerowana automatycznie przez " + ctx.server_name() + "."
        ok, info = ctx.notifier.send_email_to(user["email"], f"Dostęp do menedżera haseł – {ctx.server_name()}", body)
        if ok:
            audit.add("enrollment_code_emailed", actor=actor(sess), ip=client_ip(request), user=user_id, hint=rec["hint"])
            flash(sess, "ok", f"Kod aktywacyjny wysłano na adres {user['email']}.")
        else:
            enrollments.revoke_for(user_id)
            flash(sess, "error", f"Nie udało się wysłać e-maila: {info}")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/codes/revoke")
    async def revoke_codes(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = _user(guard(request, role="any", csrf=csrf), user_id)
        if err:
            return err
        n = enrollments.revoke_for(user_id)
        audit.add("enrollment_codes_revoked", actor=actor(sess), ip=client_ip(request), user=user_id, count=n)
        flash(sess, "ok", f"Unieważniono kody aktywacyjne: {n}.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/profile")
    async def update_profile(request: Request, user_id: str, csrf: str = Form(""),
                             display_name: str = Form(""), email: str = Form("")):
        sess, user, err = _user(guard(request, csrf=csrf), user_id)
        if err:
            return err
        try:
            users.update_profile(user_id, display_name, email)
            audit.add("user_updated", actor=actor(sess), ip=client_ip(request), user=user_id)
            flash(sess, "ok", "Zapisano dane konta.")
        except ValueError as e:
            flash(sess, "error", str(e))
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/2fa/reset")
    async def reset_user_2fa(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = _user(guard(request, csrf=csrf), user_id)
        if err:
            return err
        users.reset_totp(user_id)
        audit.add("user_2fa_reset", actor=actor(sess), ip=client_ip(request), user=user_id)
        flash(sess, "ok", "Zresetowano 2FA użytkownika – skonfiguruje je ponownie przy dodaniu kolejnego urządzenia.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/restore/{version}")
    async def restore_version(request: Request, user_id: str, version: int, csrf: str = Form("")):
        sess, user, err = _user(guard(request, csrf=csrf), user_id)
        if err:
            return err
        blob = store.read_version(user_id, version)
        meta = store.get_meta(user_id)
        if blob is None or not meta:
            flash(sess, "error", "Ta wersja nie jest już przechowywana.")
            return redirect(f"/admin/users/{user_id}")
        new_meta = store.write(user_id, blob, meta["version"], f"administrator ({sess['username']}) – przywrócono v{version}")
        audit.add("vault_restored", actor=actor(sess), ip=client_ip(request), user=user_id, version=version, new_version=new_meta["version"])
        flash(sess, "ok", f"Przywrócono wersję v{version} jako nową wersję v{new_meta['version']}. "
                          "Urządzenia użytkownika pobiorą ją przy najbliższej synchronizacji.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/disable")
    async def disable_user(request: Request, user_id: str, csrf: str = Form("")):
        sess, user, err = _user(guard(request, csrf=csrf), user_id)
        if err:
            return err
        disabled = not user.get("disabled")
        users.set_disabled(user_id, disabled)
        audit.add("user_disabled" if disabled else "user_enabled", actor=actor(sess), ip=client_ip(request), user=user_id)
        flash(sess, "ok", "Konto zablokowane – wszystkie urządzenia utraciły dostęp." if disabled else "Konto odblokowane.")
        return redirect(f"/admin/users/{user_id}")

    @router.post("/users/{user_id}/delete")
    async def delete_user(request: Request, user_id: str, csrf: str = Form(""), confirm: str = Form("")):
        sess, user, err = _user(guard(request, csrf=csrf), user_id)
        if err:
            return err
        if confirm.strip().lower() != user["username"]:
            flash(sess, "error", "Aby usunąć konto, wpisz dokładnie jego login.")
            return redirect(f"/admin/users/{user_id}")
        enrollments.revoke_for(user_id)
        devices.delete_for_user(user_id)
        ctx.reports.delete(user_id)
        users.delete(user_id)
        audit.add("user_deleted", actor=actor(sess), ip=client_ip(request), user=user_id)
        flash(sess, "ok", f"Usunięto konto „{user['username']}” wraz z sejfem i historią wersji.")
        return redirect("/admin")

    @router.post("/devices/{device_id}/revoke")
    async def revoke_device(request: Request, device_id: str, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        dev = devices.get(device_id)
        if dev and devices.revoke(device_id):
            audit.add("device_revoked", actor=actor(sess), ip=client_ip(request), user=dev["user_id"], device=dev["name"])
            flash(sess, "ok", f"Odcięto urządzenie „{dev['name']}”.")
        return redirect(f"/admin/users/{dev['user_id']}" if dev else "/admin")

    @router.post("/panic")
    async def panic(request: Request, csrf: str = Form(""), confirm: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        if confirm.strip().upper() != "ODETNIJ":
            flash(sess, "error", "Aby odciąć wszystkie urządzenia, wpisz słowo ODETNIJ.")
            return redirect("/admin")
        n_dev = devices.revoke_all()
        n_codes = enrollments.revoke_all()
        audit.add("devices_revoked_all", actor=actor(sess), ip=client_ip(request), devices=n_dev, codes=n_codes)
        flash(sess, "ok", f"Tryb awaryjny: odcięto {n_dev} urządzeń i unieważniono {n_codes} kodów. "
                          "Aplikacje zostaną zablokowane w ciągu ~30 s. Użytkownicy potrzebują nowych kodów aktywacyjnych.")
        return redirect("/admin")

    # ------------------------------------------------------------ raport bezpieczeństwa
    @router.get("/reports", response_class=HTMLResponse)
    async def reports_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        rows = [r for r in user_rows()]
        rows.sort(key=lambda r: (r["report"] is None, (r["report"] or {}).get("score", 0)))
        with_reports = [r["report"] for r in rows if r["report"]]
        summary = {
            "count": len(with_reports),
            "avg": round(sum(r["score"] for r in with_reports) / len(with_reports)) if with_reports else None,
            "breached": sum(r["breached"] for r in with_reports),
            "reused": sum(r["reused"] for r in with_reports),
            "weak": sum(r["weak"] for r in with_reports),
        }
        return render(request, "reports.html", sess, rows=rows, summary=summary,
                      enabled=settings.section("policy").get("security_report"))

    # ------------------------------------------------------------ stan serwera
    @router.get("/status", response_class=HTMLResponse)
    async def status_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        all_devices = devices.list()
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        st = ctx.ops_state.get()
        return render(request, "status.html", sess,
                      uptime=int(time.time() - STARTED_AT),
                      disk=disk_status(config.data_dir), data_bytes=data_size(config.data_dir),
                      devices_total=sum(1 for d in all_devices if not d.get("revoked")),
                      devices_active=sum(1 for d in all_devices if not d.get("revoked") and (d.get("last_seen") or "") >= day_ago),
                      users_total=len(users.list()),
                      chart=_bar_chart(audit.daily_counts("vault_saved", 14)),
                      ops=st, background=config.background_tasks,
                      network={"host": config.host, "port": config.port, "api": ", ".join(config.api_allowed_networks),
                               "admin": ", ".join(config.admin_allowed_networks), "tls": bool(config.tls_cert)})

    @router.post("/status/check-updates")
    async def check_updates(request: Request, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        latest = ctx.tasks.check_updates(settings.section("updates").get("repository", ""))
        if not latest:
            flash(sess, "error", "Nie udało się pobrać informacji o wydaniach (brak wydań na GitHubie lub brak połączenia).")
        elif _version_tuple(latest["version"]) > _version_tuple(SERVER_VERSION):
            flash(sess, "ok", f"Dostępna nowa wersja {latest['version']} (zainstalowana: {SERVER_VERSION}).")
        else:
            flash(sess, "ok", f"Serwer jest aktualny ({SERVER_VERSION}).")
        return redirect("/admin/status")

    # ------------------------------------------------------------ aktualizacja serwera
    @router.get("/update", response_class=HTMLResponse)
    async def update_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        bridge = ctx.updates
        st = bridge.status()
        latest = ctx.ops_state.get().get("latest_release") or {}
        newer = latest if latest and _version_tuple(latest.get("version", "")) > _version_tuple(SERVER_VERSION) else None
        installed = bridge.installed_versions()
        current = bridge.current_version() or SERVER_VERSION
        return render(request, "update.html", sess, st=st, available=bridge.available(), newer=newer,
                      history=bridge.history(), installed=installed, current=current,
                      can_rollback=any(v != current for v in installed), steps=STEPS,
                      refresh=st.get("state") in ("requested", "running"))

    @router.post("/update/start")
    async def update_start(request: Request, csrf: str = Form(""), version: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        latest = ctx.ops_state.get().get("latest_release") or {}
        if not latest or version != latest.get("version") or _version_tuple(version) <= _version_tuple(SERVER_VERSION):
            flash(sess, "error", "Ta wersja nie jest dostępna do instalacji – sprawdź aktualizacje ponownie.")
            return redirect("/admin/update")
        try:
            ctx.updates.request("update", version, sess["username"])
        except UpdateError as e:
            flash(sess, "error", str(e))
            return redirect("/admin/update")
        audit.add("update_requested", actor=actor(sess), ip=client_ip(request), version=version, from_version=SERVER_VERSION)
        return redirect("/admin/update")

    @router.post("/update/rollback")
    async def update_rollback(request: Request, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        try:
            ctx.updates.request("rollback", "", sess["username"])
        except UpdateError as e:
            flash(sess, "error", str(e))
            return redirect("/admin/update")
        audit.add("rollback_requested", actor=actor(sess), ip=client_ip(request), from_version=SERVER_VERSION)
        return redirect("/admin/update")

    # ------------------------------------------------------------ kopie zapasowe serwera
    @router.get("/backups", response_class=HTMLResponse)
    async def backups_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        return render(request, "backups.html", sess, backups=ctx.backups.list(), cfg=settings.section("backups"),
                      last=ctx.ops_state.get().get("last_backup"), background=config.background_tasks)

    @router.post("/backups/create")
    async def backups_create(request: Request, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        info = ctx.tasks.run_backup()
        if info:
            flash(sess, "ok", f"Utworzono kopię {info['name']} ({_fmt_size(info['size'])}).")
        else:
            flash(sess, "error", f"Kopia nie powiodła się: {(ctx.ops_state.get().get('last_backup') or {}).get('error', '')}")
        return redirect("/admin/backups")

    @router.post("/backups/settings")
    async def backups_settings(request: Request, csrf: str = Form(""), enabled: str = Form(""),
                               hour: int = Form(3), keep: int = Form(14)):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        settings.update("backups", {"enabled": bool(enabled), "hour": max(0, min(hour, 23)), "keep": max(1, min(keep, 365))})
        audit.add("settings_changed", actor=actor(sess), ip=client_ip(request), section="backups")
        flash(sess, "ok", "Zapisano harmonogram kopii zapasowych.")
        return redirect("/admin/backups")

    @router.get("/backups/{name}/download")
    async def backups_download(request: Request, name: str):
        sess, err = guard(request)
        if err:
            return err
        path = ctx.backups.path_of(name)
        if not path:
            return not_found()
        audit.add("backup_downloaded", actor=actor(sess), ip=client_ip(request), name=name)
        return FileResponse(path, media_type="application/gzip", filename=name)

    @router.post("/backups/{name}/delete")
    async def backups_delete(request: Request, name: str, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        if ctx.backups.delete(name):
            audit.add("backup_deleted", actor=actor(sess), ip=client_ip(request), name=name)
            flash(sess, "ok", f"Usunięto kopię {name}.")
        return redirect("/admin/backups")

    # ------------------------------------------------------------ dziennik
    def _audit_filters(request: Request) -> Dict[str, str]:
        q = request.query_params
        return {"event": q.get("event", ""), "text": q.get("q", ""), "since": q.get("since", ""), "until": q.get("until", "")}

    @router.get("/audit", response_class=HTMLResponse)
    async def audit_log(request: Request):
        sess, err = guard(request)
        if err:
            return err
        f = _audit_filters(request)
        events = audit.search(limit=500, event=f["event"], text=f["text"], since=f["since"] or None, until=f["until"] or None)
        return render(request, "audit.html", sess, events=events, filters=f, event_types=audit.event_types(), labels=EVENT_LABELS)

    @router.get("/audit.csv")
    async def audit_csv(request: Request):
        sess, err = guard(request)
        if err:
            return err
        f = _audit_filters(request)
        events = audit.search(limit=0, event=f["event"], text=f["text"], since=f["since"] or None, until=f["until"] or None)
        out = io.StringIO()
        writer = csv.writer(out, delimiter=";")
        writer.writerow(["czas", "zdarzenie", "kto", "adres_ip", "szczegóły"])
        for e in events:
            details = ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("time", "event", "actor", "ip"))
            writer.writerow([e.get("time", ""), e.get("event", ""), e.get("actor", ""), e.get("ip", ""), details])
        audit.add("audit_exported", actor=actor(sess), ip=client_ip(request), rows=len(events))
        return Response("﻿" + out.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="keystead-dziennik-{datetime.now():%Y%m%d}.csv"'})

    # ------------------------------------------------------------ ustawienia
    @router.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        return render(request, "settings.html", sess, cfg=settings.all(), event_labels=EVENT_LABELS,
                      network={"host": config.host, "port": config.port, "api": ", ".join(config.api_allowed_networks),
                               "admin": ", ".join(config.admin_allowed_networks), "tls": bool(config.tls_cert)})

    def _int(value: str, default: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(int(value), hi))
        except (TypeError, ValueError):
            return default

    def _http_url(value) -> str:
        value = str(value or "").strip()
        return value if re.match(r"^https?://[^\s<>\"']+$", value) else ""

    @router.post("/settings/general")
    async def settings_general(request: Request):
        form = await request.form()
        sess, err = guard(request, csrf=form.get("csrf", ""))
        if err:
            return err
        settings.update("general", {
            "max_history": _int(form.get("max_history"), 50, 1, 1000),
            "enrollment_ttl_hours": _int(form.get("enrollment_ttl_hours"), 24, 1, 720),
            "public_url": str(form.get("public_url", "")).strip().rstrip("/"),
            "app_download_url": _http_url(form.get("app_download_url", "")),
        })
        ctx.apply_runtime_settings()
        audit.add("settings_changed", actor=actor(sess), ip=client_ip(request), section="general")
        flash(sess, "ok", "Zapisano ustawienia ogólne.")
        return redirect("/admin/settings#ogolne")

    @router.post("/settings/policy")
    async def settings_policy(request: Request):
        form = await request.form()
        sess, err = guard(request, csrf=form.get("csrf", ""))
        if err:
            return err
        settings.update("policy", {
            "max_auto_lock_minutes": _int(form.get("max_auto_lock_minutes"), 15, 0, 1440),
            "allow_never_lock": bool(form.get("allow_never_lock")),
            "max_clipboard_seconds": _int(form.get("max_clipboard_seconds"), 60, 0, 3600),
            "min_master_score": _int(form.get("min_master_score"), 2, 0, 4),
            "max_offline_hours": _int(form.get("max_offline_hours"), 72, 0, 8760),
            "max_devices_per_user": _int(form.get("max_devices_per_user"), 5, 0, 100),
            "allow_personal_backups": bool(form.get("allow_personal_backups")),
            "security_report": bool(form.get("security_report")),
            "require_user_2fa": bool(form.get("require_user_2fa")),
        })
        audit.add("settings_changed", actor=actor(sess), ip=client_ip(request), section="policy")
        flash(sess, "ok", "Zapisano polityki bezpieczeństwa – aplikacje zastosują je przy najbliższej synchronizacji.")
        return redirect("/admin/settings#polityki")

    @router.post("/settings/notifications")
    async def settings_notifications(request: Request):
        form = await request.form()
        sess, err = guard(request, csrf=form.get("csrf", ""))
        if err:
            return err
        current = settings.section("notifications")
        email = dict(current["email"])
        email.update({
            "enabled": bool(form.get("email_enabled")),
            "smtp_host": str(form.get("smtp_host", "")).strip(),
            "smtp_port": _int(form.get("smtp_port"), 587, 1, 65535),
            "security": form.get("smtp_security") if form.get("smtp_security") in ("starttls", "ssl", "none") else "starttls",
            "username": str(form.get("smtp_username", "")).strip(),
            "sender": str(form.get("smtp_sender", "")).strip(),
            "recipients": str(form.get("smtp_recipients", "")).strip(),
        })
        if form.get("smtp_password"):  # puste pole = bez zmiany zapisanego hasła
            email["password"] = str(form.get("smtp_password"))
        kind = form.get("webhook_kind") if form.get("webhook_kind") in ("generic", "teams", "slack", "discord", "ntfy") else "generic"
        settings.update("notifications", {
            "email": email,
            "webhook": {"enabled": bool(form.get("webhook_enabled")), "kind": kind,
                        "url": str(form.get("webhook_url", "")).strip()},
            "events": [e for e in form.getlist("events") if e in EVENT_LABELS],
            "disk_low_percent": _int(form.get("disk_low_percent"), 10, 1, 90),
        })
        audit.add("settings_changed", actor=actor(sess), ip=client_ip(request), section="notifications")
        flash(sess, "ok", "Zapisano ustawienia powiadomień.")
        return redirect("/admin/settings#powiadomienia")

    @router.post("/settings/notifications/test")
    async def settings_notifications_test(request: Request, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        results = ctx.notifier.send(f"{ctx.server_name()}: wiadomość testowa z panelu administratora ({sess['username']}).",
                                    {"event": "test"})
        if not results:
            flash(sess, "error", "Żaden kanał powiadomień nie jest włączony.")
        else:
            text = "; ".join(f"{ch}: {'OK' if ok else 'BŁĄD – ' + info}" for ch, ok, info in results)
            flash(sess, "ok" if all(ok for _, ok, _ in results) else "error", f"Test powiadomień – {text}")
        return redirect("/admin/settings#powiadomienia")

    @router.post("/settings/branding")
    async def settings_branding(request: Request, csrf: str = Form(""), company_name: str = Form(""),
                                accent_color: str = Form("#4f46e5"), logo: Optional[UploadFile] = File(None)):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        color = accent_color if len(accent_color) == 7 and accent_color.startswith("#") and all(
            c in "0123456789abcdefABCDEF" for c in accent_color[1:]) else "#4f46e5"
        values = {"company_name": company_name.strip()[:60], "accent_color": color}
        if logo is not None and logo.filename:
            data = await logo.read(LOGO_MAX_BYTES + 1)
            if len(data) > LOGO_MAX_BYTES or not data.startswith(PNG_MAGIC):
                flash(sess, "error", "Logo musi być plikiem PNG o rozmiarze do 256 KB.")
                return redirect("/admin/settings#marka")
            os.makedirs(os.path.dirname(ctx.logo_path), mode=0o700, exist_ok=True)
            with open(ctx.logo_path, "wb") as f:
                f.write(data)
            values["has_logo"] = True
        settings.update("branding", values)
        audit.add("settings_changed", actor=actor(sess), ip=client_ip(request), section="branding")
        flash(sess, "ok", "Zapisano wygląd – aplikacje pokażą go przy najbliższej synchronizacji.")
        return redirect("/admin/settings#marka")

    @router.post("/settings/branding/logo/delete")
    async def delete_logo(request: Request, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        try:
            os.remove(ctx.logo_path)
        except OSError:
            pass
        settings.update("branding", {"has_logo": False})
        flash(sess, "ok", "Usunięto logo.")
        return redirect("/admin/settings#marka")

    @router.post("/settings/updates")
    async def settings_updates(request: Request, csrf: str = Form(""), check: str = Form(""), repository: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        repo = repository.strip().strip("/")
        if repo and (repo.count("/") != 1 or not all(p.replace("-", "").replace("_", "").replace(".", "").isalnum() for p in repo.split("/"))):
            flash(sess, "error", "Repozytorium podaj w formacie właściciel/nazwa, np. facior/KeyStead-Manager.")
            return redirect("/admin/settings#aktualizacje")
        settings.update("updates", {"check": bool(check), "repository": repo})
        flash(sess, "ok", "Zapisano ustawienia aktualizacji.")
        return redirect("/admin/settings#aktualizacje")

    # ------------------------------------------------------------ administratorzy
    @router.get("/admins", response_class=HTMLResponse)
    async def admins_page(request: Request):
        sess, err = guard(request)
        if err:
            return err
        return render(request, "admins.html", sess, admins_list=admins.list())

    @router.post("/admins/invite")
    async def admins_invite(request: Request, csrf: str = Form(""), role: str = Form("helpdesk")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        try:
            token = admins.create_invite(role, sess["username"])
        except ValueError as e:
            flash(sess, "error", str(e))
            return redirect("/admin/admins")
        base = ctx.public_url() or f"{request.url.scheme}://{request.url.netloc}"
        audit.add("admin_invited", actor=actor(sess), ip=client_ip(request), role=role)
        flash(sess, "invite", f"Zaproszenie dla roli „{ROLES[role]}” (ważne 48 h, jednorazowe):",
              link=f"{base}/admin/invite/{token}")
        return redirect("/admin/admins")

    @router.post("/admins/{username}/delete")
    async def admins_delete(request: Request, username: str, csrf: str = Form("")):
        sess, err = guard(request, csrf=csrf)
        if err:
            return err
        if username == sess["username"]:
            flash(sess, "error", "Nie możesz usunąć własnego konta.")
            return redirect("/admin/admins")
        try:
            admins.delete(username)
            for sid, s in list(sessions.items()):
                if s["username"] == username:
                    sessions.pop(sid, None)
            audit.add("admin_deleted", actor=actor(sess), ip=client_ip(request), admin=username)
            flash(sess, "ok", f"Usunięto konto „{username}”.")
        except ValueError as e:
            flash(sess, "error", str(e))
        return redirect("/admin/admins")

    # ------------------------------------------------------------ moje konto
    @router.get("/account", response_class=HTMLResponse)
    async def account(request: Request):
        sess, err = guard(request, role="any")
        if err:
            return err
        return render(request, "account.html", sess)

    @router.post("/account/password", response_class=HTMLResponse)
    async def change_password(request: Request, csrf: str = Form(""), current: str = Form(""),
                              code: str = Form(""), new: str = Form(""), new2: str = Form("")):
        sess, err = guard(request, role="any", csrf=csrf)
        if err:
            return err
        if not admins.verify(sess["username"], current, code):
            audit.add("admin_password_change_failed", actor=actor(sess), ip=client_ip(request))
            flash(sess, "error", "Nieprawidłowe obecne hasło lub kod 2FA.")
        elif new != new2:
            flash(sess, "error", "Nowe hasła różnią się.")
        else:
            try:
                admins.change_password(sess["username"], new)
                audit.add("admin_password_changed", actor=actor(sess), ip=client_ip(request))
                flash(sess, "ok", "Hasło zostało zmienione.")
            except ValueError as e:
                flash(sess, "error", str(e))
        return redirect("/admin/account")

    return router


def admin_security_headers(response: Response) -> None:
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
