"""
API HTTP serwera synchronizacji + panel WEB administratora.

GET  /api/v1/health                 – stan serwera (bez autoryzacji)
GET  /api/v1/branding               – nazwa firmy i kolor (bez autoryzacji, ekran logowania aplikacji)
GET  /api/v1/branding/logo          – logo firmy (PNG)
POST /api/v1/enroll                 – dołączenie urządzenia kodem aktywacyjnym (+ 2FA użytkownika, jeśli wymagane)
POST /api/v1/account/totp/confirm   – potwierdzenie konfiguracji 2FA użytkownika
GET  /api/v1/policy                 – polityki bezpieczeństwa firmy
POST /api/v1/report                 – zbiorczy wynik audytu sejfu (tylko liczby)
GET  /api/v1/vault/meta             – metadane bieżącej wersji sejfu (+ polityki i marka)
GET  /api/v1/vault                  – zaszyfrowany plik bieżącej wersji
PUT  /api/v1/vault                  – zapis nowej wersji (nagłówek If-Match: <wersja bazowa>)
GET  /api/v1/vault/history          – lista zachowanych wersji
GET  /api/v1/vault/history/{wersja} – zaszyfrowany plik wybranej wersji
/admin                              – panel administratora (tylko sieci prywatne / VPN)
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from server import API_PREFIX, SERVER_VERSION
from server.accounts import new_totp_secret, totp_uri
from server.admin import admin_security_headers, create_admin_router
from server.config import ServerConfig
from server.context import ServerContext
from server.security import RateLimiter, client_ip, ip_allowed, parse_networks
from server.storage import InvalidVaultError, VersionConflictError

log = logging.getLogger("keystead")


class EnrollRequest(BaseModel):
    code: str = Field(min_length=4, max_length=64)
    device_name: str = Field(min_length=1, max_length=64)
    totp: str = Field(default="", max_length=10)


class TotpConfirm(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class SecurityReport(BaseModel):
    score: int = 0
    total: int = 0
    breached: int = 0
    reused: int = 0
    weak: int = 0
    missing_totp: int = 0
    stale: int = 0
    hibp_checked: bool = False


def create_app(config: Optional[ServerConfig] = None) -> FastAPI:
    config = config or ServerConfig.from_env()
    ctx = ServerContext.create(config)
    store, devices, users, enrollments, audit, settings = (
        ctx.store, ctx.devices, ctx.users, ctx.enrollments, ctx.audit, ctx.settings)
    api_networks = parse_networks(config.api_allowed_networks)
    auth_limiter = RateLimiter(max_failures=20, window_seconds=600, block_seconds=900)
    enroll_limiter = RateLimiter(max_failures=10, window_seconds=600, block_seconds=1800)

    # Migracja z wersji bez kont: właściciele istniejących urządzeń stają się użytkownikami
    for uid in devices.user_ids():
        users.ensure(uid, "Właściciel" if uid == "owner" else uid)

    app = FastAPI(
        title="KeyStead Server – serwer synchronizacji",
        version=SERVER_VERSION,
        docs_url=None, redoc_url=None, openapi_url=None,  # brak publicznej dokumentacji API
    )
    # Skróty używane przez testy i polecenia administracyjne
    app.state.ctx = ctx
    app.state.store, app.state.devices, app.state.users = store, devices, users
    app.state.admins, app.state.enrollments, app.state.audit = ctx.admins, enrollments, audit
    app.state.settings, app.state.config = settings, config

    if config.background_tasks:
        @app.on_event("startup")
        async def _start_tasks():
            ctx.tasks.start()

        @app.on_event("shutdown")
        async def _stop_tasks():
            ctx.tasks.stop()

    @app.middleware("http")
    async def network_and_headers(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and not ip_allowed(client_ip(request), api_networks):
            return JSONResponse({"detail": "Dostęp z tej sieci jest zablokowany przez administratora serwera."}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if path.startswith("/admin"):
            admin_security_headers(response)
        return response

    async def current_device(request: Request, authorization: str = Header(default="")) -> Dict[str, Any]:
        ip = client_ip(request)
        blocked, wait = auth_limiter.is_blocked(ip)
        if blocked:
            raise HTTPException(status_code=429, detail=f"Zbyt wiele nieudanych prób. Spróbuj za {wait // 60 + 1} min.")
        scheme, _, token = authorization.partition(" ")
        device = devices.authenticate(token.strip()) if scheme.lower() == "bearer" else None
        if device is None or not users.is_active(device["user_id"]):
            if auth_limiter.fail(ip):
                audit.add("api_ip_blocked", ip=ip, reason="nieudane uwierzytelnienia")
            await asyncio.sleep(0.5)  # spowolnienie prób zgadywania
            detail = ("Konto zostało zablokowane przez administratora." if device is not None
                      else "Nieprawidłowy lub odwołany token urządzenia.")
            raise HTTPException(status_code=401, detail=detail)
        auth_limiter.success(ip)
        return device

    def _meta_headers(meta: Dict[str, Any]) -> Dict[str, str]:
        return {"ETag": f'"{meta["version"]}"', "X-Vault-Version": str(meta["version"])}

    # ------------------------------------------------------------ publiczne
    @app.get(f"{API_PREFIX}/health")
    async def health():
        return {"status": "ok", "server_version": SERVER_VERSION, "server_id": store.server_id, "enrollment": True}

    @app.get(f"{API_PREFIX}/branding")
    async def branding():
        return settings.public_branding()

    @app.get(f"{API_PREFIX}/branding/logo")
    async def branding_logo():
        if not os.path.isfile(ctx.logo_path):
            raise HTTPException(status_code=404, detail="Brak logo.")
        return FileResponse(ctx.logo_path, media_type="image/png")

    # ------------------------------------------------------------ dołączanie urządzeń
    @app.post(f"{API_PREFIX}/enroll")
    async def enroll(body: EnrollRequest, request: Request):
        ip = client_ip(request)
        blocked, wait = enroll_limiter.is_blocked(ip)
        if blocked:
            raise HTTPException(status_code=429, detail=f"Zbyt wiele nieudanych prób. Spróbuj za {wait // 60 + 1} min.")

        async def _fail(detail: str, status: int = 403, **extra):
            if enroll_limiter.fail(ip):
                audit.add("enroll_ip_blocked", ip=ip)
            audit.add("enroll_failed", ip=ip, device=body.device_name.strip(), reason=detail[:80])
            await asyncio.sleep(1.0)
            return JSONResponse(status_code=status, content={"detail": detail, **extra})

        user_id = enrollments.peek(body.code)
        if not user_id or not users.is_active(user_id):
            return await _fail("Kod aktywacyjny jest nieprawidłowy, wygasł lub został już użyty.")

        policy = settings.section("policy")
        max_devices = int(policy.get("max_devices_per_user") or 0)
        if max_devices and devices.active_count(user_id) >= max_devices:
            return await _fail(f"Osiągnięto limit urządzeń dla tego konta ({max_devices}). "
                               "Administrator musi najpierw odciąć jedno z dotychczasowych urządzeń.")

        totp_setup = None
        if policy.get("require_user_2fa"):
            if users.has_totp(user_id):
                if not body.totp:
                    # Kod aktywacyjny NIE jest zużywany – aplikacja dopyta o kod 2FA i ponowi żądanie
                    return JSONResponse(status_code=401, content={
                        "detail": "Dodanie urządzenia wymaga kodu z Twojej aplikacji uwierzytelniającej (2FA).",
                        "totp_required": True})
                if not users.verify_totp(user_id, body.totp):
                    return await _fail("Nieprawidłowy kod 2FA.", status=401, totp_required=True)
            else:
                secret = new_totp_secret()
                users.set_pending_totp(user_id, secret)
                totp_setup = {"secret": secret, "uri": totp_uri(secret, user_id, ctx.server_name())}

        if not enrollments.consume(body.code, body.device_name.strip()):
            return await _fail("Kod aktywacyjny został właśnie użyty.")
        enroll_limiter.success(ip)
        token, record = devices.create(body.device_name.strip(), user_id)
        user = users.get(user_id)
        audit.add("device_enrolled", actor=user_id, ip=ip, device=record["name"], device_id=record["device_id"])
        return {
            "token": token,
            "device_id": record["device_id"],
            "device_name": record["name"],
            "username": user["username"],
            "display_name": user["display_name"],
            "server_id": store.server_id,
            "totp_setup": totp_setup,
            "branding": settings.public_branding(),
        }

    @app.post(f"{API_PREFIX}/account/totp/confirm")
    async def confirm_totp(body: TotpConfirm, request: Request, device=Depends(current_device)):
        if not users.confirm_totp(device["user_id"], body.code):
            raise HTTPException(status_code=400, detail="Nieprawidłowy kod – sprawdź godzinę w telefonie i spróbuj ponownie.")
        audit.add("user_2fa_enabled", actor=device["user_id"], ip=client_ip(request), device=device["name"])
        return {"ok": True}

    # ------------------------------------------------------------ polityki i raporty
    @app.get(f"{API_PREFIX}/policy")
    async def policy(device=Depends(current_device)):
        return settings.public_policy()

    @app.post(f"{API_PREFIX}/report")
    async def report(body: SecurityReport, request: Request, device=Depends(current_device)):
        if not settings.section("policy").get("security_report"):
            raise HTTPException(status_code=403, detail="Raporty bezpieczeństwa są wyłączone przez administratora.")
        saved = ctx.reports.save(device["user_id"], body.model_dump(), device["name"])
        return {"ok": True, "received_at": saved["received_at"]}

    # ------------------------------------------------------------ sejf
    @app.get(f"{API_PREFIX}/vault/meta")
    async def vault_meta(device=Depends(current_device)):
        meta = store.get_meta(device["user_id"])
        user = users.get(device["user_id"]) or {}
        return {"exists": bool(meta), "meta": meta, "device": device["name"], "server_id": store.server_id,
                "user": user.get("display_name", device["user_id"]),
                "policy": settings.public_policy(), "branding": settings.public_branding()}

    @app.get(f"{API_PREFIX}/vault")
    async def vault_download(device=Depends(current_device)):
        meta = store.get_meta(device["user_id"])
        blob = store.read_version(device["user_id"]) if meta else None
        if blob is None:
            raise HTTPException(status_code=404, detail="Na serwerze nie ma jeszcze sejfu.")
        return Response(blob, media_type="application/octet-stream", headers=_meta_headers(meta))

    @app.put(f"{API_PREFIX}/vault")
    async def vault_upload(request: Request, if_match: str = Header(default=""), device=Depends(current_device)):
        try:
            base_version = int(if_match.strip().strip('"'))
        except ValueError:
            raise HTTPException(status_code=428, detail="Wymagany nagłówek If-Match z numerem wersji bazowej.")

        length = request.headers.get("content-length")
        if length and int(length) > config.max_vault_bytes:
            raise HTTPException(status_code=413, detail="Plik sejfu jest zbyt duży.")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > config.max_vault_bytes:
                raise HTTPException(status_code=413, detail="Plik sejfu jest zbyt duży.")

        try:
            meta = store.write(device["user_id"], bytes(body), base_version, device["name"])
        except VersionConflictError as e:
            return JSONResponse(
                status_code=409,
                content={"detail": "Sejf został zmieniony na innym urządzeniu.", "meta": e.current},
            )
        except InvalidVaultError as e:
            raise HTTPException(status_code=422, detail=str(e))

        audit.add("vault_saved", actor=device["user_id"], ip=client_ip(request), device=device["name"], version=meta["version"])
        log.info("Zapisano wersję %s sejfu użytkownika %s (urządzenie: %s)", meta["version"], device["user_id"], device["name"])
        return JSONResponse(content={"meta": meta}, headers=_meta_headers(meta))

    @app.get(f"{API_PREFIX}/vault/history")
    async def vault_history(device=Depends(current_device)):
        return {"versions": store.history(device["user_id"])}

    @app.get(f"{API_PREFIX}/vault/history/{{version}}")
    async def vault_history_item(version: int, device=Depends(current_device)):
        blob = store.read_version(device["user_id"], version)
        if blob is None:
            raise HTTPException(status_code=404, detail="Ta wersja nie jest już przechowywana.")
        return Response(blob, media_type="application/octet-stream", headers={"X-Vault-Version": str(version)})

    app.include_router(create_admin_router(ctx))
    return app
