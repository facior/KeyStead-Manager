"""
Zabezpieczenia sieciowe serwera: listy dozwolonych sieci, ustalanie adresu klienta
za serwerem pośredniczącym oraz ograniczanie liczby nieudanych prób (brute force).
"""

import ipaddress
import threading
import time
from typing import Dict, Iterable, List, Optional, Tuple

from starlette.requests import Request

# Nagłówki dodawane przez usługi publikujące serwer w internecie
PUBLIC_EDGE_HEADERS = ("tailscale-funnel-request", "cf-connecting-ip", "cf-ray")


def parse_networks(values: Iterable[str]) -> Optional[List[ipaddress._BaseNetwork]]:
    """Zwraca listę sieci albo None, gdy dozwolone są wszystkie adresy ("any")."""
    nets = []
    for value in values:
        if value.lower() in ("any", "*", "0.0.0.0/0"):
            return None
        nets.append(ipaddress.ip_network(value, strict=False))
    return nets


def ip_allowed(ip: str, networks: Optional[List[ipaddress._BaseNetwork]]) -> bool:
    if networks is None:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in networks if net.version == addr.version)


def client_ip(request: Request) -> str:
    """Adres klienta (uvicorn rozwiązuje X-Forwarded-For tylko od zaufanych serwerów pośredniczących)."""
    return request.client.host if request.client else ""


def limiter_key(ip: str) -> str:
    """
    Klucz ograniczania prób: dla IPv6 cała sieć /64 (jedno łącze dostaje zwykle /64 lub więcej –
    zmiana adresu w jej obrębie nie może omijać blokady), dla IPv4 pojedynczy adres.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def is_public_edge_request(request: Request) -> bool:
    """Czy żądanie przyszło z internetu przez Tailscale Funnel / Cloudflare Tunnel."""
    return any(h in request.headers for h in PUBLIC_EDGE_HEADERS)


class RateLimiter:
    """
    Blokuje adres IP po zbyt wielu nieudanych próbach w oknie czasowym.
    Domyślnie: 10 nieudanych prób w 10 minut → blokada na 15 minut.
    """

    def __init__(self, max_failures: int = 10, window_seconds: int = 600, block_seconds: int = 900):
        self.max_failures = max_failures
        self.window = window_seconds
        self.block = block_seconds
        self._failures: Dict[str, List[float]] = {}
        self._blocked_until: Dict[str, float] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> Tuple[bool, int]:
        with self._lock:
            until = self._blocked_until.get(key, 0)
            remaining = int(until - time.time())
            if remaining > 0:
                return True, remaining
            self._blocked_until.pop(key, None)
            return False, 0

    def fail(self, key: str) -> bool:
        """Rejestruje nieudaną próbę. Zwraca True, jeśli adres właśnie został zablokowany."""
        now = time.time()
        with self._lock:
            attempts = [t for t in self._failures.get(key, []) if now - t < self.window]
            attempts.append(now)
            self._failures[key] = attempts
            if len(attempts) >= self.max_failures:
                self._blocked_until[key] = now + self.block
                self._failures.pop(key, None)
                return True
            return False

    def success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


class BodyLimitMiddleware:
    """
    Limit rozmiaru treści żądań (ASGI) – zanim ktokolwiek ją odczyta i przetworzy.
    Bez tego anonimowe żądanie z kilkuset MB danych do /api/v1/enroll lub formularza panelu
    było w całości wczytywane do pamięci jedynego procesu serwera.
    """

    def __init__(self, app, limit_for):
        self.app = app
        self.limit_for = limit_for  # (metoda, ścieżka) -> maksymalna liczba bajtów

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        limit = self.limit_for(scope["method"], scope["path"])
        length = dict(scope.get("headers") or []).get(b"content-length", b"")
        if length.isdigit() and int(length) > limit:
            return await self._too_large(send)

        received = 0
        exceeded = False
        replaced = False

        async def limited_receive():
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Dalszej treści nie czytamy; aplikacja dostaje „rozłączenie”, a odpowiedź podmieniamy na 413
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            nonlocal replaced
            if exceeded:
                if not replaced:
                    replaced = True
                    await self._too_large(send)
                return
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
            if not replaced:
                await self._too_large(send)

    @staticmethod
    async def _too_large(send):
        body = b'{"detail":"\\u017b\\u0105danie jest zbyt du\\u017ce."}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
