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
