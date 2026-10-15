"""
Konfiguracja serwera ze zmiennych środowiskowych (plik /etc/keystead/server.env przy instalacji systemd).
"""

import os
from dataclasses import dataclass, field
from typing import Tuple

# Sieci prywatne, VPN (w tym Tailscale 100.64.0.0/10 i fd7a:115c:a1e0::/48) oraz localhost
PRIVATE_NETWORKS = (
    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,"
    "100.64.0.0/10,fd7a:115c:a1e0::/48,fc00::/7"
)


def _split(value: str) -> Tuple[str, ...]:
    return tuple(v.strip() for v in value.split(",") if v.strip())


@dataclass(frozen=True)
class ServerConfig:
    data_dir: str
    host: str = "127.0.0.1"
    port: int = 8787
    max_history: int = 50
    max_vault_bytes: int = 50 * 1024 * 1024
    # Kto może korzystać z API sejfów ("any" = bez ograniczeń, np. za Tailscale Funnel / Cloudflare)
    api_allowed_networks: Tuple[str, ...] = ("any",)
    # Panel administratora – domyślnie wyłącznie z sieci prywatnych / VPN, nigdy z internetu
    admin_allowed_networks: Tuple[str, ...] = field(default_factory=lambda: _split(PRIVATE_NETWORKS))
    # Serwery pośredniczące, którym ufamy w kwestii nagłówka X-Forwarded-For (tailscale serve, cloudflared, nginx)
    trusted_proxies: Tuple[str, ...] = ("127.0.0.1", "::1")
    # Własny certyfikat TLS (tryb bezpośredni, np. na adresie VPN firmy)
    tls_cert: str = ""
    tls_key: str = ""
    # Adres, pod którym użytkownicy łączą się z serwerem (wyświetlany w panelu przy kodach aktywacyjnych)
    public_url: str = ""
    enrollment_ttl_hours: int = 24
    # Zadania w tle (kopie, kontrola dysku, aktualizacje) – włączone w usłudze, wyłączone w testach
    background_tasks: bool = False

    @classmethod
    def from_env(cls) -> "ServerConfig":
        env = os.environ.get
        return cls(
            data_dir=env("KS_DATA_DIR", "/var/lib/keystead"),
            host=env("KS_HOST", "127.0.0.1"),
            port=int(env("KS_PORT", "8787")),
            max_history=int(env("KS_MAX_HISTORY", "50")),
            max_vault_bytes=int(env("KS_MAX_VAULT_MB", "50")) * 1024 * 1024,
            api_allowed_networks=_split(env("KS_API_ALLOWED_NETWORKS", "any")),
            admin_allowed_networks=_split(env("KS_ADMIN_ALLOWED_NETWORKS", PRIVATE_NETWORKS)),
            trusted_proxies=_split(env("KS_TRUSTED_PROXIES", "127.0.0.1,::1")),
            tls_cert=env("KS_TLS_CERT", ""),
            tls_key=env("KS_TLS_KEY", ""),
            public_url=env("KS_PUBLIC_URL", ""),
            enrollment_ttl_hours=int(env("KS_ENROLLMENT_TTL_HOURS", "24")),
            background_tasks=env("KS_BACKGROUND_TASKS", "1") not in ("0", "false", "no"),
        )
