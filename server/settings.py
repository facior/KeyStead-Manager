"""
Ustawienia serwera zarządzane z panelu administratora (data_dir/settings.json).

Ustawienia sieciowe i TLS (adres nasłuchu, certyfikat, dozwolone sieci) pozostają w
/etc/keystead/server.env i zmienia je instalator – błędna zmiana z panelu mogłaby odciąć dostęp do samego panelu.
"""

import copy
from typing import Any, Dict

from server.accounts import JsonFile
import os

DEFAULTS: Dict[str, Any] = {
    "general": {
        "max_history": 50,             # liczba przechowywanych wersji sejfu na użytkownika
        "enrollment_ttl_hours": 24,    # ważność kodów aktywacyjnych
        "public_url": "",              # nadpisuje KS_PUBLIC_URL (adres pokazywany użytkownikom)
        "app_download_url": "",        # własny adres instalatora aplikacji; puste = najnowsze wydanie z GitHuba
    },
    # Polityki wymuszane w aplikacji KeyStead Manager każdego użytkownika
    "policy": {
        "max_auto_lock_minutes": 15,   # 0 = bez limitu
        "allow_never_lock": False,
        "max_clipboard_seconds": 60,   # 0 = bez limitu
        "min_master_score": 2,         # 0-4 (skala miernika siły hasła w aplikacji)
        "max_offline_hours": 72,       # 0 = bez limitu; po tym czasie lokalna kopia wymaga połączenia z serwerem
        "max_devices_per_user": 5,     # 0 = bez limitu
        "allow_personal_backups": True,  # kopie do prywatnych chmur / na USB z poziomu aplikacji
        "security_report": True,       # aplikacja przesyła zbiorczy wynik audytu (tylko liczby)
        "require_user_2fa": False,     # dodanie urządzenia wymaga kodu z aplikacji uwierzytelniającej
        "allow_quick_unlock": True,    # Windows Hello w aplikacji
        "quick_unlock_days": 14,       # co ile dni hasło główne zamiast Windows Hello
        "allow_autotype": True,        # wpisywanie loginu i hasła skrótem klawiszowym
        "allow_site_icons": True,      # ikony stron przy wpisach (pobierane przez aplikację bezpośrednio ze stron)
        "allow_attachments": True,     # zaszyfrowane pliki przy wpisach
        "max_attachment_mb": 10,
        "attachment_quota_mb": 200,
    },
    # Odzyskiwanie dostępu przez firmę: klucz publiczny dla aplikacji; prywatny ma administrator (plik .ksorgkey)
    # albo – opcjonalnie – serwer, zaszyfrowany hasłem działu IT („escrow”, reset hasła z panelu)
    "recovery": {
        "enabled": False,
        "public_key": "",
        "escrow": None,
    },
    "notifications": {
        "email": {
            "enabled": False, "smtp_host": "", "smtp_port": 587, "security": "starttls",
            "username": "", "password": "", "sender": "", "recipients": "",
        },
        "webhook": {"enabled": False, "kind": "generic", "url": ""},
        "events": [
            "admin_login_failed", "admin_login_blocked", "api_ip_blocked", "enroll_ip_blocked",
            "device_enrolled", "devices_revoked_all", "disk_low", "backup_failed", "update_available",
            "update_finished", "vault_password_reset_by_admin", "vault_reset_failed", "user_offboarded",
        ],
        "disk_low_percent": 10,
    },
    "backups": {
        "enabled": True,
        "hour": 3,                     # codzienna kopia o tej godzinie (czas serwera)
        "keep": 14,                    # liczba przechowywanych kopii
    },
    "branding": {
        "company_name": "",
        "accent_color": "#4f46e5",
        "has_logo": False,
    },
    "updates": {
        "check": True,
        "repository": "facior/KeyStead-Manager",   # wydania serwera
        "app_repository": "facior/KeyStead",       # wydania aplikacji (link /download)
    },
}

EVENT_LABELS = {
    "admin_login_failed": "Nieudane logowanie do panelu",
    "admin_login_blocked": "Zablokowanie logowania do panelu po serii prób",
    "api_ip_blocked": "Zablokowanie adresu IP po nieudanych próbach urządzeń",
    "enroll_ip_blocked": "Zablokowanie adresu IP po próbach zgadnięcia kodu aktywacyjnego",
    "device_enrolled": "Dodanie nowego urządzenia",
    "device_revoked": "Odcięcie urządzenia",
    "user_created": "Utworzenie użytkownika",
    "user_disabled": "Zablokowanie konta",
    "devices_revoked_all": "Odcięcie wszystkich urządzeń (tryb awaryjny)",
    "disk_low": "Mało miejsca na dysku",
    "backup_failed": "Nieudana kopia zapasowa serwera",
    "update_available": "Dostępna nowa wersja serwera",
    "update_finished": "Zakończenie aktualizacji serwera (sukces lub błąd)",
    "vault_password_reset_by_admin": "Reset hasła głównego użytkownika przez administratora",
    "vault_reset_failed": "Nieudany reset hasła (błędne hasło działu IT)",
    "user_offboarded": "Odejście pracownika (blokada konta i lista haseł do zmiany)",
}


def _merge(defaults: Dict[str, Any], loaded: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(defaults)
    for key, value in (loaded or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


class SettingsStore:
    def __init__(self, data_dir: str):
        self.file = JsonFile(os.path.join(data_dir, "settings.json"), {})

    def all(self) -> Dict[str, Any]:
        return _merge(DEFAULTS, self.file.load())

    def section(self, name: str) -> Dict[str, Any]:
        return self.all()[name]

    def update(self, name: str, values: Dict[str, Any]) -> Dict[str, Any]:
        with self.file.lock:
            data = self.file.load()
            current = _merge(DEFAULTS.get(name, {}), data.get(name, {}))
            current.update(values)
            data[name] = current
            self.file.save(data)
            return current

    def public_policy(self) -> Dict[str, Any]:
        """Polityki przekazywane aplikacji (bez danych wewnętrznych serwera)."""
        policy = dict(self.section("policy"))
        recovery = self.section("recovery")
        key = recovery.get("public_key", "") if recovery.get("enabled") else ""
        policy["recovery_public_key"] = key if org_key_id(key) else ""
        return policy

    def public_branding(self) -> Dict[str, Any]:
        b = self.section("branding")
        return {"company_name": b["company_name"], "accent_color": b["accent_color"], "has_logo": bool(b["has_logo"])}


ORG_PUBLIC_PREFIX = "ksrec1:"


def org_key_id(public_text: str) -> str:
    """Odcisk klucza odzyskiwania firmy (ten sam algorytm co w aplikacji – core/crypto.py) albo ''."""
    import base64
    import hashlib
    text = (public_text or "").strip()
    if not text.startswith(ORG_PUBLIC_PREFIX):
        return ""
    try:
        raw = base64.b64decode(text[len(ORG_PUBLIC_PREFIX):], validate=True)
    except ValueError:
        return ""
    if len(raw) != 32:
        return ""
    digest = hashlib.sha256(b"keystead-org-key" + raw).hexdigest()[:16].upper()
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))
