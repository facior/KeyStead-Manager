"""
Konta na serwerze: użytkownicy (właściciele sejfów), administrator panelu WEB,
jednorazowe kody aktywacyjne urządzeń oraz dziennik zdarzeń.

Administrator zarządza kontami i urządzeniami, ale NIE ma dostępu do haseł użytkowników –
sejfy są szyfrowane po stronie aplikacji kluczem pochodzącym z hasła głównego użytkownika.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,31}$")
_ENROLL_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # bez mylących znaków 0/O, 1/I/L
_hasher = PasswordHasher()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


class JsonFile:
    """Plik JSON z blokadą i atomowym zapisem (uprawnienia tylko dla właściciela)."""

    def __init__(self, path: str, default: Any):
        self.path = path
        self.default = default
        self.lock = threading.RLock()

    def load(self) -> Any:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return json.loads(json.dumps(self.default))

    def save(self, data: Any) -> None:
        tmp = f"{self.path}.tmp-{uuid.uuid4().hex}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass


# --------------------------------------------------------------------- dziennik zdarzeń
class AuditLog:
    def __init__(self, data_dir: str, max_bytes: int = 5 * 1024 * 1024):
        self.path = os.path.join(data_dir, "audit.log")
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def add(self, event: str, actor: str = "", ip: str = "", **details: Any) -> None:
        record = {"time": _iso(_now()), "event": event, "actor": actor, "ip": ip, **details}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)

    def recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
        except FileNotFoundError:
            return []
        out = []
        for line in reversed(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out


# --------------------------------------------------------------------- użytkownicy
class UserStore:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.file = JsonFile(os.path.join(data_dir, "users.json"), {"users": []})

    def list(self) -> List[Dict[str, Any]]:
        return sorted(self.file.load()["users"], key=lambda u: u["username"])

    def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        return next((u for u in self.file.load()["users"] if u["user_id"] == user_id), None)

    def create(self, username: str, display_name: str = "", created_by: str = "") -> Dict[str, Any]:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise ValueError("Login: 2-32 znaki, małe litery, cyfry oraz . _ - (bez spacji i polskich znaków).")
        with self.file.lock:
            data = self.file.load()
            if any(u["username"] == username for u in data["users"]):
                raise ValueError(f"Użytkownik „{username}” już istnieje.")
            user = {
                "user_id": username,  # identyfikator katalogu danych = login (zweryfikowany wyżej)
                "username": username,
                "display_name": display_name.strip() or username,
                "created_at": _iso(_now()),
                "created_by": created_by,
                "disabled": False,
            }
            data["users"].append(user)
            self.file.save(data)
            return user

    def ensure(self, user_id: str, display_name: str = "") -> None:
        """Rejestruje istniejącego właściciela danych (migracja z wersji bez kont)."""
        if not self.get(user_id) and USERNAME_RE.match(user_id):
            try:
                self.create(user_id, display_name or user_id, created_by="migracja")
            except ValueError:
                pass

    def set_disabled(self, user_id: str, disabled: bool) -> bool:
        with self.file.lock:
            data = self.file.load()
            for u in data["users"]:
                if u["user_id"] == user_id:
                    u["disabled"] = disabled
                    self.file.save(data)
                    return True
        return False

    def delete(self, user_id: str) -> bool:
        """Usuwa konto wraz z zaszyfrowanym sejfem i historią wersji."""
        with self.file.lock:
            data = self.file.load()
            before = len(data["users"])
            data["users"] = [u for u in data["users"] if u["user_id"] != user_id]
            if len(data["users"]) == before:
                return False
            self.file.save(data)
        user_dir = os.path.join(self.data_dir, "users", user_id)
        if os.path.isdir(user_dir):
            shutil.rmtree(user_dir, ignore_errors=True)
        return True

    def is_active(self, user_id: str) -> bool:
        user = self.get(user_id)
        return bool(user) and not user.get("disabled")


# --------------------------------------------------------------------- administrator
class AdminStore:
    """Jedno lub więcej kont administratora: hasło (Argon2id) + obowiązkowy kod 2FA (TOTP)."""

    def __init__(self, data_dir: str):
        self.file = JsonFile(os.path.join(data_dir, "admins.json"), {"admins": [], "setup_token_sha256": ""})

    def has_admin(self) -> bool:
        return bool(self.file.load()["admins"])

    # --- pierwsza konfiguracja (token z terminala serwera chroni przed przejęciem panelu)
    def new_setup_token(self) -> str:
        token = secrets.token_urlsafe(18)
        with self.file.lock:
            data = self.file.load()
            data["setup_token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
            self.file.save(data)
        return token

    def check_setup_token(self, token: str) -> bool:
        stored = self.file.load().get("setup_token_sha256", "")
        return bool(stored) and hmac.compare_digest(stored, hashlib.sha256(token.strip().encode()).hexdigest())

    def create(self, username: str, password: str, totp_secret: str) -> None:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise ValueError("Nieprawidłowy login administratora.")
        if len(password) < 12:
            raise ValueError("Hasło administratora musi mieć co najmniej 12 znaków.")
        with self.file.lock:
            data = self.file.load()
            if any(a["username"] == username for a in data["admins"]):
                raise ValueError("Taki administrator już istnieje.")
            data["admins"].append({
                "username": username,
                "password_hash": _hasher.hash(password),
                "totp_secret": totp_secret,
                "created_at": _iso(_now()),
            })
            data["setup_token_sha256"] = ""  # token konfiguracyjny jest jednorazowy
            self.file.save(data)

    def verify(self, username: str, password: str, totp_code: str) -> bool:
        admin = next((a for a in self.file.load()["admins"] if a["username"] == username.strip().lower()), None)
        # Weryfikacja hasła także dla nieistniejącego loginu – stały czas odpowiedzi
        target = admin["password_hash"] if admin else _DUMMY_HASH
        try:
            _hasher.verify(target, password)
            password_ok = admin is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            password_ok = False
        if not password_ok:
            return False
        return pyotp.TOTP(admin["totp_secret"]).verify(totp_code.strip().replace(" ", ""), valid_window=1)

    def change_password(self, username: str, new_password: str) -> None:
        if len(new_password) < 12:
            raise ValueError("Hasło administratora musi mieć co najmniej 12 znaków.")
        with self.file.lock:
            data = self.file.load()
            for a in data["admins"]:
                if a["username"] == username:
                    a["password_hash"] = _hasher.hash(new_password)
                    self.file.save(data)
                    return
        raise ValueError("Nie znaleziono administratora.")

    def reset_all(self) -> None:
        """Awaryjne usunięcie kont administratorów (tylko z terminala serwera)."""
        with self.file.lock:
            self.file.save({"admins": [], "setup_token_sha256": ""})


_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))


# --------------------------------------------------------------------- kody aktywacyjne
def normalize_code(code: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", code.upper())


class EnrollmentStore:
    """Jednorazowe kody (np. K7QM-4XTP-9HRW), którymi użytkownik dołącza urządzenie do swojego konta."""

    def __init__(self, data_dir: str):
        self.file = JsonFile(os.path.join(data_dir, "enrollments.json"), {"codes": []})

    def create(self, user_id: str, ttl_hours: int, created_by: str) -> Tuple[str, Dict[str, Any]]:
        raw = "".join(secrets.choice(_ENROLL_ALPHABET) for _ in range(12))  # ~58 bitów
        code = "-".join(raw[i:i + 4] for i in range(0, 12, 4))
        record = {
            "code_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "hint": code[-4:],
            "user_id": user_id,
            "created_at": _iso(_now()),
            "expires_at": _iso(_now() + timedelta(hours=ttl_hours)),
            "created_by": created_by,
            "used_at": None,
            "used_by_device": None,
        }
        with self.file.lock:
            data = self.file.load()
            # Sprzątanie wygasłych/zużytych kodów starszych niż 30 dni
            cutoff = _now() - timedelta(days=30)
            data["codes"] = [c for c in data["codes"] if datetime.fromisoformat(c["expires_at"]) > cutoff]
            data["codes"].append(record)
            self.file.save(data)
        return code, record

    def consume(self, code: str, device_name: str) -> Optional[str]:
        """Zużywa kod i zwraca user_id albo None (zły, wygasły lub już użyty kod)."""
        digest = hashlib.sha256(normalize_code(code).encode()).hexdigest()
        with self.file.lock:
            data = self.file.load()
            for c in data["codes"]:
                if hmac.compare_digest(c["code_sha256"], digest):
                    if c["used_at"] or datetime.fromisoformat(c["expires_at"]) < _now():
                        return None
                    c["used_at"] = _iso(_now())
                    c["used_by_device"] = device_name
                    self.file.save(data)
                    return c["user_id"]
        return None

    def active_for(self, user_id: str) -> List[Dict[str, Any]]:
        now = _now()
        return [c for c in self.file.load()["codes"]
                if c["user_id"] == user_id and not c["used_at"] and datetime.fromisoformat(c["expires_at"]) > now]

    def revoke_for(self, user_id: str) -> int:
        with self.file.lock:
            data = self.file.load()
            count = 0
            for c in data["codes"]:
                if c["user_id"] == user_id and not c["used_at"]:
                    c["used_at"] = _iso(_now())
                    c["used_by_device"] = "(unieważniony)"
                    count += 1
            self.file.save(data)
            return count


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str = "KeyStead Server") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
