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
        self._listeners = []

    def add_listener(self, callback) -> None:
        """Obserwator każdego nowego zdarzenia (np. powiadomienia administratora)."""
        self._listeners.append(callback)

    def add(self, event: str, actor: str = "", ip: str = "", **details: Any) -> None:
        record = {"time": _iso(_now()), "event": event, "actor": actor, "ip": ip, **details}
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._lock:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
        for cb in list(self._listeners):
            try:
                cb(record)
            except Exception:
                pass

    def _read_all(self) -> List[Dict[str, Any]]:
        lines: List[str] = []
        for path in (self.path + ".1", self.path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines.extend(f.readlines())
            except FileNotFoundError:
                pass
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    def recent(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self.search(limit=limit)

    def search(self, limit: int = 300, event: str = "", text: str = "",
               since: Optional[str] = None, until: Optional[str] = None) -> List[Dict[str, Any]]:
        """Zdarzenia od najnowszych, z filtrami: typ, dowolny tekst, zakres dat (RRRR-MM-DD)."""
        text = text.strip().lower()
        out = []
        for rec in reversed(self._read_all()):
            if event and rec.get("event") != event:
                continue
            day = str(rec.get("time", ""))[:10]
            if since and day < since:
                continue
            if until and day > until:
                continue
            if text and text not in json.dumps(rec, ensure_ascii=False).lower():
                continue
            out.append(rec)
            if limit and len(out) >= limit:
                break
        return out

    def event_types(self) -> List[str]:
        return sorted({r.get("event", "") for r in self._read_all() if r.get("event")})

    def daily_counts(self, event: str, days: int = 14) -> List[Tuple[str, int]]:
        """Liczba zdarzeń danego typu w ostatnich dniach (do wykresu na stronie stanu)."""
        today = _now().date()
        keys = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
        counts = {k: 0 for k in keys}
        for rec in self._read_all():
            if rec.get("event") == event:
                day = str(rec.get("time", ""))[:10]
                if day in counts:
                    counts[day] += 1
        return [(k, counts[k]) for k in keys]


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

    def _modify(self, user_id: str, **fields: Any) -> bool:
        with self.file.lock:
            data = self.file.load()
            for u in data["users"]:
                if u["user_id"] == user_id:
                    u.update(fields)
                    self.file.save(data)
                    return True
        return False

    def update_profile(self, user_id: str, display_name: str, email: str) -> bool:
        email = email.strip()
        if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise ValueError("Nieprawidłowy adres e-mail.")
        return self._modify(user_id, display_name=display_name.strip() or user_id, email=email)

    # --- 2FA użytkownika (wymagane przy dodawaniu urządzeń, jeśli włączy to polityka)
    def has_totp(self, user_id: str) -> bool:
        user = self.get(user_id) or {}
        return bool(user.get("totp_secret")) and bool(user.get("totp_confirmed"))

    def set_pending_totp(self, user_id: str, secret: str) -> None:
        self._modify(user_id, totp_secret=secret, totp_confirmed=False)

    def confirm_totp(self, user_id: str, code: str) -> bool:
        user = self.get(user_id) or {}
        secret = user.get("totp_secret")
        if secret and pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=1):
            self._modify(user_id, totp_confirmed=True)
            return True
        return False

    def verify_totp(self, user_id: str, code: str) -> bool:
        user = self.get(user_id) or {}
        if not (user.get("totp_secret") and user.get("totp_confirmed")):
            return False
        return pyotp.TOTP(user["totp_secret"]).verify((code or "").strip().replace(" ", ""), valid_window=1)

    def reset_totp(self, user_id: str) -> bool:
        return self._modify(user_id, totp_secret="", totp_confirmed=False)


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

    def create(self, username: str, password: str, totp_secret: str, role: str = "admin", created_by: str = "") -> None:
        username = username.strip().lower()
        if not USERNAME_RE.match(username):
            raise ValueError("Nieprawidłowy login administratora.")
        if len(password) < 12:
            raise ValueError("Hasło administratora musi mieć co najmniej 12 znaków.")
        if role not in ROLES:
            raise ValueError("Nieznana rola.")
        with self.file.lock:
            data = self.file.load()
            if any(a["username"] == username for a in data["admins"]):
                raise ValueError("Taki administrator już istnieje.")
            data["admins"].append({
                "username": username,
                "password_hash": _hasher.hash(password),
                "totp_secret": totp_secret,
                "role": role,
                "created_at": _iso(_now()),
                "created_by": created_by,
            })
            data["setup_token_sha256"] = ""  # token konfiguracyjny jest jednorazowy
            self.file.save(data)

    def list(self) -> List[Dict[str, Any]]:
        return [{"username": a["username"], "role": a.get("role", "admin"), "created_at": a.get("created_at"),
                 "created_by": a.get("created_by", "")} for a in self.file.load()["admins"]]

    def role_of(self, username: str) -> Optional[str]:
        admin = next((a for a in self.file.load()["admins"] if a["username"] == username), None)
        return admin.get("role", "admin") if admin else None

    def delete(self, username: str) -> None:
        with self.file.lock:
            data = self.file.load()
            remaining = [a for a in data["admins"] if a["username"] != username]
            if not any(a.get("role", "admin") == "admin" for a in remaining):
                raise ValueError("Nie można usunąć ostatniego administratora z pełnymi uprawnieniami.")
            data["admins"] = remaining
            self.file.save(data)

    # --- zaproszenia kolejnych administratorów (jednorazowy link z przypisaną rolą)
    def create_invite(self, role: str, created_by: str, ttl_hours: int = 48) -> str:
        if role not in ROLES:
            raise ValueError("Nieznana rola.")
        token = secrets.token_urlsafe(24)
        with self.file.lock:
            data = self.file.load()
            invites = [i for i in data.get("invites", []) if datetime.fromisoformat(i["expires_at"]) > _now()]
            invites.append({"token_sha256": hashlib.sha256(token.encode()).hexdigest(), "role": role,
                            "created_by": created_by, "expires_at": _iso(_now() + timedelta(hours=ttl_hours))})
            data["invites"] = invites
            self.file.save(data)
        return token

    def check_invite(self, token: str) -> Optional[str]:
        """Zwraca rolę z ważnego zaproszenia (bez zużywania)."""
        digest = hashlib.sha256((token or "").strip().encode()).hexdigest()
        for inv in self.file.load().get("invites", []):
            if hmac.compare_digest(inv["token_sha256"], digest) and datetime.fromisoformat(inv["expires_at"]) > _now():
                return inv["role"]
        return None

    def consume_invite(self, token: str) -> None:
        digest = hashlib.sha256((token or "").strip().encode()).hexdigest()
        with self.file.lock:
            data = self.file.load()
            data["invites"] = [i for i in data.get("invites", []) if i["token_sha256"] != digest]
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

# admin – pełne uprawnienia; helpdesk – podgląd użytkowników i generowanie kodów aktywacyjnych
ROLES = {"admin": "Administrator", "helpdesk": "Pomoc techniczna"}


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

    def peek(self, code: str) -> Optional[str]:
        """Sprawdza kod bez zużywania (np. przed weryfikacją 2FA użytkownika)."""
        digest = hashlib.sha256(normalize_code(code).encode()).hexdigest()
        for c in self.file.load()["codes"]:
            if hmac.compare_digest(c["code_sha256"], digest):
                if c["used_at"] or datetime.fromisoformat(c["expires_at"]) < _now():
                    return None
                return c["user_id"]
        return None

    def revoke_all(self) -> int:
        with self.file.lock:
            data = self.file.load()
            count = 0
            for c in data["codes"]:
                if not c["used_at"]:
                    c["used_at"] = _iso(_now())
                    c["used_by_device"] = "(unieważniony – tryb awaryjny)"
                    count += 1
            self.file.save(data)
            return count

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
