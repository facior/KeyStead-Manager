"""
Rejestr urządzeń i tokenów dostępu.

Każde urządzenie (np. "Laptop dom", "PC praca") ma własny losowy token (256 bitów).
Serwer przechowuje wyłącznie skrót SHA-256 tokenu – wyciek pliku devices.json nie ujawnia tokenów.
Token można w każdej chwili odwołać (np. po zgubieniu laptopa).
"""

import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

TOKEN_PREFIX = "ks_"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DeviceRegistry:
    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "devices.json")
        self._lock = threading.Lock()
        os.makedirs(data_dir, mode=0o700, exist_ok=True)

    def _load(self) -> List[Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f).get("devices", [])
        except FileNotFoundError:
            return []

    def _save(self, devices: List[Dict[str, Any]]) -> None:
        tmp = f"{self.path}.tmp-{uuid.uuid4().hex}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"devices": devices}, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def create(self, name: str, user_id: str = "owner") -> Tuple[str, Dict[str, Any]]:
        """Tworzy urządzenie i zwraca (token_w_jawnej_postaci, rekord). Token jest pokazywany tylko raz."""
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        record = {
            "device_id": uuid.uuid4().hex[:12],
            "name": name.strip() or "Urządzenie",
            "user_id": user_id,
            "token_sha256": _hash(token),
            "created_at": _now(),
            "last_seen": None,
            "revoked": False,
        }
        with self._lock:
            devices = self._load()
            devices.append(record)
            self._save(devices)
        return token, record

    def authenticate(self, token: str) -> Optional[Dict[str, Any]]:
        if not token or not token.startswith(TOKEN_PREFIX):
            return None
        digest = _hash(token)
        with self._lock:
            devices = self._load()
            for dev in devices:
                if hmac.compare_digest(dev["token_sha256"], digest) and not dev.get("revoked"):
                    # Aktualizacja "ostatnio widziane" najwyżej raz na minutę (aplikacja odpytuje co 30 s)
                    last = dev.get("last_seen")
                    if not last or (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() > 60:
                        dev["last_seen"] = _now()
                        self._save(devices)
                    return dev
        return None

    def list(self) -> List[Dict[str, Any]]:
        return [{k: v for k, v in d.items() if k != "token_sha256"} for d in self._load()]

    def list_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        return [d for d in self.list() if d.get("user_id") == user_id]

    def get(self, device_id: str) -> Optional[Dict[str, Any]]:
        return next((d for d in self.list() if d["device_id"] == device_id), None)

    def user_ids(self) -> List[str]:
        return sorted({d.get("user_id", "owner") for d in self._load()})

    def delete_for_user(self, user_id: str) -> int:
        with self._lock:
            devices = self._load()
            kept = [d for d in devices if d.get("user_id") != user_id]
            self._save(kept)
            return len(devices) - len(kept)

    def active_count(self, user_id: str) -> int:
        return sum(1 for d in self.list_for_user(user_id) if not d.get("revoked"))

    def revoke_all(self) -> int:
        """Tryb awaryjny: odcina wszystkie urządzenia wszystkich użytkowników."""
        with self._lock:
            devices = self._load()
            count = 0
            for dev in devices:
                if not dev.get("revoked"):
                    dev["revoked"] = True
                    dev["revoked_at"] = _now()
                    count += 1
            self._save(devices)
            return count

    def revoke(self, device_id: str) -> bool:
        with self._lock:
            devices = self._load()
            for dev in devices:
                if dev["device_id"] == device_id and not dev.get("revoked"):
                    dev["revoked"] = True
                    dev["revoked_at"] = _now()
                    self._save(devices)
                    return True
        return False
