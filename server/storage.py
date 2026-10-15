"""
Magazyn zaszyfrowanych sejfów z historią wersji.

Układ katalogów (gotowy na wielu użytkowników / klientów):
    <data_dir>/server.json                     – identyfikator instancji serwera
    <data_dir>/users/<user_id>/vault/meta.json – bieżąca wersja
    <data_dir>/users/<user_id>/vault/versions/00000012.vault (+ .json)
"""

import hashlib
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VAULT_MAGIC = b"SECVAULT"
# MAGIC(8) + wersja i parametry KDF(13) + sól(32) + nonce(12) + tag GCM(16)
MIN_VAULT_BYTES = 8 + 13 + 32 + 12 + 16
# Pierwszy znak alfanumeryczny – identyfikator nigdy nie będzie "." ani ".." (brak wyjścia poza katalog danych)
_USER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class VersionConflictError(Exception):
    """Klient zapisuje na podstawie nieaktualnej wersji (ktoś zmienił sejf w międzyczasie)."""

    def __init__(self, current: Optional[Dict[str, Any]]):
        super().__init__("Konflikt wersji sejfu")
        self.current = current


class InvalidVaultError(Exception):
    """Przesłane dane nie wyglądają na zaszyfrowany plik sejfu."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path: str, data: bytes) -> None:
    tmp = f"{path}.tmp-{uuid.uuid4().hex}"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def validate_vault_blob(blob: bytes) -> None:
    """Weryfikuje tylko format – serwer nie potrafi (i nie powinien) odszyfrować sejfu."""
    if len(blob) < MIN_VAULT_BYTES or not blob.startswith(VAULT_MAGIC):
        raise InvalidVaultError("Dane nie są zaszyfrowanym plikiem sejfu KeyStead Manager.")


class VaultStore:
    def __init__(self, data_dir: str, max_history: int = 50):
        self.data_dir = data_dir
        self.max_history = max(1, max_history)
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        os.makedirs(self.data_dir, mode=0o700, exist_ok=True)
        self.server_id = self._load_server_id()

    # ------------------------------------------------------------ pomocnicze
    def _load_server_id(self) -> str:
        path = os.path.join(self.data_dir, "server.json")
        info = _read_json(path)
        if not info or "server_id" not in info:
            info = {"server_id": uuid.uuid4().hex, "created_at": _now()}
            _atomic_write(path, json.dumps(info, indent=2).encode("utf-8"))
        return info["server_id"]

    def _lock(self, user_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(user_id, threading.Lock())

    def _vault_dir(self, user_id: str) -> str:
        if not _USER_ID_RE.match(user_id):
            raise ValueError("Nieprawidłowy identyfikator użytkownika.")
        path = os.path.join(self.data_dir, "users", user_id, "vault")
        os.makedirs(os.path.join(path, "versions"), mode=0o700, exist_ok=True)
        return path

    def _version_paths(self, user_id: str, version: int):
        base = os.path.join(self._vault_dir(user_id), "versions", f"{version:08d}")
        return base + ".vault", base + ".json"

    # ------------------------------------------------------------ API
    def get_meta(self, user_id: str) -> Optional[Dict[str, Any]]:
        return _read_json(os.path.join(self._vault_dir(user_id), "meta.json"))

    def read_version(self, user_id: str, version: Optional[int] = None) -> Optional[bytes]:
        if version is None:
            meta = self.get_meta(user_id)
            if not meta:
                return None
            version = meta["version"]
        blob_path, _ = self._version_paths(user_id, int(version))
        try:
            with open(blob_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def write(self, user_id: str, blob: bytes, base_version: int, device_name: str) -> Dict[str, Any]:
        """
        Zapisuje nową wersję tylko wtedy, gdy klient bazował na aktualnej (optimistic locking).
        base_version = 0 oznacza "sejf jeszcze nie istnieje na serwerze".
        """
        validate_vault_blob(blob)
        with self._lock(user_id):
            current = self.get_meta(user_id)
            current_version = current["version"] if current else 0
            if base_version != current_version:
                raise VersionConflictError(current)

            new_version = current_version + 1
            meta = {
                "version": new_version,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "size": len(blob),
                "updated_at": _now(),
                "updated_by": device_name,
            }
            blob_path, meta_path = self._version_paths(user_id, new_version)
            _atomic_write(blob_path, blob)
            _atomic_write(meta_path, json.dumps(meta, indent=2).encode("utf-8"))
            # meta.json zapisujemy na końcu – to on "publikuje" nową wersję
            _atomic_write(os.path.join(self._vault_dir(user_id), "meta.json"), json.dumps(meta, indent=2).encode("utf-8"))
            self._prune(user_id, new_version)
            return meta

    def history(self, user_id: str) -> List[Dict[str, Any]]:
        versions_dir = os.path.join(self._vault_dir(user_id), "versions")
        items = []
        for name in os.listdir(versions_dir):
            if name.endswith(".json"):
                meta = _read_json(os.path.join(versions_dir, name))
                if meta:
                    items.append(meta)
        items.sort(key=lambda m: m["version"], reverse=True)
        return items

    def _prune(self, user_id: str, newest: int) -> None:
        oldest_kept = newest - self.max_history + 1
        versions_dir = os.path.join(self._vault_dir(user_id), "versions")
        for name in os.listdir(versions_dir):
            stem = name.split(".", 1)[0]
            if stem.isdigit() and int(stem) < oldest_kept:
                try:
                    os.remove(os.path.join(versions_dir, name))
                except OSError:
                    pass
