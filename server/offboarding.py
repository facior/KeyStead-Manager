"""
Odejście pracownika (offboarding): blokada konta, odcięcie urządzeń, lista kont do zmiany haseł
i – opcjonalnie – przekazanie wpisów do sejfu następcy.

Sejf pracownika otwiera klucz firmy (hasło działu IT) wyłącznie w pamięci serwera. Na liście kontrolnej
zostają tylko nazwa, adres strony i login – nigdy hasła. Lista znika po zakończeniu procesu.
"""

import os
import re
import secrets
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from server.accounts import JsonFile

STATUSES = {"todo": "do zmiany", "done": "zmienione", "skip": "pominięte"}
MAX_ITEMS = 5000
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def checklist_from_vault(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pozycje listy kontrolnej z zawartości sejfu: tylko nazwa, strona, login i kategoria (bez haseł i notatek)."""
    items = []
    for entry in data.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        if not (entry.get("password") or entry.get("totp_secret")):
            continue  # notatki bez hasła nie wymagają zmiany
        items.append({"id": secrets.token_hex(6), "source": "vault",
                      "title": _text(entry.get("title"), 200) or "(bez nazwy)", "url": _text(entry.get("url"), 300),
                      "username": _text(entry.get("username"), 200), "category": _text(entry.get("category"), 100),
                      "status": "todo", "by": "", "at": ""})
        if len(items) >= MAX_ITEMS:
            break
    items.sort(key=lambda i: (i["category"].lower(), i["title"].lower()))
    return items


def transfer_entries(source: Dict[str, Any], target: Dict[str, Any], from_name: str) -> Tuple[int, List[str]]:
    """
    Kopiuje wpisy pracownika do sejfu następcy (kategoria „Przekazane: …”). Zwraca liczbę wpisów
    i identyfikatory załączników do skopiowania między magazynami użytkowników.
    """
    category = f"Przekazane: {from_name}"[:100]
    target_entries = target.setdefault("entries", [])
    existing_ids = {e.get("id") for e in target_entries if isinstance(e, dict)}
    attachments: List[str] = []
    count = 0
    for entry in source.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        copy = dict(entry)
        if copy.get("id") in existing_ids:
            copy["id"] = secrets.token_hex(16)
        copy["category"] = category
        copy["favorite"] = False
        target_entries.append(copy)
        attachments.extend(str(a.get("id")) for a in copy.get("attachments") or [] if isinstance(a, dict) and a.get("id"))
        count += 1
    categories = target.setdefault("categories", [])
    if count and category not in categories:
        categories.append(category)
    return count, attachments


class OffboardingStore:
    """Procesy odejścia w toku: data_dir/offboarding/<użytkownik>.json."""

    def __init__(self, data_dir: str):
        self.dir = os.path.join(data_dir, "offboarding")
        self._files: Dict[str, JsonFile] = {}  # jeden obiekt (i jedna blokada) na plik

    def _file(self, user_id: str) -> JsonFile:
        if not _SAFE_ID.match(user_id or ""):
            raise ValueError("Nieprawidłowy identyfikator użytkownika.")
        if user_id not in self._files:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            self._files[user_id] = JsonFile(os.path.join(self.dir, f"{user_id}.json"), {})
        return self._files[user_id]

    def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        data = self._file(user_id).load()
        return data or None

    def start(self, user_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
        f = self._file(user_id)
        with f.lock:
            record = {"user_id": user_id, "started_at": _now(), **record}
            f.save(record)
        return record

    def update_item(self, user_id: str, item_id: str, status: str, actor: str) -> Optional[Dict[str, Any]]:
        if status not in STATUSES:
            raise ValueError("Nieprawidłowy stan pozycji.")
        f = self._file(user_id)
        with f.lock:
            data = f.load()
            for item in data.get("items", []):
                if item.get("id") == item_id:
                    item.update(status=status, by=actor if status != "todo" else "", at=_now() if status != "todo" else "")
                    f.save(data)
                    return item
        return None

    def add_item(self, user_id: str, title: str, url: str, username: str) -> Dict[str, Any]:
        f = self._file(user_id)
        with f.lock:
            data = f.load()
            if not data:
                raise ValueError("Brak procesu odejścia dla tego użytkownika.")
            item = {"id": secrets.token_hex(6), "source": "manual", "title": _text(title, 200) or "(bez nazwy)",
                    "url": _text(url, 300), "username": _text(username, 200), "category": "Dodane ręcznie",
                    "status": "todo", "by": "", "at": ""}
            data.setdefault("items", []).append(item)
            f.save(data)
        return item

    def finish(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Zakończenie: lista (z nazwami kont) jest usuwana, zostaje tylko podsumowanie w dzienniku."""
        f = self._file(user_id)
        with f.lock:
            data = f.load()
            try:
                os.remove(f.path)
            except FileNotFoundError:
                pass
        return data or None

    def active(self) -> List[Dict[str, Any]]:
        if not os.path.isdir(self.dir):
            return []
        out = []
        for name in sorted(os.listdir(self.dir)):
            if name.endswith(".json") and _SAFE_ID.match(name[:-5]):
                data = self.get(name[:-5])
                if data:
                    out.append(data)
        return out


def progress(record: Optional[Dict[str, Any]]) -> Dict[str, int]:
    items = (record or {}).get("items", [])
    return {"total": len(items), **{k: sum(1 for i in items if i.get("status") == k) for k in STATUSES}}


def copy_attachments(store, source_user: str, target_user: str, ids: List[str]) -> int:
    """Załączniki są szyfrowane osobnymi kluczami zapisanymi we wpisach – wystarczy skopiować pliki."""
    copied = 0
    for att_id in ids:
        try:
            src = store._path(source_user, att_id)
            dst = store._path(target_user, att_id)
        except Exception:
            continue
        if os.path.isfile(src) and not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
    return copied
