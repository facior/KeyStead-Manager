"""
Zaszyfrowane załączniki użytkowników: <data_dir>/users/<user_id>/attachments/<id>.bin

Serwer przechowuje wyłącznie zaszyfrowane bajty – klucz każdego pliku jest zapisany w (zaszyfrowanym) sejfie.
Identyfikator to 32 znaki szesnastkowe nadane przez aplikację; limit rozmiaru i miejsca wynika z polityki.
"""

import os
import re
import threading
import uuid
from typing import Dict, List, Optional

ATTACHMENT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
ATTACHMENT_MAGIC = b"KSATT1"


class AttachmentError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class AttachmentStore:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self._lock = threading.Lock()

    def _dir(self, user_id: str) -> str:
        return os.path.join(self.data_dir, "users", user_id, "attachments")

    def _path(self, user_id: str, att_id: str) -> str:
        if not ATTACHMENT_ID_RE.match(att_id or ""):
            raise AttachmentError("Nieprawidłowy identyfikator załącznika.", 400)
        return os.path.join(self._dir(user_id), f"{att_id}.bin")

    def list(self, user_id: str) -> List[Dict[str, object]]:
        folder = self._dir(user_id)
        if not os.path.isdir(folder):
            return []
        items = []
        for name in os.listdir(folder):
            if name.endswith(".bin") and ATTACHMENT_ID_RE.match(name[:-4]):
                items.append({"id": name[:-4], "size": os.path.getsize(os.path.join(folder, name))})
        return items

    def usage(self, user_id: str) -> Dict[str, int]:
        items = self.list(user_id)
        return {"count": len(items), "bytes": sum(int(i["size"]) for i in items)}

    def put(self, user_id: str, att_id: str, data: bytes, max_bytes: int, quota_bytes: int) -> Dict[str, object]:
        path = self._path(user_id, att_id)
        if not data.startswith(ATTACHMENT_MAGIC) or len(data) < len(ATTACHMENT_MAGIC) + 12 + 16:
            raise AttachmentError("Dane nie są zaszyfrowanym załącznikiem KeyStead.", 422)
        if len(data) > max_bytes:
            raise AttachmentError(f"Załącznik jest zbyt duży (limit {max_bytes // (1024 * 1024)} MB).", 413)
        with self._lock:
            existing = os.path.getsize(path) if os.path.exists(path) else 0
            used = self.usage(user_id)["bytes"] - existing
            if used + len(data) > quota_bytes:
                raise AttachmentError(f"Brak miejsca na załączniki (limit {quota_bytes // (1024 * 1024)} MB na osobę).", 507)
            os.makedirs(self._dir(user_id), mode=0o700, exist_ok=True)
            tmp = f"{path}.tmp-{uuid.uuid4().hex}"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        return {"id": att_id, "size": len(data)}

    def get(self, user_id: str, att_id: str) -> Optional[bytes]:
        path = self._path(user_id, att_id)
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def delete(self, user_id: str, att_id: str) -> bool:
        path = self._path(user_id, att_id)
        try:
            os.remove(path)
            return True
        except FileNotFoundError:
            return False
