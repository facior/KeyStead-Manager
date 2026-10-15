"""
Operacje serwera: raporty bezpieczeństwa użytkowników, kopie zapasowe serwera,
sprawdzanie aktualizacji, kontrola miejsca na dysku i zadania wykonywane w tle.
"""

import json
import logging
import os
import re
import shutil
import tarfile
import threading
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from server import SERVER_VERSION
from server.accounts import AuditLog, JsonFile
from server.settings import SettingsStore

log = logging.getLogger("keystead.ops")
BACKUP_RE = re.compile(r"^keystead-backup-\d{8}-\d{6}\.tar\.gz$")
REPORT_FIELDS = ("score", "total", "breached", "reused", "weak", "missing_totp", "stale")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------- raporty bezpieczeństwa
class ReportStore:
    """Zbiorczy wynik audytu sejfu przesyłany przez aplikację – wyłącznie liczby, nigdy hasła."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def _path(self, user_id: str) -> str:
        folder = os.path.join(self.data_dir, "users", user_id)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        return os.path.join(folder, "report.json")

    @staticmethod
    def sanitize(payload: Dict[str, Any]) -> Dict[str, Any]:
        clean = {}
        for key in REPORT_FIELDS:
            try:
                value = int(payload.get(key, 0))
            except (TypeError, ValueError):
                value = 0
            clean[key] = max(0, min(value, 100 if key == "score" else 1_000_000))
        clean["hibp_checked"] = bool(payload.get("hibp_checked"))
        return clean

    def save(self, user_id: str, payload: Dict[str, Any], device: str) -> Dict[str, Any]:
        report = {**self.sanitize(payload), "device": device, "received_at": _now_iso()}
        JsonFile(self._path(user_id), {}).save(report)
        return report

    def get(self, user_id: str) -> Optional[Dict[str, Any]]:
        data = JsonFile(self._path(user_id), {}).load()
        return data or None

    def delete(self, user_id: str) -> None:
        try:
            os.remove(self._path(user_id))
        except OSError:
            pass


# --------------------------------------------------------------------- kopie zapasowe serwera
class BackupService:
    """Archiwum tar.gz katalogu danych (sejfy są w nim zaszyfrowane, ale konta i ustawienia nie – chronić jak klucze!)."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.backup_dir = os.path.join(data_dir, "backups")

    def create(self) -> Dict[str, Any]:
        os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)
        name = datetime.now().strftime("keystead-backup-%Y%m%d-%H%M%S.tar.gz")
        path = os.path.join(self.backup_dir, name)
        tmp = path + ".part"

        def _exclude(info: tarfile.TarInfo):
            rel = info.name.split("/", 1)[1] if "/" in info.name else ""
            if (rel.startswith(("backups", ".before-restore-", ".restore-tmp-")) or ".tmp-" in info.name
                    or info.name.endswith(".part")):
                return None
            return info

        with tarfile.open(tmp, "w:gz") as tar:
            tar.add(self.data_dir, arcname="keystead-data", filter=_exclude)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return {"name": name, "size": os.path.getsize(path), "created_at": _now_iso()}

    def list(self) -> List[Dict[str, Any]]:
        if not os.path.isdir(self.backup_dir):
            return []
        items = []
        for name in os.listdir(self.backup_dir):
            if BACKUP_RE.match(name):
                path = os.path.join(self.backup_dir, name)
                items.append({"name": name, "size": os.path.getsize(path),
                              "created_at": datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(timespec="seconds")})
        return sorted(items, key=lambda i: i["name"], reverse=True)

    def path_of(self, name: str) -> Optional[str]:
        if not BACKUP_RE.match(name or ""):
            return None
        path = os.path.join(self.backup_dir, name)
        return path if os.path.isfile(path) else None

    def delete(self, name: str) -> bool:
        path = self.path_of(name)
        if path:
            os.remove(path)
            return True
        return False

    def prune(self, keep: int) -> int:
        removed = 0
        for item in self.list()[max(1, keep):]:
            if self.delete(item["name"]):
                removed += 1
        return removed

    @staticmethod
    def restore(archive: str, data_dir: str) -> str:
        """
        Przywraca dane serwera z archiwum (z terminala, przy zatrzymanej usłudze).
        Działa wewnątrz katalogu danych (usługa nie ma prawa zapisu wyżej): dotychczasowe pliki trafiają
        do <dane>/.before-restore-<czas>, kopie zapasowe zostają na miejscu.
        """
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        staging = os.path.join(data_dir, f".restore-tmp-{stamp}")
        previous = os.path.join(data_dir, f".before-restore-{stamp}")
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.name.startswith("keystead-data") or ".." in member.name or member.name.startswith("/"):
                    raise ValueError(f"Podejrzana ścieżka w archiwum: {member.name}")
            os.makedirs(staging)
            try:
                tar.extractall(staging, filter="data")
            except TypeError:  # Python bez parametru filter – ścieżki zweryfikowane wyżej
                tar.extractall(staging)
        restored_root = os.path.join(staging, "keystead-data")
        if not os.path.isdir(restored_root):
            shutil.rmtree(staging, ignore_errors=True)
            raise ValueError("Archiwum nie zawiera katalogu keystead-data.")

        os.makedirs(previous)
        keep = {"backups", os.path.basename(staging), os.path.basename(previous)}
        for name in os.listdir(data_dir):
            if name not in keep and not name.startswith(".before-restore-"):
                os.replace(os.path.join(data_dir, name), os.path.join(previous, name))
        for name in os.listdir(restored_root):
            if name != "backups":
                os.replace(os.path.join(restored_root, name), os.path.join(data_dir, name))
        shutil.rmtree(staging, ignore_errors=True)
        return previous


# --------------------------------------------------------------------- aktualizacje
def _version_tuple(v: str):
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:3]) if nums else (0,)


def check_latest_release(repository: str, timeout: float = 10.0) -> Optional[Dict[str, str]]:
    """Najnowsze wydanie na GitHubie albo None (brak wydań / brak sieci)."""
    url = f"https://api.github.com/repos/{repository}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "KeyStead-Server"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    tag = data.get("tag_name", "")
    return {"version": tag.lstrip("v"), "url": data.get("html_url", ""), "published_at": data.get("published_at", "")}


APP_TAG_PREFIX = "app-v"


def find_app_release(repository: str, timeout: float = 10.0) -> Optional[Dict[str, str]]:
    """Najnowsze wydanie aplikacji KeyStead Manager (tag app-vX.Y.Z) i adres jego instalatora."""
    url = f"https://api.github.com/repos/{repository}/releases?per_page=30"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "KeyStead-Server"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            releases = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    best = None
    for rel in releases if isinstance(releases, list) else []:
        tag = rel.get("tag_name") or ""
        ver = tag[len(APP_TAG_PREFIX):]
        if rel.get("draft") or rel.get("prerelease") or not tag.startswith(APP_TAG_PREFIX) \
                or not re.match(r"^\d+\.\d+\.\d+$", ver):
            continue
        setup = next((a.get("browser_download_url") for a in rel.get("assets", [])
                      if a.get("name") == f"KeyStead-Manager-Setup-{ver}.exe"), None)
        if setup and (best is None or _version_tuple(ver) > _version_tuple(best["version"])):
            best = {"version": ver, "setup_url": setup, "page_url": rel.get("html_url", "")}
    return best


class AppDownload:
    """Adres instalatora aplikacji dla użytkowników (ustawienie z panelu albo najnowsze wydanie z GitHuba, 1 h w pamięci)."""

    def __init__(self, settings: SettingsStore, ttl: float = 3600):
        self.settings = settings
        self.ttl = ttl
        self._cache: Optional[Dict[str, str]] = None
        self._cached_at = 0.0
        self._lock = threading.Lock()

    def url(self) -> str:
        custom = self.settings.section("general").get("app_download_url")
        if custom:
            return custom
        repo = self.settings.section("updates").get("repository") or "facior/KeyStead-Manager"
        with self._lock:
            if time.time() - self._cached_at > self.ttl:
                found = find_app_release(repo)
                if found or self._cache is None:
                    self._cache = found
                self._cached_at = time.time()
            cached = self._cache
        return cached["setup_url"] if cached else f"https://github.com/{repo}/releases"


# --------------------------------------------------------------------- stan i zadania w tle
class OpsState:
    """Drobny stan operacyjny (ostatnia kopia, ostatnie sprawdzenie aktualizacji, alarmy)."""

    def __init__(self, data_dir: str):
        self.file = JsonFile(os.path.join(data_dir, "ops_state.json"), {})

    def get(self) -> Dict[str, Any]:
        return self.file.load()

    def update(self, **values: Any) -> None:
        with self.file.lock:
            data = self.file.load()
            data.update(values)
            self.file.save(data)


def disk_status(path: str) -> Dict[str, Any]:
    usage = shutil.disk_usage(path)
    return {"total": usage.total, "used": usage.used, "free": usage.free,
            "free_percent": round(usage.free * 100 / usage.total, 1) if usage.total else 0}


def data_size(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        if os.path.basename(root) == "backups":
            continue
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


class BackgroundTasks:
    """Wątek wykonujący co minutę: zaplanowaną kopię, kontrolę dysku i (raz na dobę) sprawdzenie aktualizacji."""

    def __init__(self, data_dir: str, settings: SettingsStore, backups: BackupService, audit: AuditLog, state: OpsState):
        self.data_dir = data_dir
        self.settings = settings
        self.backups = backups
        self.audit = audit
        self.state = state
        self.updates = None  # UpdateBridge – ustawiany przez ServerContext
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="keystead-tasks", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("Błąd zadania w tle")
            self._stop.wait(60)

    def run_once(self, now: Optional[datetime] = None) -> None:
        now = now or datetime.now()
        st = self.state.get()
        cfg = self.settings.all()

        # 1. Codzienna kopia zapasowa serwera
        b = cfg["backups"]
        today = now.strftime("%Y-%m-%d")
        if b.get("enabled") and now.hour >= int(b.get("hour", 3)) and st.get("last_auto_backup_day") != today:
            self.run_backup(automatic=True)
            self.state.update(last_auto_backup_day=today)

        # 2. Miejsce na dysku (alarm najwyżej raz dziennie)
        disk = disk_status(self.data_dir)
        threshold = float(cfg["notifications"].get("disk_low_percent", 10))
        if disk["free_percent"] < threshold and st.get("disk_alert_day") != today:
            self.audit.add("disk_low", actor="serwer", free_percent=disk["free_percent"])
            self.state.update(disk_alert_day=today)

        # 3. Wynik aktualizacji wykonanej przez aktualizator (root nie pisze do dziennika usługi)
        self.record_update_result()

        # 4. Aktualizacje (raz na dobę)
        u = cfg["updates"]
        if u.get("check") and time.time() - float(st.get("last_update_check", 0)) > 86400:
            self.check_updates(u.get("repository", ""))

    def record_update_result(self) -> None:
        if self.updates is None:
            return
        st = self.updates.status()
        finished = st.get("finished_at")
        if finished and st.get("state") in ("success", "failed", "rolled_back") and self.state.get().get("update_recorded") != finished:
            self.audit.add("update_finished", actor=st.get("requested_by") or "serwer", result=st.get("state"),
                           version=st.get("version"), from_version=st.get("from_version"), message=st.get("message", "")[:200])
            self.state.update(update_recorded=finished)

    def run_backup(self, automatic: bool = False) -> Optional[Dict[str, Any]]:
        try:
            info = self.backups.create()
            self.backups.prune(int(self.settings.section("backups").get("keep", 14)))
            self.state.update(last_backup={"name": info["name"], "at": info["created_at"], "ok": True})
            self.audit.add("backup_created", actor="serwer" if automatic else "", name=info["name"])
            return info
        except Exception as e:
            self.state.update(last_backup={"at": _now_iso(), "ok": False, "error": str(e)})
            self.audit.add("backup_failed", actor="serwer", error=str(e))
            return None

    def check_updates(self, repository: str) -> Optional[Dict[str, str]]:
        latest = check_latest_release(repository) if repository else None
        self.state.update(last_update_check=time.time(), latest_release=latest)
        if latest and _version_tuple(latest["version"]) > _version_tuple(SERVER_VERSION):
            if self.state.get().get("notified_version") != latest["version"]:
                self.audit.add("update_available", actor="serwer", version=latest["version"])
                self.state.update(notified_version=latest["version"])
        return latest
