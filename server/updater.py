"""
Aktualizator serwera KeyStead.

Bezpieczeństwo (podział uprawnień):
- Panel administratora (usługa `keystead`, bez uprawnień) może jedynie ZAPISAĆ PROŚBĘ o aktualizację
  do /var/lib/keystead/update/request.json. Niczego nie pobiera ani nie instaluje.
- Usługa `keystead-updater` (root, uruchamiana przez systemd wyłącznie na taką prośbę):
  1. pobiera wydanie z GitHub Releases (repozytorium z /etc/keystead/updater.env – plik roota),
  2. weryfikuje podpis SHA256SUMS kluczem z /etc/keystead/release-signing.pub (ssh-keygen -Y verify)
     i sumę SHA-256 paczki – niepodpisane wydanie jest odrzucane,
  3. robi kopię zapasową danych, instaluje wersję obok bieżącej (/opt/keystead/releases/<wersja>),
  4. przełącza /opt/keystead/current, restartuje usługę i sprawdza, czy odpowiada nowa wersja,
  5. przy jakimkolwiek błędzie wraca do poprzedniej wersji.
- Stan postępu zapisuje do /var/lib/keystead-updater/status.json (katalog roota, panel tylko czyta).

Uruchomienie (systemd): python -m server.updater run
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SIGNING_NAMESPACE = "keystead-release"
SIGNING_PRINCIPAL = "keystead-release"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
MAX_TARBALL_BYTES = 50 * 1024 * 1024

STEPS = [
    ("download", "Pobieranie wydania"),
    ("verify", "Weryfikacja podpisu i sumy kontrolnej"),
    ("backup", "Kopia zapasowa danych"),
    ("install", "Instalacja nowej wersji"),
    ("switch", "Przełączenie i restart serwera"),
    ("health", "Sprawdzenie działania"),
]


def _vt(version: str):
    return tuple(int(x) for x in version.split("."))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def asset_names(version: str) -> Dict[str, str]:
    return {"tarball": f"keystead-server-{version}.tar.gz", "sums": "SHA256SUMS", "sig": "SHA256SUMS.sig"}


class UpdateError(Exception):
    """Błąd aktualizacji (komunikat dla administratora)."""


# --------------------------------------------------------------------- ścieżki
@dataclass
class UpdaterPaths:
    data_dir: str = "/var/lib/keystead"
    state_dir: str = "/var/lib/keystead-updater"
    app_dir: str = "/opt/keystead"
    config_dir: str = "/etc/keystead"

    @classmethod
    def from_env(cls, data_dir: Optional[str] = None) -> "UpdaterPaths":
        env = os.environ.get
        return cls(
            data_dir=data_dir or env("KS_DATA_DIR", "/var/lib/keystead"),
            state_dir=env("KS_UPDATER_STATE_DIR", "/var/lib/keystead-updater"),
            app_dir=env("KS_APP_DIR", "/opt/keystead"),
            config_dir=env("KS_CONFIG_DIR", "/etc/keystead"),
        )

    @property
    def request_file(self) -> str:   # zapisywany przez panel (użytkownik keystead)
        return os.path.join(self.data_dir, "update", "request.json")

    @property
    def status_file(self) -> str:    # zapisywany przez aktualizator (root)
        return os.path.join(self.state_dir, "status.json")

    @property
    def history_file(self) -> str:
        return os.path.join(self.state_dir, "history.json")

    @property
    def releases_dir(self) -> str:
        return os.path.join(self.app_dir, "releases")

    @property
    def current_link(self) -> str:
        return os.path.join(self.app_dir, "current")

    @property
    def public_key(self) -> str:
        return os.path.join(self.config_dir, "release-signing.pub")

    @property
    def updater_env(self) -> str:
        return os.path.join(self.config_dir, "updater.env")


def _read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path: str, data: Any, mode: int = 0o644) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_env_file(path: str) -> Dict[str, str]:
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip()
    except OSError:
        pass
    return values


# --------------------------------------------------------------------- strona panelu (bez uprawnień)
class UpdateBridge:
    """To, co wolno panelowi: odczyt stanu i zapis prośby. Instalacją zajmuje się wyłącznie aktualizator (root)."""

    def __init__(self, paths: UpdaterPaths):
        self.paths = paths

    def available(self) -> bool:
        """Czy na serwerze zainstalowano aktualizator (usługa + klucz weryfikujący podpisy)."""
        return os.path.isfile(self.paths.public_key) and os.path.isdir(self.paths.state_dir)

    def status(self) -> Dict[str, Any]:
        st = _read_json(self.paths.status_file, {}) or {}
        if os.path.exists(self.paths.request_file) and st.get("state") not in ("running",):
            req = _read_json(self.paths.request_file, {}) or {}
            st = {"state": "requested", "version": req.get("version"), "action": req.get("action"),
                  "requested_by": req.get("requested_by"), "message": "Oczekiwanie na uruchomienie aktualizatora..."}
        return st

    def history(self) -> List[Dict[str, Any]]:
        return list(reversed(_read_json(self.paths.history_file, []) or []))[:20]

    def installed_versions(self) -> List[str]:
        try:
            names = [n for n in os.listdir(self.paths.releases_dir) if VERSION_RE.match(n)]
        except OSError:
            return []
        return sorted(names, key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)

    def current_version(self) -> Optional[str]:
        if not os.path.lexists(self.paths.current_link):
            return None
        try:
            name = os.path.basename(os.path.realpath(self.paths.current_link))
        except OSError:
            return None
        return name if VERSION_RE.match(name) else None

    def busy(self) -> bool:
        return self.status().get("state") in ("requested", "running")

    def request(self, action: str, version: str, requested_by: str) -> None:
        if action not in ("update", "rollback"):
            raise UpdateError("Nieznana operacja.")
        if action == "update" and not VERSION_RE.match(version or ""):
            raise UpdateError("Nieprawidłowy numer wersji.")
        if self.busy():
            raise UpdateError("Aktualizacja jest już w toku.")
        os.makedirs(os.path.dirname(self.paths.request_file), mode=0o700, exist_ok=True)
        _write_json(self.paths.request_file, {"action": action, "version": version, "requested_by": requested_by,
                                              "requested_at": _now()}, mode=0o600)


# --------------------------------------------------------------------- operacje systemowe (Linux, root)
class SystemOps:
    """Operacje wymagające roota. W testach zastępowane atrapą."""

    def __init__(self, paths: UpdaterPaths):
        self.paths = paths

    def create_venv(self, release_dir: str) -> None:
        venv = os.path.join(release_dir, "venv")
        subprocess.run([sys.executable if os.path.exists(sys.executable) else "python3", "-m", "venv", venv], check=True,
                       capture_output=True)
        # Tylko gotowe paczki (wheel): żaden setup.py z PyPI nie wykonuje się z uprawnieniami roota
        subprocess.run([os.path.join(venv, "bin", "pip"), "install", "-q", "--disable-pip-version-check",
                        "--only-binary=:all:", "-r", os.path.join(release_dir, "server", "requirements.txt")],
                       check=True, capture_output=True)

    def backup_data(self) -> None:
        subprocess.run(["/usr/local/bin/keystead-admin", "backup"], check=True, capture_output=True, timeout=600)

    def activate(self, release_dir: str) -> None:
        tmp = self.paths.current_link + ".new"
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(release_dir, tmp)
        os.replace(tmp, self.paths.current_link)

    def install_units(self, release_dir: str) -> None:
        changed = False
        for unit in ("keystead.service", "keystead-updater.service", "keystead-updater.path"):
            src = os.path.join(release_dir, "server", "deploy", unit)
            dst = os.path.join("/etc/systemd/system", unit)
            if os.path.isfile(src):
                with open(src, "rb") as f:
                    new = f.read()
                old = open(dst, "rb").read() if os.path.isfile(dst) else b""
                if new != old:
                    with open(dst, "wb") as f:
                        f.write(new)
                    changed = True
        if changed:
            subprocess.run(["systemctl", "daemon-reload"], check=True)

    def restart(self) -> None:
        subprocess.run(["systemctl", "restart", "keystead.service"], check=True, timeout=120)

    def health(self, expected_version: str, timeout: int = 40) -> bool:
        env = read_env_file(os.path.join(self.paths.config_dir, "server.env"))
        host = env.get("KS_HOST", "127.0.0.1")
        if host in ("0.0.0.0", "::", ""):
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        scheme = "https" if env.get("KS_TLS_CERT") else "http"
        url = f"{scheme}://{host}:{env.get('KS_PORT', '8787')}/api/v1/health"
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # lokalny serwer, sprawdzamy tylko działanie i wersję
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3, context=ctx) as resp:
                    if json.loads(resp.read().decode()).get("server_version") == expected_version:
                        return True
            except Exception:
                pass
            time.sleep(1)
        return False


# --------------------------------------------------------------------- pobieranie z GitHub Releases
class ReleaseFetcher:
    def __init__(self, repository: str):
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repository or ""):
            raise UpdateError("Nieprawidłowe repozytorium w /etc/keystead/updater.env.")
        self.repository = repository

    def _get(self, url: str, limit: int, accept: str = "application/octet-stream") -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "KeyStead-Updater", "Accept": accept})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(limit + 1)
        if len(data) > limit:
            raise UpdateError("Plik wydania jest zbyt duży.")
        return data

    def fetch(self, version: str) -> Dict[str, bytes]:
        api = f"https://api.github.com/repos/{self.repository}/releases/tags/v{version}"
        try:
            meta = json.loads(self._get(api, 2 * 1024 * 1024, accept="application/vnd.github+json").decode("utf-8"))
        except UpdateError:
            raise
        except Exception as e:
            raise UpdateError(f"Nie znaleziono wydania v{version} na GitHubie ({e}).")
        assets = {a.get("name"): a.get("browser_download_url") for a in meta.get("assets", [])}
        names = asset_names(version)
        missing = [n for n in names.values() if n not in assets]
        if missing:
            raise UpdateError(f"Wydanie v{version} nie zawiera plików: {', '.join(missing)}.")
        return {key: self._get(assets[name], MAX_TARBALL_BYTES) for key, name in names.items()}


# --------------------------------------------------------------------- weryfikacja
def find_ssh_keygen() -> str:
    for path in (shutil.which("ssh-keygen"), r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"):
        if path and os.path.exists(path):
            return path
    raise UpdateError("Brak programu ssh-keygen (pakiet openssh-client).")


def verify_release(files: Dict[str, bytes], version: str, public_key_file: str) -> None:
    """Podpis pliku SHA256SUMS kluczem wydawcy + zgodność sumy SHA-256 paczki."""
    if not os.path.isfile(public_key_file):
        raise UpdateError("Brak klucza weryfikującego wydania (/etc/keystead/release-signing.pub).")
    with tempfile.TemporaryDirectory() as tmp:
        sig_path = os.path.join(tmp, "SHA256SUMS.sig")
        with open(sig_path, "wb") as f:
            f.write(files["sig"])
        result = subprocess.run(
            [find_ssh_keygen(), "-Y", "verify", "-f", public_key_file, "-I", SIGNING_PRINCIPAL,
             "-n", SIGNING_NAMESPACE, "-s", sig_path],
            input=files["sums"], capture_output=True, timeout=30)
    if result.returncode != 0:
        raise UpdateError("NIEPRAWIDŁOWY PODPIS wydania – aktualizacja odrzucona (plik nie pochodzi od wydawcy lub został zmieniony).")

    expected = None
    tarball_name = asset_names(version)["tarball"]
    for line in files["sums"].decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == tarball_name:
            expected = parts[0].lower()
    if not expected:
        raise UpdateError("Plik SHA256SUMS nie zawiera sumy paczki wydania.")
    if hashlib.sha256(files["tarball"]).hexdigest() != expected:
        raise UpdateError("Suma kontrolna paczki nie zgadza się z podpisaną listą – aktualizacja odrzucona.")


def extract_release(tarball: bytes, version: str, target_dir: str) -> None:
    """Rozpakowuje paczkę (tylko katalog server/, bez dowiązań i ścieżek wychodzących poza katalog)."""
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "release.tar.gz")
        with open(archive, "wb") as f:
            f.write(tarball)
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar.getmembers():
                name = m.name.lstrip("./")
                if not name.startswith("server") or ".." in m.name.split("/") or m.name.startswith("/"):
                    raise UpdateError(f"Niedozwolona ścieżka w paczce: {m.name}")
                if m.issym() or m.islnk() or m.isdev():
                    raise UpdateError(f"Niedozwolony typ pliku w paczce: {m.name}")
            os.makedirs(target_dir)
            try:
                tar.extractall(target_dir, filter="data")
            except TypeError:
                tar.extractall(target_dir)
    init = os.path.join(target_dir, "server", "__init__.py")
    try:
        with open(init, "r", encoding="utf-8") as f:
            found = re.search(r'SERVER_VERSION\s*=\s*"([^"]+)"', f.read())
    except OSError:
        found = None
    if not found or found.group(1) != version:
        raise UpdateError(f"Paczka nie zawiera serwera w wersji {version}.")


# --------------------------------------------------------------------- aktualizator
class Updater:
    def __init__(self, paths: UpdaterPaths, ops: Optional[SystemOps] = None, fetcher: Optional[ReleaseFetcher] = None):
        self.paths = paths
        self.ops = ops or SystemOps(paths)
        repo = read_env_file(paths.updater_env).get("KS_UPDATE_REPOSITORY", "facior/KeyStead-Manager")
        self.fetcher = fetcher or ReleaseFetcher(repo)
        self.status: Dict[str, Any] = {}

    # --- stan widoczny w panelu
    def _set(self, **values: Any) -> None:
        self.status.update(values)
        _write_json(self.paths.status_file, self.status)

    def _step(self, step: str) -> None:
        label = dict(STEPS)[step]
        self._set(step=step, step_label=label, step_index=[s for s, _ in STEPS].index(step) + 1, steps_total=len(STEPS),
                  message=label + "...")

    def _history(self, entry: Dict[str, Any]) -> None:
        hist = _read_json(self.paths.history_file, []) or []
        hist.append(entry)
        _write_json(self.paths.history_file, hist[-50:])

    def current_release(self) -> Optional[str]:
        link = self.paths.current_link
        return os.path.realpath(link) if os.path.lexists(link) else None

    # --- obsługa prośby z panelu
    def take_request(self) -> Optional[Dict[str, Any]]:
        """
        Odczytuje i usuwa prośbę. Plik leży w katalogu użytkownika keystead, więc jest traktowany jako niezaufany:
        tylko zwykły plik (nie dowiązanie, katalog ani FIFO), mały, należący do właściciela katalogu danych.
        Cokolwiek tam leży – zostaje usunięte, żeby nie blokować kolejnych uruchomień aktualizatora.
        """
        path = self.paths.request_file
        raw = None
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            fd = None
        if fd is not None:
            try:
                st = os.fstat(fd)
                owner_ok = True
                if hasattr(os, "getuid"):
                    owner_ok = st.st_uid == os.stat(self.paths.data_dir).st_uid
                if stat.S_ISREG(st.st_mode) and st.st_size <= 4096 and owner_ok:
                    raw = os.read(fd, 4096)
            except OSError:
                raw = None
            finally:
                os.close(fd)
        self._remove_request()
        if raw is None:
            return None
        try:
            req = json.loads(raw.decode("utf-8"))
        except ValueError:
            return None
        if not isinstance(req, dict):
            return None
        action = req.get("action")
        version = str(req.get("version") or "")
        if action not in ("update", "rollback") or (action == "update" and not VERSION_RE.match(version)):
            return None
        return {"action": action, "version": version, "requested_by": str(req.get("requested_by", ""))[:64]}

    def _remove_request(self) -> None:
        path = self.paths.request_file
        try:
            if os.path.islink(path) or not os.path.isdir(path):
                os.remove(path)
            else:
                shutil.rmtree(path)  # nie podąża za dowiązaniami wewnątrz katalogu
        except FileNotFoundError:
            pass
        except OSError:
            pass

    # --- ochrona przed cofaniem wersji (stan w katalogu roota)
    @property
    def _highest_file(self) -> str:
        return os.path.join(self.paths.state_dir, "highest.json")

    def highest_version(self) -> Optional[str]:
        """Najwyższa wersja kiedykolwiek zainstalowana (zapisywana przez roota)."""
        known = [_read_json(self._highest_file, {}).get("version")]
        cur = self.current_release()
        if cur:
            known.append(os.path.basename(cur))
        known = [v for v in known if v and VERSION_RE.match(v)]
        return max(known, key=_vt) if known else None

    def _remember_highest(self, version: str) -> None:
        best = self.highest_version()
        if best is None or _vt(version) >= _vt(best):
            _write_json(self._highest_file, {"version": version, "at": _now()})

    def run_request(self) -> Optional[Dict[str, Any]]:
        req = self.take_request()
        if not req:
            return None
        if req["action"] == "rollback":
            return self.rollback(req["requested_by"])
        return self.update(req["version"], req["requested_by"])

    # --- aktualizacja
    def update(self, version: str, requested_by: str = "") -> Dict[str, Any]:
        previous = self.current_release()
        from_version = os.path.basename(previous) if previous else None
        self.status = {"state": "running", "action": "update", "version": version, "from_version": from_version,
                       "requested_by": requested_by, "started_at": _now(), "finished_at": None}
        target = os.path.join(self.paths.releases_dir, version)
        staging = target + ".new"
        switched = False
        try:
            if from_version == version:
                raise UpdateError(f"Wersja {version} jest już zainstalowana.")
            # Tylko w górę: nawet poprawnie podpisana STARSZA wersja (ze znanymi lukami) nie zostanie zainstalowana
            highest = self.highest_version()
            if from_version and VERSION_RE.match(from_version) and _vt(version) <= _vt(from_version):
                raise UpdateError(f"Odrzucono instalację starszej wersji {version} (zainstalowana: {from_version}).")
            if highest and _vt(version) < _vt(highest):
                raise UpdateError(f"Odrzucono instalację wersji {version} starszej niż najnowsza zainstalowana ({highest}).")
            self._step("download")
            files = self.fetcher.fetch(version)
            self._step("verify")
            verify_release(files, version, self.paths.public_key)
            self._step("backup")
            self.ops.backup_data()
            self._step("install")
            shutil.rmtree(staging, ignore_errors=True)
            extract_release(files["tarball"], version, staging)
            self.ops.create_venv(staging)
            shutil.rmtree(target, ignore_errors=True)
            os.replace(staging, target)
            self._step("switch")
            self.ops.install_units(target)
            self.ops.activate(target)
            switched = True
            self.ops.restart()
            self._step("health")
            if not self.ops.health(version):
                raise UpdateError("Nowa wersja nie odpowiada poprawnie po restarcie.")
        except Exception as e:
            message = str(e) if isinstance(e, UpdateError) else f"{type(e).__name__}: {e}"
            rolled_back = False
            if switched and previous:
                try:
                    self.ops.activate(previous)
                    self.ops.restart()
                    rolled_back = True
                except Exception as e2:
                    message += f" | Powrót do poprzedniej wersji nie powiódł się: {e2}"
            shutil.rmtree(staging, ignore_errors=True)
            state = "rolled_back" if rolled_back else "failed"
            self._set(state=state, message=message + (f" Przywrócono wersję {from_version}." if rolled_back else ""),
                      finished_at=_now())
            self._history({"at": _now(), "action": "update", "from": from_version, "to": version, "result": state,
                           "message": message, "by": requested_by})
            return self.status

        self._remember_highest(version)
        self._set(state="success", message=f"Zaktualizowano do wersji {version}.", finished_at=_now())
        self._history({"at": _now(), "action": "update", "from": from_version, "to": version, "result": "success",
                       "by": requested_by})
        self.prune(keep=3)
        return self.status

    def rollback(self, requested_by: str = "") -> Dict[str, Any]:
        current = self.current_release()
        cur_version = os.path.basename(current) if current else None
        candidates = [v for v in UpdateBridge(self.paths).installed_versions() if v != cur_version]
        self.status = {"state": "running", "action": "rollback", "from_version": cur_version,
                       "requested_by": requested_by, "started_at": _now(), "finished_at": None}
        # Powrót tylko o jeden krok: z najnowszej wersji do tej, z której nastąpiła ostatnia udana aktualizacja.
        # Nie da się nim zejść do dowolnie starej wersji (ochrona przed wymuszeniem wersji ze znanymi lukami).
        hist = _read_json(self.paths.history_file, []) or []
        prev = next((h.get("from") for h in reversed(hist)
                     if h.get("action") == "update" and h.get("result") == "success"
                     and h.get("to") == cur_version and h.get("from") in candidates), None)
        highest = self.highest_version()
        if not prev or (highest and cur_version != highest):
            self._set(state="failed", finished_at=_now(),
                      message="Brak wersji do przywrócenia (powrót możliwy tylko raz – z najnowszej wersji "
                              "do wersji sprzed ostatniej aktualizacji).")
            return self.status
        target_version = prev
        self.status["version"] = target_version
        try:
            self._step("switch")
            self.ops.activate(os.path.join(self.paths.releases_dir, target_version))
            self.ops.restart()
            self._step("health")
            if not self.ops.health(target_version):
                raise UpdateError("Poprzednia wersja nie odpowiada po restarcie.")
        except Exception as e:
            if current:
                try:
                    self.ops.activate(current)
                    self.ops.restart()
                except Exception:
                    pass
            self._set(state="failed", message=f"Przywracanie nie powiodło się: {e}", finished_at=_now())
            self._history({"at": _now(), "action": "rollback", "from": cur_version, "to": target_version,
                           "result": "failed", "message": str(e), "by": requested_by})
            return self.status
        self._set(state="success", message=f"Przywrócono wersję {target_version}.", finished_at=_now())
        self._history({"at": _now(), "action": "rollback", "from": cur_version, "to": target_version,
                       "result": "success", "by": requested_by})
        return self.status

    def prune(self, keep: int = 3) -> None:
        """Usuwa najstarsze wersje (zostawia bieżącą i kilka poprzednich do ewentualnego powrotu)."""
        current = os.path.basename(self.current_release() or "")
        versions = UpdateBridge(self.paths).installed_versions()
        for v in versions[keep:]:
            if v != current:
                shutil.rmtree(os.path.join(self.paths.releases_dir, v), ignore_errors=True)


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    paths = UpdaterPaths.from_env(read_env_file("/etc/keystead/server.env").get("KS_DATA_DIR"))
    if argv[:1] == ["status"]:
        print(json.dumps(UpdateBridge(paths).status(), indent=2, ensure_ascii=False))
        return 0
    if argv[:1] != ["run"]:
        print("Użycie: python -m server.updater run|status")
        return 2
    os.makedirs(paths.state_dir, mode=0o755, exist_ok=True)
    lock_path = os.path.join(paths.state_dir, "lock")
    import fcntl as _fcntl
    with open(lock_path, "w") as lock:
        try:
            _fcntl.flock(lock, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except OSError:
            print("Aktualizator już działa.")
            return 1
        result = Updater(paths).run_request()
    if result:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("state") == "success" else 1
    print("Brak prośby o aktualizację.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
