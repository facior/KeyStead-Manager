"""
Powiadomienia administratora: e-mail (SMTP) oraz webhooki (Microsoft Teams, Slack, Discord, ntfy, dowolny JSON).

Zdarzenia z dziennika są wysyłane w tle; to samo zdarzenie najwyżej raz na 5 minut,
żeby seria nieudanych prób nie zalała skrzynki.
"""

import json
import logging
import smtplib
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

from server.settings import EVENT_LABELS, SettingsStore

log = logging.getLogger("keystead.notify")
THROTTLE_SECONDS = 300


def _describe(record: Dict[str, Any]) -> str:
    label = EVENT_LABELS.get(record.get("event", ""), record.get("event", "zdarzenie"))
    details = ", ".join(f"{k}={v}" for k, v in record.items() if k not in ("time", "event"))
    return f"{label}" + (f" ({details})" if details else "")


class Notifier:
    def __init__(self, settings: SettingsStore, server_name_getter=lambda: "KeyStead Server"):
        self.settings = settings
        self.server_name = server_name_getter
        self._last_sent: Dict[str, float] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ integracja z dziennikiem
    def on_audit_event(self, record: Dict[str, Any]) -> None:
        cfg = self.settings.section("notifications")
        event = record.get("event", "")
        if event not in cfg.get("events", []):
            return
        with self._lock:
            now = time.time()
            if now - self._last_sent.get(event, 0) < THROTTLE_SECONDS:
                return
            self._last_sent[event] = now
        self.send_async(f"{self.server_name()}: {_describe(record)}", record)

    def send_async(self, message: str, record: Optional[Dict[str, Any]] = None) -> None:
        threading.Thread(target=self.send, args=(message, record), daemon=True).start()

    # ------------------------------------------------------------ wysyłka
    def send(self, message: str, record: Optional[Dict[str, Any]] = None) -> List[Tuple[str, bool, str]]:
        """Wysyła na wszystkie włączone kanały. Zwraca [(kanał, sukces, opis)]."""
        cfg = self.settings.section("notifications")
        results = []
        if cfg["email"].get("enabled"):
            results.append(("e-mail",) + self._send_email(cfg["email"], message))
        if cfg["webhook"].get("enabled") and cfg["webhook"].get("url"):
            results.append(("webhook",) + self._send_webhook(cfg["webhook"], message, record or {}))
        for channel, ok, info in results:
            if not ok:
                log.warning("Powiadomienie (%s) nie zostało wysłane: %s", channel, info)
        return results

    def _send_email(self, cfg: Dict[str, Any], message: str, subject: str = "", to: Optional[List[str]] = None) -> Tuple[bool, str]:
        recipients = to or [r.strip() for r in str(cfg.get("recipients", "")).replace(";", ",").split(",") if r.strip()]
        if not cfg.get("smtp_host") or not recipients:
            return False, "brak serwera SMTP lub odbiorców"
        msg = EmailMessage()
        msg["Subject"] = subject or f"[{self.server_name()}] {message[:120]}"
        msg["From"] = cfg.get("sender") or cfg.get("username") or "keystead@localhost"
        msg["To"] = ", ".join(recipients)
        msg.set_content(message)
        try:
            port = int(cfg.get("smtp_port") or 587)
            context = ssl.create_default_context()
            if cfg.get("security") == "ssl":
                server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=15, context=context)
            else:
                server = smtplib.SMTP(cfg["smtp_host"], port, timeout=15)
                if cfg.get("security", "starttls") == "starttls":
                    server.starttls(context=context)
            with server:
                if cfg.get("username"):
                    server.login(cfg["username"], cfg.get("password", ""))
                server.send_message(msg)
            return True, "wysłano"
        except (OSError, smtplib.SMTPException) as e:
            return False, str(e)

    def send_email_to(self, to: str, subject: str, message: str) -> Tuple[bool, str]:
        """Pojedyncza wiadomość do wskazanego adresu (np. kod aktywacyjny dla użytkownika)."""
        cfg = self.settings.section("notifications")["email"]
        if not cfg.get("smtp_host"):
            return False, "Serwer SMTP nie jest skonfigurowany (Ustawienia → Powiadomienia)."
        return self._send_email(cfg, message, subject=subject, to=[to])

    def _send_webhook(self, cfg: Dict[str, Any], message: str, record: Dict[str, Any]) -> Tuple[bool, str]:
        kind = cfg.get("kind", "generic")
        headers = {"Content-Type": "application/json", "User-Agent": "KeyStead-Server"}
        if kind == "slack":
            body = json.dumps({"text": message})
        elif kind == "discord":
            body = json.dumps({"content": message[:1900]})
        elif kind == "teams":
            body = json.dumps({
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {"type": "AdaptiveCard", "version": "1.4",
                                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                "body": [{"type": "TextBlock", "text": message, "wrap": True}]},
                }],
            })
        elif kind == "ntfy":
            headers = {"Title": self.server_name(), "Tags": "lock", "User-Agent": "KeyStead-Server"}
            body = message
        else:
            body = json.dumps({"server": self.server_name(), "message": message, **record}, ensure_ascii=False)
        try:
            req = urllib.request.Request(cfg["url"], data=body.encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                return 200 <= resp.status < 300, f"HTTP {resp.status}"
        except Exception as e:  # urllib zgłasza różne wyjątki (HTTPError, URLError, ValueError)
            return False, str(e)
