"""
Pakiet zgodności (NIS2 / ustawa o KSC, RODO art. 32) – panel: Raport → „Raport zgodności” i „Polityka haseł”.

1. Raport zgodności (PDF) dla audytora: polityki, konta i dostęp, uwierzytelnianie wieloskładnikowe, higiena haseł,
   kopie zapasowe, rozliczalność (dziennik), kryptografia, aktualizacje oraz automatyczne zalecenia.
2. Polityka zarządzania hasłami (PDF) – dokument wewnętrzny wygenerowany z bieżących ustawień panelu,
   do zatwierdzenia i podpisania przez kierownictwo.

Raport opisuje stan techniczny systemu KeyStead – nie zawiera haseł ani nazw kont z sejfów
i nie stanowi opinii prawnej.
"""

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from server.report_pdf import _PL, _find_fonts, org_rows, org_summary

# Środki z art. 21 ust. 2 dyrektywy NIS2 (wdrażane w Polsce ustawą o krajowym systemie cyberbezpieczeństwa)
NIS2 = {
    "a": "art. 21 ust. 2 lit. a – polityki bezpieczeństwa systemów informacyjnych",
    "b": "art. 21 ust. 2 lit. b – obsługa incydentów",
    "c": "art. 21 ust. 2 lit. c – ciągłość działania, kopie zapasowe",
    "e": "art. 21 ust. 2 lit. e – bezpieczeństwo utrzymania systemów (aktualizacje)",
    "g": "art. 21 ust. 2 lit. g – cyberhigiena",
    "h": "art. 21 ust. 2 lit. h – kryptografia i szyfrowanie",
    "i": "art. 21 ust. 2 lit. i – kontrola dostępu, zasoby ludzkie, zarządzanie aktywami",
    "j": "art. 21 ust. 2 lit. j – uwierzytelnianie wieloskładnikowe",
}
SCORE_NAMES = {0: "bardzo słabe", 1: "słabe", 2: "średnie", 3: "silne", 4: "bardzo silne"}

EVENT_GROUPS = [
    ("Logowania do panelu administratora", ["admin_login"]),
    ("Nieudane logowania do panelu", ["admin_login_failed", "admin_setup_failed"]),
    ("Blokady po serii nieudanych prób", ["admin_login_blocked", "api_ip_blocked", "enroll_ip_blocked", "enroll_code_burned"]),
    ("Dodane urządzenia", ["device_enrolled"]),
    ("Odcięte urządzenia", ["device_revoked", "devices_revoked_all"]),
    ("Utworzone / zablokowane / usunięte konta", ["user_created", "user_disabled", "user_deleted"]),
    ("Odejścia pracowników", ["user_offboarded"]),
    ("Reset hasła / odzyskanie dostępu przez administratora", ["vault_password_reset_by_admin", "vault_recovered_by_admin"]),
    ("Zmiany ustawień i polityk", ["settings_changed", "recovery_settings_changed", "recovery_escrow_set", "recovery_escrow_removed"]),
    ("Zmiany administratorów", ["admin_created", "admin_invited", "admin_deleted", "admin_password_changed", "admin_reset"]),
    ("Kopie zapasowe wykonane / nieudane", ["backup_created", "backup_failed"]),
    ("Aktualizacje serwera", ["update_finished", "rollback_requested"]),
    ("Eksport dziennika i raportów", ["audit_exported", "report_pdf_downloaded", "compliance_report_downloaded"]),
]


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# --------------------------------------------------------------------- dane
def collect(ctx, period_days: int, server_version: str, tls: bool, public_url: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=period_days)).date().isoformat()
    cfg = ctx.settings.all()
    policy, recovery, backups_cfg = cfg["policy"], cfg["recovery"], cfg["backups"]
    rows = org_rows(ctx)
    summary = org_summary(rows)
    stale_limit = (now - timedelta(days=90)).isoformat()

    users = []
    for r in rows:
        devs = ctx.devices.list_for_user(r["user_id"])
        active = [d for d in devs if not d.get("revoked")]
        last_seen = max((d.get("last_seen") or "" for d in active), default="")
        users.append({**r, "stale_devices": sum(1 for d in active if (d.get("last_seen") or "") < stale_limit),
                      "last_seen": last_seen, "has_vault": bool(ctx.store.get_meta(r["user_id"]))})

    events = ctx.audit.search(limit=0, since=since)
    counts = Counter(e.get("event") for e in events)
    event_stats = [(label, sum(counts.get(k, 0) for k in keys)) for label, keys in EVENT_GROUPS]
    security_events = [e for e in events if e.get("event") in {
        "admin_login_blocked", "api_ip_blocked", "enroll_ip_blocked", "devices_revoked_all", "user_offboarded",
        "vault_password_reset_by_admin", "vault_recovered_by_admin", "recovery_escrow_set", "recovery_escrow_removed",
        "admin_created", "admin_deleted", "admin_reset", "backup_failed", "disk_low"}][:40]

    backups = ctx.backups.list()
    last_backup = _parse(backups[0]["created_at"]) if backups else None
    ops = ctx.ops_state.get()
    latest = (ops.get("latest_release") or {}).get("version")
    offboardings = [{"user_id": o["user_id"], "items": len(o.get("items", [])),
                     "todo": sum(1 for i in o.get("items", []) if i.get("status") == "todo"),
                     "started_at": o.get("started_at", "")} for o in ctx.offboarding.active()]

    data = {
        "generated_at": now, "period_days": period_days, "since": since,
        "company": cfg["branding"].get("company_name") or "", "server_version": server_version, "latest_version": latest,
        "tls": tls, "public_url": public_url,
        "policy": policy, "recovery": {"enabled": bool(recovery.get("enabled") and recovery.get("public_key")),
                                       "escrow": bool(recovery.get("escrow"))},
        "backups": {"enabled": bool(backups_cfg.get("enabled")), "hour": backups_cfg.get("hour"),
                    "keep": backups_cfg.get("keep"), "count": len(backups), "last": last_backup,
                    "last_ok": (ops.get("last_backup") or {}).get("ok", True),
                    "history": cfg["general"].get("max_history")},
        "users": users, "summary": summary, "admins": ctx.admins.list(),
        "event_stats": event_stats, "security_events": security_events, "offboardings": offboardings,
    }
    data["findings"] = findings(data, now)
    return data


def findings(d: Dict[str, Any], now: datetime) -> List[Tuple[str, str, str]]:
    """(waga, ustalenie, zalecenie) – automatyczne wnioski z ustawień i stanu systemu."""
    out: List[Tuple[str, str, str]] = []
    p, s, b = d["policy"], d["summary"], d["backups"]
    active_users = [u for u in d["users"] if not u["disabled"]]
    no_2fa = [u for u in active_users if not u["has_2fa"]]
    if not p.get("require_user_2fa") and no_2fa:
        out.append(("wysoka", f"{len(no_2fa)} aktywnych kont bez drugiego składnika (2FA) przy dodawaniu urządzeń.",
                    "Włącz w Ustawieniach „Wymagaj 2FA użytkownika przy dodawaniu nowych urządzeń”."))
    if not b["enabled"]:
        out.append(("wysoka", "Automatyczne kopie zapasowe serwera są wyłączone.", "Włącz codzienne kopie w zakładce Kopie."))
    elif not b["last"] or now - b["last"] > timedelta(hours=48) or not b["last_ok"]:
        out.append(("wysoka", "Brak udanej kopii zapasowej serwera z ostatnich 48 godzin.",
                    "Sprawdź zakładkę Kopie i miejsce na dysku; wykonaj kopię ręcznie."))
    out.append(("średnia", "Kopie zapasowe są przechowywane na tym samym serwerze co dane.",
                "Regularnie kopiuj pliki kopii poza serwer (inny dysk, NAS lub chmura) – zasada 3-2-1."))
    if s.get("breached"):
        out.append(("wysoka", f"{s['breached']} haseł występuje w znanych wyciekach danych.",
                    "Poproś użytkowników o zmianę tych haseł (Raport → „Kto wymaga uwagi”)."))
    if int(p.get("min_master_score") or 0) < 2:
        out.append(("średnia", "Minimalna siła hasła głównego jest niższa niż „średnie”.",
                    "Ustaw minimalną siłę hasła głównego na co najmniej „średnie”."))
    if not p.get("max_auto_lock_minutes") or int(p.get("max_auto_lock_minutes")) > 15:
        out.append(("średnia", "Automatyczna blokada sejfu jest dłuższa niż 15 minut lub nieograniczona.",
                    "Ogranicz maksymalny czas do automatycznej blokady do 15 minut lub krócej."))
    if p.get("allow_never_lock"):
        out.append(("średnia", "Użytkownicy mogą całkowicie wyłączyć automatyczną blokadę.", "Wyłącz opcję „Nigdy”."))
    if not d["recovery"]["enabled"]:
        out.append(("niska", "Odzyskiwanie dostępu przez firmę jest wyłączone.",
                    "Włącz odzyskiwanie (Ustawienia → Odzyskiwanie dostępu), aby nie tracić danych po zapomnieniu hasła."))
    stale = sum(u["stale_devices"] for u in active_users)
    if stale:
        out.append(("niska", f"{stale} urządzeń nie łączyło się z serwerem od ponad 90 dni.",
                    "Odetnij nieużywane urządzenia na kartach użytkowników."))
    if d["offboardings"]:
        left = sum(o["todo"] for o in d["offboardings"])
        out.append(("średnia", f"Niezakończone odejścia pracowników: {len(d['offboardings'])} ({left} haseł do zmiany).",
                    "Dokończ zmianę haseł na kartach odchodzących pracowników."))
    if d["latest_version"] and d["latest_version"] != d["server_version"]:
        out.append(("średnia", f"Dostępna nowsza wersja serwera ({d['latest_version']}).", "Zaktualizuj serwer z panelu."))
    if not d["tls"]:
        out.append(("wysoka", "Panel i API nie korzystają z szyfrowanego połączenia HTTPS.",
                    "Uruchom serwer z certyfikatem TLS lub przez Tailscale (HTTPS)."))
    missing = sum(1 for u in active_users if not u.get("report"))
    if missing:
        out.append(("niska", f"{missing} aktywnych kont nie przesłało raportu bezpieczeństwa haseł.",
                    "Upewnij się, że użytkownicy korzystają z aktualnej aplikacji i że zbieranie raportów jest włączone."))
    order = {"wysoka": 0, "średnia": 1, "niska": 2}
    return sorted(out, key=lambda f: order[f[0]])


# --------------------------------------------------------------------- PDF – wspólne
class _Doc:
    def __init__(self, title: str, subtitle: str):
        from fpdf import FPDF
        self.fonts = _find_fonts()
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=16)
        pdf.set_margins(14, 14, 14)
        if self.fonts:
            pdf.add_font("Body", "", self.fonts[0])
            pdf.add_font("Body", "B", self.fonts[1])
            self.family = "Body"
        else:
            self.family = "Helvetica"
        pdf.set_title(self.t(title))
        pdf.set_creator("KeyStead Server")
        pdf.add_page()
        pdf.set_fill_color(79, 70, 229)
        pdf.rect(0, 0, 210, 30, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(self.family, "B", 17)
        pdf.set_xy(14, 7)
        pdf.cell(0, 9, self.t(title))
        pdf.set_font(self.family, "", 9.5)
        pdf.set_xy(14, 18)
        pdf.cell(0, 6, self.t(subtitle))
        pdf.set_text_color(30, 41, 59)
        pdf.set_y(38)
        self.pdf = pdf

    def t(self, text: Any) -> str:
        text = str(text)
        return text if self.fonts else text.translate(_PL).encode("latin-1", "replace").decode("latin-1")

    def h(self, text: str, ref: str = ""):
        pdf = self.pdf
        if pdf.get_y() > 255:
            pdf.add_page()
        pdf.ln(3)
        pdf.set_font(self.family, "B", 12.5)
        pdf.set_text_color(49, 46, 129)
        pdf.cell(0, 7, self.t(text), new_x="LMARGIN", new_y="NEXT")
        if ref:
            pdf.set_font(self.family, "", 7.5)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 4, self.t(ref), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 41, 59)
        pdf.ln(1)

    def p(self, text: str, size: float = 9.5, muted: bool = False):
        self.pdf.set_font(self.family, "", size)
        self.pdf.set_text_color(100, 116, 139) if muted else self.pdf.set_text_color(30, 41, 59)
        self.pdf.multi_cell(0, size * 0.5, self.t(text), new_x="LMARGIN", new_y="NEXT", align="L")
        self.pdf.set_text_color(30, 41, 59)

    def kv(self, rows: List[Tuple[str, str]]):
        pdf = self.pdf
        for label, value in rows:
            pdf.set_font(self.family, "", 9)
            pdf.set_text_color(100, 116, 139)
            y = pdf.get_y()
            pdf.multi_cell(78, 5, self.t(label), new_x="RIGHT", new_y="TOP", align="L")
            pdf.set_text_color(30, 41, 59)
            pdf.set_font(self.family, "B", 9)
            pdf.multi_cell(0, 5, self.t(value), new_x="LMARGIN", new_y="NEXT", align="L")
            pdf.set_y(max(pdf.get_y(), y + 5))

    def table(self, cols: List[Tuple[str, float]], rows: List[List[Any]], highlight=None):
        pdf = self.pdf
        pdf.set_font(self.family, "B", 8)
        pdf.set_fill_color(226, 232, 240)
        for name, width in cols:
            pdf.cell(width, 6.5, self.t(name), fill=True)
        pdf.ln()
        pdf.set_font(self.family, "", 8)
        for i, row in enumerate(rows):
            if pdf.get_y() > 275:
                pdf.add_page()
            pdf.set_fill_color(248, 250, 252) if i % 2 else pdf.set_fill_color(255, 255, 255)
            for (name, width), value in zip(cols, row):
                red = highlight and highlight(name, value)
                pdf.set_text_color(225, 29, 72) if red else pdf.set_text_color(30, 41, 59)
                text = self.t(value)
                while text and pdf.get_string_width(text) > width - 1.5:
                    text = text[:-2] + "…" if len(text) > 2 else ""
                pdf.cell(width, 6, text, fill=True)
            pdf.ln()
        pdf.set_text_color(30, 41, 59)
        if not rows:
            pdf.cell(0, 6, self.t("brak"), new_x="LMARGIN", new_y="NEXT")

    def findings(self, items: List[Tuple[str, str, str]]):
        """Ustalenia jako karty: waga (kolor), opis i zalecenie – pełny tekst, bez ucinania."""
        pdf = self.pdf
        colors = {"wysoka": (225, 29, 72), "średnia": (217, 119, 6), "niska": (100, 116, 139)}
        pdf.ln(1)
        for weight, issue, advice in items:
            if pdf.get_y() > 262:
                pdf.add_page()
            y = pdf.get_y()
            pdf.set_fill_color(*colors.get(weight, (100, 116, 139)))
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(self.family, "B", 7.5)
            pdf.set_xy(14, y + 0.6)
            pdf.cell(17, 4.6, self.t(weight.upper()), fill=True, align="C")
            pdf.set_text_color(30, 41, 59)
            pdf.set_font(self.family, "B", 9)
            pdf.set_xy(34, y)
            pdf.multi_cell(0, 5, self.t(issue), new_x="LMARGIN", new_y="NEXT", align="L")
            pdf.set_x(34)
            pdf.set_font(self.family, "", 8.5)
            pdf.set_text_color(71, 85, 105)
            pdf.multi_cell(0, 4.6, self.t("Zalecenie: " + advice), new_x="LMARGIN", new_y="NEXT", align="L")
            pdf.set_text_color(30, 41, 59)
            pdf.ln(1.8)

    def output(self) -> bytes:
        return bytes(self.pdf.output())


def _yes(v) -> str:
    return "tak" if v else "nie"


def _limit(v, unit: str) -> str:
    return "bez limitu" if not v else f"{v} {unit}"


def _dt(d: Optional[datetime]) -> str:
    return d.astimezone().strftime("%d.%m.%Y %H:%M") if d else "—"


# --------------------------------------------------------------------- 1. raport zgodności
def build_compliance_pdf(d: Dict[str, Any]) -> bytes:
    p, s, b = d["policy"], d["summary"], d["backups"]
    company = d["company"] or "Organizacja"
    doc = _Doc("Raport zgodności – zarządzanie hasłami",
               f"{company}  ·  okres: ostatnie {d['period_days']} dni  ·  wygenerowano {_dt(d['generated_at'])}")
    doc.p("Raport opisuje stan techniczny i organizacyjny systemu zarządzania hasłami KeyStead jako dowód stosowania "
          "środków z art. 21 dyrektywy NIS2 (ustawa o krajowym systemie cyberbezpieczeństwa) oraz art. 32 RODO. "
          "Nie zawiera haseł ani nazw kont zapisanych w sejfach – serwer ich nie zna (szyfrowanie end-to-end).", 9, True)

    doc.h("1. Podsumowanie i zalecenia")
    high = sum(1 for f in d["findings"] if f[0] == "wysoka")
    doc.kv([("Aktywne konta / wszystkie", f"{s['active_users']} / {s['users']}"),
            ("Średni wynik higieny haseł", f"{s['avg_score']}/100" if s["avg_score"] is not None else "brak raportów"),
            ("Ustalenia o wysokiej wadze", str(high))])
    if d["findings"]:
        doc.findings(d["findings"])
    else:
        doc.p("Brak ustaleń – konfiguracja zgodna z zaleceniami.", 9)

    doc.h("2. Polityka haseł i dostępu (wymuszana w aplikacji)", NIS2["a"] + "; " + NIS2["i"])
    doc.kv([
        ("Minimalna siła hasła głównego", SCORE_NAMES.get(int(p.get("min_master_score") or 0), "—")),
        ("Automatyczna blokada sejfu (maks.)", _limit(p.get("max_auto_lock_minutes"), "min")),
        ("Możliwość wyłączenia blokady", _yes(p.get("allow_never_lock"))),
        ("Czyszczenie schowka (maks.)", _limit(p.get("max_clipboard_seconds"), "s")),
        ("Praca bez połączenia z serwerem (maks.)", _limit(p.get("max_offline_hours"), "godz.")),
        ("Limit urządzeń na użytkownika", _limit(p.get("max_devices_per_user"), "")),
        ("Prywatne kopie sejfu (USB, prywatne chmury)", "dozwolone" if p.get("allow_personal_backups") else "zablokowane"),
        ("Odzyskiwanie dostępu przez firmę", "włączone" + (" (klucz na serwerze, hasło działu IT)" if d["recovery"]["escrow"] else "")
         if d["recovery"]["enabled"] else "wyłączone"),
    ])

    doc.h("3. Uwierzytelnianie wieloskładnikowe", NIS2["j"])
    doc.kv([
        ("Administratorzy panelu", "hasło + kod TOTP (obowiązkowo dla każdego konta)"),
        ("2FA wymagane przy dodawaniu urządzenia", _yes(p.get("require_user_2fa"))),
        ("Konta użytkowników z włączonym 2FA", f"{s['users_2fa']} / {s['users']}"),
        ("Odblokowanie Windows Hello (biometria/PIN)", ("dozwolone, hasło główne co " + str(p.get("quick_unlock_days")) + " dni")
         if p.get("allow_quick_unlock") else "zablokowane"),
        ("Urządzenia", "każde urządzenie aktywowane jednorazowym kodem od administratora; dostęp można odciąć w każdej chwili"),
    ])

    doc.h("4. Konta, urządzenia i uprawnienia", NIS2["i"])
    doc.table([("Użytkownik", 52), ("Stan", 22), ("2FA", 12), ("Urządz.", 15), ("Nieakt. >90 d", 22), ("Wynik", 15), ("Ostatnia aktywność", 44)],
              [[u["name"], "zablokowane" if u["disabled"] else "aktywne", _yes(u["has_2fa"]), u["devices"], u["stale_devices"],
                (u.get("report") or {}).get("score", "—"), _dt(_parse(u["last_seen"]))] for u in d["users"]],
              highlight=lambda n, v: (n == "2FA" and v == "nie") or (n == "Nieakt. >90 d" and isinstance(v, int) and v > 0))
    doc.pdf.ln(2)
    doc.table([("Administrator", 60), ("Rola", 50), ("Utworzono", 72)],
              [[a["username"], "administrator" if a["role"] == "admin" else "pomoc techniczna", (a.get("created_at") or "")[:10]]
               for a in d["admins"]])
    if d["offboardings"]:
        doc.pdf.ln(2)
        doc.p("Odejścia pracowników w toku (lista haseł do zmiany):", 9)
        doc.table([("Konto", 70), ("Rozpoczęte", 50), ("Pozycji", 30), ("Do zmiany", 32)],
                  [[o["user_id"], o["started_at"][:10], o["items"], o["todo"]] for o in d["offboardings"]])

    doc.h("5. Higiena haseł (cyberhigiena)", NIS2["g"])
    doc.p("Dane z audytów wykonywanych lokalnie w aplikacjach (wyłącznie liczby).", 8.5, True)
    doc.kv([("Hasła w znanych wyciekach (HIBP)", str(s["breached"])), ("Hasła słabe", str(s["weak"])),
            ("Hasła powtórzone", str(s["reused"])), ("Hasła niezmieniane > 180 dni", str(s["stale"])),
            ("Konta bez 2FA w serwisach, które je oferują", str(s["missing_totp"])),
            ("Użytkownicy z raportem", f"{s['reports']} / {s['users']}")])

    doc.h("6. Kopie zapasowe i ciągłość działania", NIS2["c"])
    doc.kv([("Automatyczne kopie serwera", f"codziennie o {b['hour']}:00, przechowywanych {b['keep']} kopii" if b["enabled"] else "wyłączone"),
            ("Liczba kopii / ostatnia kopia", f"{b['count']} / {_dt(b['last'])}"),
            ("Historia wersji sejfu użytkownika", f"{b['history']} ostatnich wersji + ostatnia z każdego z 30 dni"),
            ("Przywracanie", "dowolnej wersji sejfu z panelu; całego serwera z kopii (kopie zawierają tylko dane zaszyfrowane)")])

    doc.h("7. Kryptografia", NIS2["h"] + "; RODO art. 32 ust. 1 lit. a")
    doc.kv([("Szyfrowanie sejfów", "AES-256-GCM, klucz z hasła głównego: Argon2id (64 MB, 3 iteracje)"),
            ("Model", "end-to-end: szyfrowanie na urządzeniu użytkownika, serwer przechowuje wyłącznie szyfrogram"),
            ("Załączniki", "osobny klucz AES-256-GCM dla każdego pliku"),
            ("Połączenie z serwerem", "HTTPS (TLS)" + (f" – {d['public_url']}" if d["public_url"] else "") if d["tls"] else "BEZ szyfrowania TLS"),
            ("Odzyskiwanie przez firmę", "klucz X25519 firmy (dostęp wymaga hasła działu IT lub pliku klucza)")])

    doc.h("8. Utrzymanie i aktualizacje", NIS2["e"])
    doc.kv([("Wersja serwera", d["server_version"] + (f" (dostępna {d['latest_version']})" if d["latest_version"] and d["latest_version"] != d["server_version"] else " (aktualna)")),
            ("Weryfikacja aktualizacji", "podpis Ed25519 każdego wydania serwera i aplikacji; blokada instalacji starszych wersji")])

    doc.h("9. Rozliczalność – dziennik zdarzeń", NIS2["b"] + "; RODO art. 5 ust. 2")
    since_pl = ".".join(reversed(d["since"].split("-")))
    doc.p(f"Zdarzenia od {since_pl} (dziennik niezmienialny z poziomu panelu, eksport CSV w zakładce Dziennik).", 8.5, True)
    doc.table([("Rodzaj zdarzenia", 140), ("Liczba", 42)], [[label, n] for label, n in d["event_stats"]])
    if d["security_events"]:
        doc.pdf.ln(2)
        doc.p("Zdarzenia istotne dla bezpieczeństwa (najnowsze):", 9)
        doc.table([("Czas", 34), ("Zdarzenie", 58), ("Kto", 40), ("Szczegóły", 50)],
                  [[e.get("time", "")[:16].replace("T", " "), e.get("event", ""), e.get("actor", ""),
                    ", ".join(f"{k}={v}" for k, v in e.items() if k not in ("time", "event", "actor", "ip"))]
                   for e in d["security_events"]])

    doc.pdf.ln(4)
    doc.p("Raport wygenerowany automatycznie przez KeyStead Server na podstawie bieżącej konfiguracji i dziennika zdarzeń. "
          "Stanowi materiał dowodowy dla audytu i nie zastępuje oceny ryzyka ani opinii prawnej.", 7.5, True)
    return doc.output()


# --------------------------------------------------------------------- 2. polityka haseł
def build_policy_pdf(d: Dict[str, Any]) -> bytes:
    p = d["policy"]
    company = d["company"] or "[nazwa organizacji]"
    doc = _Doc("Polityka zarządzania hasłami", f"{company}  ·  wersja z {d['generated_at'].astimezone():%d.%m.%Y}")

    sections = [
        ("§1. Cel i zakres",
         f"Polityka określa zasady tworzenia, przechowywania i udostępniania haseł w {company}. Obowiązuje wszystkich "
         "pracowników i współpracowników korzystających z systemów organizacji. Wspiera realizację środków z art. 21 "
         "dyrektywy NIS2 (ustawa o krajowym systemie cyberbezpieczeństwa) oraz art. 32 RODO."),
        ("§2. Menedżer haseł",
         "Hasła służbowe przechowuje się wyłącznie w menedżerze haseł KeyStead Manager połączonym z serwerem organizacji. "
         "Zabrania się zapisywania haseł w plikach, notatkach, przeglądarkach internetowych, na kartkach oraz przesyłania ich "
         "pocztą e-mail lub komunikatorami. Sejf jest szyfrowany na urządzeniu użytkownika (AES-256-GCM, Argon2id)."),
        ("§3. Hasło główne",
         f"Hasło główne do sejfu musi mieć siłę co najmniej „{SCORE_NAMES.get(int(p.get('min_master_score') or 0), 'średnie')}” "
         "według miernika aplikacji, nie może być używane w żadnym innym miejscu i jest znane wyłącznie użytkownikowi. "
         "Zaleca się frazę złożoną z kilku losowych słów. Hasło słabsze od wymaganego trzeba zmienić przy najbliższym odblokowaniu."),
        ("§4. Hasła do systemów i serwisów",
         "Hasła do kont służbowych generuje się w menedżerze haseł jako losowe (min. 16 znaków), unikalne dla każdego systemu. "
         "Tam, gdzie serwis to umożliwia, włącza się uwierzytelnianie dwuskładnikowe (kody TOTP mogą być przechowywane w sejfie). "
         "Hasła wskazane przez aplikację jako ujawnione w wyciekach lub powtórzone należy niezwłocznie zmienić."),
        ("§5. Ochrona sejfu",
         f"Sejf blokuje się automatycznie po maksymalnie {_limit(p.get('max_auto_lock_minutes'), 'minutach')} bezczynności"
         + ("" if not p.get("allow_never_lock") else " (użytkownik może wyłączyć blokadę – zalecane jest jej pozostawienie)")
         + f" oraz przy blokadzie komputera. Skopiowane hasła są usuwane ze schowka po {_limit(p.get('max_clipboard_seconds'), 's')}. "
         f"Praca bez połączenia z serwerem jest możliwa przez maksymalnie {_limit(p.get('max_offline_hours'), 'godz.')}."
         + (f" Odblokowanie Windows Hello jest dozwolone, przy czym hasło główne należy wpisać co {p.get('quick_unlock_days')} dni."
            if p.get("allow_quick_unlock") else " Odblokowanie biometryczne (Windows Hello) jest niedozwolone.")),
        ("§6. Urządzenia",
         f"Dostęp do sejfu mają wyłącznie urządzenia aktywowane jednorazowym kodem wydanym przez administratora "
         f"(limit: {_limit(p.get('max_devices_per_user'), 'urządzeń na osobę')})."
         + (" Dodanie urządzenia wymaga kodu z aplikacji uwierzytelniającej (2FA)." if p.get("require_user_2fa") else "")
         + " Utratę lub kradzież urządzenia należy niezwłocznie zgłosić administratorowi, który odcina jego dostęp."),
        ("§7. Kopie zapasowe",
         "Serwer wykonuje automatyczne, zaszyfrowane kopie zapasowe i przechowuje historię wersji sejfów. "
         + ("Użytkownicy mogą dodatkowo wykonywać prywatne kopie sejfu (wyłącznie w postaci zaszyfrowanej)."
            if p.get("allow_personal_backups") else "Wykonywanie prywatnych kopii sejfu (USB, prywatne chmury) jest zabronione.")),
        ("§8. Odzyskiwanie dostępu",
         ("W razie utraty hasła głównego dostęp przywraca administrator działu IT kluczem odzyskiwania organizacji. "
          "Użytkownik otrzymuje hasło tymczasowe i ma obowiązek niezwłocznie ustawić własne hasło główne. "
          "Każde odzyskanie dostępu jest odnotowywane w dzienniku zdarzeń.")
         if d["recovery"]["enabled"] else
         "Organizacja nie przechowuje klucza odzyskiwania – utrata hasła głównego oznacza utratę sejfu. Użytkownik może utworzyć "
         "osobisty kod odzyskiwania i przechowywać go w bezpiecznym miejscu."),
        ("§9. Zakończenie współpracy",
         "Przy odejściu pracownika administrator niezwłocznie blokuje jego konto i odcina wszystkie urządzenia, przekazuje "
         "wpisy następcy oraz zmienia hasła do systemów, które były znane pracownikowi, zgodnie z listą kontrolną w panelu "
         "administratora. Zakończenie procesu jest odnotowywane w dzienniku zdarzeń."),
        ("§10. Monitorowanie i incydenty",
         "Panel administratora rejestruje logowania, zmiany uprawnień, aktywacje i odcięcia urządzeń oraz operacje na sejfach. "
         "Podejrzenie ujawnienia hasła lub przejęcia urządzenia należy zgłosić niezwłocznie; administrator może natychmiast "
         "odciąć wszystkie urządzenia (tryb awaryjny). Raport zgodności jest generowany co najmniej raz na kwartał."),
        ("§11. Postanowienia końcowe",
         "Polityka wchodzi w życie z dniem zatwierdzenia i podlega przeglądowi co najmniej raz w roku oraz po każdej istotnej "
         "zmianie konfiguracji systemu. Naruszenie zasad polityki może skutkować konsekwencjami służbowymi."),
    ]
    for title, text in sections:
        doc.h(title)
        doc.p(re.sub(r"(?<!\.)\.\.(?!\.)", ".", text), 9.5)  # „Sp. z o.o.” / „godz.” na końcu zdania

    doc.pdf.ln(10)
    doc.p("Zatwierdził(a):  ......................................................      Data:  ....................", 9.5)
    doc.pdf.ln(4)
    doc.p("Dokument wygenerowany z bieżących ustawień serwera KeyStead – wartości liczbowe odpowiadają polityce wymuszanej "
          "w aplikacji. Przed zatwierdzeniem dostosuj treść do potrzeb organizacji.", 7.5, True)
    return doc.output()
