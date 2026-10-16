"""
Raport bezpieczeństwa firmy w PDF (panel: Raporty → Pobierz raport PDF).

Zawiera wyłącznie liczby z raportów aplikacji (wynik, wycieki, słabe/powtórzone hasła) i stan kont –
nigdy haseł ani nazw kont w sejfach. Trend liczony jest z codziennych podsumowań zapisywanych przez serwer.
"""

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/dejavu/DejaVuSans.ttf", "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
]
_PL = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ–—„”“’…", "acelnoszzACELNOSZZ--\"\"\"'.")


# --------------------------------------------------------------------- dane
def org_rows(ctx) -> List[Dict[str, Any]]:
    day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    rows = []
    for u in ctx.users.list():
        devs = [d for d in ctx.devices.list_for_user(u["user_id"]) if not d.get("revoked")]
        rows.append({
            "user_id": u["user_id"], "name": u.get("display_name") or u["user_id"], "disabled": bool(u.get("disabled")),
            "devices": len(devs), "active_24h": sum(1 for d in devs if (d.get("last_seen") or "") >= day_ago),
            "has_2fa": ctx.users.has_totp(u["user_id"]), "report": ctx.reports.get(u["user_id"]),
        })
    return rows


def org_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    reports = [r["report"] for r in rows if r.get("report")]

    def total(key):
        return sum(int(r.get(key, 0)) for r in reports)
    return {
        "users": len(rows), "active_users": sum(1 for r in rows if not r["disabled"]),
        "reports": len(reports),
        "avg_score": round(sum(int(r.get("score", 0)) for r in reports) / len(reports)) if reports else None,
        "breached": total("breached"), "reused": total("reused"), "weak": total("weak"),
        "missing_totp": total("missing_totp"), "stale": total("stale"),
        "devices": sum(r["devices"] for r in rows), "users_2fa": sum(1 for r in rows if r["has_2fa"]),
    }


class ReportHistory:
    """Codzienne podsumowanie (data_dir/report_history.json) – źródło wykresu trendu."""

    def __init__(self, data_dir: str, keep_days: int = 400):
        self.path = os.path.join(data_dir, "report_history.json")
        self.keep_days = keep_days
        self._lock = threading.Lock()

    def load(self) -> List[Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [d for d in data if isinstance(d, dict) and "date" in d] if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def record(self, summary: Dict[str, Any], day: Optional[str] = None) -> None:
        day = day or datetime.now().strftime("%Y-%m-%d")
        with self._lock:
            items = [d for d in self.load() if d["date"] != day]
            items.append({"date": day, **summary})
            items.sort(key=lambda d: d["date"])
            items = items[-self.keep_days:]
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(items, f)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)


# --------------------------------------------------------------------- PDF
def _find_fonts():
    for regular, bold in FONT_CANDIDATES:
        if os.path.isfile(regular) and os.path.isfile(bold):
            return regular, bold
    return None


def build_pdf(company: str, rows: List[Dict[str, Any]], history: List[Dict[str, Any]],
              server_version: str = "") -> bytes:
    from fpdf import FPDF

    fonts = _find_fonts()
    summary = org_summary(rows)

    def t(text: Any) -> str:
        text = str(text)
        return text if fonts else text.translate(_PL).encode("latin-1", "replace").decode("latin-1")

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    if fonts:
        pdf.add_font("Body", "", fonts[0])
        pdf.add_font("Body", "B", fonts[1])
        family = "Body"
    else:
        family = "Helvetica"
    pdf.set_title(t(f"Raport bezpieczeństwa – {company or 'KeyStead'}"))
    pdf.set_creator("KeyStead Server")
    pdf.add_page()

    # Nagłówek
    pdf.set_fill_color(79, 70, 229)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font(family, "B", 18)
    pdf.set_xy(12, 7)
    pdf.cell(0, 9, t("Raport bezpieczeństwa haseł"))
    pdf.set_font(family, "", 10)
    pdf.set_xy(12, 17)
    pdf.cell(0, 6, t(f"{company or 'KeyStead Server'}  ·  wygenerowano {datetime.now():%d.%m.%Y %H:%M}"))
    pdf.set_text_color(30, 41, 59)
    pdf.set_y(36)

    # Kafelki
    tiles = [
        ("Średni wynik", f"{summary['avg_score']}/100" if summary["avg_score"] is not None else "—"),
        ("Użytkownicy", f"{summary['active_users']} / {summary['users']}"),
        ("Hasła w wyciekach", str(summary["breached"])),
        ("Słabe / powtórzone", f"{summary['weak']} / {summary['reused']}"),
        ("Konta z 2FA (urządzenia)", f"{summary['users_2fa']} / {summary['users']}"),
        ("Raporty od aplikacji", f"{summary['reports']} / {summary['users']}"),
    ]
    x0, y0, w, h = 12, pdf.get_y(), 60, 20
    for i, (label, value) in enumerate(tiles):
        x, y = x0 + (i % 3) * (w + 3), y0 + (i // 3) * (h + 3)
        pdf.set_fill_color(241, 245, 249)
        pdf.rect(x, y, w, h, "F")
        pdf.set_xy(x + 3, y + 2.5)
        pdf.set_font(family, "", 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(w - 6, 5, t(label.upper()))
        pdf.set_xy(x + 3, y + 8.5)
        pdf.set_font(family, "B", 15)
        danger = label == "Hasła w wyciekach" and summary["breached"]
        pdf.set_text_color(225, 29, 72) if danger else pdf.set_text_color(30, 41, 59)
        pdf.cell(w - 6, 9, t(value))
    pdf.set_text_color(30, 41, 59)
    pdf.set_y(y0 + 2 * (h + 3) + 4)

    # Trend
    pdf.set_font(family, "B", 12)
    pdf.cell(0, 8, t("Trend średniego wyniku (ostatnie 90 dni)"), new_x="LMARGIN", new_y="NEXT")
    points = [(d["date"], d.get("avg_score")) for d in history[-90:] if d.get("avg_score") is not None]
    cx, cy, cw, ch = 14, pdf.get_y() + 2, 182, 42
    pdf.set_draw_color(203, 213, 225)
    pdf.rect(cx, cy, cw, ch)
    pdf.set_font(family, "", 7)
    pdf.set_text_color(100, 116, 139)
    for level in (0, 50, 100):
        ly = cy + ch - ch * level / 100
        pdf.set_draw_color(226, 232, 240)
        pdf.line(cx, ly, cx + cw, ly)
        pdf.set_xy(cx - 9, ly - 2)
        pdf.cell(8, 4, str(level), align="R")
    if len(points) >= 2:
        pdf.set_draw_color(79, 70, 229)
        pdf.set_line_width(0.6)
        step = cw / (len(points) - 1)
        coords = [(cx + i * step, cy + ch - ch * max(0, min(100, int(s))) / 100) for i, (_, s) in enumerate(points)]
        for (ax, ay), (bx, by) in zip(coords, coords[1:]):
            pdf.line(ax, ay, bx, by)
        pdf.set_line_width(0.2)
        for label_i in (0, len(points) - 1):
            d = points[label_i][0]
            pdf.set_xy(coords[label_i][0] - 10, cy + ch + 1)
            pdf.cell(20, 4, f"{d[8:10]}.{d[5:7]}", align="C")
    else:
        pdf.set_xy(cx, cy + ch / 2 - 3)
        pdf.cell(cw, 6, t("Za mało danych – trend pojawi się po kilku dniach działania serwera."), align="C")
    pdf.set_text_color(30, 41, 59)
    pdf.set_y(cy + ch + 9)

    # Tabela użytkowników (najsłabsze wyniki najpierw)
    pdf.set_font(family, "B", 12)
    pdf.cell(0, 8, t("Użytkownicy"), new_x="LMARGIN", new_y="NEXT")
    cols = [("Użytkownik", 58), ("Wynik", 18), ("Wycieki", 18), ("Słabe", 16), ("Powt.", 16), ("Stare", 16),
            ("2FA", 14), ("Urządz.", 16), ("Raport", 14)]
    pdf.set_font(family, "B", 8)
    pdf.set_fill_color(226, 232, 240)
    for name, width in cols:
        pdf.cell(width, 7, t(name), border=0, fill=True, align="C" if name != "Użytkownik" else "L")
    pdf.ln()
    pdf.set_font(family, "", 8)
    ordered = sorted(rows, key=lambda r: (r["report"] is None, (r["report"] or {}).get("score", 0)))
    for i, r in enumerate(ordered):
        rep = r["report"] or {}
        pdf.set_fill_color(248, 250, 252) if i % 2 else pdf.set_fill_color(255, 255, 255)
        name = r["name"] + (" (zablokowane)" if r["disabled"] else "")
        values = [name[:40], rep.get("score", "—"), rep.get("breached", "—"), rep.get("weak", "—"),
                  rep.get("reused", "—"), rep.get("stale", "—"), "tak" if r["has_2fa"] else "nie", r["devices"],
                  (rep.get("received_at") or "—")[:10]]
        for (col, width), value in zip(cols, values):
            if col == "Wycieki" and isinstance(value, int) and value:
                pdf.set_text_color(225, 29, 72)
            pdf.cell(width, 6.5, t(value), fill=True, align="L" if col == "Użytkownik" else "C")
            pdf.set_text_color(30, 41, 59)
        pdf.ln()
    if not rows:
        pdf.cell(0, 7, t("Brak użytkowników."), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font(family, "", 7)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(0, 4, t(
        "Raport zawiera wyłącznie liczby przesłane przez aplikacje KeyStead Manager (audyt sejfu wykonywany lokalnie na "
        "komputerze użytkownika). Serwer nie zna haseł ani nazw kont zapisanych w sejfach. Wynik 0–100: kary za hasła "
        f"w wyciekach, powtórzone, słabe, bez 2FA i niezmieniane ponad 180 dni. KeyStead Server {server_version}"))
    return bytes(pdf.output())
