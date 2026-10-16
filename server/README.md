# KeyStead Server – serwer synchronizacji

Serwer przechowuje **wyłącznie zaszyfrowane sejfy** użytkowników wraz z historią wersji.
Hasło główne nigdy nie opuszcza komputera użytkownika – ani administrator, ani ktoś, kto przejmie serwer,
nie jest w stanie odczytać haseł.

Każda firma instaluje własny serwer i sama decyduje, jak użytkownicy się z nim łączą:
przez Tailscale, dowolny firmowy VPN (WireGuard, OpenVPN, FortiClient, Cisco…), Cloudflare Tunnel
albo istniejący serwer pośredniczący. Serwer nie wymaga publicznego adresu IP.

---

## 1. Instalacja (Ubuntu 22.04 / 24.04, Debian 12)

Skopiuj projekt na serwer i w jego katalogu głównym uruchom:

```bash
sudo bash server/deploy/install.sh
```

Instalator zapyta o sposób dostępu (lub podaj `--mode`):

| Tryb | Dla kogo | Publiczny IP | Polecenie |
|---|---|---|---|
| **tailscale** | Ty / mała firma w jednej sieci Tailscale – serwer widoczny tylko dla Twoich urządzeń | nie | `--mode tailscale` |
| **tailscale-funnel** | dostęp z dowolnego komputera przez internet (np. komputer w pracy bez Tailscale) | nie | `--mode tailscale-funnel` |
| **cloudflare** | firma z własną domeną, dostęp z internetu | nie | `--mode cloudflare --public-url https://vault.firma.pl --cf-token <TOKEN>` |
| **proxy** | firma z istniejącym nginx / Caddy / Traefik | — | `--mode proxy --public-url https://vault.firma.pl` |
| **direct** | firma z własnym VPN (WireGuard, OpenVPN, FortiClient…) lub tylko sieć lokalna | nie | `--mode direct --listen 10.8.0.1` |

Opcje dodatkowe:
- `--allow-from 10.8.0.0/24` – API sejfów dostępne tylko z tej sieci (np. podsieć VPN firmy),
- `--admin-from 10.8.0.0/24` – panel administratora tylko z tej sieci (domyślnie: sieci prywatne / VPN / Tailscale),
- `--cert plik.crt --key plik.key` – w trybie `direct` własny certyfikat firmy zamiast samopodpisanego.

Ponowne uruchomienie instalatora (np. ze zmianą trybu) aktualizuje serwer – dane, konta i tokeny zostają.

### Tryby Tailscale (dla Ciebie)

Wymagania: Tailscale na serwerze (`curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`)
oraz w panelu https://login.tailscale.com/admin/dns włączone **MagicDNS** i **HTTPS Certificates**.

- `--mode tailscale` – adres `https://<serwer>.<sieć>.ts.net`, dostępny tylko z urządzeń w Twojej sieci Tailscale.
  W aplikacji przycisk **🔍 Tailscale** sam znajdzie serwer.
- `--mode tailscale-funnel` – ten sam adres, ale dostępny także z internetu (komputer w pracy nie potrzebuje Tailscale).
  Panel administratora pozostaje dostępny wyłącznie z Twojej sieci Tailscale.

### Tryb direct (firmowy VPN / sieć lokalna)

Serwer nasłuchuje na adresie wewnętrznym (np. adresie serwera w sieci WireGuard) z certyfikatem TLS.
Bez własnego certyfikatu instalator generuje certyfikat samopodpisany i wypisuje jego **odcisk SHA-256**.
Przy pierwszym połączeniu aplikacja pokaże ten odcisk do porównania i zapamięta certyfikat
(późniejsza podmiana certyfikatu zostanie wykryta). Odcisk widać też w panelu administratora.

---

## 2. Panel administratora (WEB)

Adres: `<adres serwera>/admin` – instalator wypisuje dokładny adres i **jednorazowy token konfiguracyjny**.

1. Otwórz panel, wpisz token, ustaw login i hasło administratora (min. 12 znaków).
2. Zeskanuj kod QR w aplikacji uwierzytelniającej (Google/Microsoft Authenticator, Aegis…) – logowanie do panelu
   zawsze wymaga kodu 2FA.
3. W panelu:
   - **Użytkownicy → Nowy użytkownik** – tworzy konto i od razu pokazuje **kod aktywacyjny** (np. `K7QM-4XTP-9HRW`),
   - **Zarządzaj** – kolejne kody (każde urządzenie osobno), lista urządzeń z możliwością odcięcia,
     blokada konta (natychmiast odcina wszystkie urządzenia), usunięcie konta z sejfem,
   - **Dziennik zdarzeń** – logowania, aktywacje urządzeń, zapisy sejfów, nieudane próby.

Kod aktywacyjny jest jednorazowy i ważny 24 h (zmienisz to w **Ustawieniach**).

### Pozostałe sekcje panelu

| Sekcja | Co zawiera |
|---|---|
| **Użytkownicy** | konta, urządzenia, kody aktywacyjne (także wysyłka e-mailem), historia wersji sejfu z przywracaniem, reset 2FA, blokada/usunięcie, **tryb awaryjny** – odcięcie wszystkich urządzeń jednym przyciskiem |
| **Raport bezpieczeństwa** | wynik audytu sejfu każdego użytkownika (wycieki, powtórzone i słabe hasła, brak 2FA) – serwer dostaje **wyłącznie liczby**, nigdy hasła ani nazwy kont |
| **Stan serwera** | wersja, czas działania, miejsce na dysku, aktywne urządzenia, wykres synchronizacji, informacja o nowej wersji na GitHubie |
| **Kopie** | kopia całego serwera na żądanie i codziennie o wybranej godzinie, rotacja, pobieranie archiwum |
| **Dziennik** | filtry (typ zdarzenia, tekst, zakres dat) i eksport do CSV |
| **Ustawienia** | ogólne, **polityki bezpieczeństwa** wymuszane w aplikacjach, powiadomienia (e-mail SMTP, Teams, Slack, Discord, ntfy, dowolny webhook), nazwa i logo firmy, aktualizacje |
| **Administratorzy** | zaproszenia (jednorazowy link) z rolą *Administrator* albo *Pomoc techniczna* (tylko podgląd i kody aktywacyjne) |

**Polityki bezpieczeństwa** (aplikacje stosują je w ciągu ~30 s): maksymalny czas automatycznej blokady i przechowywania
hasła w schowku, minimalna siła hasła głównego (słabsze trzeba zmienić przy odblokowaniu), maksymalny czas pracy bez
połączenia z serwerem, limit urządzeń na osobę, zakaz własnych kopii (USB / prywatne chmury), raporty bezpieczeństwa
oraz **2FA użytkownika przy dodawaniu urządzeń** (konfigurowane przy pierwszym urządzeniu).

**Przywrócenie całego serwera z kopii** (usługa zatrzymana; poprzednie dane trafiają do `/var/lib/keystead/.before-restore-…`):
```bash
sudo systemctl stop keystead
sudo keystead-admin restore-backup /var/lib/keystead/backups/keystead-backup-RRRRMMDD-GGMMSS.tar.gz
sudo systemctl start keystead
```

**Zabezpieczenia panelu:** dostępny tylko z sieci z `KS_ADMIN_ALLOWED_NETWORKS` i nigdy dla ruchu z internetu
przychodzącego przez Tailscale Funnel / Cloudflare; hasło Argon2id + obowiązkowe 2FA; blokada po 5 nieudanych
próbach; sesja wygasa po 30 min bezczynności; ochrona CSRF; brak JavaScriptu i restrykcyjna polityka CSP.

**Utrata telefonu z 2FA:** `sudo keystead-admin reset-admin`, potem `sudo keystead-admin setup-token`.

### Odzyskiwanie dostępu (pracownik zapomniał hasła głównego)

1. W aplikacji KeyStead Manager administrator wybiera **Ustawienia → Odzyskiwanie dostępu → Narzędzia administratora →
   Utwórz klucz odzyskiwania firmy**. Plik klucza prywatnego (zabezpieczony hasłem) zostaje u administratora – nigdy na serwerze.
2. Klucz publiczny wkleja w panelu: **Ustawienia → Odzyskiwanie dostępu (firma)** i włącza opcję.
   Aplikacje użytkowników dodają klucz przy synchronizacji (użytkownik widzi jego odcisk; zmiana klucza wymaga jego zgody).
3. Odzyskanie: karta użytkownika → **Pobierz pakiet odzyskiwania** → w aplikacji „Odzyskaj dostęp użytkownika”
   (pakiet + plik klucza + hasło) → **Wgraj wynik** w panelu → przekaż użytkownikowi hasło tymczasowe.
   Przy odblokowaniu aplikacja wymusi ustawienie własnego hasła.

Użytkownicy mogą też utworzyć **osobisty kod odzyskiwania** (Ustawienia w aplikacji) i odzyskać dostęp sami
(„Nie pamiętam hasła” na ekranie logowania). Obie funkcje wymagają aplikacji 1.2+ na wszystkich urządzeniach.

### Załączniki i raport PDF

- **Załączniki** (skany, licencje, klucze) są szyfrowane w aplikacji osobnym kluczem zapisanym w sejfie –
  serwer przechowuje tylko zaszyfrowane pliki (`/var/lib/keystead/users/<login>/attachments`). Limity rozmiaru
  i miejsca na osobę ustawisz w **politykach**; można też całkowicie wyłączyć załączniki.
- **Raporty → Pobierz raport PDF**: średni wynik, trend z ostatnich 90 dni (serwer zapisuje codzienne podsumowanie),
  lista użytkowników z liczbami wycieków / słabych / powtórzonych haseł i stanem 2FA. Wyłącznie liczby – bez haseł.
- Nowe polityki: Windows Hello (i co ile dni hasło główne), Autotype, załączniki.

### Aktualizacja z panelu

**Stan serwera → Aktualizacja i historia wersji.** Gdy na GitHubie pojawi się nowe wydanie, panel pokazuje przycisk
**Zaktualizuj do X.Y.Z** i postęp: pobieranie → weryfikacja podpisu → kopia danych → instalacja → restart → kontrola działania.

- Panel (usługa bez uprawnień) tylko zapisuje prośbę; instaluje osobna usługa `keystead-updater` (root), uruchamiana przez systemd.
- Instalowane są **wyłącznie wydania podpisane kluczem wydawcy** (`/etc/keystead/release-signing.pub`, `ssh-keygen -Y verify`)
  – podmienione lub niepodpisane pliki są odrzucane, zanim cokolwiek zostanie zmienione.
- Każda wersja ma własny katalog `/opt/keystead/releases/<wersja>`, a `/opt/keystead/current` wskazuje bieżącą.
  Jeśli nowa wersja nie odpowiada po restarcie, serwer **sam wraca do poprzedniej**. Przechowywane są 3 ostatnie wersje,
  a przycisk **Przywróć poprzednią wersję** cofa aktualizację ręcznie.
- Podgląd z terminala: `sudo sh -c 'cd /opt/keystead/current && venv/bin/python -m server.updater status'`
  (zawsze z katalogu programu – Python uruchomiony z `-m` wczytuje moduły z bieżącego katalogu),
  logi: `journalctl -u keystead-updater`.

Dla wydawcy (komputer z kluczem prywatnym): `python tools/release.py init-key` (jednorazowo),
następnie po podniesieniu `SERVER_VERSION` w `server/__init__.py`: `python tools/release.py X.Y.Z --notes "Co nowego"`.

---

## 3. Po stronie użytkownika

Aplikację (instalator Windows) użytkownik pobiera ze stałego linku serwera **`https://<adres-serwera>/download`** –
podawanego przy kodach aktywacyjnych i w e-mailach. Link prowadzi do najnowszego instalatora z GitHuba albo pod adres
ustawiony w panelu (**Ustawienia → Ogólne → Adres instalatora aplikacji**). Aplikacja sama aktualizuje się później
do nowych, podpisanych wersji.

W aplikacji: ekran logowania → zakładka **🌐 Serwer**:
1. adres serwera (lub **🔍 Tailscale**, aby wykryć go automatycznie),
2. kod aktywacyjny od administratora,
3. hasło główne sejfu.

Przy pierwszym połączeniu aplikacja zaproponuje wysłanie istniejącego sejfu albo utworzenie nowego.
Na kolejnych urządzeniach użytkownik używa nowego kodu i tego samego hasła głównego.
Firmowe proxy jest wykrywane automatycznie z ustawień systemu.

---

## 4. Polecenia administracyjne (terminal serwera)

| Polecenie | Opis |
|---|---|
| `sudo keystead-admin list-users` | użytkownicy i liczba urządzeń |
| `sudo keystead-admin add-user jan.kowalski --name "Jan Kowalski"` | nowe konto + kod aktywacyjny |
| `sudo keystead-admin enroll-code jan.kowalski` | nowy kod aktywacyjny |
| `sudo keystead-admin list-devices` / `revoke-device <id>` | urządzenia / odcięcie urządzenia |
| `sudo keystead-admin status --user jan.kowalski` | stan sejfu użytkownika |
| `sudo keystead-admin setup-token` / `reset-admin` | konfiguracja / reset konta administratora |
| `journalctl -u keystead -f` | logi serwera |

Konfiguracja: `/etc/keystead/server.env`, po zmianie `sudo systemctl restart keystead`.
Kopia zapasowa serwera: archiwum katalogu `/var/lib/keystead` (wyłącznie zaszyfrowane sejfy i skróty tokenów).

---

## 5. Bezpieczeństwo – podsumowanie

- Zero-knowledge: serwer przechowuje tylko zaszyfrowane pliki; każdy użytkownik ma osobny sejf.
- Tokeny urządzeń: 256 bitów, na serwerze tylko skrót SHA-256; w aplikacji Windows szyfrowane DPAPI.
- Kody aktywacyjne: jednorazowe, z terminem ważności, przechowywane jako skrót.
- Ograniczanie prób: logowanie urządzeń (20 prób / 10 min), kody aktywacyjne (10 prób / 10 min), panel (5 prób / 15 min).
- Listy dozwolonych sieci dla API i panelu; adres klienta za serwerem pośredniczącym odczytywany tylko od zaufanych pośredników.
- Usługa systemd z utwardzeniem (brak dostępu do reszty systemu poza katalogiem danych).
