# 🛡️ KeyStead Server

Serwer synchronizacji dla menedżera haseł **KeyStead Manager**.

Serwer przechowuje **wyłącznie zaszyfrowane sejfy** użytkowników wraz z historią wersji.
Hasła są szyfrowane i odszyfrowywane tylko w aplikacji na komputerze użytkownika (zero-knowledge) –
ani administrator, ani ktoś, kto przejmie serwer, nie jest w stanie ich odczytać.

- 👥 wielu użytkowników, każdy z własnym sejfem
- 🖥️ panel WEB administratora (logowanie z obowiązkowym 2FA)
- 📱 dołączanie urządzeń jednorazowymi kodami aktywacyjnymi
- 🕓 historia wersji i przywracanie jednym kliknięciem
- 🌐 działa bez publicznego IP: Tailscale, Tailscale Funnel, Cloudflare Tunnel, firmowy VPN lub serwer pośredniczący

## Szybki start (Ubuntu 22.04 / 24.04, Debian 12)

```bash
git clone https://github.com/facior/KeyStead-Manager.git
cd KeyStead-Manager
sudo bash server/deploy/install.sh
```

Instalator zapyta o sposób dostępu i na końcu wypisze adres serwera oraz jednorazowy token
do pierwszej konfiguracji panelu administratora (`<adres serwera>/admin`).

Przykład – serwer dostępny tylko w Twojej sieci Tailscale:

```bash
sudo bash server/deploy/install.sh --mode tailscale
```

Pełna dokumentacja (tryby dostępu, panel administratora, polecenia, bezpieczeństwo):
**[server/README.md](server/README.md)**

## Wymagania

- Ubuntu 22.04+ lub Debian 12+ z systemd
- Python 3.10+ (instalowany automatycznie)
- dla trybów Tailscale: zainstalowany i zalogowany Tailscale z włączonymi MagicDNS i HTTPS Certificates


## Wersje, autor i licencja

- **Numeracja wersji:** pierwsze dwie liczby są wspólne dla aplikacji i serwera (nowe funkcje wydawane razem),
  ostatnia oznacza poprawki tylko w jednej części. Aplikacja **2.0.x** współpracuje z serwerem **2.0.x** i nowszym.
- **Autor:** Łukasz Kubieniec – [github.com/facior](https://github.com/facior)
- **Licencja:** © 2026 Łukasz Kubieniec. Wszelkie prawa zastrzeżone. Oprogramowanie zastrzeżone – udostępnienie kodu
  nie oznacza udzielenia licencji; szczegóły w pliku [LICENSE](LICENSE).
