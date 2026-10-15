#!/usr/bin/env bash
# Instalator serwera KeyStead Manager dla Ubuntu (22.04 / 24.04) i Debiana.
#
# Użycie (z katalogu głównego projektu):
#   sudo bash server/deploy/install.sh                      # menu wyboru sposobu dostępu
#   sudo bash server/deploy/install.sh --mode tailscale     # prywatnie w sieci Tailscale
#   sudo bash server/deploy/install.sh --mode tailscale-funnel
#   sudo bash server/deploy/install.sh --mode cloudflare --public-url https://vault.firma.pl [--cf-token TOKEN]
#   sudo bash server/deploy/install.sh --mode proxy --public-url https://vault.firma.pl
#   sudo bash server/deploy/install.sh --mode direct --listen 10.8.0.1 [--cert plik.crt --key plik.key]
#
# Opcje wspólne:
#   --port N            port wewnętrzny (domyślnie 8787; w trybie direct 8443)
#   --allow-from CIDR   API tylko z tych sieci, np. 10.8.0.0/24 (lista po przecinku; domyślnie bez ograniczeń)
#   --admin-from CIDR   panel administratora tylko z tych sieci (domyślnie sieci prywatne / VPN)
#   --public-url URL    adres, pod którym użytkownicy łączą się z serwerem
set -euo pipefail

APP_DIR=/opt/keystead
DATA_DIR=/var/lib/keystead
CONF_DIR=/etc/keystead
TLS_DIR=$CONF_DIR/tls
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PRIVATE_NETS="127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fd7a:115c:a1e0::/48,fc00::/7"

MODE="" PORT="" LISTEN="" CERT="" KEY="" PUBLIC_URL="" ALLOW_FROM="any" ADMIN_FROM="$PRIVATE_NETS" CF_TOKEN=""

die() { echo "!! $*" >&2; exit 1; }
info() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --listen) LISTEN="$2"; shift 2 ;;
        --cert) CERT="$2"; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --public-url) PUBLIC_URL="${2%/}"; shift 2 ;;
        --allow-from) ALLOW_FROM="$2"; shift 2 ;;
        --admin-from) ADMIN_FROM="$2"; shift 2 ;;
        --cf-token) CF_TOKEN="$2"; shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) die "Nieznana opcja: $1 (zobacz --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "Uruchom jako root: sudo bash $0"

has_tailscale() { command -v tailscale &>/dev/null && tailscale status &>/dev/null; }

if [[ -z "$MODE" ]]; then
    if [[ -t 0 ]]; then
        cat <<'EOF'

Jak użytkownicy będą łączyć się z serwerem?
  1) Tailscale – prywatnie, tylko urządzenia w Twojej sieci Tailscale        (zalecane dla siebie)
  2) Tailscale Funnel – publicznie przez internet, bez publicznego IP i domeny
  3) Cloudflare Tunnel – publicznie pod własną domeną, bez publicznego IP
  4) Za istniejącym serwerem pośredniczącym firmy (nginx / Caddy / Traefik)
  5) Bezpośrednio w sieci firmy / VPN (WireGuard, OpenVPN, FortiClient…) z własnym certyfikatem
EOF
        read -rp "Wybór [1-5]: " choice
        case "$choice" in
            1) MODE=tailscale ;; 2) MODE=tailscale-funnel ;; 3) MODE=cloudflare ;;
            4) MODE=proxy ;; 5) MODE=direct ;; *) die "Nieprawidłowy wybór." ;;
        esac
    else
        die "Podaj --mode (tailscale | tailscale-funnel | cloudflare | proxy | direct)."
    fi
fi

case "$MODE" in
    tailscale|tailscale-funnel)
        has_tailscale || die "Tailscale nie jest zainstalowany lub zalogowany.
   Zainstaluj: curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
   W panelu https://login.tailscale.com/admin/dns włącz MagicDNS i HTTPS Certificates."
        HOST=127.0.0.1; PORT=${PORT:-8787} ;;
    cloudflare|proxy)
        HOST=127.0.0.1; PORT=${PORT:-8787}
        [[ -n "$PUBLIC_URL" ]] || { [[ -t 0 ]] && read -rp "Publiczny adres serwera (np. https://vault.firma.pl): " PUBLIC_URL; }
        PUBLIC_URL="${PUBLIC_URL%/}" ;;
    direct)
        PORT=${PORT:-8443}
        if [[ -z "$LISTEN" ]]; then
            [[ -t 0 ]] || die "W trybie direct podaj --listen <adres IP serwera w sieci VPN/LAN>."
            echo "Adresy IP tego serwera:"
            ip -o -4 addr show | awk '$2 != "lo" {split($4, a, "/"); print "   " $2 ": " a[1]}'
            read -rp "Na którym adresie ma nasłuchiwać serwer (np. 192.168.0.10): " LISTEN
        fi
        # Adres bez maski sieci (lista systemowa pokazuje np. 192.168.0.78/24) i bez spacji
        LISTEN="$(echo "$LISTEN" | tr -d '[:space:]')"
        LISTEN="${LISTEN%%/*}"
        if [[ "$LISTEN" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
            for octet in "${BASH_REMATCH[@]:1}"; do
                (( octet <= 255 )) || die "Nieprawidłowy adres IP: $LISTEN"
            done
            LISTEN_KIND=ip
        elif [[ "$LISTEN" == *:* ]]; then
            LISTEN_KIND=ip6
        elif [[ "$LISTEN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
            LISTEN_KIND=dns
        else
            die "Nieprawidłowy adres nasłuchu: '$LISTEN' (podaj sam adres IP, np. 192.168.0.10)."
        fi
        HOST="$LISTEN" ;;
    *) die "Nieznany tryb: $MODE" ;;
esac

info "Instalacja pakietów systemowych"
apt-get update -qq
apt-get install -y -qq python3 python3-venv curl sudo openssl >/dev/null

info "Użytkownik systemowy 'keystead'"
id keystead &>/dev/null || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin keystead

info "Kopiowanie aplikacji do $APP_DIR"
install -d -m 755 "$APP_DIR"
rm -rf "$APP_DIR/server"
cp -r "$SRC_DIR/server" "$APP_DIR/server"
find "$APP_DIR/server" -name '__pycache__' -prune -exec rm -rf {} +

info "Środowisko Python"
[[ -d "$APP_DIR/venv" ]] || python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/server/requirements.txt"

install -d -m 700 -o keystead -g keystead "$DATA_DIR"
install -d -m 755 "$CONF_DIR"

# ------------------------------------------------------------------ certyfikat (tryb direct)
TLS_CERT="" TLS_KEY="" FINGERPRINT=""
if [[ "$MODE" == "direct" ]]; then
    install -d -m 750 -o root -g keystead "$TLS_DIR"
    MARKER="$TLS_DIR/.generated-for"
    if [[ -n "$CERT" && -n "$KEY" ]]; then
        info "Używam dostarczonego certyfikatu"
        install -m 644 -o root -g keystead "$CERT" "$TLS_DIR/server.crt"
        install -m 640 -o root -g keystead "$KEY" "$TLS_DIR/server.key"
        echo "provided" > "$MARKER"
    elif [[ ! -f "$TLS_DIR/server.crt" || ( "$(cat "$MARKER" 2>/dev/null)" != "provided" && "$(cat "$MARKER" 2>/dev/null)" != "$LISTEN" ) ]]; then
        # Brak certyfikatu albo wygenerowany dla innego adresu → nowy certyfikat samopodpisany
        info "Generuję certyfikat samopodpisany (ważny 10 lat) dla $LISTEN"
        case "$LISTEN_KIND" in
            ip|ip6) SAN="IP:$LISTEN,DNS:$(hostname)" ;;
            *)      SAN="DNS:$LISTEN,DNS:$(hostname)" ;;
        esac
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=KeyStead Server" -addext "subjectAltName=$SAN" \
            -addext "extendedKeyUsage=serverAuth" \
            -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" 2>/dev/null \
            || die "Nie udało się wygenerować certyfikatu (openssl)."
        chown root:keystead "$TLS_DIR/server.key" "$TLS_DIR/server.crt"
        chmod 640 "$TLS_DIR/server.key"; chmod 644 "$TLS_DIR/server.crt"
        echo "$LISTEN" > "$MARKER"
    fi
    TLS_CERT="$TLS_DIR/server.crt"; TLS_KEY="$TLS_DIR/server.key"
    FINGERPRINT="$(openssl x509 -in "$TLS_CERT" -noout -fingerprint -sha256 | cut -d= -f2)"
    URL_HOST="$LISTEN"; [[ "$LISTEN_KIND" == ip6 ]] && URL_HOST="[$LISTEN]"
    [[ -n "$PUBLIC_URL" ]] || PUBLIC_URL="https://$URL_HOST:$PORT"
fi

# ------------------------------------------------------------------ Tailscale
if [[ "$MODE" == tailscale* ]]; then
    TS_NAME="$(tailscale status --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))')"
    PUBLIC_URL="https://$TS_NAME"
fi

info "Konfiguracja $CONF_DIR/server.env (tryb: $MODE)"
cat > "$CONF_DIR/server.env" <<EOF
# Tryb dostępu: $MODE  (wygenerowano przez install.sh – ponowne uruchomienie instalatora nadpisze ten plik)
KS_DATA_DIR=$DATA_DIR
KS_HOST=$HOST
KS_PORT=$PORT
KS_MAX_HISTORY=50
KS_MAX_VAULT_MB=50
KS_PUBLIC_URL=$PUBLIC_URL
KS_API_ALLOWED_NETWORKS=$ALLOW_FROM
KS_ADMIN_ALLOWED_NETWORKS=$ADMIN_FROM
KS_TRUSTED_PROXIES=127.0.0.1,::1
KS_TLS_CERT=$TLS_CERT
KS_TLS_KEY=$TLS_KEY
EOF
chmod 644 "$CONF_DIR/server.env"

info "Polecenie administracyjne keystead-admin"
cat > /usr/local/bin/keystead-admin <<'EOF'
#!/usr/bin/env bash
set -a; source /etc/keystead/server.env; set +a
cd /opt/keystead
exec sudo -E -u keystead /opt/keystead/venv/bin/python -m server "$@"
EOF
chmod 755 /usr/local/bin/keystead-admin

info "Usługa systemd"
install -m 644 "$SRC_DIR/server/deploy/keystead.service" /etc/systemd/system/keystead.service
systemctl daemon-reload
systemctl enable keystead.service >/dev/null
systemctl restart keystead.service
SCHEME=http; [[ -n "$TLS_CERT" ]] && SCHEME=https
CHECK_HOST="$HOST"; [[ "${LISTEN_KIND:-}" == ip6 ]] && CHECK_HOST="[$HOST]"
STARTED=0
for _ in $(seq 1 20); do
    if curl -fsSk --max-time 2 "$SCHEME://$CHECK_HOST:$PORT/api/v1/health" >/dev/null 2>&1; then
        STARTED=1; break
    fi
    sleep 1
done
if [[ $STARTED -ne 1 ]]; then
    echo "!! Serwer nie odpowiada na $SCHEME://$CHECK_HOST:$PORT – ostatnie wpisy dziennika:" >&2
    journalctl -u keystead -n 25 --no-pager >&2 || true
    die "Instalacja przerwana. Po poprawieniu problemu uruchom instalator ponownie."
fi

# ------------------------------------------------------------------ publikacja
ADMIN_HINT=""
case "$MODE" in
    tailscale)
        info "Publikacja w sieci Tailscale (prywatnie)"
        tailscale funnel --https=443 off &>/dev/null || true
        tailscale serve --bg --https=443 "http://127.0.0.1:$PORT" >/dev/null
        ADMIN_HINT="$PUBLIC_URL/admin   (z dowolnego urządzenia w Twojej sieci Tailscale)" ;;
    tailscale-funnel)
        info "Publikacja przez Tailscale Funnel (internet)"
        tailscale serve --https=443 off &>/dev/null || true
        tailscale funnel --bg --https=443 "http://127.0.0.1:$PORT" >/dev/null
        ADMIN_HINT="$PUBLIC_URL/admin   (TYLKO z urządzeń w Twojej sieci Tailscale – z internetu panel jest ukryty)" ;;
    cloudflare)
        if [[ -n "$CF_TOKEN" ]]; then
            if ! command -v cloudflared &>/dev/null; then
                info "Instalacja cloudflared"
                curl -fsSL -o /tmp/cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$(dpkg --print-architecture).deb"
                dpkg -i /tmp/cloudflared.deb >/dev/null && rm -f /tmp/cloudflared.deb
            fi
            cloudflared service install "$CF_TOKEN" >/dev/null 2>&1 || true
            info "Tunel Cloudflare zainstalowany jako usługa"
        fi
        ADMIN_HINT="przez tunel SSH:  ssh -L 8787:127.0.0.1:$PORT <serwer>  →  http://127.0.0.1:8787/admin
     (panel nigdy nie jest publikowany przez Cloudflare)" ;;
    proxy)
        ADMIN_HINT="przez tunel SSH:  ssh -L 8787:127.0.0.1:$PORT <serwer>  →  http://127.0.0.1:8787/admin
     albo z sieci firmy przez serwer pośredniczący: $PUBLIC_URL/admin" ;;
    direct)
        ADMIN_HINT="$PUBLIC_URL/admin   (z sieci lokalnej / VPN)"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            if ! ufw status | grep -qE "^$PORT(/tcp)?\s+ALLOW"; then
                ADMIN_HINT="$ADMIN_HINT
     ⚠️  Zapora ufw jest włączona – otwórz port dla sieci lokalnej, np.:
         sudo ufw allow from 192.168.0.0/16 to any port $PORT proto tcp"
            fi
        fi ;;
esac

# ------------------------------------------------------------------ token pierwszej konfiguracji
SETUP_OUT="$(/usr/local/bin/keystead-admin setup-token 2>/dev/null || true)"
SETUP_TOKEN="$(echo "$SETUP_OUT" | awk 'NF==1 && length($1)>20 {print $1; exit}')"

cat <<EOF

=====================================================================
 KeyStead Manager – serwer działa (tryb: $MODE)
=====================================================================
 Adres serwera dla aplikacji:  ${PUBLIC_URL:-"(uzupełnij KS_PUBLIC_URL w $CONF_DIR/server.env)"}
EOF
[[ -n "$FINGERPRINT" ]] && cat <<EOF
 Odcisk certyfikatu (SHA-256) – aplikacja poprosi o jego potwierdzenie przy pierwszym połączeniu:
     $FINGERPRINT
EOF
cat <<EOF

 Panel administratora: $ADMIN_HINT
EOF
if [[ -n "$SETUP_TOKEN" ]]; then
cat <<EOF
 Token pierwszej konfiguracji panelu (jednorazowy):
     $SETUP_TOKEN
EOF
else
echo " Konto administratora już istnieje (reset: sudo keystead-admin reset-admin)."
fi
case "$MODE" in
    cloudflare) [[ -z "$CF_TOKEN" ]] && cat <<EOF

 Cloudflare Tunnel – dokończ konfigurację:
   1. https://one.dash.cloudflare.com → Networks → Tunnels → Create tunnel (cloudflared)
   2. Skopiuj token i uruchom ponownie:  sudo bash $0 --mode cloudflare --public-url $PUBLIC_URL --cf-token <TOKEN>
   3. W tunelu dodaj Public Hostname: ${PUBLIC_URL#https://} → http://127.0.0.1:$PORT
EOF
    ;;
    proxy) cat <<EOF

 Przykład dla Caddy:
   ${PUBLIC_URL#https://} {
       reverse_proxy 127.0.0.1:$PORT
   }
 Przykład dla nginx (wewnątrz bloku server z certyfikatem):
   location / {
       proxy_pass http://127.0.0.1:$PORT;
       proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto \$scheme;
       client_max_body_size 60m;
   }
EOF
    ;;
esac
cat <<EOF

 Dalej: zaloguj się do panelu, utwórz użytkowników i wygeneruj im kody aktywacyjne.
 Polecenia: sudo keystead-admin list-users | add-user | enroll-code | status
 Logi:      journalctl -u keystead -f
=====================================================================
EOF
