# KeyStead Server – administrator's guide

KeyStead Server stores **only encrypted vaults** and their version history. Master passwords never leave users'
computers, so neither the administrator nor anyone who takes over the server can read stored passwords.

Each company runs its own server and decides how users reach it: Tailscale, any company VPN (WireGuard, OpenVPN,
FortiClient, Cisco…), Cloudflare Tunnel or an existing reverse proxy. No public IP address is required.

> **Language:** the admin panel and the KeyStead Manager app are currently in **Polish**. Panel and menu names are
> given in Polish, followed by an English explanation.

**Contents:**
[1. Installation](#1-installation-ubuntu-2204--2404-debian-12) ·
[2. Admin panel](#2-admin-panel) ·
[3. Account recovery](#3-account-recovery) ·
[4. Employee offboarding](#4-employee-offboarding) ·
[5. Reports and compliance](#5-reports-and-compliance) ·
[6. Updates](#6-updates) ·
[7. For users](#7-for-users) ·
[8. Server commands](#8-server-commands) ·
[9. Security summary](#9-security-summary)

---

## 1. Installation (Ubuntu 22.04 / 24.04, Debian 12)

Copy the project to the server and run this from its root directory:

```bash
sudo bash server/deploy/install.sh
```

The installer asks how users will connect. You can also pass `--mode`:

| Mode | Best for | Public IP | Option |
|---|---|---|---|
| **tailscale** | One person or a small team on one Tailscale network; the server is visible only to your devices | no | `--mode tailscale` |
| **tailscale-funnel** | Access from any computer over the internet (for example, a work PC without Tailscale) | no | `--mode tailscale-funnel` |
| **cloudflare** | Companies with their own domain, access from the internet | no | `--mode cloudflare --public-url https://vault.example.com --cf-token <TOKEN>` |
| **proxy** | Companies with an existing nginx, Caddy or Traefik | — | `--mode proxy --public-url https://vault.example.com` |
| **direct** | Companies with their own VPN (WireGuard, OpenVPN, FortiClient…) or a local network only | no | `--mode direct --listen 10.8.0.1` |

Additional options:
- `--allow-from 10.8.0.0/24` – the vault API is reachable only from this network (for example, your VPN subnet).
- `--admin-from 10.8.0.0/24` – the admin panel is reachable only from this network (default: private, VPN and
  Tailscale networks).
- `--cert server.crt --key server.key` – in `direct` mode, use your company certificate instead of a self-signed one.

Running the installer again (for example, to change the mode) upgrades the server in place. Data, accounts and
tokens are kept.

### Tailscale modes

Requirements: Tailscale on the server (`curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`) and
**MagicDNS** plus **HTTPS Certificates** enabled at https://login.tailscale.com/admin/dns.

- `--mode tailscale` – address `https://<server>.<tailnet>.ts.net`, reachable only from devices on your Tailscale
  network. In the app, the **🔍 Tailscale** button finds the server automatically.
- `--mode tailscale-funnel` – the same address, also reachable from the internet, so work computers don't need
  Tailscale. The admin panel stays reachable only from your Tailscale network.

### Direct mode (company VPN or local network)

The server listens on an internal address (for example, the server's WireGuard address) with a TLS certificate.
Without your own certificate, the installer generates a self-signed one and prints its **SHA-256 fingerprint**.
On first connection the app shows this fingerprint for comparison and remembers the certificate, so a later
certificate swap is detected. The fingerprint is also shown in the admin panel.

---

## 2. Admin panel

Address: `<server address>/admin`. The installer prints the exact address and a **one-time setup token**.

1. Open the panel, enter the token, and set the administrator login and password (at least 12 characters).
2. Scan the QR code with an authenticator app (Google or Microsoft Authenticator, Aegis…). Signing in to the panel
   always requires a 2FA code.
3. Create users: **Użytkownicy → Nowy użytkownik** (Users → New user). The panel immediately shows an
   **activation code** (for example, `K7QM-4XTP-9HRW`) to give to the employee.

Activation codes are one-time and valid for 24 hours (change this in **Ustawienia**, Settings). Each device
needs its own code.

### Panel sections

| Section | What it contains |
|---|---|
| **Użytkownicy** (Users) | Accounts, devices and activation codes (also sent by e-mail); vault version history with restore; 2FA reset; account block or deletion; **emergency mode**, which cuts off all devices with one button. The user card also has **password reset** and **employee offboarding**. |
| **Raport** (Reports) | Each user's vault audit score (breached, reused and weak passwords, missing 2FA). The server receives **numbers only**, never passwords or account names. PDF reports and compliance documents. |
| **Stan serwera** (Server status) | Version, uptime, disk space, active devices, sync chart, update information. |
| **Kopie** (Backups) | Full server backup on demand and daily at a chosen time, rotation, archive download. |
| **Dziennik** (Audit log) | Sign-ins, device activations, vault saves, failed attempts. Filters by event type, text and date, and CSV export. |
| **Ustawienia** (Settings) | General settings, **security policies**, account recovery, administrator notifications (SMTP e-mail, Teams, Slack, Discord, ntfy or any webhook), company name and logo, updates. |
| **Administratorzy** (Administrators) | Invitations (one-time link) with the role *Administrator* or *Pomoc techniczna* (Helpdesk: view only, plus activation codes for new accounts). |

### Security policies

Apps apply policies within about 30 seconds:
- maximum auto-lock time and how long passwords stay in the clipboard;
- minimum master password strength (weaker passwords must be changed at the next unlock);
- maximum time working without a connection to the server;
- device limit per person;
- ban on private backups (USB, personal cloud);
- security reports sent from the apps;
- user 2FA when adding a new device (set up with the first device);
- Windows Hello (and how often the master password is required), Autotype, attachments (size and storage limits,
  or disabled completely).

### Attachments

Attachments (scans, licences, keys) are encrypted in the app with a separate key stored inside the vault.
The server keeps only encrypted files in `/var/lib/keystead/users/<login>/attachments`.

### Panel protection

The panel is reachable only from networks in `KS_ADMIN_ALLOWED_NETWORKS`, and never from internet traffic coming in
through Tailscale Funnel or Cloudflare. Other protections: Argon2id passwords plus mandatory 2FA, a lockout after
5 failed attempts, sessions that expire after 30 minutes of inactivity, CSRF protection, and no JavaScript with
a strict Content Security Policy.

**Lost the phone with your 2FA app?** Run `sudo keystead-admin reset-admin`, then `sudo keystead-admin setup-token`.

### Restoring the whole server from a backup

Stop the service first. Previous data is moved to `/var/lib/keystead/.before-restore-…`.

```bash
sudo systemctl stop keystead
sudo keystead-admin restore-backup /var/lib/keystead/backups/keystead-backup-YYYYMMDD-HHMMSS.tar.gz
sudo systemctl start keystead
```

Keep copies of backups **off the server** as well, for example by downloading the archive from **Kopie**.

---

## 3. Account recovery

For employees who forgot their master password. There are two ways.

### A. Recovery with the company key file (most secure)

1. In KeyStead Manager, the administrator opens **Ustawienia → Odzyskiwanie dostępu → Narzędzia administratora →
   Utwórz klucz odzyskiwania firmy** (Settings → Account recovery → Administrator tools → Create company recovery
   key). The private key file (password-protected) stays with the administrator and never goes to the server.
2. Paste the public key in the panel under **Ustawienia → Odzyskiwanie dostępu (firma)** (Settings → Company
   recovery) and turn the option on. Users' apps add the key during sync. Users see its fingerprint, and changing
   the key requires their consent.
3. To recover a user: on the user card, click **Pobierz pakiet odzyskiwania** (Download recovery package). In the
   app, choose "Odzyskaj dostęp użytkownika" (Recover user access) and provide the package, key file and key
   password. Then upload the result in the panel (**Wgraj wynik**) and give the user the temporary password.
   The app makes them set their own password at the next unlock.

### B. One-click reset from the panel

Under **Ustawienia → Odzyskiwanie dostępu**, you can store the company key on the server, encrypted with an
**IT department password**. Generate a new key, or upload an existing `.ksorgkey` file. After that, on the user
card, enter the IT password and click **Resetuj hasło główne** (Reset master password). The panel shows
a temporary password, and the app makes the user change it at the next sign-in.

> **Trade-off:** this is more convenient, but anyone who takes over the server *and* learns the IT password can open
> vaults. Use a long IT password known only to the IT department. After 5 wrong IT passwords, reset is blocked for
> 15 minutes, and every use is recorded in the audit log.

Reset works only for vaults that already contain the company key; the user card shows whether a vault does.

Users can also create a **personal recovery code** in the app and recover access themselves with
"Nie pamiętam hasła" (I forgot my password) on the login screen.

---

## 4. Employee offboarding

On the user card, open the **👋 Odejście pracownika** (Employee leaving) section and type the user's login to confirm.
KeyStead then does the following:

1. **Blocks the account** and **revokes all devices** immediately.
2. Builds a **checklist of accounts** whose passwords the employee knew. It shows only the title, website and
   username, **never passwords**. Mark each item as changed or skipped. The checklist is deleted from the server
   when you finish the process.
3. Optionally **hands the employee's entries and attachments over to a successor's vault**, in the category
   "Przekazane: <name>" (Handed over: <name>).

Steps 2 and 3 need the **IT department password** from [method B](#b-one-click-reset-from-the-panel). The
employee's vault is opened only in server memory, with the company key. Without the IT password, the account is
still blocked and its devices revoked, and you fill in the checklist by hand.

---

## 5. Reports and compliance

Under **Raport** (Reports):
- **PDF security report:** average score, 90-day trend (the server stores a daily summary), and a per-user list of
  breached, weak and reused passwords and 2FA status. Numbers only, never passwords.
- **📄 Raport zgodności (PDF)** (Compliance report): evidence for **NIS2 / the Polish National Cybersecurity System
  Act (KSC)** and **GDPR (RODO)**. It covers policies, accounts and permissions, 2FA, password hygiene, backups,
  encryption, updates and the audit log, with automatic recommendations that refer to the measures in Article 21
  of NIS2.
- **📝 Polityka zarządzania hasłami (PDF)** (Password management policy): a ready-made internal policy document
  filled in with the values from your settings, ready to approve and sign.

---

## 6. Updates

Go to **Stan serwera → Aktualizacja i historia wersji** (Server status → Update and version history). When a new
release is published, the panel shows **Zaktualizuj do X.Y.Z** (Update to X.Y.Z) and its progress: download →
signature check → data backup → install → restart → health check.

- The panel service has no privileges and only files a request. A separate `keystead-updater` service, started by
  systemd, performs the installation.
- **Only releases signed with the publisher's key are installed** (`/etc/keystead/release-signing.pub`, checked with
  `ssh-keygen -Y verify`). Tampered or unsigned files are rejected before anything changes.
- Each version lives in its own directory, `/opt/keystead/releases/<version>`, and `/opt/keystead/current` points to
  the active one. If the new version doesn't respond after the restart, the server **rolls back automatically**.
  The last 3 versions are kept, and **Przywróć poprzednią wersję** (Restore previous version) undoes an update by hand.
- Status from the terminal: `sudo sh -c 'cd /opt/keystead/current && venv/bin/python -m server.updater status'`.
  Logs: `journalctl -u keystead-updater`.

---

## 7. For users

Users download the Windows app from the server's permanent link, **`https://<server address>/download`**. This link
is included with activation codes and e-mails. It points to the latest installer on GitHub, or to an address you set
in **Ustawienia → Ogólne → Adres instalatora aplikacji** (Settings → General → App installer address). After that,
the app updates itself to new signed versions.

In the app, on the login screen, the user opens the **🌐 Serwer** (Server) tab and enters:
1. the server address (or clicks **🔍 Tailscale** to detect it),
2. the activation code from the administrator,
3. their master password.

On first connection, the app offers to upload an existing vault or create a new one. On additional devices, the
user needs a new code and the same master password. Corporate proxies are detected automatically from Windows settings.

---

## 8. Server commands

| Command | Description |
|---|---|
| `sudo keystead-admin list-users` | Users and their device count |
| `sudo keystead-admin add-user jan.kowalski --name "Jan Kowalski"` | New account plus activation code |
| `sudo keystead-admin enroll-code jan.kowalski` | New activation code |
| `sudo keystead-admin list-devices` / `revoke-device <id>` | List devices / cut off a device |
| `sudo keystead-admin status --user jan.kowalski` | State of a user's vault |
| `sudo keystead-admin setup-token` / `reset-admin` | Admin account setup / reset |
| `journalctl -u keystead -f` | Server logs |

Configuration: `/etc/keystead/server.env`; after changing it, run `sudo systemctl restart keystead`.
Server data lives in `/var/lib/keystead` (encrypted vaults and token hashes only).

---

## 9. Security summary

- **Zero-knowledge:** the server stores only encrypted files, and each user has a separate vault.
- **Device tokens:** 256-bit, stored on the server only as SHA-256 hashes, and protected with DPAPI in the Windows app.
- **Activation codes:** one-time, time-limited, stored as hashes.
- **Rate limits:** device sign-in (20 attempts per 10 minutes), activation codes (10 per 10 minutes), admin panel
  (5 per 15 minutes).
- **Network allow-lists** for the API and the panel. Behind a reverse proxy, the client address is trusted only
  from configured proxies.
- **Hardened systemd service** with no access to the rest of the system outside its data directory.
- **Signed updates** with automatic rollback.

---

## Versions, author and licence

- **Versions:** the first two numbers are shared by the app and the server; the last one is for fixes in one part
  only. App **2.0.x** works with server **2.0.x** and newer.
- **Author:** Łukasz Kubieniec – [github.com/facior](https://github.com/facior)
- **Licence:** © 2026 Łukasz Kubieniec. All rights reserved. This is proprietary software. Publishing the source code
  does not grant a licence; see [LICENSE](../LICENSE).
