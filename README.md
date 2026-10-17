# 🛡️ KeyStead Server

**Self-hosted sync and administration server for the [KeyStead Manager](https://github.com/facior/KeyStead)
password manager.**

KeyStead Server stores **only encrypted vaults** and their version history. Passwords are encrypted and decrypted
exclusively in the KeyStead Manager app on each user's computer (zero-knowledge). Neither the server administrator
nor anyone who takes over the server can read them.

- 👥 **Multiple users**, each with their own vault and devices
- 🖥️ **Web admin panel** with mandatory 2FA: accounts, devices, audit log, backups, updates
- 📱 **Device enrollment** with one-time activation codes
- 🛡️ **Security policies** enforced in the app: auto-lock, clipboard, master password strength, offline time,
  device limits, Autotype, attachments, Windows Hello
- 🕓 **Version history** with one-click restore
- 🔑 **Account recovery** for employees who forgot their master password
- 👋 **Employee offboarding:** block the account, revoke all devices, hand entries over to a successor and get a
  checklist of passwords to change
- 📋 **Compliance reports (PDF)** for NIS2 / the Polish National Cybersecurity System Act (KSC) and GDPR, plus a
  ready-to-use password management policy
- ⬆️ **Signed updates from the panel**, with automatic rollback if the new version fails
- 🌐 **No public IP needed:** works over Tailscale, Tailscale Funnel, Cloudflare Tunnel, your company VPN or an
  existing reverse proxy

> **Language:** the admin panel and the app are currently in **Polish**.

## Quick start (Ubuntu 22.04 / 24.04, Debian 12)

```bash
git clone https://github.com/facior/KeyStead-Manager.git
cd KeyStead-Manager
sudo bash server/deploy/install.sh
```

The installer asks how users will reach the server. When it finishes, it prints the server address and
a one-time token for setting up the admin panel at `<server address>/admin`.

Example: a server reachable only from your Tailscale network:

```bash
sudo bash server/deploy/install.sh --mode tailscale
```

**Full guide** (access modes, admin panel, recovery, offboarding, updates, commands, security):
**[server/README.md](server/README.md)**

## Requirements

- Ubuntu 22.04+ or Debian 12+ with systemd
- Python 3.10+ (installed automatically)
- For the Tailscale modes: Tailscale installed and logged in, with **MagicDNS** and **HTTPS Certificates** enabled

## Versions

The first two numbers are shared by the app and the server; the last one is for fixes in one part only.
App **2.0.x** works with server **2.0.x** and newer.

## Author and licence

- **Author:** Łukasz Kubieniec – [github.com/facior](https://github.com/facior)
- **Licence:** © 2026 Łukasz Kubieniec. All rights reserved. This is proprietary software. Publishing the source code
  does not grant a licence; see [LICENSE](LICENSE).
