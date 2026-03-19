# UFW-audit v0.6.0

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.6.0-blue)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-informational)
![Language](https://img.shields.io/badge/language-Bash-lightgrey)

Lightweight **UFW Firewall Audit Script** for Linux — designed for regular users,
not system administrators.

UFW-audit analyses your UFW configuration, detects exposed network services,
classifies risks per service, and gives plain-language explanations and
ready-to-run remediation commands.

---

## Features

- **Coloured ASCII banner** with system info (distro, host, UFW version, user, date)
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Service-aware audit engine** — detects 18 common network services and analyses their UFW exposure:

  | Service                          | Default port      | Risk     |
  |----------------------------------|-------------------|----------|
  | SSH Server                       | 22/tcp            | High     |
  | VNC Server                       | 5900/tcp          | High     |
  | Samba (Windows file sharing)     | 445/tcp, 139/tcp  | Critical |
  | FTP Server                       | 21/tcp            | Critical |
  | Apache Web Server                | 80/tcp, 443/tcp   | Medium   |
  | Nginx Web Server                 | 80/tcp, 443/tcp   | Medium   |
  | MySQL / MariaDB                  | 3306/tcp          | High     |
  | PostgreSQL                       | 5432/tcp          | High     |
  | Transmission (web UI)            | 9091/tcp          | Medium   |
  | qBittorrent (web UI)             | 8080/tcp          | Medium   |
  | Avahi (local network discovery)  | 5353/udp          | Low      |
  | CUPS (network printing)          | 631/tcp           | Low      |
  | Cockpit (web admin)              | 9090/tcp          | Medium   |
  | WireGuard VPN                    | 51820/udp         | High     |
  | Redis                            | 6379/tcp          | High     |
  | Jellyfin                         | 8096/tcp          | Medium   |
  | Plex Media Server                | 32400/tcp         | Medium   |
  | Home Assistant                   | 8123/tcp          | Medium   |

- **Docker analysis** — dedicated section detecting iptables bypass risk and listing exposed container ports
- **Listening ports analysis** — unified single-pass analysis; ephemeral and system ports silently skipped; NetBIOS handled with contextual warning
- **Exposure classification** per service: `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **Contextual explanations** — plain-language description of the risk for each detected situation
- **Ready-to-run remediation commands** — exact `ufw` commands to fix each issue
- **--fix mode** — interactive fix section after the summary; each automatable fix requires `[y/N]` confirmation; manual-only items displayed without execution
- **JSON export** — `--json` for summary, `--json-full` for complete audit including ports and UFW rules
- **Categorised summary** — findings split into three blocks: *Action required* / *Possible improvements* / *Normal configuration*; auto-generated interpretation phrase
- **Implicit policy note** — informs when high-risk services rely on default deny policy rather than explicit rules
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH
- **Bilingual interface** — English by default, French with `--french`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Optional detailed report** — full log file with system info, findings, and recommendations
- **JSON report** — machine-readable export alongside the `.log` file when using `-d --json`

---

## Requirements

- Linux system — Debian, Ubuntu, or a derivative (other distributions will work but display a warning)
- UFW installed (`sudo apt install ufw`)
- Bash 4+
- `ss` recommended (`iproute2` package) — falls back to `netstat` if absent
- `python3` recommended for pretty-printed JSON export (optional)
- `docker` CLI for Docker analysis (optional)

---

## Installation

```bash
# Download
curl -O https://raw.githubusercontent.com/Masbateno/Automated-UFW-audit/main/ufw_audit.sh

# Make executable
chmod +x ufw_audit.sh
```

---

## Usage

```bash
# Standard audit (recommended)
sudo ./ufw_audit.sh

# Audit in French
sudo ./ufw_audit.sh --french

# Verbose mode — shows raw ss/netstat output and port details
sudo ./ufw_audit.sh -v

# Detailed mode — generates a full report file
sudo ./ufw_audit.sh -d

# Fix mode — propose and apply corrections interactively
sudo ./ufw_audit.sh --fix

# Fix mode — apply all corrections without confirmation
sudo ./ufw_audit.sh --fix --yes

# Export summary as JSON
sudo ./ufw_audit.sh --json

# Export full audit as JSON + report file
sudo ./ufw_audit.sh --json-full -d

# No colour output (useful for pipes and log redirection)
sudo ./ufw_audit.sh --no-color > audit.txt

# Re-ask all custom port questions (after changing a service port)
sudo ./ufw_audit.sh --reconfigure

# Show version
./ufw_audit.sh -V

# Show help
./ufw_audit.sh -h
```

All options can be combined:

```bash
sudo ./ufw_audit.sh --french -v -d --fix
```

---

## Custom port configuration

When a service is detected on a non-standard port (e.g. SSH on port 2222), the
script prompts once:

```
  ┌──────────────────────────────────────────────────────────┐
  │  SSH Server                                              │
  │  Port not detected automatically.                        │
  │                                                          │
  │  On which port is this service listening?                │
  │  Enter = default port: 22                                │
  └──────────────────────────────────────────────────────────┘
  Port: 2222
  ↳ Port saved for future audits.
```

The answer is saved to `~/.ufw_audit.conf` and reused on subsequent runs.
To reset all saved ports:

```bash
sudo ./ufw_audit.sh --reconfigure
```

---

## Example output

```
╔══════════════════════════════════════════════════════════════╗
║   ██╗   ██╗███████╗██╗    ██╗  ┌──────────────────────────┐  ║
║   ██║   ██║██╔════╝██║    ██║  │  UFW-AUDIT  v0.6.0       │  ║
║   ██║   ██║█████╗  ██║ █╗ ██║  │  UFW firewall audit      │  ║
║   ██║   ██║██╔══╝  ██║███╗██║  └──────────────────────────┘  ║
║   ╚██████╔╝██║     ╚███╔███╔╝              _ _               ║
║    ╚═════╝ ╚═╝      ╚══╝╚══╝             _(-_-)_             ║
║                                            audit             ║
╠══════════════════════════════════════════════════════════════╣
║  System       : Ubuntu 24.04 LTS                             ║
║  Host         : my-machine                                   ║
║  UFW          : v0.36.2                                      ║
║  User         : alice                                        ║
║  Date         : 19/03/2026 10:00                             ║
╚══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                  │
└─────────────────────────────────────────────────────────────┘

  ▶ SSH Server
✔ [OK] Service active and enabled at boot
✖ [ALERT] Your SSH access is reachable from any address on the internet.

    What to do?
    → To restrict SSH to your local network:
    →   sudo ufw delete allow 22/tcp
    →   sudo ufw allow from 192.168.1.0/24 to any port 22

┌─────────────────────────────────────────────────────────────┐
│  DOCKER ANALYSIS                                            │
└─────────────────────────────────────────────────────────────┘

✖ [ALERT] Docker is installed and active. By default, Docker modifies
  iptables directly and bypasses UFW rules.

╔══════════════════════════════════════════════════════════════╗
║  AUDIT SUMMARY                                               ║
╠══════════════════════════════════════════════════════════════╣
║  Security score    :  7/10                                   ║
║  Risk level        :  ⚠ MEDIUM                               ║
║  Network context   :  🏠 Local network only                  ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ Action required                                           ║
╠══════════════════════════════════════════════════════════════╣
║    ✖  Your SSH access is reachable from any address…         ║
╠══════════════════════════════════════════════════════════════╣
║  Score breakdown                                             ║
╠══════════════════════════════════════════════════════════════╣
║  -2  Your SSH access is reachable from any addres…           ║
║  -1  Docker is installed and active…                         ║
╚══════════════════════════════════════════════════════════════╝

  Corrections are needed. Prioritize items marked "Action required".

╔══════════════════════════════════════════════════════════════╗
║  AVAILABLE FIXES                                             ║
╠══════════════════════════════════════════════════════════════╣
║    ✔  1 automatic fix(es) available                          ║
╚══════════════════════════════════════════════════════════════╝

  ✖  Your SSH access is reachable from any address…
  → sudo ufw delete allow 22/tcp
  Apply this fix? [y/N]
```

---

## Report files

With `-d`, a timestamped report is created in the same directory as the script:

```
ufw_audit_20260319_100000.log
ufw_audit_20260319_100000.json   ← with --json or --json-full
```

---

## Options reference

| Option                | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| *(no option)*         | Run standard audit                                               |
| `-v`, `--verbose`     | Show technical details (raw port table, per-port exposure)       |
| `-d`, `--detailed`    | Generate a full report file                                      |
| `-r`, `--reconfigure` | Re-ask all custom port questions                                  |
| `--fix`               | Propose and apply fixes interactively after the audit            |
| `--yes`               | Apply all fixes without confirmation (requires `--fix`)          |
| `--json`              | Export summary as JSON (stdout, or file with `-d`)               |
| `--json-full`         | Export full audit as JSON including ports and UFW rules          |
| `--no-color`          | Disable ANSI colour output                                       |
| `--french`            | Switch interface to French                                       |
| `-V`, `--version`     | Show version and exit                                            |
| `-h`, `--help`        | Show help and exit                                               |

---

## Files

| File                            | Description                                       |
|---------------------------------|---------------------------------------------------|
| `ufw_audit.sh`                  | Main script                                       |
| `~/.ufw_audit.conf`             | Per-user custom port configuration (auto-created, permissions 600) |
| `ufw_audit_YYYYMMDD_HHMMSS.log` | Detailed report (created with `-d`)               |
| `ufw_audit_YYYYMMDD_HHMMSS.json`| JSON export (created with `-d --json`)            |

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Author

so6