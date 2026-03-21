# ufw-audit v0.9

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.9-blue)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.8%2B-blue)

Lightweight **UFW firewall audit tool** for Linux — designed for regular users,
not system administrators.

ufw-audit analyses your UFW configuration, detects exposed network services,
classifies risks per service, and gives plain-language explanations and
ready-to-run remediation commands.

---

## Features

- **Coloured ASCII banner** with system info (distro, host, UFW version, user, date)
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (public IP vs NAT); penalties
  increased on internet-exposed machines; firewall inactive caps score at 3/10
- **Service-aware audit engine** — detects 22 common network services and analyses
  their UFW exposure:

  | Service                          | Default port       | Risk     | Basis |
  |----------------------------------|--------------------|----------|-------|
  | SSH Server                       | 22/tcp             | Critical | Heavily targeted by automated brute-force; full shell access if compromised |
  | VNC Server                       | 5900/tcp           | Critical | Often unencrypted, weak auth; equivalent to physical machine access |
  | Samba (Windows file sharing)     | 445/tcp, 139/tcp   | Critical | LAN-only by design; ransomware vector (EternalBlue/WannaCry) if exposed |
  | FTP Server                       | 21/tcp             | Critical | Unencrypted protocol; credentials and files transmitted in plain text |
  | MySQL / MariaDB                  | 3306/tcp           | Critical | Password auth, CVE history; full database exfiltration if exposed |
  | PostgreSQL                       | 5432/tcp           | Critical | Password auth; RCE possible via pg_execute_server_program extension |
  | Redis                            | 6379/tcp           | Critical | No auth by default; documented RCE via configuration — actively exploited |
  | Apache Web Server                | 80/tcp, 443/tcp    | Medium   | Standard web exposure; risk depends on hosted content |
  | Nginx Web Server                 | 80/tcp, 443/tcp    | Medium   | Standard web exposure; risk depends on hosted content |
  | Transmission (web UI)            | 9091/tcp           | Medium   | Download control and file access limited to torrent directory |
  | qBittorrent (web UI)             | 8080/tcp           | Medium   | Download control and file access limited to torrent directory |
  | Jellyfin                         | 8096/tcp           | Medium   | Media library access; no critical system data |
  | Plex Media Server                | 32400/tcp          | Medium   | Media library access; no critical system data |
  | Gitea                            | 3000/tcp           | Medium   | Git forge; disable public registration if not needed |
  | Syncthing                        | 8384/tcp, 22000/tcp| Medium   | Web UI on localhost by default; sync port may be internet-facing |
  | Avahi (local network discovery)  | 5353/udp           | Low      | LAN-only mDNS; no data access, discovery only |
  | CUPS (network printing)          | 631/tcp            | Low      | Listens on localhost by default; negligible if not exposed |
  | Cockpit (web admin)              | 9090/tcp           | High     | Web admin interface; full system control if compromised |
  | WireGuard VPN                    | 51820/udp          | High     | Intentional internet exposure; full internal network access if keys stolen |
  | Home Assistant                   | 8123/tcp           | High     | Controls physical devices (locks, alarms); local network access via automations |
  | Nextcloud                        | 80/tcp, 443/tcp    | High     | Personal cloud; full file/contact/calendar access if compromised |
  | Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp | High     | No auth by default; anyone can control IoT devices if exposed |

- **Risk context** — for each detected high/critical service, a two-axis contextual
  summary is displayed: exposure surface and potential threat
- **Docker analysis** — detects iptables bypass risk (`daemon.json`) and lists
  exposed container ports
- **Listening ports analysis** — single-pass analysis of all listening ports;
  ephemeral and OS-internal ports silently skipped; NetBIOS handled with contextual
  warning
- **UFW log analysis** — parses `/var/log/ufw.log` over a configurable period
  (`--log-days=N`, default 7); reports total blocked attempts, top source IPs with
  geolocation, top targeted ports, bruteforce detection (>10 attempts/60s), and
  attempts on installed service ports
- **IP geolocation** — source IPs enriched with country and operator via `whois`;
  private ranges identified as local network; graceful fallback if `whois` absent
- **DDNS / external exposure detection** — detects active DDNS clients (ddclient,
  inadyn, No-IP, DuckDNS); extracts configured domain; crosses with unrestricted
  UFW ALLOW rules to identify internet-exposed ports
- **Exposure classification** per service:
  `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **Contextual explanations** — plain-language description of the risk for each
  detected situation
- **Ready-to-run remediation commands** — exact `ufw` commands to fix each issue
- **Fix mode** — interactive fix section after the summary; each automatable fix
  requires `[y/N]` confirmation
- **Categorised summary** — findings split into three blocks:
  *Action required* / *Possible improvements* / *Normal configuration*
- **Implicit policy note** — informs when high-risk services rely on the default
  deny policy rather than explicit UFW rules
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH
- **Bilingual interface** — English by default, French with `--french`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Optional detailed report** — timestamped `.log` file with full findings

> **ℹ Note on service coverage:** Detection and classification for the following
> services has been validated through real-world testing: SSH, Samba, Avahi, CUPS,
> Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx.
> Other services are implemented but not yet validated by a formal test protocol.
> If you run one of these services and notice incorrect behaviour, please open an
> issue on GitHub — feedback is very welcome.

---

## Requirements

- Linux system — Debian, Ubuntu, Linux Mint, or any derivative
- Python 3.8 or higher (`python3 --version`)
- UFW installed (`sudo apt install ufw`)
- `ss` command available (provided by the `iproute2` package, present by default
  on most distributions)
- `whois` for IP geolocation (optional — `sudo apt install whois`)
- `docker` CLI for Docker analysis (optional)

---

## Installation

```bash
# Clone or download the repository, then:
cd ufw_audit_project/

# Install system-wide
sudo ./install.sh
```

The installer will:

1. Check Python 3.8+ is available
2. Verify all source files are present
3. Copy the package to `/usr/local/lib/ufw_audit/`
4. Copy data files and locales to `/usr/local/share/ufw-audit/`
5. Create the entry point at `/usr/local/bin/ufw-audit`
6. Write an install manifest to `/usr/local/share/ufw-audit/install.manifest`

To preview what the installer would do without making any changes:

```bash
sudo ./install.sh --dry-run
```

---

## Uninstallation

```bash
sudo ./install.sh --uninstall
```

The uninstaller reads the manifest and removes exactly what was installed —
no more, no less. Directories are only removed if empty after file removal.
User configuration (`~/.config/ufw-audit/`) is offered separately with a
`[y/N]` prompt.

---

## Usage

```bash
# Standard audit
sudo ufw-audit

# Audit in French
sudo ufw-audit --french

# Verbose mode — shows raw port table and per-port details
sudo ufw-audit -v

# Detailed mode — generates a full timestamped report file
sudo ufw-audit -d

# Verbose + detailed + French
sudo ufw-audit --french -v -d

# Fix mode — propose and apply corrections interactively
sudo ufw-audit --fix

# Fix mode — apply all corrections without confirmation
sudo ufw-audit --fix --yes

# Analyse logs over a custom period (default: 7 days)
sudo ufw-audit --log-days=30

# No colour output (useful for pipes and log redirection)
sudo ufw-audit --no-color > audit.txt

# Show version
ufw-audit --version

# Show help
ufw-audit --help
```

All options can be combined:

```bash
sudo ufw-audit --french -v -d --fix
```

---

## Options reference

| Option              | Description                                                      |
|---------------------|------------------------------------------------------------------|
| *(no option)*       | Run standard audit                                               |
| `-v`, `--verbose`   | Show technical details (raw port table, per-port exposure)       |
| `-d`, `--detailed`  | Generate a full timestamped report file in the current directory |
| `--fix`             | Propose and apply fixes interactively after the audit            |
| `--yes`             | Apply all fixes without confirmation (requires `--fix`)          |
| `--log-days=N`      | Number of days of UFW logs to analyse (default: 7)               |
| `--no-color`        | Disable ANSI colour output                                       |
| `--french`          | Switch interface to French                                       |
| `--reconfigure`     | Reset saved custom port configuration                            |
| `--version`         | Show version and exit                                            |
| `--help`            | Show help and exit                                               |

---

## Custom port configuration

When a service is detected but its port cannot be auto-detected, the tool prompts
once and saves the answer for future runs. Configuration is stored per-user in
`~/.config/ufw-audit/config.conf`.

To reset all saved configuration:

```bash
sudo ufw-audit --reconfigure
```

---

## Example output

```
╔══════════════════════════════════════════════════════════════╗
║   ██╗   ██╗███████╗██╗    ██╗  ┌────────────────────────┐    ║
║   ██║   ██║██╔════╝██║    ██║  │  UFW-AUDIT  v0.9       │    ║
║   ██║   ██║█████╗  ██║ █╗ ██║  │  UFW firewall audit    │    ║
║   ██║   ██║██╔══╝  ██║███╗██║  └────────────────────────┘    ║
║   ╚██████╔╝██║     ╚███╔███╔╝              _ _               ║
║    ╚═════╝ ╚═╝      ╚══╝╚══╝             _(-_-)_             ║
║                                            audit             ║
╠══════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                            ║
║  Host          : my-machine                                  ║
║  UFW           : v0.36.2                                     ║
║  User          : alice                                       ║
║  Date          : 20/03/2026 10:00                            ║
╚══════════════════════════════════════════════════════════════╝


┌──────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                     │
└──────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Risk context — CRITICAL
    Exposure : Heavily targeted by automated scanners and brute-force attacks
    Threat   : Full shell access, privilege escalation, lateral movement

✖ [ALERT] Port 22/tcp is open to the internet without source restriction.
    → sudo ufw delete allow 22/tcp
    → sudo ufw allow from 192.168.1.0/24 to any port 22


┌──────────────────────────────────────────────────────────────┐
│  DOCKER ANALYSIS                                               │
└──────────────────────────────────────────────────────────────┘

✖ [ALERT] Docker bypasses UFW via iptables — UFW rules do not apply to containers.
    → sudo mkdir -p /etc/docker && echo '{"iptables": false}' | sudo tee /etc/docker/daemon.json


╔══════════════════════════════════════════════════════════════╗
║  Security score : 7/10                                       ║
║  Risk level     : ⚠ MEDIUM                                   ║
║  Network context: 🏠 Local network only                      ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ Action required                                           ║
║    ✖  Port 22/tcp is open to the internet without sourc…     ║
║    ✖  Docker bypasses UFW via iptables…                      ║
╚══════════════════════════════════════════════════════════════╝

  Corrections are needed. Prioritize items marked "Action required".
```

---

## Report files

With `-d`, a timestamped report is created in the current directory:

```
ufw_audit_20260320_100000.log
```

---

## Installed files

| Location                                        | Description                              |
|-------------------------------------------------|------------------------------------------|
| `/usr/local/bin/ufw-audit`                      | Entry point (executable)                 |
| `/usr/local/lib/ufw_audit/`                     | Python package                           |
| `/usr/local/lib/ufw_audit/checks/`              | Individual check modules                 |
| `/usr/local/share/ufw-audit/locales/`           | Language files (`en.json`, `fr.json`)    |
| `/usr/local/share/ufw-audit/data/`              | Service registry (`services.json`)       |
| `/usr/local/share/doc/ufw-audit/`               | Documentation                            |
| `/usr/local/share/ufw-audit/install.manifest`   | Install manifest (used by `--uninstall`) |
| `~/.config/ufw-audit/config.conf`               | Per-user configuration (auto-created)    |
| `./ufw_audit_YYYYMMDD_HHMMSS.log`               | Detailed report (created with `-d`)      |

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Author

so6
