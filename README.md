*[Lire en français](README_FR.md)*

# ufw-audit v0.10

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.10-blue)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.8%2B-yellow)

Lightweight UFW firewall audit tool for Linux — designed for regular users, not system administrators.

ufw-audit analyses your UFW configuration, detects exposed network services, classifies risks per service, and provides plain-language explanations with ready-to-run remediation commands.

---

## Features

- **ASCII banner** with system information (distro, host, UFW version, user, date)
- **UFW status check** — active/inactive, default incoming policy
- **UFW rule analysis** — duplicate rules, unrestricted `allow from any`, IPv6 consistency
- **Contextual scoring** — network context detection (direct public IP vs NAT); penalties doubled on internet-exposed machines; firewall inactive caps score at 3/10
- **Detection of 22 common network services** with UFW exposure analysis and two-axis risk context (exposure + threat) for critical and high-risk services
- **Docker analysis** — iptables bypass detection and list of ports exposed by running containers
- **Listening ports analysis** — unified single-pass analysis; ephemeral and system ports silently skipped; NetBIOS handled with contextual warning
- **UFW log analysis** — parses `/var/log/ufw.log` over a configurable period (`--log-days=N`, default 7 days); total blocked attempts, top source IPs with geolocation, top targeted ports, bruteforce detection (>10 attempts/60s), attempts on installed service ports
- **IP geolocation** — source IPs enriched with country and operator via `whois`; private ranges identified as local network; results cached per session
- **DDNS / external exposure detection** — detects active DDNS clients (ddclient, inadyn, No-IP, DuckDNS); extracts the configured domain; crosses with unrestricted UFW ALLOW rules to identify internet-exposed ports
- **Exposure classification** per service: `open to internet` / `local network only` / `blocked by UFW` / `no rule`
- **Fix mode** — interactive section after the summary; each automatable fix requires `[y/N]` confirmation; manual-only items displayed without execution
- **Categorised summary** — findings split into three blocks: *Action required* / *Possible improvements* / *Normal configuration*; auto-generated interpretation phrase
- **Implicit policy note** — flags when high-risk services rely on the default `deny` policy rather than explicit rules
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH
- **Bilingual interface** — English by default, French with `--french`
- **No-colour mode** — `--no-color` for clean output in pipes and log files
- **Optional detailed report** — timestamped log file with system info, findings, and recommendations

---

## Detected services

| Service                          | Default port         | Risk     | Context                                                                              |
|----------------------------------|----------------------|----------|--------------------------------------------------------------------------------------|
| SSH Server                       | 22/tcp               | Critical | Heavily targeted by automated scanners; full shell access if compromised             |
| VNC Server                       | 5900/tcp             | Critical | Often unencrypted, weak auth; equivalent to physical machine access                  |
| Samba (Windows file sharing)     | 445/tcp, 139/tcp     | Critical | LAN-only by design; ransomware vector (EternalBlue/WannaCry) if exposed              |
| FTP Server                       | 21/tcp               | Critical | Unencrypted protocol; credentials and files transmitted in plain text                |
| MySQL / MariaDB                  | 3306/tcp             | Critical | Password auth, CVE history; full database exfiltration if exposed                    |
| PostgreSQL                       | 5432/tcp             | Critical | Configurable auth; RCE possible via pg_execute_server_program                        |
| Redis                            | 6379/tcp             | Critical | No auth by default historically; documented RCE — actively exploited                 |
| Cockpit (web admin)              | 9090/tcp             | High     | Web admin interface; full system control if compromised                              |
| WireGuard VPN                    | 51820/udp            | High     | Intentional internet exposure; full internal network access if keys stolen           |
| Home Assistant                   | 8123/tcp             | High     | Controls physical devices (locks, alarms); local network access via automations      |
| Nextcloud                        | 80/tcp, 443/tcp      | High     | Personal file server; full file/contact/calendar access if compromised               |
| Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp   | High     | No auth by default; anyone can control IoT devices if exposed                        |
| Apache Web Server                | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Nginx Web Server                 | 80/tcp, 443/tcp      | Medium   | Standard web exposure; risk depends on hosted content                                |
| Jellyfin                         | 8096/tcp             | Medium   | Media library access; no critical system data                                        |
| Plex Media Server                | 32400/tcp            | Medium   | Media library access; no critical system data                                        |
| Transmission (web UI)            | 9091/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| qBittorrent (web UI)             | 8080/tcp             | Medium   | Download control; file access limited to torrent directory                           |
| Gitea                            | 3000/tcp             | Medium   | Git forge; disable public registration if not needed                                 |
| Avahi (local network discovery)  | 5353/udp             | Low      | LAN-only mDNS; no data access, discovery only                                        |
| CUPS (network printing)          | 631/tcp              | Low      | Listens on localhost by default; negligible if not exposed                           |
| Syncthing                        | 8384/tcp, 22000/tcp  | Low      | Web UI on localhost by default; sync port may be internet-facing                     |

> **ℹ Note on service coverage:** Detection and classification for the following services has been validated through real-world testing: SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Other services are implemented but not yet validated by a formal test protocol. If you run one of these services and notice incorrect behaviour, please open an issue on GitHub.

---

## Requirements

- Linux system — Debian, Ubuntu, Linux Mint, or derivative
- UFW installed: `sudo apt install ufw`
- Python 3.8+
- `ss` recommended (`iproute2` package) — available by default on modern systems
- `python3-geoip2` + GeoLite2 database recommended for IP geolocation (optional): `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI for Docker analysis (optional)

---

## Installation

```bash
# Clone or download the repository
git clone https://github.com/Masbateno/Automated-UFW-audit.git
cd ufw-audit

# Install (requires root)
chmod +x install.sh
sudo ./install.sh
```

The installer:
- Checks for Python 3.8+
- Copies the package to `/usr/local/lib/ufw_audit/`
- Copies data files to `/usr/local/share/ufw-audit/`
- Creates the entry point at `/usr/local/bin/ufw-audit`
- Installs bash completion to `/etc/bash_completion.d/ufw-audit`
- Writes an installation manifest to `/usr/local/share/ufw-audit/install.manifest`
- Displays every action taken

### Dry-run — see without touching

```bash
sudo ./install.sh --dry-run
```

### Bash completion

After installation, activate bash completion for the current session:

```bash
source /etc/bash_completion.d/ufw-audit
```

To activate permanently (all future sessions):

```bash
echo "source /etc/bash_completion.d/ufw-audit" >> ~/.bashrc
```

Then use `ufw-audit --<TAB>` to complete options.

---

## Uninstall

```bash
sudo ./install.sh --uninstall
```

The installer reads the manifest, removes exactly the installed files, only removes a directory if it is empty, and offers to remove the user configuration separately.

---

## Usage

```bash
# Standard audit
sudo ufw-audit

# Audit in French
sudo ufw-audit --french

# Verbose mode — technical details and port table
sudo ufw-audit -v

# Detailed mode — generate a full report file
sudo ufw-audit -d

# Fix mode — propose and apply corrections interactively
sudo ufw-audit -f

# Fix mode — apply all corrections without confirmation
sudo ufw-audit -f -y

# No-colour output (useful for pipes and redirection)
sudo ufw-audit -n > audit.txt

# Analyse logs over 14 days instead of 7
sudo ufw-audit --log-days=14

# Reconfigure custom ports
sudo ufw-audit -r

# Show version (no sudo required)
ufw-audit -V

# Show help (no sudo required)
ufw-audit -h
```

Options can be combined:

```bash
sudo ufw-audit -v -d --fix
```

---

## Custom port configuration

When a service is detected on a non-standard port (e.g. SSH on port 2222), the script offers to save the port once. The answer is saved to `~/.config/ufw-audit/config.conf` and reused on subsequent audits. To reconfigure:

```bash
sudo ufw-audit --reconfigure
```

---

## Example output

```
╔══════════════════════════════════════════════════════════════╗
║   ██╗   ██╗███████╗██╗    ██╗  ┌────────────────────────┐    ║
║   ██║   ██║██╔════╝██║    ██║  │  UFW-AUDIT  v0.9.0     │    ║
║   ██║   ██║█████╗  ██║ █╗ ██║  │  UFW firewall audit    │    ║
║   ██║   ██║██╔══╝  ██║███╗██║  └────────────────────────┘    ║
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


┌──────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                   │
└──────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Risk context — CRITICAL
    Exposure : Heavily targeted by automated scanners and brute-force attacks
    Threat   : Full shell access to the machine, privilege escalation

✖ [ALERT] Port 22/tcp: exposure = open to internet
    → sudo ufw delete allow 22/tcp
    → sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp


┌──────────────────────────────────────────────────────────────┐
│  DOCKER ANALYSIS                                             │
└──────────────────────────────────────────────────────────────┘

✖ [ALERT] Docker bypasses UFW rules via iptables (daemon.json missing)
    → sudo mkdir -p /etc/docker && echo '{"iptables": false}' | sudo tee /etc/docker/daemon.json

╔══════════════════════════════════════════════════════════════╗
║  Security score : 7/10                                       ║
║  Risk level     : ⚠ MEDIUM                                   ║
║  Network context: 🏠 Local network only                      ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ Action required                                           ║
║    ✖  Port 22/tcp: exposure = open to internet               ║
║    ✖  Docker bypasses UFW rules via iptables…                ║
╠══════════════════════════════════════════════════════════════╣
║  Score breakdown                                             ║
║    -2  Port 22/tcp open to internet                          ║
║    -1  Docker iptables bypass                                ║
╚══════════════════════════════════════════════════════════════╝

  Corrections needed. Prioritize items marked "Action required".
```

---

## Report files

With `-d`, a timestamped report is created in the current directory:

```
ufw_audit_20260319_100000.log
```

The report contains: system information, all timestamped findings, complete listening port list, detailed log analysis (top IPs with geolocation, top ports, bruteforce, hits on installed service ports), risk context for critical/high services, score summary.

---

## Options reference

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| *(no option)*           | Standard audit                                                     |
| `-v`, `--verbose`       | Show technical details (port table, per-port exposure)             |
| `-d`, `--detailed`      | Generate a full report file                                        |
| `-f`, `--fix`           | Propose and apply corrections interactively                        |
| `-y`, `--yes`           | Apply all corrections without confirmation (use with `-f`)         |
| `-r`, `--reconfigure`   | Reconfigure all custom ports                                       |
| `-n`, `--no-color`      | Disable ANSI colour output                                         |
| `--json`                | Export summary as JSON                                             |
| `--json-full`           | Export full audit details as JSON                                  |
| `--log-days=N`          | Analyse logs over N days (default: 7)                              |
| `--french`              | Switch interface to French                                         |
| `-V`, `--version`       | Show version and exit (no sudo required)                           |
| `-h`, `--help`          | Show help and exit (no sudo required)                              |

---

## Files

| File                                 | Description                                                          |
|--------------------------------------|----------------------------------------------------------------------|
| `/usr/local/bin/ufw-audit`           | Entry point                                                          |
| `/usr/local/lib/ufw_audit/`          | Python package                                                       |
| `/usr/local/share/ufw-audit/`        | Data files (locales, services.json, manifest)                        |
| `/usr/local/share/doc/ufw-audit/`    | Documentation                                                        |
| `/etc/bash_completion.d/ufw-audit`   | Bash completion                                                      |
| `~/.config/ufw-audit/config.conf`    | User configuration (custom ports, auto-created, permissions 600)     |
| `ufw_audit_YYYYMMDD_HHMMSS.log`      | Detailed report (created with `-d`, in the current directory)        |

---

## Important note

ufw-audit is an audit and diagnostic tool, not a security shield. It analyses your configuration and flags problems — but it does not apply corrections automatically without your consent, and it cannot detect everything. Some software like Docker can bypass UFW by manipulating iptables directly: ufw-audit detects this specific case and flags it, but other similar vectors exist that fall outside the current scope of the project. In short: ufw-audit helps you see more clearly — it does not replace good general security hygiene.

---

## Roadmap

**v0.9** — Complete Python rewrite, 421 unit tests, transparent installer with manifest, bash completion, bilingual EN/FR, 22 services with two-axis risk context

**v0.10** *(current)* — Optional GeoIP2 geolocation, whois removal, short CLI flags, bash completion for install.sh, score scope disclaimer

**v0.11** — CLI consolidation, field testing, non-interactive mode (`--quiet`, meaningful exit codes), `check_virtualization()` — libvirt/KVM/VirtualBox and Snap confinement detection (iptables bypass risk, similar to Docker)

**v0.12** — Cron/email automation support, `AUTOMATION.md`

**v1.0** — Stable, complete, validated CLI

**Post v1.0**
- Web UI (`--gui`) — graphical interface for non-technical users, pedagogical approach, simplified scope
- Launchpad PPA / `.deb` package if adoption warrants it

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Author

so6