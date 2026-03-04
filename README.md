# UFW-audit v0.4.0

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.4.0-blue)
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
- **Service-aware audit engine** — detects 13 common network services and analyses
  their UFW exposure:

  |Service                         |Default port      |Risk      |
  |--------------------------------|------------------|----------|
  | SSH Server                     | 22/tcp           | High     |
  | VNC Server                     | 5900/tcp         | High     |
  | Samba (Windows file sharing)   | 445/tcp, 139/tcp | Critical |
  | FTP Server                     | 21/tcp           | Critical |
  | Apache Web Server              | 80/tcp, 443/tcp  | Medium   |
  | Nginx Web Server               | 80/tcp, 443/tcp  | Medium   |
  | MySQL / MariaDB                | 3306/tcp         | High     |
  | PostgreSQL                     | 5432/tcp         | High     |
  | Transmission (web UI)          | 9091/tcp         | Medium   |
  | qBittorrent (web UI)           | 8080/tcp         | Medium   |
  | Avahi (local network discovery)| 5353/udp         | Low      |          
  | CUPS (network printing)        | 631/tcp          | Low      |
  | Cockpit (web admin)            | 9090/tcp         | Medium   |

- **Exposure classification** per service: `open to internet` / `local network only`
  / `blocked by UFW` / `no rule`
- **Contextual explanations** — plain-language description of the risk for each
  detected situation
- **Ready-to-run remediation commands** — exact `ufw` commands to fix each issue
- **Custom port support** — if a service runs on a non-standard port, the script
  asks once and remembers the answer in `~/.ufw_audit.conf`
- **Listening ports overview** — total count of active listening ports via `ss` or
  `netstat`
- **Security score** (0–10) with risk level: LOW / MEDIUM / HIGH
- **Bilingual interface** — English by default, French with `--french`
- **Optional detailed report** — full log file with system info, findings, and
  recommendations

---

## Requirements

- Linux system — Debian, Ubuntu, or a derivative (other distributions will work but
  display a warning)
- UFW installed (`sudo apt install ufw`)
- Bash 4+
- `ss` recommended (`iproute2` package) — falls back to `netstat` if absent

---

## Installation

```bash
# Download
curl -O curl -O https://raw.githubusercontent.com/Masbateno/Automated-UFW-audit/main/ufw_audit.sh

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

# Re-ask all custom port questions (after changing a service port)
sudo ./ufw_audit.sh --reconfigure

# Show version
./ufw_audit.sh -V

# Show help
./ufw_audit.sh -h
```

All options can be combined:

```bash
sudo ./ufw_audit.sh --french -v -d
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
║   ██║   ██║██╔════╝██║    ██║  │  UFW-AUDIT  v0.4.0       │  ║
║   ██║   ██║█████╗  ██║ █╗ ██║  │  UFW firewall audit      │  ║
║   ██║   ██║██╔══╝  ██║███╗██║  └──────────────────────────┘  ║
║   ╚██████╔╝██║     ╚███╔███╔╝              _ _               ║
║    ╚═════╝ ╚═╝      ╚══╝╚══╝             _(-_-)_             ║
║                                            audit             ║
╠══════════════════════════════════════════════════════════════╣
║  System       : Ubuntu 24.04.4 LTS                           ║
║  Host         : my-machine                                   ║
║  UFW          : v0.36.2                                      ║
║  User         : alice                                        ║
║  Date         : 04/03/2026 14:35                             ║
╚══════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────┐
│  FIREWALL STATUS                                            │
└─────────────────────────────────────────────────────────────┘

✔ [OK] UFW firewall is active
✔ [OK] Default policy: incoming connections blocked (recommended)

┌─────────────────────────────────────────────────────────────┐
│  NETWORK SERVICES ANALYSIS                                  │
└─────────────────────────────────────────────────────────────┘

  ▶ SSH Server
✔ [OK] Service active and enabled at boot
✖ [ALERT] Your SSH access is reachable from any address on the internet.
          Automated brute-force attempts are very common on this port.

    What to do?
    → To restrict SSH to your local network (replace 192.168.1.0/24
      with your network range, find it with 'ip route') :
    →   sudo ufw delete allow 22/tcp
    →   sudo ufw allow from 192.168.1.0/24 to any port 22

  ▶ Samba (Windows file sharing)
✔ [OK] Access explicitly blocked by UFW. Good configuration.

┌─────────────────────────────────────────────────────────────┐
│  AUDIT SUMMARY                                              │
└─────────────────────────────────────────────────────────────┘

╔══════════════════════════════════════════════════════════════╗
║  AUDIT SUMMARY                                               ║
╠══════════════════════════════════════════════════════════════╣
║  ✔ OK         :  4                                           ║
║  ⚠ Warning    :  1                                           ║
║  ✖ Alert      :  1                                           ║
╠══════════════════════════════════════════════════════════════╣
║  Security score    :  7/10                                   ║
║  Risk level        :  ⚠ MEDIUM                               ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Report file

With `-d`, a timestamped report is created in the same directory as the script:

```
ufw_audit_20260304_143512.log
```

The report contains: system information, language used, full findings with
recommendations, and the audit summary.

---

## Options reference

| Option                | Description                                                |
|-----------------------|------------------------------------------------------------|
| *(no option)*         | Run standard audit                                         |
| `-v`, `--verbose`     | Show technical details (raw port table, per-port exposure) |
| `-d`, `--detailed`    | Generate a full report file                                |
| `-r`, `--reconfigure` | Re-ask all custom port questions                           |
| `--french`            | Switch interface to French                                 |
| `-V`, `--version`     | Show version and exit                                      |
| `-h`, `--help`        | Show help and exit                                         |

---

## Files

| File                            | Description                                       |
|---------------------------------|---------------------------------------------------|
| `ufw_audit.sh`                  | Main script                                       |
| `~/.ufw_audit.conf`             | Per-user custom port configuration (auto-created) |
| `ufw_audit_YYYYMMDD_HHMMSS.log` | Detailed report (created with `-d`)               |

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Author

so6
