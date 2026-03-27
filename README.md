*[Lire en français](README_FR.md)* · *[Technical documentation](DOCUMENTS/README_TECH.md)*

# 🔥 ufw-audit — Smart UFW Firewall Auditor

Analyse your UFW configuration in seconds, detect critical misconfigurations, and fix them automatically.

> ⚡ Designed to be **simple, readable, and actionable**
> 🛡️ Built to catch the mistakes that actually expose your machine

---

## 🚀 Why ufw-audit?

UFW is simple… but **easy to misconfigure**.

A single rule like:

```bash
sudo ufw allow from any
```

👉 leaves your machine **wide open to the entire Internet**.

**ufw-audit detects this type of problem immediately**, explains the risk, and suggests a fix.

---

## ✨ Key features

### 🔍 Full audit

- UFW rule analysis (`ufw status`)
- Detection of dangerous configurations
- IPv4 / IPv6 consistency check

### 🚨 Intelligent risk detection

- Overly permissive rules (`Anywhere ALLOW IN Anywhere`)
- Critical ports exposed (Redis, MySQL, PostgreSQL…)
- Redundant or useless rules
- Services that are actually exposed — not just "open in UFW"

### 🧠 Real system analysis

- Cross-checks UFW against ports actually listening (`ss`)
- Eliminates false positives (e.g. loopback-only services)
- Filters system ports (DNS, DHCP, mDNS…)

### 🌍 Internet exposure check

- Detects active DDNS clients (ddclient, inadyn, No-IP, DuckDNS…)
- Clear list of services reachable from outside

### 🛠️ Automatic fixes

- Removal of dangerous rules
- Cleanup of duplicates
- Interactive or automatic mode (`-f -y`)

### 📝 Detailed reports

- Full exportable report (`-d`)
- Audit history with integrated management (`--manage-logs`)
- Silent mode for scripts / CI (`-q`)

---

## 📦 Installation

```bash
git clone https://github.com/Masbateno/Automated-UFW-audit.git
cd Automated-UFW-audit
sudo ./install.sh
```

### 🔍 Transparent by design

The installer is built so that **nothing happens silently**. Every action is printed to the terminal as it occurs. A complete installation manifest is written to `/usr/local/share/ufw-audit/install.manifest` — a precise record of every file and directory created on your system.

What the installer does:
- Checks for Python 3.8+
- Copies the package to `/usr/local/lib/ufw_audit/`
- Copies data files to `/usr/local/share/ufw-audit/`
- Creates the entry point `/usr/local/bin/ufw-audit`
- Installs bash completion to `/etc/bash_completion.d/ufw-audit`
- Writes the installation manifest

### 👁 Preview before installing

Not sure? Run a dry-run first — it shows every action that *would* be taken, without touching your system:

```bash
sudo ./install.sh --dry-run
```

### 🧹 Clean uninstall

The uninstaller reads the manifest and removes **exactly** what was installed — no more, no less. Directories are only removed if empty. Your user configuration (`~/.config/ufw-audit/`) is kept by default and removed only if you explicitly confirm.

```bash
sudo ./install.sh --uninstall
```

---

## ⚡ Quick start

```bash
# Standard audit
sudo ufw-audit

# Detailed mode (save report to file)
sudo ufw-audit -d

# Interactive fix mode
sudo ufw-audit -f

# Apply all fixes without confirmation
sudo ufw-audit -f -y

# Silent mode (scripts / CI)
sudo ufw-audit -q
echo $?   # 0 = clean · 1 = warnings · 2 = alerts · 3 = error

# French interface
sudo ufw-audit --french
```

---

## 🧪 Example output

```text
✖ [ALERT] Port 22/tcp: exposure = open to internet
    → sudo ufw delete allow 22/tcp
    → sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp

╔══════════════════════════════════════════════════════════════╗
║  Security score : 7/10                                       ║
║  Risk level     : ⚠ MEDIUM                                   ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ Action required                                           ║
║    ✖  Port 22/tcp: exposure = open to internet               ║
╠══════════════════════════════════════════════════════════════╣
║  Score breakdown                                             ║
║    -2  Port 22/tcp exposed to internet                       ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 📊 Security score

Each audit produces a score out of 10:

| Score | Meaning |
|-------|---------|
| **10/10** | Clean configuration |
| **7 – 9** | Some improvements possible |
| **< 5** | ⚠️ Serious issues |
| **≤ 2** | 🔥 Critical — major exposure |

Scores account for network context: penalties are doubled on machines directly exposed to the Internet.

---

## 🧠 What makes ufw-audit different

✔ Doesn't just read UFW rules
✔ Checks **services actually listening** via `ss`
✔ Avoids false positives (loopback, system ports, dangling rules)
✔ Provides **ready-to-run fix commands**
✔ Designed for regular use (cron, CI…)

---

## 🔄 Detected cases

| Case | Level |
|------|-------|
| `ufw allow from any` — full open | ✖ Alert |
| `80/tcp` + `80` — redundant rule | ✖ Alert |
| Redis exposed on `0.0.0.0` with open UFW rule | ✖ Alert |
| Docker bypasses UFW via iptables | ⚠ Warning |
| IPv6 not covered | ⚠ Warning |
| Service on loopback only (no real risk) | ℹ Info |
| Open port with no active service (orphan rule) | ℹ Info |

---

## ⏱️ Automation

Set up an automated audit:

```bash
sudo ufw-audit --install-cron
```

A 4-step wizard: job name, schedule type (daily / specific weekdays / specific month days / custom cron expression), time, optional notification email.

Manage existing jobs:

```bash
sudo ufw-audit --manage-cron
```

---

## 🌍 Languages

- 🇬🇧 English (default)
- 🇫🇷 French (`--french`)

---

## 📁 Project structure

```text
Automated-UFW-audit/
├── README.md                   # project overview (EN) — you are here
├── README_FR.md                # project overview (FR)
├── LICENSE                     # MIT License
├── .gitignore
├── install.sh                  # installer / uninstaller
├── ufw-audit.bash-completion   # bash tab-completion
├── DOCUMENTS/                  # full documentation
│   ├── README_TECH.md          # complete technical reference (EN)
│   ├── README_TECH_FR.md       # complete technical reference (FR)
│   ├── CHANGELOG.md / _FR.md   # version history
│   ├── TESTING.md / _FR.md     # test plan & validated scenarios
│   ├── AUTOMATION.md / _FR.md  # cron & CI automation guide
│   └── README_DEV.md / _FR.md  # developer notes
├── ufw_audit/                  # main Python package
│   ├── __main__.py             # orchestrator — entry point
│   ├── cli.py                  # CLI argument parsing
│   ├── config.py               # user config & email store (~/.config/ufw-audit/)
│   ├── cron.py                 # multi-job scheduler (--install-cron / --manage-cron)
│   ├── display.py              # terminal output helpers
│   ├── fixes.py                # interactive fix mode UI
│   ├── i18n.py                 # translation loader
│   ├── manage_logs.py          # report file management UI
│   ├── output.py               # print primitives (OK / WARN / ALERT / INFO)
│   ├── panorama.py             # services panorama table builder
│   ├── registry.py             # known services registry (services.json loader)
│   ├── report.py               # plain-text report writer
│   ├── report_markdown.py      # markdown → HTML email report
│   ├── scoring.py              # scoring engine (0–10)
│   ├── sysinfo.py              # system info collection
│   ├── checks/
│   │   ├── firewall.py         # UFW status & rule analysis
│   │   ├── services.py         # 22 known services — exposure classification
│   │   ├── ports.py            # listening ports analysis (ss)
│   │   ├── logs.py             # UFW log parsing & brute-force detection
│   │   ├── ddns.py             # DDNS / internet exposure detection
│   │   ├── docker.py           # Docker iptables-bypass detection
│   │   └── virtualization.py   # hypervisor & snap bridge detection
│   ├── data/
│   │   └── services.json       # 22 service definitions (ports, risk, context)
│   └── locales/
│       ├── en.json             # English strings
│       └── fr.json             # French strings
└── tests/                      # unit test suite (one file per module)
```

---

## 🛡️ Important note

ufw-audit is an audit and diagnostic tool — **not a security shield**. It analyses your configuration and flags problems, but does not replace good general security hygiene. Some software like Docker can bypass UFW by directly manipulating iptables: ufw-audit detects this specific case, but other similar vectors exist outside the current scope of the project.

⚠️ Always review changes before applying them in production.

---

## 📌 Roadmap

**v0.15** — Security code review: input validation, file permissions, shell call surfaces, error handling, Python best practices

**v1.0** — Stable, complete, validated release

**Post v1.0** — Web UI (`--gui`) for non-technical users

---

## 🤝 Contributing

Contributions welcome — issues, suggestions, pull requests.

---

## 📄 License

MIT License — © 2026 Cédric Clauzel

---

## 💬 TL;DR

> ufw-audit turns UFW into a **reliable, verified, and understandable** firewall.
