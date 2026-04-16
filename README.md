*[Lire en français](README_FR.md)* · *[Technical documentation](DOCUMENTS/README_TECH.md)*

# 🔒 ufw-audit

Smart UFW security audit — fast, readable, actionable.

Analyses your UFW configuration, exposed services and logs to detect real risks, with clear recommendations.

---

## ⚡ TL;DR

```bash
sudo apt install pipx && pipx ensurepath
# open a new terminal, then:
pipx install ufw-audit
sudo ~/.local/bin/ufw-audit --install-completion
sudo ufw-audit
```

---

## 🛠 Installation

### Prerequisites

- Linux: Debian, Ubuntu, Mint or derivative
- UFW: `sudo apt install ufw`
- pipx: `sudo apt install pipx && pipx ensurepath`

> Open a new terminal after `pipx ensurepath` to activate the PATH.

### Install

```bash
pipx install ufw-audit
```

### Enable sudo + bash completion

pipx installs the binary in `~/.local/bin/`, which is not in sudo's restricted PATH.
`--install-completion` creates the symlink `/usr/local/bin/ufw-audit` and installs the bash completion script:

```bash
sudo ~/.local/bin/ufw-audit --install-completion
source /etc/bash_completion.d/ufw-audit
```

After this step, `sudo ufw-audit` works normally.

### Update

```bash
pipx upgrade ufw-audit
```

### Uninstall

```bash
pipx uninstall ufw-audit
```

---

## 🚀 Why ufw-audit?

- 🔍 **Full audit** — firewall, services, ports, logs, DDNS, Docker, virtualisation
- 🎯 **Smart prioritisation** — score + classification (OK / Warning / Action required)
- 🧠 **Context-aware** — network exposure + service criticality
- 🛠 **Optional auto-fix** — corrections proposed or applied automatically
- 📊 **Clear output** — human-readable + scriptable
- 🌍 **Bilingual EN/FR**

---

## 🔎 What the tool analyses

**🔥 Firewall (UFW)**
- Active/inactive status
- Dangerous rules (`allow from any`)
- IPv4 / IPv6 consistency
- Duplicates and errors

**🌐 Exposed services (22+)**
- SSH, Redis, PostgreSQL, Docker, etc.
- Detection via systemd / active ports
- Real exposure, risk level, UFW consistency

**📡 Ports**
- Open ports (`ss`)
- Interfaces (loopback / LAN / public)
- Unintended exposures

**📜 UFW logs**
- Suspicious attempts, brute-force detection
- IP analysis (optional GeoIP)

**☁️ DDNS / Docker / Virtualisation**
- Advanced network correlations
- Indirect exposure detection

---

## 📊 Example output

```
✔ Firewall active
⚠ SSH exposed to the Internet
✖ Redis open without restriction

Score: 6/10
→ Action required
```

---

## ▶️ Usage

```bash
sudo ufw-audit           # standard audit
sudo ufw-audit -f        # interactive fix mode
sudo ufw-audit -f -y     # auto-fix without confirmation
sudo ufw-audit -v        # verbose
sudo ufw-audit -q        # silent — exit code 0/1/2/3
sudo ufw-audit --french  # French interface
```

---

## 🔌 Custom services (plugin system)

Drop a `.json` file into `~/.config/ufw-audit/services.d/` to add services that are not in the built-in registry.

```bash
mkdir -p ~/.config/ufw-audit/services.d/
# create my-services.json — same format as ufw_audit/data/services.json
```

> **Note (pipx / sudo):** ufw-audit requires `sudo`. Under `sudo`, `~` resolves to `/root`.  
> Place your plugin files in `/root/.config/ufw-audit/services.d/` for them to be active at runtime.
>
> This will change in a future `.deb` release, where the system-wide directory `/etc/ufw-audit/services.d/` will be used instead.

---

## 🤖 Automation

- 🕒 Built-in cron (`--install-cron`)
- 📧 Email notifications (HTML + plain text)
- 📁 Report management (`--manage-logs`)
- 🔁 Multi-job scheduling (`--manage-cron`)

> Email notifications require a working Postfix setup. See [AUTOMATION.md](DOCUMENTS/AUTOMATION.md) for step-by-step configuration instructions.

---

## 🧪 Quality & reliability

- ✅ 2729 unit tests
- 🧱 Modular architecture (snapshot / check separated)
- 🧪 Tested on Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.18.0

- 🔒 **CHECK 34 — AppArmor / SELinux MAC policy** — AppArmor enforce/complain profiles + SELinux mode; WARN −1 pt if inactive, no enforce profiles (server), or no MAC at all; desktop is more lenient (no enforce → INFO)
- 💾 **CHECK 35 — Backup solution audit** — detects borgmatic, borg, restic, timeshift, duplicati, bacula, rclone, tarsnap, deja-dup; two confidence levels (active = binary + config/service evidence vs. installed only); WARN −1 pt if no backup tool found on server; desktop and container are more lenient
- 🧩 **Kernel listing** — `kernel_modules` always shows installed kernels with running annotation; no cleanup needed → INFO listing; reboot-pending and obsolete cases unchanged
- 📋 **Profile pass** — `desktop.conf` gains 6 new overrides (SSH password auth, X11 forwarding, rootkit scan age, password quality); `container.conf` gains 12 new `skip_sections` (kernel, Secure Boot, auditd, rootkit, file integrity, disk, memory, fail2ban, ClamAV, NTP, MAC policy, backup)
- 🗣 **`--explain` 76 → 86 keys** — CHECKs 31/32/33 fully covered (auditd ×4, secure_boot ×2, file_integrity ×4); CIS Ubuntu 22.04 L1/L2 references; profile-variant display for `auditd.missing_sensitive_rules` and `secure_boot.disabled`
- 🔧 **bash-completion Debian fix** — `long_opts` single-line to avoid Debian bash multiline parsing issues
- 🐛 **Profile override fix** — findings downgraded to INFO by a profile now correctly leave the summary box; `nature` cleared on downgrade
- 🧹 **Summary box cleanup** — "Configuration normale" section removed; summary shows only actionable items
- 📁 **`--manage-logs` UX** — when changing location, proposes moving existing reports (`[y/N]`); all known directories (current + previous) displayed together with a continuous index — every report is reachable and actionable regardless of which path is currently active
- ✅ 2729/2729 unit tests (+222)

## v1.17.0

- 🔍 **CHECK 31 — Linux Audit Framework (auditd)** — detects installation, service status, loaded rules, and coverage of sensitive files (/etc/passwd, /etc/shadow, /etc/sudoers); WARN −1 pt each for inactive service, no rules, uncovered sensitive files (server profile)
- 🔐 **CHECK 32 — Secure Boot** — UEFI Secure Boot state via mokutil/efivars/bootctl; WARN −1 pt if disabled on desktop; INFO if disabled on server/VM or unknown BIOS
- 🗂 **CHECK 33 — File integrity monitoring (AIDE/Tripwire)** — detects installation, database initialisation, and last check date; WARN −1 pt if no database or no recent check (>30 days)
- 🗣 **`--explain` profile variants** — 17 keys show 3 dedicated sections (server / desktop / container) with profile-adapted explanations; uniform yellow note for keys that don't differ between profiles
- 🖥 **`workstation` → `desktop` profile** — profile renamed for clarity; `workstation` alias kept for backward compatibility
- 🏷 **`cmd_type` on findings** — findings now distinguish `fix` from `check` commands with different prefixes in the summary
- 🐛 **IPv6 avahi false alarm fixed** — avahi-daemon, systemd-resolve, and similar internal processes no longer trigger UFW rule suggestions
- 📋 **Logs journald fallback** — Debian 13 without rsyslog automatically reads from `journalctl -k`
- ⚙️ **Hardening sysctl persistence** — fix commands now write to `/etc/sysctl.d/99-hardening.conf`
- 🚀 **Trusted Publishing** — GitHub Actions OIDC → PyPI; no API token required
- ✅ 2507/2507 unit tests (+215)

## v1.16.0

- 🖥 **CHECK 19 — Desktop application detection** — detects known GUI apps (Steam, Discord, Zoom, Signal…) running as processes; INFO findings, no deduction; section shown only when apps detected
- 🕐 **CHECK 28 — NTP time synchronisation** — checks systemd-timesyncd/chronyd/ntpd; WARN −1 pt if disabled or not yet synchronised
- 🛡 **CHECK 29 — Fail2ban intrusion prevention** — dedicated standalone check; WARN −1 pt if service inactive or no jails configured; detects active SSH jail
- 🔍 **CHECK 30 — Rootkit & integrity scan** — rkhunter/chkrootkit detection; WARN −1 pt for outdated DB, missing scan, or stale scan (>30 days)
- 🎯 **`--target N` exit code 4** — returns exit code 4 when score < target (CI-ready); takes priority over codes 1/2
- 🚨 **CLI validation** — `--explain=`, `--profile=`, `--lang=`, `--webhook=`, `--target=` with empty value now raise a clear error
- 📐 **5 thematic group headers** — output reorganised into FIREWALL & NETWORK / EXPOSURE & SERVICES / ACCESS CONTROL / SYSTEM HARDENING / DETECTION & HEALTH; thick `━` cyan separator
- ✅ 2292/2292 unit tests (+153)

## v1.15.1

- 🔧 **Hotfix bash-completion** — `--explain` no longer gets a trailing `=`; value options (`--target=`, `--log-days=`, `--profile=`) no longer add a space after `=`

## v1.15.0

- 🌐 **CHECK 26 — IoT/local source dominance** — detects when a single private IP accounts for ≥ 70% of all blocked UFW traffic (typical of LAN-scanning IoT devices)
- 📧 **CHECK 27 — SMTP local exposure** — detects Postfix/Exim/Sendmail listening on all interfaces (0.0.0.0:25) vs. localhost only; WARN −1 pt when publicly reachable
- 🔧 **`--fix` dry-run by default** — `--fix` previews corrections without executing; `--fix --apply` to execute interactively; `--fix --apply --yes` to auto-confirm with audit trail
- 🎯 **`--target N` score cible** — shows a target line in the summary box: green `✔` when reached, yellow `▲` with gap when not
- 🎛 **`--explain` TUI** — clamped navigation (no wrap), in-curses detail screen (ESC to return), ESC/q behavior corrected, group headers restored on scroll-up; 73→77 keys
- ❌ **Cancel at any wizard step** — `q` exits cleanly in `--install-cron`, `--manage-cron`, `--manage-logs`
- ✅ 2139/2139 unit tests (+93)

---

## 🧠 Philosophy

Not just listing ports — understanding the real risk.

ufw-audit prioritises what matters: real exposure, attack surface, potential impact.

---

## 📁 Project structure

```text
Automated-UFW-audit/
├── README.md / README_FR.md        # project overview (EN/FR)
├── LICENSE
├── pyproject.toml                  # build config (pip/pipx install)
├── DOCUMENTS/
│   ├── README_TECH.md / _FR.md     # complete technical reference
│   ├── README_DEV.md / _FR.md      # developer documentation
│   ├── CHANGELOG_FULL.md / _FR.md  # full version history
│   ├── TESTING.md / _FR.md         # test plan & validated scenarios
│   └── AUTOMATION.md / _FR.md      # cron & automation guide
├── ufw_audit/                      # Python package
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt, ssh
│   ├── data/
│   │   ├── services.json           # 22 built-in service definitions
│   │   ├── profiles/               # built-in audit profiles (server, desktop, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← user plugin directory (sudo: /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← user-defined audit profiles
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 2729 unit tests
```

---

## 📄 License

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contributing

Bug reports, new detections, UX improvements — contributions welcome.
