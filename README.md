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

- ✅ 1890 unit tests
- 🧱 Modular architecture (snapshot / check separated)
- 🧪 Tested on Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.13.0

- 💽 **Disk Health Audit** (CHECK 22) — SMART health (PASSED/FAILED, −3 pts), critical attributes (reallocated sectors, pending sectors, uncorrectable errors, −1 pt each), partition usage (≥ 90% WARN −1 pt, ≥ 80% INFO); new **`disk`** domain (6th); NVMe supported
- 📊 **Partition table** — DISK HEALTH section shows per-partition usage with colored progress bars (green/yellow/red)
- 🔍 **SMART tips** — verbose finding with guided `smartctl` commands (full report, short/long tests, watch, abort, history)
- 🧠 **Memory & Swap Audit** (CHECK 23) — SSD wear detection (swappiness > 30, −1 pt), unjustified swap warning, profile-aware recommendations (server: 1, workstation: 10)
- 📖 **`--explain` 33 → 63 keys** — 30 new keys across 7 new groups; `--explain list` now displays labeled group headers
- ✅ 1890/1890 unit tests (+187)

## v1.12.0

- 🖥️ **`--help` redesign** — 7 named sections (AUDIT / OUTPUT / FIXES / INTEGRATIONS / CONFIGURATION / MAINTENANCE / STANDALONE); EXIT CODES section for scripting
- ⌨️ **6 new short options** — `-J` (--json-full), `-C` (--manage-cron), `-p` (--profile), `-e` (--explain), `-D` (--diff), `-w` (--webhook)
- 🔧 **4 Debian VM fixes** — risk context shown for all active services; GeoIP `mkdir -p` prefix; unattended-upgrades → INFO on workstation; expired accounts with ISO dates, UID < 1000 excluded
- ✅ 1703/1703 unit tests (+16)

## v1.11.0

- 📖 **`--explain` Phase A2** — 20→33 explainable keys (11 new SSH directives, fail2ban, kernel modules, pipe_to_shell, enabled_inactive)
- 👤 **User Account Audit** (CHECK 17) — UID 0 non-root accounts (ALERT, −3 pts), empty passwords on login-capable accounts (ALERT, −2 pts), expired accounts (INFO)
- 🔑 **Password Policy Audit** (CHECK 18) — no PAM quality module (WARN, −1 pt), explicit minlen < 8 (WARN, −1 pt), PASS_MAX_DAYS ≥ 365 (INFO only — NIST SP 800-63B)
- ✅ 1675/1675 unit tests (+134)

## v1.10.0

- 💡 **`--explain` hint** — every actionable finding now shows `? ufw-audit --explain <key>` directly under it in the summary box
- 🧩 **Kernel Module Audit** (CHECK 14) — detects loaded risky kernel modules (cramfs, hfs, squashfs, usb_storage, dccp, sctp, rds, tipc); −1 pt per category (max −2 pts)
- 🕐 **Cron Job Audit** (CHECK 15) — flags `curl/wget | sh` pipes in cron (−2 pts), world-writable scripts (−1 pt), unexpected user crontabs (INFO)
- ⚠️ **Service State Audit** (CHECK 16) — warns when a security service (ufw, fail2ban, apparmor, auditd…) is enabled at boot but currently inactive/failed; −1 pt per service (max −3 pts)
- ✅ 1541/1541 unit tests (+209)

## v1.9.0

- 📦 **System Updates Audit** (CHECK 13) — detects pending security packages (−2 pts flat) and absent `unattended-upgrades` (−1 pt compound risk); apt-based, deduplicates package names
- 📖 **`--explain KEY`** — structured per-finding explanation: WHY IT IS A RISK / HOW TO FIX / CIS Ubuntu 22.04 reference; 20 keys; `--explain list` shows all; no root required
- 🌐 **Webhooks** — `--webhook URL` POSTs audit result after each run; generic (Grafana/custom) and Slack formats (auto-detected); non-fatal, stdlib-only
- 📊 **Domain Scores** — per-domain security sub-scores (SSH / Files & Access / Updates / Hardening / Firewall & Services) displayed in terminal + included in JSON and webhook
- 🔄 **`--diff` mode** — silent audit + delta-only display (what changed since last audit)
- ✅ 1332/1332 unit tests (+228)

## v1.8.0

- 🔑 **SSH Security Audit** (CHECK 11) — full `sshd_config` analysis (15 directives: +AllowTcpForwarding, +PubkeyAuthentication; weak Ciphers/MACs/KEX), private key audit (type, size, passphrase), `authorized_keys`, `~/.ssh/config`, `known_hosts`
- 🔐 **Sensitive Files & Sudoers** (CHECK 12) — permissions on `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers`; SSH host key permissions; `NOPASSWD:ALL` detection in sudoers
- 👤 **Real-user targeting** — SSH check inspects `SUDO_USER`'s home directory, not root's
- 🖥️ **Distro-aware install hints** — detects apt/dnf/pacman/zypper/apk and proposes the right install command when SSH is absent
- 🌐 **i18n fix** — "What to do?" / "Que faire ?" label now fully translated (was hardcoded French)
- 📋 **INFO detail in verbose mode** — `-v` now shows recommendation details for INFO findings
- ✅ 1104/1104 unit tests (+138)

## v1.7.0

- 🎛️ **Audit profiles** — named profiles (`server`, `workstation`, `container`) shipped as `.conf` files; `--profile=NAME` CLI flag, persisted across runs
- 🔑 **`Deduction.key`** — deterministic profile override matching; no heuristics on translated strings
- 📧 **Multi-email cron** — `--install-cron` now supports multiple notification recipients
- 🗑️ **Bulk cron delete** — `--manage-cron` supports `d:1,3` / `d:1-3` / `d:all`
- 📉 **Ephemeral port filter** — comparative report no longer floods with transient UDP ports (Avahi, VPN…)
- 🔄 **`--reset-baseline`** — clears the stored audit baseline and exits
- ✅ 966/966 unit tests

## v1.6.0

- 🛡️ **Hardening check** — unattended-upgrades, rp_filter, ICMP redirects, fail2ban, AppArmor, log_martians, ICMP broadcast
- 🔗 **IPv6 consistency** — cross-checks kernel IPv6 / UFW IPv6 / active IPv6 listeners
- 📊 **Comparative report** — score delta, port changes, service changes since last audit
- 🔌 **Plugin API** — third-party check functions via `ufw_audit.checks` entry-point group
- ✅ 928/928 unit tests

## v1.5.0

- 🖥️ **Banner enriched** — kernel version, iptables version and build, nftables version displayed at startup
- 🔥 **Firewall Stack Analysis** — new section detecting raw iptables ACCEPT rules bypassing UFW, nftables rulesets running in parallel, and unexpected IP forwarding
- 🌐 **Network Context** — new section showing active network interfaces (type, status, IP) and established TCP connections
- ✅ 766/766 unit tests

## v1.4.0

- 🔌 **Plugin system** — drop `.json` files into `~/.config/ufw-audit/services.d/` to add custom service definitions
- ⚙️ **Process-aware port findings** — uncovered ports with an identified process produce a WARN (improvement) instead of ALERT (action), with a disclaimer note
- 📊 **`--json` / `--json-full`** — SIEM-ready JSON output modes
- 🛡️ **Default deny awareness** — uncovered ports downgraded to INFO when UFW default policy is deny/reject (no false alerts on hardened systems)
- ✅ 676/676 unit tests

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
│   │   ├── profiles/               # built-in audit profiles (server, workstation, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← user plugin directory (sudo: /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← user-defined audit profiles
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 1049 unit tests
```

---

## 📄 License

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contributing

Bug reports, new detections, UX improvements — contributions welcome.
