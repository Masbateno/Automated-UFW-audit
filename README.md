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

**🌐 Exposed services (28+)**
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

- ✅ 4134 unit tests
- 🧱 Modular architecture (snapshot / check separated)
- 🧪 Tested on Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.24.0

- ✨ **CHECK 46 — iptables/nftables audit** — when UFW is inactive, audits the underlying firewall layer (INPUT/FORWARD policies, conntrack stateful filtering, iptables vs nftables backend)
- ✨ **5 new critical services** — Telnet (23/tcp), RDP/xRDP (3389/tcp), MongoDB (27017/tcp), Elasticsearch (9200/tcp), Memcached (11211/tcp+udp) — registry now covers **28 services**
- ✨ **Installed-but-inactive critical services** — CRITICAL/HIGH packages installed but not running now show `⚠ [ATTENTION]` + risk context block (was `ℹ [INFO]`)
- ✨ **Kernel apt update check** — ✔ [OK] when kernel is confirmed current; detects available updates; supports Ubuntu (apt-cache policy) and Debian (apt list --upgradable)
- ✨ **Audit profile in banner** — active profile (server / desktop / container) shown as INFO after the banner header
- ✅ 4134/4134 unit tests (+92)

### v1.23.0

- ✨ **`--format=FORMAT`** — unified output flag: `json | json-full | csv | markdown | html`; legacy flags (`-j`, `-J`, `--output csv`, `--html`) kept as aliases
- ✨ **`--check=list`** — prints all 31 filterable section names (no sudo required)
- ✨ **`--manage-logs` log preview** — Enter opens a scrollable viewer; `s` toggles full/summary mode (score + ALERT/WARN only); `g/G` top/bottom
- ✨ **Risk context scope qualifier** — `[CRITIQUE • LAN]` on all service labels when network context is local
- 🔧 **TUI help bar harmonization** — consistent hints across `--explain`, `--manage-logs`, preview viewer
- ✅ 4042/4042 unit tests (+35)

### v1.22.3

- 🐛 **Snakeoil cert filter extended** — now covers nginx/apache/postfix config paths (previously only `/etc/ssl/private`)
- 🐛 **DDNS reflected in exposure view** — internet-facing row shows `⚠ warn` when DDNS is active
- 🐛 **High-numbered listen ports shown** — removed incorrect `port < 32768` ephemeral filter
- 🐛 **SSH notes display fixed** — local-exposure and non-standard-port notes no longer concatenated on one line
- ✅ 4004/4004 unit tests (+3)

### v1.22.1

- 🔧 **`recurrence.py` float policy unified** — `update_recurrence` now normalizes floats to `int` (consistent with `load_recurrence`); `import os` removed
- 🧪 **Test suite hardening** — `test_message_uses_translation_key`; `fw_policy=None → alert` asserted; `test_float_value_in_prev_is_normalized`
- ✅ 4001/4001 unit tests (+5)

### v1.22.0

- 🔗 **Signal correlation engine** — 5 compound-risk rules combining individual findings (root login + no Fail2ban → ALERT; password auth + brute-force → ALERT; NOPASSWD sudo + unexpected SUID → WARN; etc.)
- 🔁 **Recurring finding tracker** — counts consecutive audit appearances per key; persisted at `~/.config/ufw-audit/recurrence.json`
- 📡 **Port exposure analysis** — groups exposed listening services by interface scope and risk level; `fw_policy` allowlist fix
- 📋 **Comparative report — finding-key diff** — new/resolved ALERT+WARN keys shown between audits; migration guard for pre-v1.22 baselines
- 🐛 **IPv6 false-positive fix** — WARN downgraded to INFO when only link-local/ULA addresses assigned (machine not internet-reachable via IPv6)
- 🐛 **Kernel message fix** — redundant "(running: X, latest: X)" suppressed when both values are identical
- 🐛 **Snakeoil cert filter** — `ssl-cert-snakeoil.pem` no longer triggers TLS audit on Debian/Ubuntu
- 🔍 **`--explain`** — 87→112 keys (+25 across 7 new groups: auth logs, umask, firewall logging, TLS/SSL certs, systemd timers, firmware, Docker)
- ✅ 3996/3996 unit tests (+218)

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
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt, ssh, ssl_certs, systemd_timers, firmware
│   ├── data/
│   │   ├── services.json           # 22 built-in service definitions
│   │   ├── profiles/               # built-in audit profiles (server, desktop, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← user plugin directory (sudo: /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← user-defined audit profiles
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 3996 unit tests
```

---

## 📄 License

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contributing

Bug reports, new detections, UX improvements — contributions welcome.
