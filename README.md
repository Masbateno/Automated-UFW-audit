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

## 🤖 Automation

- 🕒 Built-in cron (`--install-cron`)
- 📧 Email notifications (HTML + plain text)
- 📁 Report management (`--manage-logs`)
- 🔁 Multi-job scheduling (`--manage-cron`)

---

## 🧪 Quality & reliability

- ✅ 639 unit tests
- 🧱 Modular architecture (snapshot / check separated)
- 🧪 Tested on Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.1.0

- 📋 Summary box redesigned — long messages word-wrapped, never truncated
- 🔧 Fix commands shown inline in summary box (`→ cmd` under each finding)
- 🔴 Red disclaimer under "Possible improvements" block
- 🐛 vsftpd `listen_port` and Transmission `rpc-port` (JSON) now detected
- 🔒 Domain validation regex hardened; Docker public-IP detection improved
- ✅ 639/639 unit tests

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
├── install.sh                      # shell installer [DEPRECATED]
├── DOCUMENTS/
│   ├── README_TECH.md / _FR.md     # complete technical reference
│   ├── README_DEV.md / _FR.md      # developer documentation
│   ├── CHANGELOG_FULL.md / _FR.md  # full version history
│   ├── TESTING.md / _FR.md         # test plan & validated scenarios
│   └── AUTOMATION.md / _FR.md      # cron & automation guide
├── ufw_audit/                      # Python package
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt
│   ├── data/
│   │   ├── services.json           # 22 service definitions
│   │   └── ufw-audit.bash-completion
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 639 unit tests
```

---

## 📄 License

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contributing

Bug reports, new detections, UX improvements — contributions welcome.
