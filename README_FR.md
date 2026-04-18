*[Read in English](README.md)* · *[Documentation technique](DOCUMENTS/README_TECH_FR.md)*

# 🔒 ufw-audit

Audit de sécurité UFW — rapide, lisible, actionnable.

Analyse votre configuration UFW, vos services exposés et vos logs pour détecter les risques réels, avec des recommandations claires.

---

## ⚡ TL;DR

```bash
sudo apt install pipx && pipx ensurepath
# ouvrir un nouveau terminal, puis :
pipx install ufw-audit
sudo ~/.local/bin/ufw-audit --install-completion
sudo ufw-audit
```

---

## 🛠 Installation

### Prérequis

- Linux : Debian, Ubuntu, Mint ou dérivé
- UFW : `sudo apt install ufw`
- pipx : `sudo apt install pipx && pipx ensurepath`

> Ouvrir un nouveau terminal après `pipx ensurepath` pour activer le PATH.

### Installer

```bash
pipx install ufw-audit
```

### Activer sudo + autocomplétion bash

pipx installe le binaire dans `~/.local/bin/`, absent du PATH restreint de sudo.
`--install-completion` crée le lien symbolique `/usr/local/bin/ufw-audit` et installe le script d'autocomplétion bash :

```bash
sudo ~/.local/bin/ufw-audit --install-completion
source /etc/bash_completion.d/ufw-audit
```

Après cette étape, `sudo ufw-audit` fonctionne normalement.

### Mettre à jour

```bash
pipx upgrade ufw-audit
```

### Désinstaller

```bash
pipx uninstall ufw-audit
```

---

## 🚀 Pourquoi ufw-audit ?

- 🔍 **Audit complet** — firewall, services, ports, logs, DDNS, Docker, virtualisation
- 🎯 **Priorisation intelligente** — score + classification (OK / Warning / Action requise)
- 🧠 **Analyse contextuelle** — exposition réseau + criticité du service
- 🛠 **Auto-fix optionnel** — corrections proposées ou appliquées automatiquement
- 📊 **Sortie claire** — lisible par humain + exploitable en script
- 🌍 **Bilingue EN/FR**

---

## 🔎 Ce que l'outil analyse

**🔥 Firewall (UFW)**
- Statut actif/inactif
- Règles dangereuses (`allow from any`)
- Cohérence IPv4 / IPv6
- Duplications et erreurs

**🌐 Services exposés (22+)**
- SSH, Redis, PostgreSQL, Docker, etc.
- Détection via systemd / ports actifs
- Exposition réelle, niveau de risque, cohérence UFW

**📡 Ports**
- Ports ouverts (`ss`)
- Interfaces (loopback / LAN / public)
- Détection des expositions involontaires

**📜 Logs UFW**
- Tentatives suspectes, détection brute-force
- Analyse IP (GeoIP optionnel)

**☁️ DDNS / Docker / Virtualisation**
- Corrélations réseau avancées
- Détection d'expositions indirectes

---

## 📊 Exemple de sortie

```
✔ Firewall actif
⚠ SSH exposé sur Internet
✖ Redis ouvert sans restriction

Score : 6/10
→ Action requise
```

---

## ▶️ Utilisation

```bash
sudo ufw-audit           # audit standard
sudo ufw-audit -f        # mode correction interactif
sudo ufw-audit -f -y     # auto-fix sans confirmation
sudo ufw-audit -v        # verbose
sudo ufw-audit -q        # silencieux — code de retour 0/1/2/3
sudo ufw-audit --french  # interface française
```

---

## 🔌 Services personnalisés (système de plugins)

Déposez un fichier `.json` dans `~/.config/ufw-audit/services.d/` pour ajouter des services absents du registre intégré.

```bash
mkdir -p ~/.config/ufw-audit/services.d/
# créer mon-service.json — même format que ufw_audit/data/services.json
```

> **Note (pipx / sudo) :** ufw-audit nécessite `sudo`. Sous `sudo`, `~` correspond à `/root`.  
> Placez vos fichiers de plugins dans `/root/.config/ufw-audit/services.d/` pour qu'ils soient actifs à l'exécution.
>
> Ce comportement changera lors du passage en `.deb`, où le répertoire système `/etc/ufw-audit/services.d/` sera utilisé à la place.

---

## 🤖 Automatisation

- 🕒 Cron intégré (`--install-cron`)
- 📧 Notifications email (HTML + texte)
- 📁 Gestion des rapports (`--manage-logs`)
- 🔁 Multi-jobs planifiés (`--manage-cron`)

> Les notifications email nécessitent une configuration Postfix fonctionnelle. Voir [AUTOMATION_FR.md](DOCUMENTS/AUTOMATION_FR.md) pour les instructions pas à pas.

---

## 🧪 Qualité & fiabilité

- ✅ 3494 tests unitaires
- 🧱 Architecture modulaire (snapshot / check séparés)
- 🧪 Testé sur Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.20.0

- 📋 **Contrôle niveau de journalisation UFW** — détecte si la journalisation UFW est désactivée (`off` → ALERT −2 pts) ou en mode verbeux (`high`/`full` → INFO)
- 🔒 **Audit umask système** — lit le umask depuis toutes les sources (`/etc/login.defs`, PAM, `/etc/profile`, processus courant) ; valeurs permissives (0002/0000) → WARN −1 pt ; conflits entre sources détectés
- 🔍 **Analyse auth.log SSH** — détection brute-force (>10 tentatives échouées/60 s depuis la même IP → ALERT) ; dernières connexions réussies ; principales sources d'échec
- 📈 **Historique des scores** — `--history` affiche un sparkline des audits passés (▁▂▃▄▅▆▇█) ; journal JSONL dans `~/.config/ufw-audit/history.jsonl`
- 🚫 **Liste d'exceptions** — `--ignore KEY` masque définitivement un finding ; `--show-ignored` liste toutes les exceptions actives ; persisté dans `ignore.yml`
- 🐛 **Ports système process-aware** — les ports UPnP/mDNS/DNS ne sont plus silencieusement ignorés quand ils appartiennent à une application utilisateur (ex. Spotify sur `1900/udp`)
- ✅ 3494/3494 tests unitaires (+235)

---

## 🧠 Philosophie

Pas juste lister des ports — comprendre le risque réel.

ufw-audit priorise ce qui compte : exposition réelle, surface d'attaque, impact potentiel.

---

## 📁 Structure du projet

```text
Automated-UFW-audit/
├── README.md / README_FR.md        # présentation du projet (EN/FR)
├── LICENSE
├── pyproject.toml                  # config de build (installation pip/pipx)
├── DOCUMENTS/
│   ├── README_TECH.md / _FR.md     # référence technique complète
│   ├── README_DEV.md / _FR.md      # documentation développeur
│   ├── CHANGELOG_FULL.md / _FR.md  # historique complet des versions
│   ├── TESTING.md / _FR.md         # plan de test & scénarios validés
│   └── AUTOMATION.md / _FR.md      # guide d'automatisation cron
├── ufw_audit/                      # package Python
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt, ssh
│   ├── data/
│   │   ├── services.json           # définitions des 22 services intégrés
│   │   ├── profiles/               # profils d'audit intégrés (server, desktop, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← plugins utilisateur (sudo : /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← profils d'audit personnalisés
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 3494 tests unitaires
```

---

## 📄 Licence

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contribuer

Bug reports, nouvelles détections, améliorations UX — contributions bienvenues.
