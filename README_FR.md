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

- ✅ 2507 tests unitaires
- 🧱 Architecture modulaire (snapshot / check séparés)
- 🧪 Testé sur Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.17.0

- 🔍 **CHECK 31 — Linux Audit Framework (auditd)** — détecte l'installation, l'état du service, les règles chargées et la couverture des fichiers sensibles (/etc/passwd, /etc/shadow, /etc/sudoers) ; WARN −1 pt chacun pour service inactif, aucune règle, fichiers non couverts (profil server)
- 🔐 **CHECK 32 — Secure Boot** — état UEFI via mokutil/efivars/bootctl ; WARN −1 pt si désactivé sur desktop ; INFO si désactivé sur server/VM ou BIOS inconnu
- 🗂 **CHECK 33 — Intégrité des fichiers (AIDE/Tripwire)** — détecte l'installation, l'initialisation de la base et la date du dernier check ; WARN −1 pt si base absente ou check absent/trop ancien (>30 jours)
- 🗣 **Variantes `--explain` par profil** — 17 clés affichent 3 sections dédiées (server / desktop / container) avec des explications adaptées ; note uniforme jaune pour les clés sans différence entre profils
- 🖥 **Profil `workstation` → `desktop`** — renommé pour plus de clarté ; alias `workstation` conservé pour la rétrocompatibilité
- 🏷 **`cmd_type` sur les findings** — les findings distinguent désormais les commandes `fix` des commandes `check` avec des préfixes différents dans le résumé
- 🐛 **Fausse alerte IPv6 avahi corrigée** — avahi-daemon, systemd-resolve et processus internes similaires ne déclenchent plus de suggestions de règles UFW
- 📋 **Repli journald dans les logs** — Debian 13 sans rsyslog lit automatiquement depuis `journalctl -k`
- ⚙️ **Persistance des commandes sysctl** — les corrections de durcissement écrivent désormais dans `/etc/sysctl.d/99-hardening.conf`
- 🚀 **Trusted Publishing** — déploiement sur PyPI via OIDC GitHub Actions ; aucun token API requis
- ✅ 2507/2507 tests unitaires (+215)

## v1.16.0

- 🖥 **CHECK 19 — Détection d'applications de bureau** — détecte les applications GUI connues (Steam, Discord, Zoom, Signal…) en cours d'exécution ; findings INFO, sans déduction ; section affichée uniquement si des applis sont détectées
- 🕐 **CHECK 28 — Synchronisation NTP** — vérifie systemd-timesyncd/chronyd/ntpd ; WARN −1 pt si désactivé ou pas encore synchronisé
- 🛡 **CHECK 29 — Prévention d'intrusion Fail2ban** — check dédié indépendant ; WARN −1 pt si service inactif ou aucun jail configuré ; détecte le jail SSH actif
- 🔍 **CHECK 30 — Scan rootkit & intégrité** — détection rkhunter/chkrootkit ; WARN −1 pt pour base de données obsolète, scan absent ou scan trop ancien (>30 jours)
- 🎯 **`--target N` code de sortie 4** — retourne le code de sortie 4 si le score < cible (intégration CI) ; prioritaire sur les codes 1/2
- 🚨 **Validation CLI** — `--explain=`, `--profile=`, `--lang=`, `--webhook=`, `--target=` avec valeur vide lèvent maintenant une erreur explicite
- 📐 **5 en-têtes de groupes thématiques** — sortie réorganisée en FIREWALL & RÉSEAU / EXPOSITION & SERVICES / CONTRÔLE D'ACCÈS / DURCISSEMENT SYSTÈME / DÉTECTION & SANTÉ ; séparateur `━` cyan épais
- ✅ 2292/2292 tests unitaires (+153)

## v1.15.1

- 🔧 **Hotfix autocomplétion bash** — `--explain` n'obtient plus de `=` parasite ; les options à valeur (`--target=`, `--log-days=`, `--profile=`) n'ajoutent plus d'espace après le `=`

## v1.15.0

- 🌐 **CHECK 26 — Dominance source locale IoT** — détecte quand une seule IP privée représente ≥ 70 % du trafic UFW bloqué (typique des appareils IoT qui scannent le LAN)
- 📧 **CHECK 27 — Exposition SMTP locale** — détecte Postfix/Exim/Sendmail en écoute sur toutes les interfaces (0.0.0.0:25) vs localhost uniquement ; WARN −1 pt si accessible publiquement
- 🔧 **`--fix` aperçu par défaut** — `--fix` seul prévisualise les corrections sans les exécuter ; `--fix --apply` pour exécuter de manière interactive ; `--fix --apply --yes` pour confirmer automatiquement avec journal d'audit
- 🎯 **`--target N` objectif de score** — affiche une ligne cible dans la boîte de synthèse : `✔` vert si atteint, `▲` jaune avec l'écart sinon
- 🎛 **TUI `--explain`** — navigation bloquée (pas de wrap), écran détail in-curses (ESC pour revenir), correction ESC/q, en-têtes de groupes restaurés au scroll-up ; 73→77 clés
- ❌ **Annulation à chaque étape des wizards** — `q` quitte proprement dans `--install-cron`, `--manage-cron`, `--manage-logs`
- ✅ 2139/2139 tests unitaires (+93)

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
└── tests/                          # 2507 tests unitaires
```

---

## 📄 Licence

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contribuer

Bug reports, nouvelles détections, améliorations UX — contributions bienvenues.
