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

- ✅ 2139 tests unitaires
- 🧱 Architecture modulaire (snapshot / check séparés)
- 🧪 Testé sur Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.15.1

- 🔧 **Hotfix autocomplétion bash** — `--explain` n'obtient plus de `=` parasite ; les options à valeur (`--target=`, `--log-days=`, `--profile=`) n'ajoutent plus d'espace après le `=`

## v1.15.0

- 🌐 **CHECK 26 — Dominance source locale IoT** — détecte quand une seule IP privée représente ≥ 70 % du trafic UFW bloqué (typique des appareils IoT qui scannent le LAN)
- 📧 **CHECK 27 — Exposition SMTP locale** — détecte Postfix/Exim/Sendmail en écoute sur toutes les interfaces (0.0.0.0:25) vs localhost uniquement ; WARN −1 pt si accessible publiquement
- 🔧 **`--fix` aperçu par défaut** — `--fix` seul prévisualise les corrections sans les exécuter ; `--fix --apply` pour exécuter de manière interactive ; `--fix --apply --yes` pour confirmer automatiquement avec journal d'audit
- 🎯 **`--target N` objectif de score** — affiche une ligne cible dans la boîte de synthèse : `✔` vert si atteint, `▲` jaune avec l'écart sinon
- 🎛 **TUI `--explain`** — navigation bloquée (pas de wrap), écran détail in-curses (ESC pour revenir), correction ESC/q, en-têtes de groupes restaurés au scroll-up ; 73→77 clés
- ❌ **Annulation à chaque étape des wizards** — `q` quitte proprement dans `--install-cron`, `--manage-cron`, `--manage-logs`
- ✅ 2139/2139 tests unitaires (+93)

## v1.14.0

- 🛡️ **Audit sécurité Samba** (CHECK 24) — SMB1 ALERT −2 pts, mots de passe nuls ALERT −3 pts, signature serveur désactivée WARN −1 pt, partage invité accessible en écriture ALERT −2 pts/partage, lecture invité WARN −1 pt/partage, `map to guest` WARN −1 pt ; nouveau domaine **samba**
- 🦠 **Audit antivirus ClamAV** (CHECK 25) — détection installation, fraîcheur base de données (WARN/ALERT), statut démon clamd, âge du dernier scan
- 🔄 **Correctif `--diff` info_count** — les changements de niveau INFO (ex. swappiness) sont désormais correctement détectés entre deux audits
- 📖 **`--explain` 63→73 clés** — 4 clés ClamAV + 6 clés Samba, 17 groupes au total
- ✅ 2045/2045 tests unitaires (+155)

## 🆕 v1.13.0

- 💽 **Audit santé disques** (CHECK 22) — santé SMART (PASSED/FAILED, −3 pts), attributs critiques (secteurs réalloués, en attente, erreurs non corrigibles, −1 pt chacun), utilisation partitions (≥ 90% WARN −1 pt, ≥ 80% INFO) ; nouveau domaine **`disk`** (6e) ; support NVMe
- 📊 **Tableau des partitions** — la section ÉTAT DES DISQUES affiche l'usage par partition avec des barres de progression colorées (vert/jaune/rouge)
- 🔍 **Conseils SMART** — finding verbose avec commandes `smartctl` guidées (rapport complet, tests court/long, watch, interrompre, historique)
- 🧠 **Audit mémoire & swap** (CHECK 23) — détection usure SSD (swappiness > 30, −1 pt), avertissement swap injustifié, recommandations selon profil (server : 1, workstation : 10)
- 📖 **`--explain` 33 → 63 clés** — 30 nouvelles clés dans 7 nouveaux groupes ; `--explain list` affiche désormais les en-têtes de groupes
- ✅ 1890/1890 tests unitaires (+187)

## v1.12.0

- 🖥️ **Refonte `--help`** — 7 sections nommées (AUDIT / OUTPUT / FIXES / INTEGRATIONS / CONFIGURATION / MAINTENANCE / STANDALONE) ; section EXIT CODES pour l'usage en scripts
- ⌨️ **6 nouvelles options courtes** — `-J` (--json-full), `-C` (--manage-cron), `-p` (--profile), `-e` (--explain), `-D` (--diff), `-w` (--webhook)
- 🔧 **4 correctifs Debian VM** — contexte risque pour tous les services actifs ; GeoIP `mkdir -p` ; unattended-upgrades → INFO sur workstation ; comptes expirés avec dates ISO, UID < 1000 exclus
- ✅ 1703/1703 tests unitaires (+16)

## v1.11.0

- 📖 **`--explain` Phase A2** — 20→33 clés explicables (11 nouvelles directives SSH, fail2ban, modules noyau, pipe_to_shell, enabled_inactive)
- 👤 **Audit des comptes utilisateurs** (CHECK 17) — comptes UID 0 non-root (ALERT, −3 pts), mots de passe vides sur comptes avec shell (ALERT, −2 pts), comptes expirés (INFO)
- 🔑 **Audit de la politique de mots de passe** (CHECK 18) — absence de module PAM qualité (WARN, −1 pt), minlen < 8 explicite (WARN, −1 pt), PASS_MAX_DAYS ≥ 365 (INFO uniquement — NIST SP 800-63B)
- ✅ 1675/1675 tests unitaires (+134)

## v1.10.0

- 💡 **Suggestion `--explain`** — chaque finding actionnable affiche désormais `? ufw-audit --explain <clé>` directement sous lui dans le résumé
- 🧩 **Audit des modules noyau** (CHECK 14) — détecte les modules noyau risqués chargés (cramfs, hfs, squashfs, usb_storage, dccp, sctp, rds, tipc) ; −1 pt par catégorie (max −2 pts)
- 🕐 **Audit des tâches cron** (CHECK 15) — signale les pipes `curl/wget | sh` dans cron (−2 pts), les scripts accessibles en écriture par tous (−1 pt), les crontabs d'utilisateurs inattendus (INFO)
- ⚠️ **Audit de l'état des services** (CHECK 16) — alerte si un service de sécurité (ufw, fail2ban, apparmor, auditd…) est activé au boot mais inactif/en échec ; −1 pt par service (max −3 pts)
- ✅ 1541/1541 tests unitaires (+209)

## v1.9.0

- 📦 **Audit des mises à jour système** (CHECK 13) — détecte les paquets de sécurité en attente (−2 pts fixe) et l'absence de `unattended-upgrades` (−1 pt risque composé) ; apt uniquement, déduplique les noms de paquets
- 📖 **`--explain KEY`** — explication structurée par constat : POURQUOI C'EST UN RISQUE / COMMENT CORRIGER / référence CIS Ubuntu 22.04 ; 20 clés ; `--explain list` liste tout ; sans droit root
- 🌐 **Webhooks** — `--webhook URL` envoie le résultat d'audit après chaque exécution ; formats générique (Grafana/personnalisé) et Slack (auto-détecté) ; non-fatal, stdlib uniquement
- 📊 **Scores par domaine** — sous-scores de sécurité par domaine (SSH / Fichiers & Accès / Mises à jour / Durcissement / Pare-feu & Services) affichés en terminal + inclus dans JSON et webhook
- 🔄 **Mode `--diff`** — audit silencieux + affichage delta uniquement (changements depuis le dernier audit)
- ✅ 1332/1332 tests unitaires (+228)

## v1.8.0

- 🔑 **Audit de sécurité SSH** (CHECK 11) — analyse complète de `sshd_config` (15 directives : +AllowTcpForwarding, +PubkeyAuthentication ; Ciphers/MACs/KEX faibles), audit des clés privées (type, taille, passphrase), `authorized_keys`, `~/.ssh/config`, `known_hosts`
- 🔐 **Fichiers sensibles & sudoers** (CHECK 12) — permissions de `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` ; permissions des clés hôtes SSH ; détection de `NOPASSWD:ALL` dans sudoers
- 👤 **Ciblage utilisateur réel** — le check SSH inspecte le home de `SUDO_USER`, pas celui de root
- 🖥️ **Suggestion d'installation adaptée à la distro** — détecte apt/dnf/pacman/zypper/apk et propose la bonne commande si SSH est absent
- 🌐 **Correction i18n** — le label "Que faire ?" est désormais entièrement traduit (était toujours en français)
- 📋 **Détail des INFO en mode verbose** — `-v` affiche les recommandations pour les constats INFO
- ✅ 1104/1104 tests unitaires (+138)

## v1.7.0

- 🎛️ **Profils d'audit** — profils nommés (`server`, `workstation`, `container`) livrés en `.conf` ; option `--profile=NAME`, persistante entre les exécutions
- 🔑 **`Deduction.key`** — correspondance d'override déterministe ; plus d'heuristique sur les chaînes traduites
- 📧 **Multi-email cron** — `--install-cron` supporte plusieurs destinataires de notification
- 🗑️ **Suppression multiple de crons** — `--manage-cron` : `d:1,3` / `d:1-3` / `d:all`
- 📉 **Filtre des ports éphémères** — le rapport comparatif ne se noie plus dans les ports UDP transitoires (Avahi, VPN…)
- 🔄 **`--reset-baseline`** — supprime la baseline stockée et quitte proprement
- ✅ 966/966 tests unitaires

## v1.6.0

- 🛡️ **Durcissement système** — unattended-upgrades, rp_filter, redirections ICMP, fail2ban, AppArmor, log_martians, broadcast ICMP
- 🔗 **Cohérence IPv6** — croise la configuration noyau IPv6 / UFW IPv6 / listeners IPv6 actifs
- 📊 **Rapport comparatif** — delta de score, changements de ports et de services depuis le dernier audit
- 🔌 **API plugin** — fonctions de vérification tierces via le groupe d'entry-points `ufw_audit.checks`
- ✅ 928/928 tests unitaires

## v1.5.0

- 🖥️ **Bannière enrichie** — version du noyau, version iptables et backend, version nftables affichées au démarrage
- 🔥 **Analyse de la pile pare-feu** — nouvelle section détectant les règles iptables ACCEPT brutes contournant UFW, les rulesets nftables parallèles, et le forwarding IP inattendu
- 🌐 **Contexte réseau** — nouvelle section affichant les interfaces réseau actives (type, état, IP) et les connexions TCP établies
- ✅ 766/766 tests unitaires

## v1.4.0

- 🔌 **Système de plugins** — déposez des fichiers `.json` dans `~/.config/ufw-audit/services.d/` pour ajouter des définitions de services personnalisés
- ⚙️ **Ports avec processus identifié** — un port non couvert avec un processus connu génère un WARN (amélioration) au lieu d'une ALERT (action)
- 📊 **`--json` / `--json-full`** — modes de sortie JSON pour intégration SIEM
- 🛡️ **Prise en compte de la politique de refus par défaut** — les ports non couverts sont rétrogradés en INFO si la politique UFW par défaut est deny/reject
- ✅ 676/676 tests unitaires



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
│   │   ├── profiles/               # profils d'audit intégrés (server, workstation, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← plugins utilisateur (sudo : /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← profils d'audit personnalisés
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 966 tests unitaires
```

---

## 📄 Licence

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contribuer

Bug reports, nouvelles détections, améliorations UX — contributions bienvenues.
