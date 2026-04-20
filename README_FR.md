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

- ✅ 3996 tests unitaires
- 🧱 Architecture modulaire (snapshot / check séparés)
- 🧪 Testé sur Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.22.3

- 🐛 **Ports liés à une interface exclus de l'exposition** — `0.0.0.0%virbr0` (dnsmasq/KVM) n'est plus traité comme toutes-interfaces
- 🐛 **Ports UDP éphémères filtrés de l'exposition** — les sockets avahi/mDNS à numéro élevé ne polluent plus la surface d'attaque
- ✨ **`ufw status verbose` affiché dans la section règles** — après les findings en mode `-v`
- ✅ 4007/4007 tests unitaires (+2)

### v1.22.2

- 🐛 **Filtre snakeoil étendu** — couvre désormais les chemins nginx/apache/postfix (auparavant limité à `/etc/ssl/private`)
- 🐛 **DDNS reflété dans la vue d'exposition** — la ligne internet affiche `⚠ warn` quand DDNS est actif
- 🐛 **Ports serveur à numéro élevé affichés** — filtre `port < 32768` incorrect supprimé
- 🐛 **Affichage des notes SSH corrigé** — les notes d'exposition locale et de port non-standard ne sont plus concaténées sur une ligne
- ✅ 4004/4004 tests unitaires (+3)

### v1.22.1

- 🔧 **Politique float unifiée dans `recurrence.py`** — `update_recurrence` normalise désormais les floats en `int` (cohérent avec `load_recurrence`) ; `import os` supprimé
- 🧪 **Durcissement suite de tests** — `test_message_uses_translation_key` ; `fw_policy=None → alert` affirmé ; `test_float_value_in_prev_is_normalized`
- ✅ 4001/4001 tests unitaires (+5)

### v1.22.0

- 🔗 **Moteur de corrélation de signaux** — 5 règles de risque composé combinant des findings individuels (connexion root + pas de Fail2ban → ALERT ; auth par mot de passe + brute-force → ALERT ; sudo NOPASSWD + SUID inattendu → WARN ; etc.)
- 🔁 **Suivi des findings récurrents** — comptage des apparitions consécutives par clé ; persisté dans `~/.config/ufw-audit/recurrence.json`
- 📡 **Analyse d'exposition des ports** — regroupe les services en écoute exposés par portée d'interface et niveau de risque ; correctif allowlist `fw_policy`
- 📋 **Rapport comparatif — diff de clés de findings** — nouvelles clés ALERT+WARN apparues ou résolues entre les audits ; garde de migration pour les baselines antérieures à v1.22
- 🐛 **Correctif faux positif IPv6** — WARN rétrogradé en INFO quand uniquement des adresses link-local/ULA sont assignées (machine non joignable via IPv6)
- 🐛 **Correctif message noyaux** — parenthèse redondante "(actif : X, récent : X)" supprimée quand les deux valeurs sont identiques
- 🐛 **Filtre certificat snakeoil** — `ssl-cert-snakeoil.pem` ne déclenche plus l'audit TLS sur Debian/Ubuntu
- 🔍 **`--explain`** — 87→112 clés (+25 sur 7 nouveaux groupes : journaux auth, umask, journalisation pare-feu, certificats TLS/SSL, timers systemd, firmware, Docker)
- ✅ 3996/3996 tests unitaires (+218)

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
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt, ssh, ssl_certs, systemd_timers, firmware
│   ├── data/
│   │   ├── services.json           # définitions des 22 services intégrés
│   │   ├── profiles/               # profils d'audit intégrés (server, desktop, container)
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← plugins utilisateur (sudo : /root/...)
│   │   # ~/.config/ufw-audit/profiles/    ← profils d'audit personnalisés
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 3996 tests unitaires
```

---

## 📄 Licence

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contribuer

Bug reports, nouvelles détections, améliorations UX — contributions bienvenues.
