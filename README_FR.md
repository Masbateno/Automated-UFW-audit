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

---

## 🧪 Qualité & fiabilité

- ✅ 676 tests unitaires
- 🧱 Architecture modulaire (snapshot / check séparés)
- 🧪 Testé sur Debian, Ubuntu, Kali, Mint

---

## 🆕 v1.4.0

- 🔌 **Système de plugins** — déposez des fichiers `.json` dans `~/.config/ufw-audit/services.d/` pour ajouter des définitions de services personnalisés
- ⚙️ **Ports avec processus identifié** — un port non couvert avec un processus connu génère un WARN (amélioration) au lieu d'une ALERT (action), avec une note de mise en garde
- 📊 **`--json` / `--json-full`** — modes de sortie JSON pour intégration SIEM
- 🛡️ **Correction crash GeoIP2** — `AddressNotFoundError` ne plante plus l'audit ; instructions d'installation affichées si la bibliothèque ou la base est absente
- 📬 **Sujet email cron enrichi** — `[UFW-AUDIT] hostname - Score X/10`
- 🛡️ **Prise en compte de la politique de refus par défaut** — les ports non couverts sont rétrogradés en INFO si la politique UFW par défaut est deny/reject (pas de fausses alertes sur les systèmes bien configurés)
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
│   ├── checks/                     # firewall, services, ports, logs, ddns, docker, virt
│   ├── data/
│   │   ├── services.json           # définitions des 22 services intégrés
│   │   └── ufw-audit.bash-completion
│   │   # ~/.config/ufw-audit/services.d/  ← plugins utilisateur (sudo : /root/...)
│   └── locales/
│       ├── en.json
│       └── fr.json
└── tests/                          # 676 tests unitaires
```

---

## 📄 Licence

MIT — © 2026 Cédric Clauzel

---

## 🤝 Contribuer

Bug reports, nouvelles détections, améliorations UX — contributions bienvenues.
