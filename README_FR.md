*[Read in English](README.md)* · *[Documentation technique](DOCUMENTS/README_TECH_FR.md)*

# 🔥 ufw-audit — Audit intelligent de votre firewall UFW

Analysez votre configuration UFW en quelques secondes, détectez les erreurs critiques et corrigez-les automatiquement.

> ⚡ Pensé pour être **simple, lisible et actionnable**
> 🛡️ Fait pour éviter les erreurs qui exposent vraiment votre machine

---

## 🚀 Pourquoi ufw-audit ?

UFW est simple… mais **facile à mal configurer**.

Une seule règle comme :

```bash
sudo ufw allow from any
```

👉 et votre machine est **ouverte à tout Internet**.

**ufw-audit détecte immédiatement ce type de problème**, explique le risque, et propose une correction.

---

## ✨ Fonctionnalités clés

### 🔍 Audit complet

- Analyse des règles UFW (`ufw status`)
- Détection des configurations dangereuses
- Vérification des incohérences IPv4 / IPv6

### 🚨 Détection intelligente des risques

- Règles trop permissives (`Anywhere ALLOW IN Anywhere`)
- Ports critiques exposés (Redis, MySQL, PostgreSQL…)
- Règles redondantes ou inutiles
- Services actifs réellement exposés (pas juste "ouverts dans UFW")

### 🧠 Analyse réelle du système

- Croise UFW avec les ports réellement ouverts (`ss`)
- Ignore les faux positifs (ex : services en loopback uniquement)
- Filtre les ports système (DNS, DHCP, mDNS…)

### 🌍 Vérification de l'exposition Internet

- Détection des clients DDNS actifs (ddclient, inadyn, No-IP, DuckDNS…)
- Liste claire des services accessibles depuis l'extérieur

### 🛠️ Corrections automatiques

- Suppression des règles dangereuses
- Nettoyage des doublons
- Mode interactif ou automatique (`-f -y`)

### 📝 Rapports détaillés

- Rapport complet exportable (`-d`)
- Historique des audits avec gestion intégrée (`--manage-logs`)
- Mode silencieux pour scripts / CI (`-q`)

---

## 📦 Installation

```bash
git clone https://github.com/Masbateno/Automated-UFW-audit.git
cd Automated-UFW-audit
sudo ./install.sh
```

### 🔍 Transparent par conception

L'installeur est conçu pour que **rien ne se passe silencieusement**. Chaque action est affichée dans le terminal au fur et à mesure. Un manifeste d'installation complet est écrit dans `/usr/local/share/ufw-audit/install.manifest` — un relevé précis de chaque fichier et répertoire créé sur votre système.

Ce que fait l'installeur :
- Vérifie la présence de Python 3.8+
- Copie le paquet dans `/usr/local/lib/ufw_audit/`
- Copie les fichiers de données dans `/usr/local/share/ufw-audit/`
- Crée le point d'entrée `/usr/local/bin/ufw-audit`
- Installe la complétion bash dans `/etc/bash_completion.d/ufw-audit`
- Écrit le manifeste d'installation

### 👁 Aperçu avant installation

Pas certain ? Lancez d'abord un dry-run — il affiche chaque action qui *serait* effectuée, sans toucher votre système :

```bash
sudo ./install.sh --dry-run
```

### 🧹 Désinstallation propre

Le désinstalleur lit le manifeste et supprime **exactement** ce qui a été installé — ni plus, ni moins. Les répertoires ne sont supprimés que s'ils sont vides. Votre configuration utilisateur (`~/.config/ufw-audit/`) est conservée par défaut et supprimée uniquement sur confirmation explicite.

```bash
sudo ./install.sh --uninstall
```

---

## ⚡ Utilisation rapide

```bash
# Audit standard
sudo ufw-audit

# Mode détaillé (rapport sauvegardé)
sudo ufw-audit -d

# Correction interactive
sudo ufw-audit -f

# Tout corriger sans confirmation
sudo ufw-audit -f -y

# Mode silencieux (scripts / CI)
sudo ufw-audit -q
echo $?   # 0 = OK · 1 = avertissements · 2 = alertes · 3 = erreur

# En français
sudo ufw-audit --french
```

---

## 🧪 Exemple de sortie

```text
✖ [ALERT] Port 22/tcp : exposition = ouvert sur internet
    → sudo ufw delete allow 22/tcp
    → sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp

╔══════════════════════════════════════════════════════════════╗
║  Score de sécurité : 7/10                                    ║
║  Niveau de risque  : ⚠ MEDIUM                                ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ Actions requises                                          ║
║    ✖  Port 22/tcp : exposition = ouvert sur internet         ║
╠══════════════════════════════════════════════════════════════╣
║  Déductions                                                  ║
║    -2  Port 22/tcp exposé sur internet                       ║
╚══════════════════════════════════════════════════════════════╝
```

---

## 📊 Score de sécurité

Chaque audit produit un score sur 10 :

| Score | Signification |
|-------|---------------|
| **10/10** | Configuration saine |
| **7 – 9** | Quelques améliorations possibles |
| **< 5** | ⚠️ Problèmes sérieux |
| **≤ 2** | 🔥 Critique — exposition majeure |

Le score tient compte du contexte réseau : les pénalités sont doublées si la machine est directement exposée sur Internet.

---

## 🧠 Ce qui rend ufw-audit différent

✔ Ne se contente pas de lire les règles UFW
✔ Vérifie les **services réellement actifs** via `ss`
✔ Évite les faux positifs (loopback, ports système, règles orphelines)
✔ Fournit des **commandes de correction prêtes à l'emploi**
✔ Conçu pour une utilisation régulière (cron, CI…)

---

## 🔄 Cas détectés

| Cas | Niveau |
|-----|--------|
| `ufw allow from any` — ouverture totale | ✖ Alerte |
| `80/tcp` + `80` — règle redondante | ✖ Alerte |
| Redis exposé sur `0.0.0.0` avec règle UFW ouverte | ✖ Alerte |
| Docker contourne UFW via iptables | ⚠ Avertissement |
| IPv6 non couvert | ⚠ Avertissement |
| Service en loopback uniquement (pas de risque réel) | ℹ Info |
| Port ouvert sans service actif (règle orpheline) | ℹ Info |

---

## ⏱️ Automatisation

Installer un audit automatique :

```bash
sudo ufw-audit --install-cron
```

Un assistant en 4 étapes : nom du job, type de planification (quotidien / jours de semaine / jours du mois / expression cron custom), heure, email de notification optionnel.

Pour gérer les jobs existants :

```bash
sudo ufw-audit --manage-cron
```

---

## 🌍 Langues

- 🇬🇧 English (par défaut)
- 🇫🇷 Français (`--french`)

---

## 📁 Structure du projet

```text
Automated-UFW-audit/
├── README.md                   # présentation du projet (EN)
├── README_FR.md                # présentation du projet (FR) — vous êtes ici
├── LICENSE                     # licence MIT
├── .gitignore
├── install.sh                  # installeur / désinstalleur
├── ufw-audit.bash-completion   # complétion bash
├── DOCUMENTS/                  # documentation complète
│   ├── README_TECH.md          # référence technique complète (EN)
│   ├── README_TECH_FR.md       # référence technique complète (FR)
│   ├── CHANGELOG.md / _FR.md   # historique des versions
│   ├── TESTING.md / _FR.md     # plan de test & scénarios validés
│   ├── AUTOMATION.md / _FR.md  # guide d'automatisation cron & CI
│   └── README_DEV.md / _FR.md  # notes développeur
├── ufw_audit/                  # paquet Python principal
│   ├── __main__.py             # orchestrateur — point d'entrée
│   ├── cli.py                  # parsing des arguments CLI
│   ├── config.py               # configuration utilisateur & emails (~/.config/ufw-audit/)
│   ├── cron.py                 # planificateur multi-jobs (--install-cron / --manage-cron)
│   ├── display.py              # helpers d'affichage terminal
│   ├── fixes.py                # interface du mode correction interactif
│   ├── i18n.py                 # chargeur de traductions
│   ├── manage_logs.py          # interface de gestion des rapports
│   ├── output.py               # primitives d'impression (OK / WARN / ALERT / INFO)
│   ├── panorama.py             # constructeur du tableau panorama des services
│   ├── registry.py             # registre des services connus (chargeur services.json)
│   ├── report.py               # rédacteur de rapport texte
│   ├── report_markdown.py      # rapport email markdown → HTML
│   ├── scoring.py              # moteur de score (0–10)
│   ├── sysinfo.py              # collecte des informations système
│   ├── checks/
│   │   ├── firewall.py         # statut UFW & analyse des règles
│   │   ├── services.py         # 22 services connus — classification d'exposition
│   │   ├── ports.py            # analyse des ports en écoute (ss)
│   │   ├── logs.py             # analyse des logs UFW & détection de bruteforce
│   │   ├── ddns.py             # détection DDNS / exposition Internet
│   │   ├── docker.py           # détection du contournement iptables par Docker
│   │   └── virtualization.py   # détection hyperviseur & bridges snap
│   ├── data/
│   │   └── services.json       # définitions des 22 services (ports, risque, contexte)
│   └── locales/
│       ├── en.json             # chaînes anglaises
│       └── fr.json             # chaînes françaises
└── tests/                      # suite de tests unitaires (un fichier par module)
```

---

## 🛡️ Note importante

ufw-audit est un outil d'audit et de diagnostic — **pas un bouclier de sécurité**. Il analyse votre configuration et signale les problèmes, mais ne remplace pas une bonne hygiène de sécurité générale. Certains logiciels comme Docker peuvent contourner UFW en manipulant iptables directement : ufw-audit détecte ce cas spécifique, mais d'autres vecteurs similaires existent en dehors du périmètre actuel.

⚠️ Toujours vérifier les modifications avant de les appliquer en production.

---

## 📌 Roadmap

**v0.15** — Audit de sécurité du code : validation des entrées, permissions fichiers, surfaces d'appel shell, gestion d'erreurs, pratiques Python

**v1.0** — Version stable, complète, validée

**Post v1.0** — Interface web (`--gui`) pour utilisateurs non techniques

---

## 🤝 Contribution

Contributions bienvenues — issues, suggestions, pull requests.

---

## 📄 Licence

MIT License — © 2026 Cédric Clauzel

---

## 💬 En bref

> ufw-audit transforme UFW en firewall **fiable, vérifié et compréhensible**.
