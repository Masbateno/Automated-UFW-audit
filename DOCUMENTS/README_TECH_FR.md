*[Read in English](README_TECH.md)* · *[Vue d'ensemble](../README_FR.md)*

# ufw-audit v0.21

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.21-brightgreen)
![CI](https://github.com/Masbateno/Automated-UFW-audit/actions/workflows/tests.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.8%2B-yellow)

Outil d'audit de pare-feu UFW pour Linux — conçu pour les utilisateurs ordinaires, pas uniquement pour les administrateurs système.

ufw-audit analyse votre configuration UFW, détecte les services réseau exposés, classe les risques par service, et fournit des explications en langage clair avec des commandes de correction prêtes à l'emploi.

---

## Fonctionnalités

- **Bannière ASCII** avec informations système (distro, hôte, version UFW, utilisateur, date)
- **Vérification du statut UFW** — actif/inactif, politique par défaut entrante
- **Analyse des règles UFW** — règles en doublon, `allow from any` sans restriction de port, cohérence IPv6
- **Score contextuel** — détection du contexte réseau (IP publique directe vs NAT) ; pénalités doublées sur les machines exposées sur internet ; pare-feu inactif plafonne le score à 3/10
- **Détection de 22 services réseau courants** avec analyse de leur exposition UFW et contexte de risque à deux axes (exposition + menace) pour les services critiques et élevés
- **Docker** — détection du contournement iptables et liste des ports exposés par les containers en cours d'exécution
- **Virtualisation** — détecte les hyperviseurs actifs (libvirt/KVM, VirtualBox, VMware, LXD/LXC) et les paquets Snap réseau qui peuvent créer des interfaces bridge et manipuler iptables directement, contournant UFW — même risque que Docker
- **Ports en écoute** — passe unique unifiée ; ports éphémères et système ignorés proprement ; NetBIOS géré avec avertissement contextuel
- **Logs UFW** — parse `/var/log/ufw.log` sur une période configurable (`--log-days=N`, défaut 7 jours) ; total des tentatives bloquées, top IPs sources avec géolocalisation, top ports ciblés, détection bruteforce (>10 tentatives/60s), tentatives sur les ports de services installés
- **Géolocalisation IP** — IPs sources enrichies avec pays et opérateur via GeoIP2 (optionnel, `python3-geoip2` + base GeoLite2) ; plages privées identifiées comme réseau local ; résultats mis en cache par session
- **Détection DDNS / exposition externe** — détecte les clients DDNS actifs (ddclient, inadyn, No-IP, DuckDNS) ; extrait le domaine configuré ; croise avec les règles UFW ALLOW sans restriction pour identifier les ports exposés sur internet
- **Classification d'exposition** par service : `ouvert sur internet` / `réseau local uniquement` / `bloqué par UFW` / `pas de règle`
- **Mode fix** — section interactive après le résumé ; chaque correction automatisable demande une confirmation `[y/N]` ; éléments manuels affichés sans exécution ; `-y / --yes` applique tout sans confirmation avec une bannière d'avertissement et un résumé des commandes exécutées
- **Résumé catégorisé** — findings répartis en trois blocs : *Action requise* / *Améliorations possibles* / *Configuration normale* ; phrase d'interprétation automatique
- **Note de politique implicite** — signale quand des services à risque élevé s'appuient sur la politique `deny` par défaut plutôt que sur des règles explicites
- **Score de sécurité** (0–10) avec niveau de risque : FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE
- **Panorama des services** — tableau compact de l'ensemble des 22 services connus après l'audit services (SERVICE / STATUT / PORT(S) / UFW), services non installés affichés en grisé
- **Interface bilingue** — anglais par défaut, français avec `--french`
- **Mode sans couleur** — `--no-color` pour une sortie propre dans les pipes et fichiers log
- **Rapport détaillé optionnel** — fichier log horodaté avec en-tête ASCII art, informations système, findings et recommandations
- **`--manage-logs`** — interface interactive pour lister les rapports sauvegardés (nom, taille, date) et les supprimer par index ou en totalité
- **`--install-cron`** — wizard de planification : nommer le cron, choisir le type de schedule (tous les jours / certains jours de la semaine / certains jours du mois / expression cron personnalisée), définir l'heure et un email de notification optionnel ; aperçu en langage naturel avant confirmation ; crons nommés (`/etc/cron.d/ufw-audit-{nom}`)
- **`--manage-cron`** — TUI en boucle : lister les crons installés, modifier le planning ou l'email de notification, supprimer ; la commande `m` ouvre le carnet d'adresses email (ajout / suppression d'adresses enregistrées), accessible même sans cron installé

---

## Services détectés

| Service                          | Port par défaut      | Risque   | Contexte                                                                           |
|----------------------------------|----------------------|----------|------------------------------------------------------------------------------------|
| SSH Server                       | 22/tcp               | Critique | Très ciblé par les scans automatisés ; accès shell complet si compromis            |
| VNC Server                       | 5900/tcp             | Critique | Souvent sans chiffrement, auth faible ; équivalent à un accès physique             |
| Samba (partage fichiers Windows) | 445/tcp, 139/tcp     | Critique | Conçu pour LAN uniquement ; vecteur ransomware (EternalBlue/WannaCry) si exposé    |
| FTP Server                       | 21/tcp               | Critique | Protocole non chiffré ; credentials et fichiers transmis en clair                  |
| MySQL / MariaDB                  | 3306/tcp             | Critique | Auth par mot de passe, historique CVE ; exfiltration complète si exposé            |
| PostgreSQL                       | 5432/tcp             | Critique | Auth configurable ; RCE possible via pg_execute_server_program                     |
| Redis                            | 6379/tcp             | Critique | Pas d'auth par défaut historiquement ; RCE documenté et exploité activement        |
| Cockpit (admin web)              | 9090/tcp             | Élevé    | Interface d'admin système ; contrôle complet si compromis                          |
| WireGuard VPN                    | 51820/udp            | Élevé    | Exposition internet intentionnelle ; accès réseau interne complet si clés volées   |
| Home Assistant                   | 8123/tcp             | Élevé    | Contrôle équipements physiques (serrures, alarmes) ; accès réseau local            |
| Nextcloud                        | 80/tcp, 443/tcp      | Élevé    | Serveur de fichiers personnel ; accès fichiers/contacts/calendriers si compromis   |
| Mosquitto (MQTT)                 | 1883/tcp, 8883/tcp   | Élevé    | Pas d'auth par défaut ; contrôle équipements IoT si exposé                         |
| Apache Web Server                | 80/tcp, 443/tcp      | Moyen    | Exposition web standard ; risque selon le contenu hébergé                          |
| Nginx Web Server                 | 80/tcp, 443/tcp      | Moyen    | Exposition web standard ; risque selon le contenu hébergé                          |
| Jellyfin                         | 8096/tcp             | Moyen    | Accès bibliothèque média ; pas de données système critiques                        |
| Plex Media Server                | 32400/tcp            | Moyen    | Accès bibliothèque média ; pas de données système critiques                        |
| Transmission (UI web)            | 9091/tcp             | Moyen    | Contrôle téléchargements ; accès fichiers limité au répertoire torrent             |
| qBittorrent (UI web)             | 8080/tcp             | Moyen    | Contrôle téléchargements ; accès fichiers limité au répertoire torrent             |
| Gitea                            | 3000/tcp             | Moyen    | Forge Git ; désactiver l'inscription publique si non nécessaire                    |
| Avahi (découverte réseau local)  | 5353/udp             | Faible   | mDNS LAN uniquement ; pas d'accès aux données, découverte seulement                |
| CUPS (impression réseau)         | 631/tcp              | Faible   | Écoute sur localhost par défaut ; risque négligeable si non exposé                 |
| Syncthing                        | 8384/tcp, 22000/tcp  | Faible   | UI web sur localhost par défaut ; port de sync potentiellement exposé              |

> **ℹ Note sur la couverture des services :** La détection et la classification des services suivants ont été validées par des tests réels : SSH, Samba, Avahi, CUPS, Redis, WireGuard, Docker, Mosquitto, Syncthing, Nginx. Les autres services sont implémentés mais pas encore validés par un protocole de test formel. Si vous utilisez l'un de ces services et observez un comportement incorrect, merci d'ouvrir une issue sur GitHub.

---

## Prérequis

- Système Linux — Debian, Ubuntu, Linux Mint, ou dérivé
- UFW installé : `sudo apt install ufw`
- Python 3.8+
- `ss` recommandé (paquet `iproute2`) — disponible par défaut sur les systèmes modernes
- `python3-geoip2` + base GeoLite2 recommandés pour la géolocalisation IP (optionnel) : `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI pour l'analyse Docker (optionnel)

---

## Installation

```bash
# Cloner ou télécharger le dépôt
git clone https://github.com/Masbateno/Automated-UFW-audit.git
cd Automated-UFW-audit

# Rendre l'installateur exécutable
chmod +x install.sh

# Installer (nécessite les droits root)
sudo ./install.sh
```

L'installateur :
- Vérifie la présence de Python 3.8+
- Copie le package dans `/usr/local/lib/ufw_audit/`
- Copie les données dans `/usr/local/share/ufw-audit/`
- Crée le point d'entrée `/usr/local/bin/ufw-audit`
- Installe l'autocomplétion bash dans `/etc/bash_completion.d/ufw-audit`
- Génère un manifeste d'installation dans `/usr/local/share/ufw-audit/install.manifest`
- Affiche chaque action effectuée

### Choix d'installation

ufw-audit est installé globalement sous `/usr/local/` — la même convention qu'Ansible, Certbot ou Fail2ban.

**Pourquoi pas d'environnement virtuel ?**
ufw-audit n'a **aucune dépendance PyPI tierce** — uniquement la bibliothèque standard Python. Il tourne en `root` et interagit directement avec les ressources système (`ufw`, `/var/log/ufw.log`, `ss`). Un venv ajouterait de la complexité et un second chemin Python à maintenir sans aucun bénéfice.

**Dépendance au Python système**
Le shebang du point d'entrée (`#!/usr/bin/env python3`) est généré au moment de l'installation et pointe vers le binaire `python3` actif. Python 3.8+ est requis et vérifié lors des vérifications initiales. Une mise à jour du Python système qui change le binaire `python3` par défaut sera prise en compte automatiquement.

**Rollback en cas d'échec**
L'installateur suit chaque fichier et répertoire créés. En cas d'erreur à n'importe quelle étape (ex. copie impossible en cours d'installation), un `trap` se déclenche à la sortie et supprime ce qui a déjà été installé, laissant le système propre. Une installation partielle sans manifeste est impossible.

### Dry-run — voir sans toucher

```bash
sudo ./install.sh --dry-run
```

### Autocomplétion bash

Après l'installation, activez l'autocomplétion pour la session courante :

```bash
source /etc/bash_completion.d/ufw-audit
```

Pour l'activer en permanence (toutes les sessions futures) :

```bash
echo "source /etc/bash_completion.d/ufw-audit" >> ~/.bashrc
```

Puis utilisez `ufw-audit --<TAB>` pour compléter les options.

---

## Désinstallation

```bash
sudo ./install.sh --uninstall
```

L'installateur lit le manifeste, supprime exactement les fichiers installés, ne supprime un répertoire que s'il est vide, et propose de supprimer la configuration utilisateur séparément.

---

## Utilisation

```bash
# Audit standard
sudo ufw-audit

# Audit en français
sudo ufw-audit --french

# Mode verbeux — détails techniques et tableau des ports
sudo ufw-audit -v

# Mode détaillé — génère un fichier rapport complet
sudo ufw-audit -d

# Mode fix — propose et applique les corrections interactivement
sudo ufw-audit -f

# Mode fix — applique toutes les corrections sans confirmation
sudo ufw-audit -f -y

# Sortie sans couleur (utile pour les pipes et la redirection)
sudo ufw-audit -n > audit.txt

# Analyser les logs sur 14 jours au lieu de 7
sudo ufw-audit --log-days=14

# Reconfigurer les ports personnalisés
sudo ufw-audit -r

# Mode silencieux — aucune sortie, utilisez le code de retour
sudo ufw-audit -q; echo $?   # 0=propre, 1=avertissements, 2=alertes, 3=erreur

# Afficher la version (sans sudo)
ufw-audit -V

# Afficher l'aide (sans sudo)
ufw-audit -h

# Gérer les rapports sauvegardés interactivement
sudo ufw-audit --manage-logs

# Configurer un audit automatique (wizard de planification)
sudo ufw-audit --install-cron

# Lister, modifier ou supprimer les crons installés
sudo ufw-audit --manage-cron
```

Les options se combinent :

```bash
sudo ufw-audit --french -v -d -f
```

---

## Configuration des ports personnalisés

Quand un service est détecté sur un port non standard (ex. SSH sur 2222), le script propose de sauvegarder le port. La réponse est sauvegardée dans `~/.config/ufw-audit/config.conf` et réutilisée lors des audits suivants. Pour reconfigurer :

```bash
sudo ufw-audit -r
```

---

## Exemple de sortie

```
╔══════════════════════════════════════════════════════════════════════════════╗
║ ██╗   ██╗ ███████╗ ██╗    ██╗      █████╗  ██╗   ██╗ ██████╗  ██╗ ████████╗  ║
║ ██║   ██║ ██╔════╝ ██║    ██║     ██╔══██╗ ██║   ██║ ██╔══██╗ ██║ ╚══██╔══╝  ║
║ ██║   ██║ █████╗   ██║ █╗ ██║ ═══ ███████║ ██║   ██║ ██║  ██║ ██║    ██║     ║
║ ██║   ██║ ██╔══╝   ██║███╗██║     ██╔══██║ ██║   ██║ ██║  ██║ ██║    ██║     ║
║ ╚██████╔╝ ██║      ╚███╔███╔╝     ██║  ██║ ╚██████╔╝ ██████╔╝ ██║    ██║     ║
║  ╚═════╝  ╚═╝       ╚══╝╚══╝      ╚═╝  ╚═╝  ╚═════╝  ╚═════╝  ╚═╝    ╚═╝     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  UFW-AUDIT v0.15  │  UFW firewall audit                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 27/03/2026 10:00                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│  STATUT DU PARE-FEU                                                            │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] UFW est installé
✔ [OK] Pare-feu UFW actif
✔ [OK] Politique par défaut : connexions entrantes bloquées (recommandé)

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES RÈGLES UFW                                                        │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] Aucune règle UFW en doublon détectée
✔ [OK] Aucune règle 'allow from any' sans restriction de port détectée
✔ [OK] Configuration IPv6 cohérente avec les règles UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES SERVICES RÉSEAU                                                   │
└──────────────────────────────────────────────────────────────────────────────┘

  ▶ SSH Server
    ┄ Contexte de risque — CRITIQUE
    Exposition        : Très ciblé par les scans automatisés et les attaques brute-force
    Menace potentielle : Accès shell complet à la machine, élévation de privilèges

✖ [ALERTE] Port 22/tcp — ouvert sur internet — aucune restriction source dans UFW

  ▶ Nginx Web Server
✔ [OK] Service actif et configuré pour démarrer automatiquement au boot
⚠ [ATTENTION] Port 80/tcp — ouvert sur internet — aucune restriction source dans UFW

  ▶ Redis
    ┄ Contexte de risque — CRITIQUE
    Exposition        : Sans authentification par défaut historiquement, très souvent mal configuré
    Menace potentielle : Accès en lecture/écriture à toutes les données, exécution de code à distance (RCE)

✔ [OK] Service actif et configuré pour démarrer automatiquement au boot
ℹ [INFO] Port 6379/tcp — couvert par la politique de refus par défaut (pas de règle UFW explicite nécessaire)

┌──────────────────────────────────────────────────────────────────────────────┐
│  PANORAMA DES SERVICES                                                         │
└──────────────────────────────────────────────────────────────────────────────┘

  SERVICE                           STATUT         PORT(S)               UFW
  ────────────────────────────────  ─────────────  ────────────────────  ───
  SSH Server                        ACTIF          22/tcp                ✖
  Nginx Web Server                  ACTIF          80/tcp, 443/tcp       ⚠
  Redis                             ACTIF          6379/tcp              ✖
  ...

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES PORTS EN ÉCOUTE                                                   │
└──────────────────────────────────────────────────────────────────────────────┘

ℹ [INFO] Port système interne — aucun risque : 53/udp (DNS)
ℹ [INFO] Port 25/tcp — lié uniquement à localhost — pas d'exposition externe
✔ [OK] Tous les ports en écoute sur 0.0.0.0 sont couverts par une règle UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES LOGS UFW                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

  Période analysée : 7 jour(s) — 7 jour(s) de logs disponibles

✔ [OK] Activité normale — 47 tentative(s) bloquée(s) sur 7 jour(s), aucune menace détectée
ℹ [INFO] Top IPs sources : 203.0.113.42 (US, Virginia) — 18 tentative(s)
ℹ [INFO] Top ports ciblés : 22/tcp — 31 tentative(s)

╔══════════════════════════════════════════════════════════════════════════════╗
║  Score de sécurité : 6/10                                                    ║
║  Niveau de risque : ✖ MOYEN                                                  ║
║  Contexte réseau : 🌐 Exposé sur internet                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ✖ Action requise                                                            ║
║    ✖  Port 22/tcp — ouvert sur internet — aucune restriction…                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠ Améliorations possibles                                                   ║
║    ⚠  Port 80/tcp — ouvert sur internet — aucune restriction…                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Décomposition du score                                                      ║
║    -2  SSH Server 22/tcp open_world                                          ║
║    -1  Nginx Web Server 80/tcp open_world                                    ║
║    -1  SSH Server 22/tcp open_world                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

  Corrections nécessaires. Traitez en priorité les éléments marqués "Action requise".
```

---

## Fichiers de rapport

Avec `-d`, un rapport horodaté est créé dans un répertoire configurable (demandé au premier lancement, sauvegardé dans `config.conf`) :

```
ufw_audit_20260323_100000.log
```

Le rapport s'ouvre avec un en-tête ASCII art sur 62 caractères et contient : informations système, tous les findings horodatés, liste complète des ports en écoute, analyse détaillée des logs (top IPs avec géolocalisation, top ports, bruteforce, tentatives sur les ports de services installés), contexte de risque pour les services critiques et élevés, résumé du score.

---

## Référence des options

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| *(sans option)*         | Audit standard                                                     |
| `-v`, `--verbose`       | Afficher les détails techniques (tableau des ports, exposition)    |
| `-d`, `--detailed`      | Générer un fichier rapport complet                                 |
| `-q`, `--quiet`         | Supprimer toute sortie — utiliser le code de retour                |
| `-f`, `--fix`           | Proposer et appliquer les corrections interactivement              |
| `-y`, `--yes`           | Appliquer toutes les corrections sans confirmation (avec `-f`)     |
| `-r`, `--reconfigure`   | Reconfigurer tous les ports personnalisés                          |
| `-n`, `--no-color`      | Désactiver la sortie ANSI couleur                                  |
| `--json`                | Exporter le résumé en JSON                                         |
| `--json-full`           | Exporter l'audit complet en JSON                                   |
| `--log-days=N`          | Analyser les logs sur N jours (défaut : 7)                         |
| `--manage-logs`         | Interface interactive pour gérer les rapports sauvegardés          |
| `--install-cron`        | Configurer un audit nocturne automatique (cron)                    |
| `--french`              | Passer l'interface en français                                     |
| `-V`, `--version`       | Afficher la version et quitter (sans sudo)                         |
| `-h`, `--help`          | Afficher l'aide et quitter (sans sudo)                             |

---

## Fichiers

| Fichier                                  | Description                                                              |
|------------------------------------------|--------------------------------------------------------------------------|
| `/usr/local/bin/ufw-audit`               | Point d'entrée                                                           |
| `/usr/local/bin/ufw-audit-nightly`       | Script wrapper nocturne (créé par `--install-cron`)                      |
| `/usr/local/lib/ufw_audit/`              | Package Python                                                           |
| `/usr/local/share/ufw-audit/`            | Données (locales, services.json, manifeste)                              |
| `/usr/local/share/doc/ufw-audit/`        | Documentation                                                            |
| `/etc/bash_completion.d/ufw-audit`       | Autocomplétion bash                                                      |
| `/etc/cron.d/ufw-audit`                  | Entrée cron système (créée par `--install-cron`)                         |
| `~/.config/ufw-audit/config.conf`        | Configuration utilisateur (ports personnalisés, répertoire logs ; 600)   |
| `ufw_audit_YYYYMMDD_HHMMSS.log`          | Rapport détaillé (créé avec `-d`, dans le répertoire configuré)          |

---

## Codes de retour

En mode `--quiet`, le code de retour indique le résultat de l'audit :

| Code | Signification |
|------|---------------|
| `0`  | Audit propre — aucune alerte, aucun avertissement |
| `1`  | Avertissements détectés |
| `2`  | Alertes détectées — action requise |
| `3`  | Erreur technique |

Exemple cron — audit quotidien à 6h, mail en cas de problème :

```bash
0 6 * * * sudo ufw-audit --quiet -d || echo "ufw-audit exit $? on $(hostname)" | mail -s "UFW Alert" admin@example.com
```

---

## Précision importante

ufw-audit est un outil d'audit et de diagnostic, pas un bouclier de sécurité. Il analyse votre configuration et vous signale les problèmes — mais il ne les corrige pas automatiquement sans votre accord, et il ne peut pas tout détecter. Certains logiciels comme Docker peuvent contourner UFW en manipulant directement iptables : ufw-audit détecte ce cas spécifique et vous le signale, mais il existe d'autres vecteurs similaires qui sortent du périmètre actuel du projet. En résumé : ufw-audit vous aide à voir plus clair, il ne se substitue pas à une bonne hygiène de sécurité générale.

---

## Roadmap

**v0.9** — Réécriture complète en Python, 421 tests unitaires, installateur transparent avec manifeste, autocomplétion bash, bilingue EN/FR, 22 services avec contexte de risque à deux axes

**v0.10** — Géolocalisation GeoIP2 optionnelle, suppression whois, options courtes CLI, autocomplétion install.sh, note de périmètre du score

**v0.11** — Consolidation CLI & tests terrain (Mint/Debian/Kali), mode non-interactif (`--quiet`, codes de sortie 0-3), `check_virtualization()`, déduplication des ports, corrections de scoring

**v0.11.1** — Patch sécurité : 20 vulnérabilités corrigées (injection shell, injection ANSI, traversée de chemins, attaques symlink, ReDoS, JSON bomb, durcissement des permissions fichiers)

**v0.11.2** — Passe UX/output : bandeau redessiné (art bloc "UFW-AUDIT" complet, largeur 80 chars, étage version), verdict log, corrections de cohérence des sections dans le rapport, corrections grammaticales des locales

**v0.11.3** — Prompt emplacement des logs, panorama des services, `--manage-logs`, `--install-cron` / `--remove-cron`, en-tête ASCII art dans les rapports, bannière auto-fix et résumé des commandes, `AUTOMATION.md`

**v0.11.4** — Patch correctifs : détection wildcards open-any (espaces trailing, variantes `/tcp`/`/udp`), doublons sémantiques (`PORT/proto` vs `PORT`), ignorance des commentaires, services CRITICAL/HIGH exposés → alerte, règles bare port DDNS, `TESTING.md`

**v0.12** — Rapports email markdown : conversion HTML zéro-dépendance, emails MIME multipart (plaintext + HTML), rendu HTML dans nightly script, nettoyage des boîtes UTF-8

**v0.13** — Planificateur multi-cron : crons nommés, wizard de planification en 4 étapes (tous les jours / jours de la semaine / jours du mois / expression personnalisée), TUI `--manage-cron`, `--remove-cron` avec sélection explicite, module `cron.py` isolé

**v0.14** — Refactoring : `__main__.py` réduit de ~1820 à ~481 lignes ; nouveaux modules dédiés : `display.py`, `fixes.py`, `manage_logs.py`, `panorama.py`, `sysinfo.py` ; `check_rules()` déplacé vers `checks/firewall.py` ; orchestrateur pur sans logique métier

**v0.14.1** *(stable)* — Corrections post-sortie : faux positif ALERT pour services liés au loopback (Redis/6379), faux positifs DDNS (ports système, règles orphelines, règles bare), `--remove-cron` non supprimé à la sortie, bannière VERSION affichant `v0.13.0b`

**v0.15** — Durcissement sécurité (validation des entrées, permissions fichiers, surfaces d'appel shell, gestion d'erreurs) ; refactoring DRY (`checks/_run.py`, `_paths.py`, `_truncate`) ; corrections install script (copie `__init__.py`, vérification version Python, glob locales/docs, nouveaux modules) ; correction bug détection wildcard IPv6 (`open_any_pattern` couvre désormais les lignes `Anywhere (v6)`) ; correction message port loopback (clé `ports.uncovered_local`) ; suite de tests de régression complète validée en direct

**v0.15.1** — Robustesse install script : trap + rollback en cas d'échec partiel, suppression du dead code `do_copy_dir` ; correction bug : open-any sans index `[N]` ne produit plus de commande de fix invalide ; nettoyage sortie UI fix (`capture_output`) ; `_meta.version` des locales corrigé ; choix d'installation documenté dans README_TECH

**v0.16** — Deux corrections de faux positifs panorama : `Exposure.NOT_LISTENING` (port du registre non en écoute → panorama ✔, aucun message) et `Exposure.LOOPBACK_NO_RULE` (port loopback sans règle UFW → panorama ✔, message INFO) ; suite de régression complète (C6 × 9 services, C8 OPEN_LOCAL, E1 loopback)

**v0.17** — Suite de tests unitaires entièrement verte : 505/505 ; 15 échecs préexistants corrigés dans 6 fichiers de tests ; deux corrections de code (`_extract_duckdns_domain` parsing paramètre query, garde plage DOW dans `cron_to_human`)

**v0.18** — 26 nouveaux tests unitaires pour `fixes.py` (`run_fixes()`) : classification des items, ordre de suppression UFW, chemins subprocess, mode interactif, mode auto (`--yes`), résumé automatique ; suite atteint 531/531

**v0.19** — CI GitHub Actions : pytest sur chaque push/PR, matrice Python 3.8 / 3.10 / 3.12

**v0.20** — 17 tests en mode dégradé (`tests/test_degraded.py`) : `ss` absent, règles UFW vides, fichier de log manquant, dégradation multi-modules combinée ; suite atteint 548/548

**v0.21** *(actuel)* — Passe qualité pré-v1.0 : 78 nouveaux tests + 3 corrections ; `virtualization.py` entièrement couvert ; faux positif CGNAT/IPv6 corrigé ; lignes de config commentées non détectées ; exclusion des modes CLI appliquée ; carnet d'adresses email dans `--manage-cron` (ajout/suppression/tout effacer) ; suite atteint 619/619

**v1.0** — CLI stable, complète, validée

**Post v1.0**
- Interface Web (`--gui`) — interface graphique pour utilisateurs non-techniques, approche pédagogique, périmètre simplifié
- PPA Launchpad / paquet `.deb` si adoption suffisante

---

## Licence

MIT License — © 2026 Cédric Clauzel. Voir `LICENSE` pour les détails.

---

## Auteur

Cédric Clauzel
