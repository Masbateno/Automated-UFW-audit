*[Read in English](README.md)*

# ufw-audit v0.10

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v0.10-blue)
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
- **Analyse Docker** — détection du contournement iptables et liste des ports exposés par les containers en cours d'exécution
- **Analyse des ports en écoute** — passe unique unifiée ; ports éphémères et système ignorés proprement ; NetBIOS géré avec avertissement contextuel
- **Analyse des logs UFW** — parse `/var/log/ufw.log` sur une période configurable (`--log-days=N`, défaut 7 jours) ; total des tentatives bloquées, top IPs sources avec géolocalisation, top ports ciblés, détection bruteforce (>10 tentatives/60s), tentatives sur les ports de services installés
- **Géolocalisation IP** — IPs sources enrichies avec pays et opérateur via `whois` ; plages privées identifiées comme réseau local ; résultats mis en cache par session
- **Détection DDNS / exposition externe** — détecte les clients DDNS actifs (ddclient, inadyn, No-IP, DuckDNS) ; extrait le domaine configuré ; croise avec les règles UFW ALLOW sans restriction pour identifier les ports exposés sur internet
- **Classification d'exposition** par service : `ouvert sur internet` / `réseau local uniquement` / `bloqué par UFW` / `pas de règle`
- **Mode fix** — section interactive après le résumé ; chaque correction automatisable demande une confirmation `[y/N]` ; éléments manuels affichés sans exécution
- **Résumé catégorisé** — findings répartis en trois blocs : *Action requise* / *Améliorations possibles* / *Configuration normale* ; phrase d'interprétation automatique
- **Note de politique implicite** — signale quand des services à risque élevé s'appuient sur la politique `deny` par défaut plutôt que sur des règles explicites
- **Score de sécurité** (0–10) avec niveau de risque : FAIBLE / MOYEN / ÉLEVÉ
- **Interface bilingue** — anglais par défaut, français avec `--french`
- **Mode sans couleur** — `--no-color` pour une sortie propre dans les pipes et fichiers log
- **Rapport détaillé optionnel** — fichier log horodaté avec informations système, findings et recommandations

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

# Installer (nécessite les droits root)
chmod +x install.sh
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

# Afficher la version (sans sudo)
ufw-audit -V

# Afficher l'aide (sans sudo)
ufw-audit -h
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

## Précision importante

ufw-audit est un outil d'audit et de diagnostic, pas un bouclier de sécurité. Il analyse votre configuration et vous signale les problèmes — mais il ne les corrige pas automatiquement sans votre accord, et il ne peut pas tout détecter. Certains logiciels comme Docker peuvent contourner UFW en manipulant directement iptables : ufw-audit détecte ce cas spécifique et vous le signale, mais il existe d'autres vecteurs similaires qui sortent du périmètre actuel du projet. En résumé : ufw-audit vous aide à voir plus clair, il ne se substitue pas à une bonne hygiène de sécurité générale.

---

## Référence des options

| Option                  | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| `-v`, `--verbose`       | Afficher les détails techniques (tableau des ports, exposition)    |
| `-d`, `--detailed`      | Générer un fichier rapport complet                                 |
| `-f`, `--fix`           | Proposer et appliquer les corrections interactivement              |
| `-y`, `--yes`           | Appliquer toutes les corrections sans confirmation (avec `-f`)     |
| `-r`, `--reconfigure`   | Reconfigurer tous les ports personnalisés                          |
| `-n`, `--no-color`      | Désactiver la sortie ANSI couleur                                  |
| `--json`                | Exporter le résumé en JSON                                         |
| `--json-full`           | Exporter l'audit complet en JSON                                   |
| `--log-days=N`          | Analyser les logs sur N jours (défaut : 7)                         |
| `--french`              | Passer l'interface en français                                     |
| `-V`, `--version`       | Afficher la version et quitter (sans sudo)                         |
| `-h`, `--help`          | Afficher l'aide et quitter (sans sudo)                             |

---

## Fichiers

| Fichier                              | Description                                                         |
|--------------------------------------|---------------------------------------------------------------------|
| `/usr/local/bin/ufw-audit`           | Point d'entrée                                                      |
| `/usr/local/lib/ufw_audit/`          | Package Python                                                      |
| `/usr/local/share/ufw-audit/`        | Données (locales, services.json, manifeste)                         |
| `/usr/local/share/doc/ufw-audit/`    | Documentation                                                       |
| `/etc/bash_completion.d/ufw-audit`   | Autocomplétion bash                                                 |
| `~/.config/ufw-audit/config.conf`    | Configuration utilisateur (ports personnalisés, créé automatiquement)|
| `ufw_audit_YYYYMMDD_HHMMSS.log`      | Rapport détaillé (créé avec `-d`, dans le répertoire courant)       |

---

## Roadmap

**v0.9** — Réécriture complète en Python, 421 tests unitaires, installateur transparent avec manifeste, autocomplétion bash, bilingue EN/FR, 22 services avec contexte de risque à deux axes

**v0.10** *(actuelle)* — Géolocalisation GeoIP2 optionnelle, suppression whois, options courtes CLI, autocomplétion install.sh, note de périmètre du score

**v0.11** — Consolidation CLI, tests terrain, mode non-interactif (`--quiet`, codes de sortie), `check_virtualization()` — détection libvirt/KVM/VirtualBox et confinement Snap

**v0.12** — Support automatisation cron/email, `AUTOMATION.md`

**v1.0** — CLI stable, complète, validée

**Post v1.0**
- Interface Web (`--gui`) — interface graphique pour utilisateurs non-techniques, approche pédagogique, périmètre simplifié
- PPA Launchpad / paquet `.deb` si adoption suffisante

---

## Licence

Ce projet est sous licence MIT. Voir `LICENSE` pour les détails.

---

## Auteur

so6