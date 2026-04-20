*[Read in English](README_TECH.md)* · *[Vue d'ensemble](../README_FR.md)*

# ufw-audit v1.22.3

![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/badge/version-v1.22.3-brightgreen)
![CI](https://github.com/Masbateno/Automated-UFW-audit/actions/workflows/tests.yml/badge.svg)
![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20Mint-informational)
![Language](https://img.shields.io/badge/language-Python%203.9%2B-yellow)

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
- **Vérification durcissement** — audit du durcissement système : unattended-upgrades, mode AppArmor, rp_filter, redirections ICMP, log_martians, broadcast ICMP ; déductions scorées pour les paramètres les plus impactants
- **Cohérence IPv6** — détecte les ports IPv6 actifs sans règle UFW v6 correspondante ; détection de conflit quand IPv6 est désactivé globalement mais des ports en écoute sont présents
- **Rapport comparatif** — baseline enregistrée après chaque audit (`~/.config/ufw-audit/last_baseline.json`) ; au prochain lancement, affiche le delta de score, les variations d'alertes/avertissements, les ports apparus/fermés, les services démarrés/arrêtés
- **API Plugin** — déposer un fichier Python dans `~/.config/ufw-audit/checks.d/` pour ajouter une vérification personnalisée ; les plugins sont fail-safe (les exceptions n'interrompent jamais l'audit) et les séquences ANSI sont nettoyées
- **Audit de sécurité SSH** — analyse complète de `sshd_config` (15 directives + Ciphers/MACs/KEX faibles) ; audit des clés privées (type, taille, passphrase) ; inspection `authorized_keys` ; vérification côté client `~/.ssh/config` ; comptage des entrées `known_hosts` ; cible le home de `SUDO_USER` ; suggestions d'installation adaptées à la distro
- **Fichiers sensibles & sudoers** — audit des permissions de `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group`, `/etc/sudoers` (modifiable par tous → ALERT, trop permissif → WARN) ; permissions des clés hôtes privées SSH sous `/etc/ssh/` ; détection de `NOPASSWD:ALL` dans sudoers et sudoers.d
- **Audit des mises à jour système** — détecte les paquets de sécurité en attente via `apt-get -s upgrade` (−2 pts fixe) ; absence de `unattended-upgrades` combinée à des mises à jour de sécurité en attente (−1 pt composé) ; mises à jour régulières → INFO uniquement
- **Détection d'applications de bureau** — détecte les applications GUI connues (Steam, Discord, Zoom, Signal, VLC, Spotify, Slack, Telegram, Chrome, Firefox…) en cours d'exécution ; findings INFO, sans déduction ; section affichée uniquement si au moins une appli est détectée
- **Synchronisation NTP** — vérifie si systemd-timesyncd, chronyd ou ntpd est actif et synchronisé ; WARN −1 pt si NTP est désactivé ou l'horloge pas encore synchronisée
- **Prévention d'intrusion Fail2ban** — check autonome dédié ; détecte l'installation, l'état du service, les jails actifs et la présence d'un jail SSH ; WARN −1 pt si service inactif ou aucun jail configuré
- **Scan rootkit & intégrité** — détection rkhunter/chkrootkit ; WARN −1 pt pour base de données rkhunter obsolète (≥7 jours), scan absent ou dernier scan trop ancien (>30 jours)
- **Linux Audit Framework (auditd)** — détecte l'installation, l'état du service, les règles chargées et la couverture des fichiers sensibles (/etc/passwd, /etc/shadow, /etc/sudoers) ; WARN −1 pt chacun pour service inactif, aucune règle, fichiers non couverts (profil server uniquement)
- **Secure Boot** — état UEFI via `mokutil --sb-state` → `/sys/firmware/efi/efivars/` → `bootctl status` ; WARN −1 pt si désactivé sur desktop ; INFO si désactivé sur server/VM ou BIOS/inconnu
- **Intégrité des fichiers (AIDE/Tripwire)** — détecte l'installation, l'initialisation de la base et la date du dernier check ; AIDE préféré à Tripwire ; WARN −1 pt si base absente ou check absent/trop ancien (>30 jours)
- **`--explain KEY`** — explication structurée par constat (POURQUOI C'EST UN RISQUE / COMMENT CORRIGER / référence CIS Ubuntu 22.04) ; 76 clés explicables dans 19 groupes ; 17 clés affichent des sections par profil (`[ server ]` / `[ desktop ]` / `[ container ]`) ; note uniforme jaune pour les clés sans différence entre profils ; TUI interactif avec délai ESC réduit à 25 ms ; sans droit root
- **Scores par domaine** — sous-scores de sécurité par domaine (SSH / Sécurité Samba / Fichiers & Accès / Mises à jour / Durcissement / Santé Disque / Pare-feu & Services) ; 7 domaines ; affichés en barre █/░ après l'audit ; inclus dans la sortie JSON et le payload webhook
- **Webhooks** — `--webhook URL` envoie le résultat d'audit en JSON après chaque audit ; formats générique (Grafana/automation) et Slack (auto-détecté) ; non-fatal ; `--webhook-format=auto|generic|slack`
- **Mode `--diff`** — lance l'audit silencieusement et affiche uniquement le delta comparatif (changements depuis le dernier audit) ; suit le score, le nombre d'alertes/avertissements et le nombre d'INFO (les changements de niveau INFO sont donc détectés)
- **Audit sécurité Samba** — analyse complète de `smb.conf` : détection protocole SMB1 (ALERT, −2 pts) ; mots de passe nuls activés (ALERT, −3 pts) ; signature serveur désactivée (WARN, −1 pt) ; partages accessibles en écriture par l'invité (ALERT, −2 pts/partage) ; partages lisibles par l'invité (WARN, −1 pt/partage) ; `map to guest = bad user` (WARN, −1 pt) ; vérification bind interfaces (INFO) ; domaine **samba** dédié
- **Audit antivirus ClamAV** — détection installation (`clamscan`/`clamdscan`/`freshclam`) ; fraîcheur de la base de données virus via mtime (WARN −1 pt > 7 jours, ALERT −2 pts > 30 jours) ; statut démon clamd avec repli sur le fichier socket pour les containers ; date du dernier scan parsée depuis les chemins de logs standards (WARN −1 pt > 30 jours, −1 pt > 90 jours) ; déductions routées vers le domaine **hardening**
- **Dominance source locale IoT** — détecte quand une seule IP privée représente ≥ 70 % du trafic UFW bloqué sur ≥ 50 entrées de log (WARN, −1 pt, `logs.local_dominance`) ; typique des appareils IoT qui scannent le LAN ou des serveurs mal configurés
- **Exposition SMTP locale** — détecte les MTA (Postfix, Exim, Sendmail) en écoute sur toutes les interfaces (`0.0.0.0:25` ou `:::25`) vs localhost uniquement ; `SmtpSnapshot.from_system()` utilise `ps -eo comm` + `ss -tlnp`/repli `netstat` ; WARN −1 pt si exposition publique
- **`--fix` aperçu par défaut** — `--fix` seul affiche un aperçu de toutes les corrections disponibles avec `→ cmd` sans exécuter ; `--fix --apply` active le flux d'application interactif ; `--fix --apply --yes` confirme tout automatiquement avec journal d'audit
- **`--target N`** — objectif de score (1–10) ; affiché dans la boîte de synthèse comme `✔ atteint` (vert) ou `▲ +N pt(s) manquant(s)` (jaune) ; retourne le code de sortie 4 si le score < cible (intégration CI, prioritaire sur les codes 1/2)
- **5 en-têtes de groupes thématiques** — sortie de l'audit réorganisée en cinq groupes nommés : FIREWALL & RÉSEAU / EXPOSITION & SERVICES / CONTRÔLE D'ACCÈS / DURCISSEMENT SYSTÈME / DÉTECTION & SANTÉ ; chaque groupe introduit par un séparateur `━` cyan pleine largeur avec le titre centré
- **`cmd_type` sur les findings** — `Finding` gagne `cmd_type: str = "fix"` / `"check"` ; la boîte de synthèse utilise `→` pour les commandes de correction et `ℹ` pour les commandes de vérification
- **Profils d'audit** — `server` (défaut), `desktop` (remplace `workstation`), `container` ; alias `workstation` conservé ; profil actif affiché dans la boîte de synthèse
- **Contrôle niveau de journalisation UFW** — détecte le niveau UFW (`ufw status verbose`) ; `off` → ALERT −2 pts (aucune visibilité sur le trafic bloqué) ; `low`/`medium` → OK ; `high`/`full` → INFO (mode verbeux, sans déduction)
- **Audit umask système** — `UmaskSnapshot` lit le umask depuis `/etc/login.defs`, PAM, `/etc/profile`, RC shells et processus courant ; umask permissif (0002/0000) → WARN −1 pt ; sources conflictuelles → WARN −1 pt ; `_fix_cmd()` propose `/etc/profile.d/umask.conf`
- **Analyse auth.log SSH** — `AuthLogSnapshot` parse `/var/log/auth.log` ; détection brute-force (>10 tentatives échouées depuis la même IP en 60 s → ALERT −2 pts) ; dernières connexions réussies affichées ; top sources d'échec listées ; `days=0` (log vide/rotaté) géré avec clé dédiée sans interpolation de zéro
- **Historique des scores** — JSONL dans `~/.config/ufw-audit/history.jsonl` ; `--history` affiche les N derniers scores sous forme de sparkline (▁▂▃▄▅▆▇█) avec dates ; rotation automatique à 90 entrées
- **Liste d'exceptions (ignore)** — `--ignore KEY` ajoute une clé de finding dans `ignore.yml` ; `--show-ignored` liste toutes les exceptions ; `ScoreEngine.ignore_keys` frozenset masque les findings correspondants sans les scorer ; indice affiché dans la sortie ; `{check_key}` utilisé dans la locale pour éviter le conflit de signature de `t()`
- **Classification process-aware des ports système** — frozenset `_SYSTEM_DAEMONS` dans `checks/ports.py` ; les ports de `_SYSTEM_PORTS` (DNS, DHCP, mDNS, UPnP…) ne sont classés `SYSTEM_INTERNAL` que si l'application propriétaire est un démon OS connu ; les apps utilisateur (ex. Spotify sur `1900/udp`) passent aux vérifications d'exposition normales
- **Audit expiration certificats TLS/SSL** — analyse Let's Encrypt (`/etc/letsencrypt/live/*/fullchain.pem`), `/etc/ssl/private/*.{pem,crt,cert}`, directives nginx `ssl_certificate`, `SSLCertificateFile` apache2, `smtpd_tls_cert_file` postfix ; expiré → ALERT −2 pts ; <7 j → ALERT −2 pts ; <30 j → WARN −1 pt ; total plafonné à −4 pts ; `_MAX_CERTS=30` ; chemins entre guillemets et liens symboliques cassés gérés
- **Audit sécurité timers systemd** — `systemctl list-timers --all --no-pager` ; curl/wget pipé vers un shell dans ExecStart → WARN −2 pts (flat) ; scripts `.sh` world-writable dans ExecStart → WARN −1 pt (flat) ; timers créés par l'utilisateur dans `/etc/systemd/system/` sans `User=` → INFO ; deux regex indépendantes prévient les faux négatifs sur `/bin/bash`/`bash -c` ; `lstrip("-@")` gère les préfixes systemd ; `_MAX_TIMERS=100`
- **Audit firmware & microcode** — `fwupdmgr get-updates` (cache, sans réseau forcé) ; firmware device en attente → WARN −1 pt ; paquet microcode CPU via `dpkg -l` ; Intel → `intel-microcode` ; AMD → `amd64-microcode` ; non Intel/AMD → INFO ; absent → WARN −1 pt ; correspondance exacte par colonne pour les paquets qualifiés par architecture ; résultats erreur et mises à jour découplés
- **Export HTML `--html`** — `build_html_output()` produit un fichier HTML autosuffisant (sans JS, sans ressources externes) ; CSS embarqué ; cercle de score coloré ; badges ALERT/WARN/INFO/OK ; tableau déductions ; `_h()` applique `html.escape(quote=True)` à toutes les données utilisateur — protection XSS
- **`--check LIST` / `--skip LIST`** — n'exécuter que les checks nommés (`--check=ssh,firewall`) ou les exclure (`--skip=clamav,rootkit`) ; mutuellement exclusifs ; helper `_section_enabled()` dans `runner.py` ; `validate_check_filters()` avertit sur les noms inconnus ; `skip_sections` du profil respecté
- **`--output-dir PATH`** — surcharger le répertoire de sauvegarde du rapport pour l'exécution courante ; `get_or_prompt_log_dir()` priorise ce paramètre sur la config sauvegardée ; sans persistance
- **Moteur de corrélation de signaux** — `correlation.py` : 5 règles de risque composé (root+sans-fail2ban → ALERT ; auth-mot-de-passe+brute-force → ALERT ; root+password → ALERT ; NOPASSWD+SUID → WARN ; stale+sans-fail2ban → WARN ; logging-off+sans-fail2ban+sans-auditd → WARN) ; `CorrelationRule` avec frozensets `all_of`/`any_of` ; évalué post-finalize sur les clés ALERT+WARN ; liste `triggered_by` identifie les findings déclencheurs
- **Suivi des findings récurrents** — `recurrence.py` : compteur d'apparitions consécutives par clé ALERT/WARN ; `~/.config/ufw-audit/recurrence.json` ; écriture atomique ; valeurs corrompues/négatives normalisées ; clés vides filtrées au chargement
- **Analyse d'exposition des ports** — `exposure.py` : regroupe les services en écoute exposés par portée d'interface et niveau de risque ; allowlist `fw_policy not in ("deny", "reject")` ; attribut direct `lp.port` pour le filtre ports éphémères
- **Rapport comparatif — diff de clés de findings** — `AuditBaseline.finding_keys` persiste les clés ALERT+WARN actives ; `AuditDelta` ajoute `new_finding_keys` / `resolved_finding_keys` ; garde de migration contre le flood de faux positifs à la première exécution après mise à jour ; `display_delta()` affiche chaque clé apparue/résolue
- **Correctif faux positif IPv6 link-local** — parseur `_read_global_ipv6()` ; champ `has_global_ipv6` ; WARN −2 pts rétrogradé en INFO quand seules des adresses link-local (fe80::/10) ou ULA (fc/fd::/7) sont assignées — machine non joignable via IPv6 depuis internet
- **Correctif message noyaux obsolètes** — clé locale `kernels_obsolete_same` ; supprime la parenthèse redondante "(actif : X, récent : X)" quand le noyau actif est identique au plus récent installé
- **Filtre certificat snakeoil** — `ssl-cert-snakeoil.pem` exclu du scan `/etc/ssl/private` ; empêche le certificat de test Debian/Ubuntu de déclencher l'audit TLS
- **`--explain`** — 87→112 clés (+25 sur 7 nouveaux groupes : Journaux d'authentification, Umask, Journalisation du pare-feu, Certificats TLS/SSL, Timers Systemd, Firmware, Docker)

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
- Python 3.9+
- `ss` recommandé (paquet `iproute2`) — disponible par défaut sur les systèmes modernes
- `python3-geoip2` + base GeoLite2 recommandés pour la géolocalisation IP (optionnel) : `sudo apt install python3-geoip2 geoip-database`
- `docker` CLI pour l'analyse Docker (optionnel)

---

## Installation

### Prérequis

- Système Linux — Debian, Ubuntu, Linux Mint, ou dérivé
- UFW installé : `sudo apt install ufw`
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

Après cette étape, `sudo ufw-audit` fonctionne normalement et `ufw-audit --<TAB>` complète les options.

---

## Désinstallation

```bash
pipx uninstall ufw-audit
```

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

# Désactiver la résolution d'IP publique (machine isolée ou sans accès HTTP sortant)
sudo ufw-audit --offline
sudo ufw-audit -o

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

# Installer l'autocomplétion bash et créer le lien symbolique sudo PATH (une seule fois après pipx install)
sudo ufw-audit --install-completion
```

> Les notifications email nécessitent une configuration Postfix fonctionnelle. Voir [AUTOMATION_FR.md](AUTOMATION_FR.md) pour les instructions pas à pas (installation, relais SMTP, réécriture expéditeur, test).

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
║  UFW-AUDIT v1.3.0  │  Audit pare-feu UFW                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  System        : Ubuntu 24.04 LTS                                            ║
║  Host          : my-machine                                                  ║
║  UFW           : v0.36.2                                                     ║
║  User          : alice                                                       ║
║  Date          : 27/03/2026 10:00                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│  STATUT DU PARE-FEU                                                          │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] UFW est installé
✔ [OK] Pare-feu UFW actif
✔ [OK] Politique par défaut : connexions entrantes bloquées (recommandé)

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES RÈGLES UFW                                                      │
└──────────────────────────────────────────────────────────────────────────────┘

✔ [OK] Aucune règle UFW en doublon détectée
✔ [OK] Aucune règle 'allow from any' sans restriction de port détectée
✔ [OK] Configuration IPv6 cohérente avec les règles UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES SERVICES RÉSEAU                                                 │
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
│  PANORAMA DES SERVICES                                                       │
└──────────────────────────────────────────────────────────────────────────────┘

  SERVICE                           STATUT         PORT(S)               UFW
  ────────────────────────────────  ─────────────  ────────────────────  ───
  SSH Server                        ACTIF          22/tcp                ✖
  Nginx Web Server                  ACTIF          80/tcp, 443/tcp       ⚠
  Redis                             ACTIF          6379/tcp              ✖
  ...

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES PORTS EN ÉCOUTE                                                 │
└──────────────────────────────────────────────────────────────────────────────┘

ℹ [INFO] Port système interne — aucun risque : 53/udp (DNS)
ℹ [INFO] Port 25/tcp — lié uniquement à localhost — pas d'exposition externe
✔ [OK] Tous les ports en écoute sur 0.0.0.0 sont couverts par une règle UFW

┌──────────────────────────────────────────────────────────────────────────────┐
│  ANALYSE DES LOGS UFW                                                        │
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
║    -2  SSH Server 22/tcp exposé sur internet                                 ║
║    -1  Nginx Web Server 80/tcp exposé sur internet                           ║
║    -1  SSH Server 22/tcp exposé sur internet                                 ║
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
| `--explain=KEY`         | Afficher l'explication d'une clé de constat (`--explain list` liste tout) |
| `--diff`                | Audit silencieux — afficher uniquement le delta de la baseline      |
| `--webhook=URL`         | Envoyer le résultat d'audit en JSON à l'URL après chaque audit     |
| `--webhook-format=FMT`  | Format webhook : `auto` (défaut), `generic` ou `slack`            |
| `--log-days=N`          | Analyser les logs sur N jours (défaut : 7)                         |
| `-o`, `--offline`       | Désactiver la résolution d'IP publique et l'appel webhook (aucun appel HTTP) |
| `--manage-logs`         | Interface interactive pour gérer les rapports sauvegardés          |
| `--install-cron`        | Configurer un audit nocturne automatique (cron)                    |
| `--install-completion`  | Installer l'autocomplétion bash et créer le lien symbolique sudo PATH |
| `--french`              | Passer l'interface en français                                     |
| `-V`, `--version`       | Afficher la version et quitter (sans sudo)                         |
| `-h`, `--help`          | Afficher l'aide et quitter (sans sudo)                             |

---

## Fichiers

| Fichier                                  | Description                                                              |
|------------------------------------------|--------------------------------------------------------------------------|
| `~/.local/bin/ufw-audit`                 | Point d'entrée pipx                                                      |
| `/usr/local/bin/ufw-audit`               | Lien symbolique pour l'accès sudo (créé par `--install-completion`)      |
| `/etc/bash_completion.d/ufw-audit`       | Autocomplétion bash (créée par `--install-completion`)                   |
| `/usr/local/bin/ufw-audit-nightly`       | Script wrapper nocturne (créé par `--install-cron`)                      |
| `/etc/cron.d/ufw-audit-{nom}`            | Entrée cron nommée (créée par `--install-cron`)                          |
| `~/.config/ufw-audit/config.conf`        | Configuration utilisateur (ports personnalisés, répertoire logs ; 600)   |
| `~/.config/ufw-audit/services.d/*.json`  | Répertoire de plugins — définitions de services personnalisés (voir note) |
| `ufw_audit_YYYYMMDD_HHMMSS.log`          | Rapport détaillé (créé avec `-d`, dans le répertoire configuré)          |

> **Répertoire de plugins et `sudo` :** ufw-audit s'exécute en root. Sous `sudo`, `Path.home()` retourne `/root`,
> donc le répertoire de plugins actif est `/root/.config/ufw-audit/services.d/`, et non le home de l'utilisateur appelant.
> Placez vos fichiers de plugins à cet emplacement pour qu'ils soient chargés à l'exécution.
>
> **Futur paquet `.deb` :** ce comportement changera au profit du répertoire système `/etc/ufw-audit/services.d/`,
> conformément à la convention Debian et pour éliminer l'ambiguïté liée à `sudo`/home.

---

## Codes de retour

En mode `--quiet`, le code de retour indique le résultat de l'audit :

| Code | Signification |
|------|---------------|
| `0`  | Audit propre — aucune alerte, aucun avertissement |
| `1`  | Avertissements détectés |
| `2`  | Alertes détectées — action requise |
| `3`  | Erreur technique |
| `4`  | Score inférieur au seuil `--target N` |

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

**v0.21** — Passe qualité pré-v1.0 : 78 nouveaux tests + 3 corrections ; `virtualization.py` entièrement couvert ; faux positif CGNAT/IPv6 corrigé ; lignes de config commentées non détectées ; exclusion des modes CLI appliquée ; carnet d'adresses email dans `--manage-cron` (ajout/suppression/tout effacer) ; suite atteint 619/619

**v0.22** — Passe qualité interne : 5 modules refactorisés (`__main__`, `firewall`, `services`, `scoring`, `output`) ; alignement des cadres corrigé sur toutes les interfaces ; `meta: dict` supprimé de `CheckResult` → `open_ports: List[str]` typé

**v0.22.1** — Hotfix : pare-feu détecté comme inactif sur les locales non-anglaises ; variable `LANGUAGE` maintenant vidée avec `LC_ALL=C`

**v1.0** — Version stable ; `pipx install ufw-audit` comme méthode d'installation principale ; `--install-completion` crée l'autocomplétion bash et le lien symbolique sudo PATH ; Python 3.9 minimum ; matrice CI mise à jour (3.9 / 3.10 / 3.12) ; clé locale `not_listening` ajoutée ; install.sh déprécié

**v1.2.0** — Passe qualité : 12 corrections défensives sur 8 modules ; regex IPv4 privée `172.x` corrigée ; `Deduction.context` validé ; cap visible dans le breakdown du score ; 639/639

**v1.2.1** — Nettoyage packaging : `install.sh` supprimé ; corrections `pyproject.toml` (LICENSE, classifier, URL Issues)

**v1.3.0** — i18n complète : toutes les raisons de déduction traduites via `t()` ; flag `--offline`/`-o` ; détection d'adresse IPv6 publique ; chaîne de fallback 3 providers ; 652/652

**v1.4.0** — Système de plugins (`services.d/*.json`) ; findings ports avec processus identifié (WARN + note au lieu d'ALERT) ; sortie JSON SIEM (`--json` / `--json-full`) ; correction crash GeoIP2 (`AddressNotFoundError`) ; sujet email cron enrichi hostname + score ; prise en compte de la politique de refus par défaut UFW (ports non couverts rétrogradés en INFO si policy = deny/reject) ; 676/676

**v1.4.1** — Hotfix : `--install-completion` absent des suggestions TAB de la complétion bash (liste `long_opts` mise à jour)

**v1.4.2** — Hotfix : ports NetBIOS 137/138 encore signalés malgré une règle UFW explicite ; `_is_covered_by_ufw()` déplacé avant la branche NetBIOS dans `_categorize_port()` ; 677/677

**v1.5.0** — Bannière enrichie (noyau, version iptables + backend, version nftables) ; nouvelle section ANALYSE DE LA PILE PARE-FEU (contournement iptables brut, nftables parallèle, ip_forward) ; nouvelle section CONTEXTE RÉSEAU (tableau interfaces, connexions établies) ; 766/766

**v1.6.0** — Nouvelle section DURCISSEMENT (fail2ban, mises à jour auto, AppArmor, rp_filter, redirections ICMP, log_martians, broadcast ICMP) ; nouvelle section COHÉRENCE IPv6 ; rapport comparatif (delta de baseline) ; API plugin de vérification ; 928/928

**v1.7.0** — Profils d'audit (`server`/`workstation`/`container`, format INI, héritage `extends`, `--profile=NAME`) ; `Deduction.key` pour correspondance d'override déterministe ; notifications cron multi-email ; suppression cron en lot (`d:1,3` / `d:1-3` / `d:all`) ; filtre des ports éphémères dans le rapport comparatif ; `--reset-baseline` ; 966/966

**v1.8.0** — Audit sécurité SSH (15 directives, clés privées, authorized_keys, known_hosts) ; fichiers sensibles & sudoers (monde-écriture, trop-permissif, NOPASSWD:ALL) ; ciblage home `SUDO_USER` ; suggestions distro-aware ; correctif i18n (`recommendation_label`) ; détail INFO en verbose ; 1104/1104

**v1.9.0** — Audit mises à jour système (CHECK 13 : apt en attente, unattended-upgrades, −2/−1 pts composés) ; `--explain KEY` avec WHY/HOW/CIS Ubuntu 22.04 (20 clés) ; webhooks (`--webhook`, générique + Slack, non-fatal) ; scores par domaine (5 domaines, barre, JSON/webhook) ; mode `--diff` ; passage qualité ; 1332/1332

**v1.10.0** — Suggestion `--explain` dans le résumé (Phase A1) ; audit modules noyau (CHECK 14 : cramfs/hfs/squashfs/usb_storage/dccp/sctp/rds/tipc, −1 pt/catégorie) ; audit tâches cron (CHECK 15 : pipe-to-shell −2 pts, scripts accessibles en écriture −1 pt ; /etc/cron.d parsé en format crontab) ; audit état des services (CHECK 16 : requête systemctl en deux étapes, services de sécurité inactifs, −1 pt/service max −3) ; passage qualité (shlex.quote dans les cmds de correction, key= sur tous les findings firewall.py, 9 fichiers de tests étendus) ; 1541/1541

**v1.11.0** — `--explain` A2 (20→33 clés : 11 SSH + fail2ban + 2 modules noyau + pipe_to_shell + enabled_inactive) ; audit comptes utilisateurs (CHECK 17 : UID 0 −3 pts, mot de passe vide −2 pts, expirés INFO) ; audit politique de mots de passe (CHECK 18 : absence module PAM −1 pt, minlen faible −1 pt, PASS_MAX_DAYS≥365 INFO) ; passage qualité ; 1675/1675

**v1.12.0** — Refonte `--help` (7 sections) ; 6 nouvelles options courtes (-J -C -p -e -D -w) ; correctifs autocomplétion bash ; 4 correctifs Debian VM (contexte risque tous services, GeoIP mkdir, unattended workstation, dates expiration avec filtre UID) ; 1703/1703

**v1.13.0** — audit santé disques (CHECK 22 : SMART + partitions, support NVMe, nouveau domaine `disk`) ; audit mémoire & swap (CHECK 23 : usure SSD, swap injustifié 3 conditions, swappiness adapté au profil) ; tableau partitions avec barres de progression colorées ; conseils SMART ; `--explain` 33→63 clés (15 groupes) ; passages qualité (disk.py + memory.py) ; 1890/1890

**v1.14.0** — audit sécurité Samba (CHECK 24 : SMB1 −2, mots de passe nuls −3, signature serveur −1, partage invité écriture −2/partage, lecture −1/partage, map_to_guest −1 ; domaine samba) ; audit antivirus ClamAV (CHECK 25 : fraîcheur BD, statut démon, âge dernier scan) ; correctif `--diff` info_count ; `--explain` 63→73 clés (17 groupes) ; 2045/2045

**v1.15.0** — CHECK 26 dominance source locale IoT (≥ 70 % trafic bloqué depuis une IP privée, WARN −1 pt) ; CHECK 27 exposition SMTP locale (Postfix/Exim/Sendmail sur 0.0.0.0:25, WARN −1 pt) ; `--fix` aperçu par défaut + `--apply` pour exécuter ; `--target N` objectif de score dans la boîte de synthèse ; TUI `--explain` navigation bloquée + écran détail in-curses ; annulation wizard avec `q` ; `--explain` 73→77 clés ; passage qualité smtp.py ; 2139/2139

**v1.15.1** *(actuel)* — Hotfix autocomplétion bash : `--explain` sans `=` parasite ; `compopt -o nospace` pour les options à valeur
- `--diff` — comparer l'audit courant avec un précédent export `--json` pour détecter les nouveaux ports/services (dérive d'audit)
- `--fix --safe` — mode auto-fix restreint aux findings LOW/MEDIUM uniquement ; les findings CRITICAL/HIGH ne sont jamais appliqués sans confirmation explicite

**Post v1.0**
- Interface Web (`--gui`) — interface graphique pour utilisateurs non-techniques, approche pédagogique, périmètre simplifié
- PPA Launchpad / paquet `.deb` — le répertoire de plugins migrera vers `/etc/ufw-audit/services.d/`

---

## Licence

MIT License — © 2026 Cédric Clauzel. Voir `LICENSE` pour les détails.

---

## Auteur

Cédric Clauzel
