#!/bin/bash
# ==========================================================
# UFW-audit v0.4.0
# UFW firewall security audit for Linux
# Target  : Debian/Ubuntu and derivatives
# Audience: regular user, non-system administrator
# ==========================================================

set -uo pipefail
export LC_ALL=C.UTF-8

VERSION="0.4.0"

OK_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0
SCORE=10

VERBOSE=false
HELP=false
VERSION_ONLY=false
AUDIT_REQUESTED=false
RECONFIGURE=false
LANG_FR=false
LOG_LEVEL="minimal"
LOGFILE=""
PORT_TOOL=""
DISTRO_NAME=""

REAL_USER=""
REAL_HOME=""
CONFIG_FILE=""

GREEN=$'\e[32m'
RED=$'\e[31m'
YELLOW=$'\e[33m'
CYAN=$'\e[36m'
BLUE=$'\e[34m'
BOLD=$'\e[1m'
DIM=$'\e[2m'
RESET=$'\e[0m'

# ==========================================================
# INTERNATIONALISATION
#
# t KEY  — returns the string for the current language.
# All user-visible strings are defined here.
# Add a new language by adding another branch in t().
# ==========================================================

t() {
    local KEY="$1"
    if $LANG_FR; then
        case "$KEY" in
            # --- banner ---
            banner_subtitle)    echo "Audit pare-feu UFW" ;;
            banner_system)      echo "Système      :" ;;
            banner_host)        echo "Hôte         :" ;;
            banner_ufw)         echo "UFW          :" ;;
            banner_user)        echo "Utilisateur  :" ;;
            banner_date)        echo "Date         :" ;;
            banner_unknown)     echo "inconnu" ;;
            # --- sections ---
            sec_prereq)         echo "VÉRIFICATION DES PRÉREQUIS" ;;
            sec_firewall)       echo "ÉTAT DU PARE-FEU" ;;
            sec_services)       echo "ANALYSE DES SERVICES RÉSEAU" ;;
            sec_ports)          echo "PORTS EN ÉCOUTE (VUE GÉNÉRALE)" ;;
            sec_summary)        echo "RÉSUMÉ DE L'AUDIT" ;;
            # --- summary ---
            sum_ok)             echo "✔ OK         :" ;;
            sum_warn)           echo "⚠ Attention  :" ;;
            sum_alert)          echo "✖ Alerte     :" ;;
            sum_score)          echo "Score de sécurité :" ;;
            sum_risk)           echo "Niveau de risque  :" ;;
            sum_risk_high)      echo "ÉLEVÉ" ;;
            sum_risk_med)       echo "MOYEN" ;;
            sum_risk_low)       echo "FAIBLE" ;;
            sum_msg_alert)      echo "Des alertes ont été détectées." ;;
            sum_msg_alert2)     echo "Suivez les recommandations ci-dessus pour sécuriser votre système." ;;
            sum_msg_warn)       echo "Quelques points méritent votre attention." ;;
            sum_msg_warn2)      echo "Consultez les recommandations ci-dessus." ;;
            sum_msg_ok)         echo "Votre configuration semble correcte." ;;
            sum_msg_ok2)        echo "Pensez à relancer cet audit régulièrement." ;;
            sum_cfg_ports)      echo "Configuration des ports :" ;;
            sum_cfg_report)     echo "Rapport d'audit        :" ;;
            # --- log messages ---
            log_start)          echo "Démarrage de l'audit" ;;
            log_ufw_ok)         echo "UFW est installé" ;;
            log_ufw_missing)    echo "UFW n'est pas installé sur ce système." ;;
            log_ufw_install)    echo "Installez UFW avec : sudo apt install ufw" ;;
            log_ufw_abort)      echo "Prérequis manquant. Audit interrompu." ;;
            log_ss_ok)          echo "Outil d'analyse réseau disponible (ss)" ;;
            log_netstat_warn)   echo "Outil 'ss' absent, utilisation de 'netstat' (moins précis)." ;;
            log_netstat_fix)    echo "Installez iproute2 : sudo apt install iproute2" ;;
            log_notool_warn)    echo "Aucun outil d'analyse réseau disponible. L'analyse des ports sera ignorée." ;;
            log_fw_active)      echo "Le pare-feu UFW est actif" ;;
            log_fw_inactive)    echo "Le pare-feu UFW est désactivé. Votre machine n'est actuellement pas protégée." ;;
            log_fw_enable)      echo "Pour activer UFW (configurez d'abord vos règles pour ne pas perdre l'accès SSH si besoin) :\n  sudo ufw enable" ;;
            log_policy_ok)      echo "Politique par défaut : connexions entrantes bloquées (recommandé)" ;;
            log_policy_warn)    echo "Impossible de lire la politique par défaut. Vérifiez avec : sudo ufw status verbose" ;;
            log_policy_alert)   echo "Politique par défaut : connexions entrantes autorisées. Votre machine accepte toutes les connexions entrantes non filtrées." ;;
            log_policy_fix)     echo "Pour bloquer les connexions entrantes par défaut :\n  sudo ufw default deny incoming" ;;
            log_svc_active)     echo "Service actif et démarré automatiquement au démarrage" ;;
            log_svc_nodaemon)   echo "Le service est actif en ce moment, mais ne redémarrera pas automatiquement." ;;
            log_svc_unknown)    echo "Service installé, état indéterminé" ;;
            log_svc_custom)     echo "Port personnalisé" ;;
            log_svc_default)    echo "par défaut" ;;
            log_svc_blocked)    echo "Accès bloqué explicitement par UFW. Bonne configuration." ;;
            log_no_services)    echo "Aucun service réseau connu n'a été détecté sur ce système." ;;
            log_no_ports)       echo "Aucun port en écoute détecté" ;;
            log_ports_count)    echo "port(s) en écoute détecté(s) sur ce système" ;;
            log_ports_skip)     echo "Analyse ignorée (aucun outil réseau disponible)" ;;
            log_report_ok)      echo "Rapport détaillé :" ;;
            log_report_fail)    echo "Impossible de créer le fichier de rapport dans" ;;
            log_distro_warn)    echo "Distribution non reconnue. Ce script est optimisé pour Debian/Ubuntu et ses dérivés." ;;
            log_cfg_found)      echo "Configuration trouvée :" ;;
            log_cfg_reset)      echo "Pour la réinitialiser :" ;;
            log_reconf)         echo "Mode reconfiguration : les ports personnalisés seront redemandés." ;;
            # --- port resolution ---
            port_not_detected)  echo "Port non détecté automatiquement." ;;
            port_question)      echo "Sur quel port ce service écoute-t-il ?" ;;
            port_default_hint)  echo "Entrée = port par défaut" ;;
            port_used_default)  echo "Port par défaut utilisé" ;;
            port_saved)         echo "Port mémorisé pour les prochains audits." ;;
            port_invalid)       echo "Entrée invalide. Port par défaut utilisé" ;;
            port_from_cfg)      echo "Port lu depuis la configuration" ;;
            port_auto)          echo "Port détecté automatiquement" ;;
            # --- recommendation header ---
            reco_header)        echo "Que faire ?" ;;
            # --- help ---
            help_usage)         echo "Usage : sudo ./ufw_audit.sh [options]" ;;
            help_opts)          echo "Options :" ;;
            help_verbose)       echo "  -v, --verbose       Afficher les détails techniques de l'audit" ;;
            help_detailed)      echo "  -d, --detailed      Générer un fichier de rapport complet" ;;
            help_reconf)        echo "  -r, --reconfigure   Redemander les ports personnalisés" ;;
            help_french)        echo "  --french            Afficher les messages en français" ;;
            help_version)       echo "  -V, --version       Afficher la version" ;;
            help_help)          echo "  -h, --help          Afficher cette aide" ;;
            help_default)       echo "Sans option, l'audit standard est lancé automatiquement." ;;
            # --- errors ---
            err_root)           echo "Ce script nécessite les droits administrateur." ;;
            err_root_hint)      echo "Lancez-le avec" ;;
            err_unknown_opt)    echo "Option inconnue :" ;;
            err_use_help)       echo "Utilisez --help pour voir les options disponibles." ;;
        esac
    else
        case "$KEY" in
            # --- banner ---
            banner_subtitle)    echo "UFW firewall audit" ;;
            banner_system)      echo "System       :" ;;
            banner_host)        echo "Host         :" ;;
            banner_ufw)         echo "UFW          :" ;;
            banner_user)        echo "User         :" ;;
            banner_date)        echo "Date         :" ;;
            banner_unknown)     echo "unknown" ;;
            # --- sections ---
            sec_prereq)         echo "PREREQUISITE CHECK" ;;
            sec_firewall)       echo "FIREWALL STATUS" ;;
            sec_services)       echo "NETWORK SERVICES ANALYSIS" ;;
            sec_ports)          echo "LISTENING PORTS (OVERVIEW)" ;;
            sec_summary)        echo "AUDIT SUMMARY" ;;
            # --- summary ---
            sum_ok)             echo "✔ OK         :" ;;
            sum_warn)           echo "⚠ Warning    :" ;;
            sum_alert)          echo "✖ Alert      :" ;;
            sum_score)          echo "Security score    :" ;;
            sum_risk)           echo "Risk level        :" ;;
            sum_risk_high)      echo "HIGH" ;;
            sum_risk_med)       echo "MEDIUM" ;;
            sum_risk_low)       echo "LOW" ;;
            sum_msg_alert)      echo "Alerts were detected." ;;
            sum_msg_alert2)     echo "Follow the recommendations above to secure your system." ;;
            sum_msg_warn)       echo "Some points deserve your attention." ;;
            sum_msg_warn2)      echo "Review the recommendations above." ;;
            sum_msg_ok)         echo "Your configuration looks good." ;;
            sum_msg_ok2)        echo "Remember to run this audit regularly." ;;
            sum_cfg_ports)      echo "Port configuration :" ;;
            sum_cfg_report)     echo "Audit report       :" ;;
            # --- log messages ---
            log_start)          echo "Starting audit" ;;
            log_ufw_ok)         echo "UFW is installed" ;;
            log_ufw_missing)    echo "UFW is not installed on this system." ;;
            log_ufw_install)    echo "Install UFW with: sudo apt install ufw" ;;
            log_ufw_abort)      echo "Missing prerequisite. Audit aborted." ;;
            log_ss_ok)          echo "Network analysis tool available (ss)" ;;
            log_netstat_warn)   echo "Tool 'ss' not found, using 'netstat' (less accurate)." ;;
            log_netstat_fix)    echo "Install iproute2: sudo apt install iproute2" ;;
            log_notool_warn)    echo "No network analysis tool available. Port analysis will be skipped." ;;
            log_fw_active)      echo "UFW firewall is active" ;;
            log_fw_inactive)    echo "UFW firewall is disabled. Your machine is currently unprotected." ;;
            log_fw_enable)      echo "To enable UFW (configure your rules first to avoid losing SSH access) :\n  sudo ufw enable" ;;
            log_policy_ok)      echo "Default policy: incoming connections blocked (recommended)" ;;
            log_policy_warn)    echo "Cannot read default policy. Check with: sudo ufw status verbose" ;;
            log_policy_alert)   echo "Default policy: incoming connections allowed. Your machine accepts all unfiltered incoming connections." ;;
            log_policy_fix)     echo "To block incoming connections by default:\n  sudo ufw default deny incoming" ;;
            log_svc_active)     echo "Service active and enabled at boot" ;;
            log_svc_nodaemon)   echo "Service is currently active but will not restart automatically." ;;
            log_svc_unknown)    echo "Service installed, state undetermined" ;;
            log_svc_custom)     echo "Custom port" ;;
            log_svc_default)    echo "default" ;;
            log_svc_blocked)    echo "Access explicitly blocked by UFW. Good configuration." ;;
            log_no_services)    echo "No known network services were detected on this system." ;;
            log_no_ports)       echo "No listening ports detected" ;;
            log_ports_count)    echo "listening port(s) detected on this system" ;;
            log_ports_skip)     echo "Analysis skipped (no network tool available)" ;;
            log_report_ok)      echo "Detailed report:" ;;
            log_report_fail)    echo "Cannot create report file in" ;;
            log_distro_warn)    echo "Unrecognised distribution. This script is optimised for Debian/Ubuntu and derivatives." ;;
            log_cfg_found)      echo "Configuration found:" ;;
            log_cfg_reset)      echo "To reset it:" ;;
            log_reconf)         echo "Reconfigure mode: custom ports will be asked again." ;;
            # --- port resolution ---
            port_not_detected)  echo "Port not detected automatically." ;;
            port_question)      echo "On which port is this service listening?" ;;
            port_default_hint)  echo "Enter = default port" ;;
            port_used_default)  echo "Default port used" ;;
            port_saved)         echo "Port saved for future audits." ;;
            port_invalid)       echo "Invalid input. Default port used" ;;
            port_from_cfg)      echo "Port read from configuration" ;;
            port_auto)          echo "Port auto-detected" ;;
            # --- recommendation header ---
            reco_header)        echo "What to do?" ;;
            # --- help ---
            help_usage)         echo "Usage: sudo ./ufw_audit.sh [options]" ;;
            help_opts)          echo "Options:" ;;
            help_verbose)       echo "  -v, --verbose       Show technical audit details" ;;
            help_detailed)      echo "  -d, --detailed      Generate a full report file" ;;
            help_reconf)        echo "  -r, --reconfigure   Re-ask custom ports" ;;
            help_french)        echo "  --french            Display messages in French" ;;
            help_version)       echo "  -V, --version       Show version" ;;
            help_help)          echo "  -h, --help          Show this help" ;;
            help_default)       echo "Without options, the standard audit is run automatically." ;;
            # --- errors ---
            err_root)           echo "This script requires administrator privileges." ;;
            err_root_hint)      echo "Run it with" ;;
            err_unknown_opt)    echo "Unknown option:" ;;
            err_use_help)       echo "Use --help to see available options." ;;
        esac
    fi
}

# ==========================================================
# ALIGNMENT HELPER — corrects frame offset caused by ANSI codes
# ==========================================================

banner_row() {
    local RAW_LABEL="$1"
    local VALUE="$2"
    local TOTAL="${3:-58}"

    local VIS_LABEL VIS_VALUE
    VIS_LABEL=$(echo -e "$RAW_LABEL" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\n' | wc -m)
    VIS_VALUE=$(echo -e "$VALUE"     | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\n' | wc -m)

    local PAD=$(( TOTAL - VIS_LABEL - VIS_VALUE ))
    (( PAD < 1 )) && PAD=1

    echo -e "${BLUE}${BOLD}║${RESET}  ${RAW_LABEL}${VALUE}$(printf '%*s' "$PAD" '')  ${BLUE}${BOLD}║${RESET}"
}

# ==========================================================
# ASCII BANNER — compact badge + system info
# ==========================================================

show_banner() {
    local SYS_NAME SYS_HOST SYS_DATE SYS_USER SYS_UFW
    SYS_NAME="${DISTRO_NAME:-$(uname -s)}"
    SYS_HOST="$(hostname 2>/dev/null || echo "$(t banner_unknown)")"
    SYS_DATE="$(date '+%d/%m/%Y %H:%M')"
    SYS_USER="${REAL_USER:-$(whoami)}"
    SYS_UFW="$(ufw version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "N/A")"

    SYS_NAME="${SYS_NAME:0:40}"
    SYS_HOST="${SYS_HOST:0:40}"
    SYS_USER="${SYS_USER:0:40}"

    local W=58

    echo -e "${BLUE}${BOLD}"
    echo    "╔══════════════════════════════════════════════════════════════╗"
    echo -e "║  ${RESET}${CYAN}${BOLD} ██╗   ██╗███████╗██╗    ██╗${RESET}${BLUE}${BOLD}  ┌──────────────────────────┐  ║"
    echo -e "║  ${RESET}${CYAN}${BOLD} ██║   ██║██╔════╝██║    ██║${RESET}${BLUE}${BOLD}  │  ${RESET}${BOLD}UFW-AUDIT  v${VERSION}${RESET}${BLUE}${BOLD}       │  ║"
    echo -e "║  ${RESET}${CYAN}${BOLD} ██║   ██║█████╗  ██║ █╗ ██║${RESET}${BLUE}${BOLD}  │  $(t banner_subtitle)     │  ║"
    echo -e "║  ${RESET}${CYAN}${BOLD} ██║   ██║██╔══╝  ██║███╗██║${RESET}${BLUE}${BOLD}  └──────────────────────────┘  ║"
    echo -e "║  ${RESET}${CYAN}${BOLD} ╚██████╔╝██║     ╚███╔███╔╝${RESET}${BLUE}${BOLD}              _ _               ║"
    echo -e "║  ${RESET}${CYAN}${BOLD}  ╚═════╝ ╚═╝      ╚══╝╚══╝ ${RESET}${BLUE}${BOLD}            _(-_-)_             ║"
    echo -e "║  ${RESET}${BLUE}${BOLD}                                          audit             ║"
    echo    "╠══════════════════════════════════════════════════════════════╣"
    banner_row "${DIM}$(t banner_system)${RESET}" "$SYS_NAME"   $W
    banner_row "${DIM}$(t banner_host)${RESET}"   "$SYS_HOST"   $W
    banner_row "${DIM}$(t banner_ufw)${RESET}"    "v${SYS_UFW}" $W
    banner_row "${DIM}$(t banner_user)${RESET}"   "$SYS_USER"   $W
    banner_row "${DIM}$(t banner_date)${RESET}"   "$SYS_DATE"   $W
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

# ==========================================================
# SERVICE REGISTRY
# Format : "label|packages|systemd services|default ports|risk|config_key"
# config_key : "fixed" | "auto" | "ask" | key_name
# Service labels are kept as technical names (language-neutral)
# ==========================================================

SERVICES=(
    "SSH Server|openssh-server|ssh|22/tcp|high|ssh_port"
    "VNC Server|x11vnc tigervnc-standalone-server|x11vnc vncserver|5900/tcp|high|ask"
    "Samba (Windows file sharing)|samba|smbd|445/tcp 139/tcp|critical|fixed"
    "FTP Server|vsftpd proftpd|vsftpd proftpd|21/tcp|critical|auto"
    "Apache Web Server|apache2|apache2|80/tcp 443/tcp|medium|ask"
    "Nginx Web Server|nginx|nginx|80/tcp 443/tcp|medium|ask"
    "MySQL / MariaDB|mysql-server mariadb-server|mysql mariadb|3306/tcp|high|auto"
    "PostgreSQL|postgresql|postgresql|5432/tcp|high|auto"
    "Transmission (web UI)|transmission-daemon|transmission-daemon|9091/tcp|medium|auto"
    "qBittorrent (web UI)|qbittorrent-nox|qbittorrent-nox|8080/tcp|medium|ask"
    "Avahi (local network discovery)|avahi-daemon|avahi-daemon|5353/udp|low|fixed"
    "CUPS (network printing)|cups|cups|631/tcp|low|auto"
    "Cockpit (web admin)|cockpit|cockpit|9090/tcp|medium|auto"
)

# ==========================================================
# RISK EXPLANATIONS — per service and per situation
# ==========================================================

get_risk_explanation() {
    local LABEL="$1"
    local SITUATION="$2"

    if $LANG_FR; then
        case "$LABEL" in
            "SSH Server")
                case "$SITUATION" in
                    open_world) echo "Votre accès SSH est accessible depuis n'importe quelle adresse sur internet. Des tentatives de connexion automatisées (bruteforce) sont très fréquentes sur ce port." ;;
                    open_local) echo "Votre accès SSH est restreint à votre réseau local. C'est une bonne configuration." ;;
                    deny)       echo "L'accès SSH est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "SSH est actif mais aucune règle UFW ne le concerne. Vérifiez que la politique par défaut bloque bien les connexions entrantes." ;;
                    inactive)   echo "OpenSSH Server est installé et actif pour l'instant, mais ne redémarrera pas automatiquement. Vérifiez si c'est intentionnel." ;;
                    disabled)   echo "OpenSSH Server est installé mais le service est arrêté et désactivé. Aucun risque immédiat — pensez à le désinstaller s'il ne vous est pas utile." ;;
                esac ;;
            "VNC Server")
                case "$SITUATION" in
                    open_world) echo "Votre serveur VNC (bureau à distance) est accessible depuis internet. VNC transmet souvent les données sans chiffrement, ce qui représente un risque important." ;;
                    open_local) echo "Votre serveur VNC est restreint au réseau local. C'est acceptable, mais préférez SSH avec tunnel si possible." ;;
                    deny)       echo "L'accès VNC est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "Un serveur VNC est actif. Vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Un serveur VNC est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Un serveur VNC est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Samba (Windows file sharing)")
                case "$SITUATION" in
                    open_world) echo "Samba est accessible depuis internet. C'est un risque critique — Samba est conçu pour le réseau local uniquement et ne devrait jamais être exposé sur internet." ;;
                    open_local) echo "Samba est restreint à votre réseau local. C'est la configuration normale pour un partage de fichiers domestique." ;;
                    deny)       echo "L'accès Samba est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "Samba est actif. Vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Samba est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Samba est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "FTP Server")
                case "$SITUATION" in
                    open_world) echo "Votre serveur FTP est accessible depuis internet. FTP est un protocole ancien qui transmet vos identifiants et fichiers sans aucun chiffrement — c'est un risque critique." ;;
                    open_local) echo "Votre serveur FTP est restreint au réseau local. C'est mieux, mais FTP reste non chiffré — SFTP (via SSH) est une alternative plus sûre." ;;
                    deny)       echo "L'accès FTP est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "Un serveur FTP est actif. Vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Un serveur FTP est installé et actif, mais ne redémarrera pas automatiquement. Envisagez de le désinstaller au profit de SFTP." ;;
                    disabled)   echo "Un serveur FTP est installé mais arrêté et désactivé. Envisagez de le désinstaller au profit de SFTP (via SSH)." ;;
                esac ;;
            "Apache Web Server"|"Nginx Web Server")
                case "$SITUATION" in
                    open_world) echo "Votre serveur web est accessible depuis internet. C'est normal s'il héberge un site public — vérifiez simplement que seuls les ports HTTP et HTTPS sont ouverts." ;;
                    open_local) echo "Votre serveur web est restreint à votre réseau local. C'est adapté pour un usage domestique ou de développement." ;;
                    deny)       echo "L'accès au serveur web est explicitement bloqué par UFW." ;;
                    no_rule)    echo "Un serveur web est actif. Vérifiez sa configuration d'accès dans UFW." ;;
                    inactive)   echo "Un serveur web est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Un serveur web est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "MySQL / MariaDB")
                case "$SITUATION" in
                    open_world) echo "Votre base de données MySQL/MariaDB est accessible depuis internet. C'est un risque très élevé — une base de données ne devrait jamais être directement exposée sur internet." ;;
                    open_local) echo "Votre base de données est restreinte au réseau local. Idéalement, elle ne devrait écouter que sur votre propre machine (localhost)." ;;
                    deny)       echo "L'accès à la base de données est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "MySQL/MariaDB est actif. Par défaut il écoute uniquement en local (localhost), ce qui est correct. Vérifiez que cela n'a pas été modifié." ;;
                    inactive)   echo "MySQL/MariaDB est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "MySQL/MariaDB est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "PostgreSQL")
                case "$SITUATION" in
                    open_world) echo "Votre base de données PostgreSQL est accessible depuis internet. C'est un risque très élevé — une base de données ne devrait jamais être exposée directement sur internet." ;;
                    open_local) echo "PostgreSQL est restreint au réseau local. Vérifiez que c'est bien intentionnel." ;;
                    deny)       echo "L'accès à PostgreSQL est explicitement bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "PostgreSQL est actif. Par défaut il écoute uniquement en local, ce qui est correct." ;;
                    inactive)   echo "PostgreSQL est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "PostgreSQL est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Transmission (web UI)"|"qBittorrent (web UI)")
                case "$SITUATION" in
                    open_world) echo "L'interface web de votre client torrent est accessible depuis internet. N'importe qui pourrait contrôler vos téléchargements ou accéder à vos fichiers." ;;
                    open_local) echo "L'interface web de votre client torrent est restreinte au réseau local. C'est une configuration correcte pour un usage domestique." ;;
                    deny)       echo "L'accès à l'interface web du client torrent est bloqué par UFW." ;;
                    no_rule)    echo "Votre client torrent avec interface web est actif. Vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Un client torrent avec interface web est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Un client torrent avec interface web est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Avahi (local network discovery)")
                case "$SITUATION" in
                    open_world) echo "Avahi est un service de découverte de périphériques sur le réseau local. Il ne devrait pas être accessible depuis internet." ;;
                    open_local) echo "Avahi fonctionne normalement sur votre réseau local. C'est son comportement attendu." ;;
                    deny)       echo "Avahi est bloqué par UFW." ;;
                    no_rule)    echo "Avahi est actif. C'est un service de découverte réseau conçu pour le réseau local — son comportement est normal." ;;
                    inactive)   echo "Avahi est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Avahi est installé mais arrêté et désactivé. Pas de risque." ;;
                esac ;;
            "CUPS (network printing)")
                case "$SITUATION" in
                    open_world) echo "Votre service d'impression est accessible depuis internet. Ce n'est probablement pas intentionnel." ;;
                    open_local) echo "CUPS est restreint au réseau local. C'est la configuration normale pour un partage d'imprimante domestique." ;;
                    deny)       echo "L'accès à CUPS est bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "CUPS (impression) est actif. Il écoute généralement uniquement en local, ce qui est correct." ;;
                    inactive)   echo "CUPS est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "CUPS est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Cockpit (web admin)")
                case "$SITUATION" in
                    open_world) echo "Cockpit est une interface d'administration web pour votre système. L'exposer sur internet permet à n'importe qui de tenter d'accéder à la gestion complète de votre machine." ;;
                    open_local) echo "Cockpit est restreint au réseau local. C'est une configuration adaptée pour un usage domestique." ;;
                    deny)       echo "L'accès à Cockpit est bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "Cockpit est actif. Vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Cockpit est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Cockpit est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            *)
                case "$SITUATION" in
                    open_world) echo "Ce service est accessible depuis internet sans restriction." ;;
                    open_local) echo "Ce service est restreint à votre réseau local." ;;
                    deny)       echo "Ce service est bloqué par UFW." ;;
                    no_rule)    echo "Ce service est actif mais aucune règle UFW ne le concerne explicitement." ;;
                    inactive)   echo "Ce service est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Ce service est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
        esac
    else
        case "$LABEL" in
            "SSH Server")
                case "$SITUATION" in
                    open_world) echo "Your SSH access is reachable from any address on the internet. Automated brute-force attempts are very common on this port." ;;
                    open_local) echo "Your SSH access is restricted to your local network. Good configuration." ;;
                    deny)       echo "SSH access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "SSH is active but no UFW rule covers it. Check that the default policy blocks incoming connections." ;;
                    inactive)   echo "OpenSSH Server is installed and currently active, but will not restart automatically. Check if this is intentional." ;;
                    disabled)   echo "OpenSSH Server is installed but stopped and disabled. No immediate risk — consider removing it if not needed." ;;
                esac ;;
            "VNC Server")
                case "$SITUATION" in
                    open_world) echo "Your VNC server (remote desktop) is reachable from the internet. VNC often transmits data without encryption, which represents a significant risk." ;;
                    open_local) echo "Your VNC server is restricted to the local network. Acceptable, but prefer SSH tunnelling when possible." ;;
                    deny)       echo "VNC access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "A VNC server is active. Check that it is not reachable from the internet." ;;
                    inactive)   echo "A VNC server is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "A VNC server is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Samba (Windows file sharing)")
                case "$SITUATION" in
                    open_world) echo "Samba is reachable from the internet. This is a critical risk — Samba is designed for local networks only and should never be exposed to the internet." ;;
                    open_local) echo "Samba is restricted to your local network. This is the normal setup for home file sharing." ;;
                    deny)       echo "Samba access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "Samba is active. Check that it is not reachable from the internet." ;;
                    inactive)   echo "Samba is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Samba is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "FTP Server")
                case "$SITUATION" in
                    open_world) echo "Your FTP server is reachable from the internet. FTP is an old protocol that transmits credentials and files without any encryption — this is a critical risk." ;;
                    open_local) echo "Your FTP server is restricted to the local network. Better, but FTP is still unencrypted — SFTP (via SSH) is a safer alternative." ;;
                    deny)       echo "FTP access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "An FTP server is active. Check that it is not reachable from the internet." ;;
                    inactive)   echo "An FTP server is installed and currently active, but will not restart automatically. Consider removing it in favour of SFTP." ;;
                    disabled)   echo "An FTP server is installed but stopped and disabled. Consider removing it in favour of SFTP (via SSH)." ;;
                esac ;;
            "Apache Web Server"|"Nginx Web Server")
                case "$SITUATION" in
                    open_world) echo "Your web server is reachable from the internet. This is normal if it hosts a public site — just make sure only HTTP and HTTPS ports are open." ;;
                    open_local) echo "Your web server is restricted to your local network. Suitable for home use or development." ;;
                    deny)       echo "Web server access is explicitly blocked by UFW." ;;
                    no_rule)    echo "A web server is active. Check its UFW access configuration." ;;
                    inactive)   echo "A web server is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "A web server is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "MySQL / MariaDB")
                case "$SITUATION" in
                    open_world) echo "Your MySQL/MariaDB database is reachable from the internet. This is a very high risk — a database should never be directly exposed to the internet." ;;
                    open_local) echo "Your database is restricted to the local network. Ideally it should only listen on your own machine (localhost)." ;;
                    deny)       echo "Database access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "MySQL/MariaDB is active. By default it only listens locally (localhost), which is correct. Check this has not been changed." ;;
                    inactive)   echo "MySQL/MariaDB is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "MySQL/MariaDB is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "PostgreSQL")
                case "$SITUATION" in
                    open_world) echo "Your PostgreSQL database is reachable from the internet. This is a very high risk — a database should never be directly exposed to the internet." ;;
                    open_local) echo "PostgreSQL is restricted to the local network. Check that this is intentional." ;;
                    deny)       echo "PostgreSQL access is explicitly blocked by UFW. Good configuration." ;;
                    no_rule)    echo "PostgreSQL is active. By default it only listens locally, which is correct." ;;
                    inactive)   echo "PostgreSQL is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "PostgreSQL is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Transmission (web UI)"|"qBittorrent (web UI)")
                case "$SITUATION" in
                    open_world) echo "Your torrent client's web interface is reachable from the internet. Anyone could control your downloads or access your files." ;;
                    open_local) echo "Your torrent client's web interface is restricted to the local network. Suitable for home use." ;;
                    deny)       echo "Torrent client web interface access is blocked by UFW." ;;
                    no_rule)    echo "Your torrent client with web interface is active. Check that it is not reachable from the internet." ;;
                    inactive)   echo "A torrent client with web interface is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "A torrent client with web interface is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Avahi (local network discovery)")
                case "$SITUATION" in
                    open_world) echo "Avahi is a device discovery service for the local network. It should not be reachable from the internet." ;;
                    open_local) echo "Avahi is working normally on your local network. This is its expected behaviour." ;;
                    deny)       echo "Avahi is blocked by UFW." ;;
                    no_rule)    echo "Avahi is active. It is a local network discovery service — its behaviour is normal." ;;
                    inactive)   echo "Avahi is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Avahi is installed but stopped and disabled. No risk." ;;
                esac ;;
            "CUPS (network printing)")
                case "$SITUATION" in
                    open_world) echo "Your printing service is reachable from the internet. This is probably not intentional." ;;
                    open_local) echo "CUPS is restricted to the local network. This is the normal setup for home printer sharing." ;;
                    deny)       echo "CUPS access is blocked by UFW. Good configuration." ;;
                    no_rule)    echo "CUPS (printing) is active. It generally only listens locally, which is correct." ;;
                    inactive)   echo "CUPS is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "CUPS is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Cockpit (web admin)")
                case "$SITUATION" in
                    open_world) echo "Cockpit is a web administration interface for your system. Exposing it to the internet lets anyone attempt to access full system management." ;;
                    open_local) echo "Cockpit is restricted to the local network. Suitable for home use." ;;
                    deny)       echo "Cockpit access is blocked by UFW. Good configuration." ;;
                    no_rule)    echo "Cockpit is active. Check that it is not reachable from the internet." ;;
                    inactive)   echo "Cockpit is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Cockpit is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            *)
                case "$SITUATION" in
                    open_world) echo "This service is reachable from the internet without restriction." ;;
                    open_local) echo "This service is restricted to your local network." ;;
                    deny)       echo "This service is blocked by UFW." ;;
                    no_rule)    echo "This service is active but no UFW rule covers it explicitly." ;;
                    inactive)   echo "This service is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "This service is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
        esac
    fi
}

# ==========================================================
# RECOMMENDATIONS — per service and per situation
# ==========================================================

get_recommendation() {
    local LABEL="$1"
    local SITUATION="$2"
    local PORTS="$3"
    local MAIN_PORT
    MAIN_PORT=$(echo "$PORTS" | awk '{print $1}' | cut -d'/' -f1)

    if $LANG_FR; then
        case "$SITUATION" in
            open_world)
                case "$LABEL" in
                    "SSH Server")
                        echo "Pour restreindre SSH à votre réseau local (remplacez 192.168.1.0/24 par votre plage réseau, trouvable avec 'ip route') :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "VNC Server")
                        echo "Pour restreindre VNC à votre réseau local (remplacez 192.168.1.0/24 par votre plage réseau) :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "Samba (Windows file sharing)")
                        echo "Pour restreindre Samba à votre réseau local (remplacez 192.168.1.0/24 par votre plage réseau) :\n  sudo ufw delete allow 445/tcp\n  sudo ufw delete allow 139/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port 445\n  sudo ufw allow from 192.168.1.0/24 to any port 139" ;;
                    "FTP Server")
                        echo "FTP étant non chiffré, nous vous recommandons de l'arrêter et d'utiliser SFTP (inclus avec SSH) :\n  sudo systemctl stop vsftpd\n  sudo systemctl disable vsftpd\nSi vous devez absolument conserver FTP, restreignez-le au réseau local :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "MySQL / MariaDB"|"PostgreSQL")
                        echo "Bloquez l'accès depuis internet — une base de données ne doit pas être exposée publiquement :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw deny $MAIN_PORT/tcp" ;;
                    "Transmission (web UI)"|"qBittorrent (web UI)"|"Cockpit (web admin)"|"Apache Web Server"|"Nginx Web Server")
                        echo "Pour restreindre l'accès à votre réseau local (remplacez 192.168.1.0/24 par votre plage réseau) :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "CUPS (network printing)"|"Avahi (local network discovery)")
                        echo "Pour bloquer l'accès depuis internet :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw deny $MAIN_PORT" ;;
                    *)
                        echo "Pour restreindre ce service à votre réseau local (remplacez 192.168.1.0/24) :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                esac ;;
            open_local)
                case "$LABEL" in
                    "MySQL / MariaDB"|"PostgreSQL")
                        echo "Si ce service n'est utilisé que sur votre propre machine, restreignez-le à localhost uniquement en éditant sa configuration." ;;
                esac ;;
            inactive|disabled)
                case "$LABEL" in
                    "FTP Server")     echo "Pour désinstaller FTP et utiliser SFTP à la place (inclus avec OpenSSH) :\n  sudo apt remove vsftpd proftpd" ;;
                    "SSH Server")     [[ "$SITUATION" == "disabled" ]] && echo "Si vous n'utilisez pas SSH, vous pouvez le désinstaller proprement :\n  sudo apt remove openssh-server" ;;
                esac ;;
        esac
    else
        case "$SITUATION" in
            open_world)
                case "$LABEL" in
                    "SSH Server")
                        echo "To restrict SSH to your local network (replace 192.168.1.0/24 with your network range, find it with 'ip route') :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "VNC Server")
                        echo "To restrict VNC to your local network (replace 192.168.1.0/24 with your network range) :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "Samba (Windows file sharing)")
                        echo "To restrict Samba to your local network (replace 192.168.1.0/24 with your network range) :\n  sudo ufw delete allow 445/tcp\n  sudo ufw delete allow 139/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port 445\n  sudo ufw allow from 192.168.1.0/24 to any port 139" ;;
                    "FTP Server")
                        echo "As FTP is unencrypted, we recommend stopping it and using SFTP (included with SSH) :\n  sudo systemctl stop vsftpd\n  sudo systemctl disable vsftpd\nIf you must keep FTP, restrict it to the local network :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "MySQL / MariaDB"|"PostgreSQL")
                        echo "Block internet access — a database must not be publicly exposed :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw deny $MAIN_PORT/tcp" ;;
                    "Transmission (web UI)"|"qBittorrent (web UI)"|"Cockpit (web admin)"|"Apache Web Server"|"Nginx Web Server")
                        echo "To restrict access to your local network (replace 192.168.1.0/24 with your network range) :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "CUPS (network printing)"|"Avahi (local network discovery)")
                        echo "To block internet access :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw deny $MAIN_PORT" ;;
                    *)
                        echo "To restrict this service to your local network (replace 192.168.1.0/24) :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                esac ;;
            open_local)
                case "$LABEL" in
                    "MySQL / MariaDB"|"PostgreSQL")
                        echo "If this service is only used on your own machine, restrict it to localhost only by editing its configuration." ;;
                esac ;;
            inactive|disabled)
                case "$LABEL" in
                    "FTP Server")   echo "To remove FTP and use SFTP instead (included with OpenSSH) :\n  sudo apt remove vsftpd proftpd" ;;
                    "SSH Server")   [[ "$SITUATION" == "disabled" ]] && echo "If you do not use SSH, you can cleanly remove it :\n  sudo apt remove openssh-server" ;;
                esac ;;
        esac
    fi
}

# ==========================================================
# HELPERS
# ==========================================================

use_logfile() { [[ -n "$LOGFILE" ]]; }
is_detailed() { [[ "$LOG_LEVEL" == "detailed" ]] && use_logfile; }

# ==========================================================
# ROOT CHECK + REAL USER HOME RESOLUTION
# ==========================================================

check_root() {
    if (( EUID != 0 )) && $AUDIT_REQUESTED; then
        echo -e "${RED}[ERROR]${RESET} $(t err_root)"
        echo -e "$(t err_root_hint): ${YELLOW}sudo $0${RESET}"
        exit 1
    fi
    REAL_USER="${SUDO_USER:-$USER}"
    REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    CONFIG_FILE="$REAL_HOME/.ufw_audit.conf"
}

# ==========================================================
# ARGUMENT PARSER
# ==========================================================

parse_arguments() {
    if [[ $# -eq 0 ]]; then
        AUDIT_REQUESTED=true
        return
    fi
    # First pass: detect --french early so t() works for error messages
    for arg in "$@"; do
        [[ "$arg" == "--french" ]] && LANG_FR=true
    done
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)      VERBOSE=true;        AUDIT_REQUESTED=true ;;
            -h|--help)         HELP=true ;;
            -d|--detailed)     LOG_LEVEL="detailed"; AUDIT_REQUESTED=true ;;
            -V|--version)      VERSION_ONLY=true ;;
            -r|--reconfigure)  RECONFIGURE=true;     AUDIT_REQUESTED=true ;;
            --french)          LANG_FR=true;          AUDIT_REQUESTED=true ;;
            *)
                echo -e "${RED}[ERROR]${RESET} $(t err_unknown_opt) $1"
                echo -e "$(t err_use_help)"
                exit 1 ;;
        esac
        shift
    done
}

# ==========================================================
# VERSION / HELP
# ==========================================================

show_version() { echo -e "${GREEN}UFW-audit v$VERSION${RESET}"; }

show_help() {
    echo -e "${GREEN}UFW-audit v$VERSION${RESET}"
    echo "$(t help_usage)"
    echo
    echo "$(t help_opts)"
    echo "$(t help_verbose)"
    echo "$(t help_detailed)"
    echo "$(t help_reconf)"
    echo "$(t help_french)"
    echo "$(t help_version)"
    echo "$(t help_help)"
    echo
    echo "$(t help_default)"
    echo
}

# ==========================================================
# DISTRIBUTION DETECTION
# ==========================================================

detect_distro() {
    [[ ! -f /etc/os-release ]] && return
    local OS_ID OS_ID_LIKE
    OS_ID=$(grep -oP '(?<=^ID=)[^\n]+' /etc/os-release | tr -d '"')
    OS_ID_LIKE=$(grep -oP '(?<=^ID_LIKE=)[^\n]+' /etc/os-release 2>/dev/null | tr -d '"' || echo "")
    DISTRO_NAME=$(grep -oP '(?<=^PRETTY_NAME=)[^\n]+' /etc/os-release | tr -d '"')

    if [[ "$OS_ID" != "debian" && "$OS_ID" != "ubuntu" \
       && "$OS_ID_LIKE" != *"debian"* && "$OS_ID_LIKE" != *"ubuntu"* ]]; then
        log WARN "$(t log_distro_warn)" ""
    fi
}

# ==========================================================
# LOGGING
# ==========================================================

log() {
    local LEVEL="$1"
    local MESSAGE="$2"
    local RECOMMENDATION="${3:-}"
    local TIMESTAMP
    TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    local COLOR="" PREFIX="" ICON=""

    case "$LEVEL" in
        INFO)  COLOR="$CYAN";   ICON="ℹ"
               $LANG_FR && PREFIX="[INFO]"    || PREFIX="[INFO]" ;;
        OK)    COLOR="$GREEN";  ICON="✔";  OK_COUNT=$(( OK_COUNT + 1 ))
               PREFIX="[OK]" ;;
        WARN)  COLOR="$YELLOW"; ICON="⚠";  WARN_COUNT=$(( WARN_COUNT + 1 )); SCORE=$(( SCORE - 1 ))
               $LANG_FR && PREFIX="[ATTENTION]" || PREFIX="[WARNING]" ;;
        ALERT) COLOR="$RED";    ICON="✖";  ALERT_COUNT=$(( ALERT_COUNT + 1 )); SCORE=$(( SCORE - 2 ))
               $LANG_FR && PREFIX="[ALERTE]"    || PREFIX="[ALERT]" ;;
        ERROR) COLOR="$RED";    ICON="✖"
               $LANG_FR && PREFIX="[ERREUR]"    || PREFIX="[ERROR]" ;;
    esac

    echo -e "${COLOR}${BOLD}${ICON} ${PREFIX}${RESET}${COLOR} $MESSAGE${RESET}"

    if use_logfile; then
        echo "$TIMESTAMP $PREFIX $MESSAGE" >> "$LOGFILE"
        if is_detailed && [[ -n "$RECOMMENDATION" ]]; then
            {
                echo "  → Recommendation:"
                while IFS= read -r line; do echo "    $line"; done <<< "$(echo -e "$RECOMMENDATION")"
                echo
            } >> "$LOGFILE"
        fi
    fi
}

log_section() {
    local TITLE="$1"
    local W=61
    local TLEN=${#TITLE}
    local PAD=$(( W - TLEN - 2 ))
    (( PAD < 0 )) && PAD=0
    echo
    echo -e "${BLUE}${BOLD}┌─────────────────────────────────────────────────────────────┐${RESET}"
    printf  "${BLUE}${BOLD}│${RESET}  ${BOLD}%s%${PAD}s${RESET}${BLUE}${BOLD}│${RESET}\n" "$TITLE" ""
    echo -e "${BLUE}${BOLD}└─────────────────────────────────────────────────────────────┘${RESET}"
    echo
    use_logfile && { echo; echo "=== $TITLE ==="; echo; } >> "$LOGFILE"
}

log_service_header() {
    local TITLE="$1"
    echo -e "  ${BOLD}${CYAN}▶ $TITLE${RESET}"
    use_logfile && echo "  > $TITLE" >> "$LOGFILE"
}

log_detail() {
    local MESSAGE="$1"
    $VERBOSE    && echo -e "    ${DIM}↳ $MESSAGE${RESET}" > /dev/tty
    is_detailed && echo    "    ↳ $MESSAGE" >> "$LOGFILE"
}

log_recommendation() {
    local TEXT="$1"
    [[ -z "$TEXT" ]] && return
    echo
    echo -e "    ${YELLOW}${BOLD}$(t reco_header)${RESET}"
    while IFS= read -r line; do
        echo -e "    ${YELLOW}→ ${line}${RESET}"
    done <<< "$(echo -e "$TEXT")"
    echo
    if use_logfile; then
        {
            echo "    $(t reco_header)"
            while IFS= read -r line; do echo "    → $line"; done <<< "$(echo -e "$TEXT")"
            echo
        } >> "$LOGFILE"
    fi
}

# ==========================================================
# LOG FILE
# ==========================================================

init_logfile() {
    [[ "$LOG_LEVEL" != "detailed" ]] && return
    local SCRIPT_DIR TIMESTAMP
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
    LOGFILE="$SCRIPT_DIR/ufw_audit_$TIMESTAMP.log"
    touch "$LOGFILE" 2>/dev/null || {
        echo -e "${RED}[ERROR]${RESET} $(t log_report_fail) $SCRIPT_DIR"
        exit 1
    }
    log OK "$(t log_report_ok) $LOGFILE"
    {
        echo "=========================================================="
        echo "UFW-AUDIT REPORT v$VERSION"
        echo "Date        : $(date)"
        echo "Language    : $( $LANG_FR && echo "French" || echo "English" )"
        echo "=========================================================="
        echo
        echo "[SYSTEM INFORMATION]"
        echo "System      : ${DISTRO_NAME:-unknown}"
        echo "Host        : $(hostname)"
        echo "Kernel      : $(uname -r)"
        echo "UFW         : $(ufw version 2>/dev/null | head -1 || echo "N/A")"
        echo "User        : $REAL_USER"
        echo "Port config : $CONFIG_FILE"
        echo
        echo "=========================================================="
        echo
    } > "$LOGFILE"
}

finalize_log() {
    use_logfile || return
    (( SCORE < 0 )) && SCORE=0
    {
        echo
        echo "=========================================================="
        echo "[AUDIT SUMMARY]"
        echo "OK      : $OK_COUNT"
        echo "Warning : $WARN_COUNT"
        echo "Alert   : $ALERT_COUNT"
        echo "Score   : $SCORE/10"
        echo "Risk    : $(get_risk_level)"
        echo
        echo "[NEXT STEPS]"
        echo "1. Address all alerts first."
        echo "2. Review warnings and assess their impact."
        echo "3. Re-run the audit after each change to verify."
        echo "=========================================================="
    } >> "$LOGFILE"
}

get_risk_level() {
    local S=$SCORE
    (( S < 0 )) && S=0
    if   (( S <= 4 )); then echo "$(t sum_risk_high)"
    elif (( S <= 7 )); then echo "$(t sum_risk_med)"
    else                    echo "$(t sum_risk_low)"
    fi
}

# ==========================================================
# USER CONFIGURATION FILE MANAGEMENT
# ==========================================================

config_load() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        {
            echo "# UFW-audit — custom port configuration"
            echo "# Created automatically by ufw_audit.sh"
            echo "# You can edit this file manually."
            echo "# To reset: sudo ./ufw_audit.sh --reconfigure"
            echo "#"
            echo "# Format: key=value   e.g.: ssh_port=22022"
            echo
        } > "$CONFIG_FILE"
        chown "$REAL_USER:$REAL_USER" "$CONFIG_FILE" 2>/dev/null || true
    fi
}

config_get() {
    local KEY="$1"
    [[ ! -f "$CONFIG_FILE" ]] && return
    grep -E "^${KEY}=" "$CONFIG_FILE" 2>/dev/null | cut -d'=' -f2- | tr -d ' \t' || true
}

config_set() {
    local KEY="$1" VALUE="$2"
    if grep -qE "^${KEY}=" "$CONFIG_FILE" 2>/dev/null; then
        sed -i "s|^${KEY}=.*|${KEY}=${VALUE}|" "$CONFIG_FILE"
    else
        echo "${KEY}=${VALUE}" >> "$CONFIG_FILE"
    fi
    chown "$REAL_USER:$REAL_USER" "$CONFIG_FILE" 2>/dev/null || true
}

config_delete_key() {
    local KEY="$1"
    [[ -f "$CONFIG_FILE" ]] && sed -i "/^${KEY}=/d" "$CONFIG_FILE"
}

# ==========================================================
# AUTOMATIC PORT DETECTION — per service
# ==========================================================

detect_port_auto() {
    local LABEL="$1"
    case "$LABEL" in
        "SSH Server")
            local P; P=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "FTP Server")
            local P; P=$(grep -E "^listen_port" /etc/vsftpd.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "MySQL / MariaDB")
            local P; P=$(grep -rE "^port[[:space:]]*=" /etc/mysql/ 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "PostgreSQL")
            local P; P=$(grep -rE "^port[[:space:]]*=" /etc/postgresql/ 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "Transmission (web UI)")
            local P; P=$(grep -E '"rpc-port"' /etc/transmission-daemon/settings.json 2>/dev/null | grep -oE '[0-9]+' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "CUPS (network printing)")
            local P; P=$(grep -E "^Listen" /etc/cups/cupsd.conf 2>/dev/null | grep -oE '[0-9]+$' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
        "Cockpit (web admin)")
            local P; P=$(grep -E "^Port" /etc/cockpit/cockpit.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return ;;
    esac
    echo ""
}

# ==========================================================
# PORT RESOLUTION
# ==========================================================

resolve_ports() {
    local LABEL="$1"
    local DEFAULT_PORTS="$2"
    local CONFIG_KEY="$3"

    [[ "$CONFIG_KEY" == "fixed" ]] && { echo "$DEFAULT_PORTS"; return; }

    if $RECONFIGURE && [[ "$CONFIG_KEY" != "auto" && "$CONFIG_KEY" != "ask" ]]; then
        config_delete_key "$CONFIG_KEY"
    fi

    local PROTO
    PROTO=$(echo "$DEFAULT_PORTS" | awk '{print $1}' | cut -d'/' -f2)

    # 1. From ~/.ufw_audit.conf
    if [[ "$CONFIG_KEY" != "auto" && "$CONFIG_KEY" != "ask" ]]; then
        local SAVED
        SAVED=$(config_get "$CONFIG_KEY")
        if [[ -n "$SAVED" ]]; then
            $VERBOSE    && echo -e "    ${DIM}↳ $(t port_from_cfg): $SAVED${RESET}" > /dev/tty
            is_detailed && echo    "    ↳ $(t port_from_cfg): $SAVED" >> "$LOGFILE"
            echo "${SAVED}/${PROTO}"
            return
        fi
    fi

    # 2. Auto-detection
    if [[ "$CONFIG_KEY" != "ask" ]]; then
        local AUTO_PORT
        AUTO_PORT=$(detect_port_auto "$LABEL")
        if [[ -n "$AUTO_PORT" ]]; then
            $VERBOSE    && echo -e "    ${DIM}↳ $(t port_auto): $AUTO_PORT${RESET}" > /dev/tty
            is_detailed && echo    "    ↳ $(t port_auto): $AUTO_PORT" >> "$LOGFILE"
            [[ "$CONFIG_KEY" != "auto" ]] && config_set "$CONFIG_KEY" "$(echo "$AUTO_PORT" | cut -d'/' -f1)"
            echo "$AUTO_PORT"
            return
        fi
    fi

    # 3. Interactive prompt — all output to /dev/tty, only resolved port on stdout
    local DEFAULT_PORT_DISPLAY
    DEFAULT_PORT_DISPLAY=$(echo "$DEFAULT_PORTS" | awk '{print $1}' | cut -d'/' -f1)

    {
        echo
        echo -e "  ${BLUE}${BOLD}┌──────────────────────────────────────────────────────────┐${RESET}"
        printf  "  ${BLUE}${BOLD}│${RESET}  ${BOLD}%-56s${BLUE}${BOLD}│${RESET}\n" "$LABEL"
        printf  "  ${BLUE}${BOLD}│${RESET}  ${DIM}%-56s${RESET}${BLUE}${BOLD}│${RESET}\n" "$(t port_not_detected)"
        echo -e "  ${BLUE}${BOLD}│${RESET}"
        printf  "  ${BLUE}${BOLD}│${RESET}  %-56s${BLUE}${BOLD}│${RESET}\n" "$(t port_question)"
        printf  "  ${BLUE}${BOLD}│${RESET}  ${DIM}%-56s${RESET}${BLUE}${BOLD}│${RESET}\n" "$(t port_default_hint): ${DEFAULT_PORT_DISPLAY}"
        echo -e "  ${BLUE}${BOLD}└──────────────────────────────────────────────────────────┘${RESET}"
        echo -n "  Port: "
    } > /dev/tty

    local USER_INPUT
    read -r USER_INPUT < /dev/tty

    local RESOLVED_PORT
    if [[ -z "$USER_INPUT" ]]; then
        RESOLVED_PORT="$DEFAULT_PORT_DISPLAY"
        echo -e "  ${DIM}↳ $(t port_used_default): $RESOLVED_PORT${RESET}" > /dev/tty
    elif [[ "$USER_INPUT" =~ ^[0-9]+$ ]] && (( USER_INPUT >= 1 && USER_INPUT <= 65535 )); then
        RESOLVED_PORT="$USER_INPUT"
        echo -e "  ${GREEN}↳ $(t port_saved)${RESET}" > /dev/tty
    else
        echo -e "  ${YELLOW}↳ $(t port_invalid): $DEFAULT_PORT_DISPLAY${RESET}" > /dev/tty
        RESOLVED_PORT="$DEFAULT_PORT_DISPLAY"
    fi

    [[ "$CONFIG_KEY" != "auto" && "$CONFIG_KEY" != "ask" ]] && config_set "$CONFIG_KEY" "$RESOLVED_PORT"
    echo "${RESOLVED_PORT}/${PROTO}"
}

# ==========================================================
# PREREQUISITE CHECK
# ==========================================================

check_dependencies() {
    log_section "$(t sec_prereq)"

    if command -v ufw >/dev/null 2>&1; then
        log OK "$(t log_ufw_ok)"
    else
        log ALERT "$(t log_ufw_missing)" "$(t log_ufw_install)"
        echo -e "\n  ${YELLOW}→ sudo apt install ufw${RESET}\n"
        log ERROR "$(t log_ufw_abort)"
        exit 1
    fi

    if command -v ss >/dev/null 2>&1; then
        PORT_TOOL="ss"
        log OK "$(t log_ss_ok)"
    elif command -v netstat >/dev/null 2>&1; then
        PORT_TOOL="netstat"
        log WARN "$(t log_netstat_warn)" "$(t log_netstat_fix)"
    else
        PORT_TOOL=""
        log WARN "$(t log_notool_warn)" "$(t log_netstat_fix)"
    fi
}

# ==========================================================
# FIREWALL STATUS
# ==========================================================

check_firewall_status() {
    log_section "$(t sec_firewall)"
    local UFW_STATUS
    UFW_STATUS=$(ufw status verbose 2>/dev/null)

    if grep -q "Status: active" <<< "$UFW_STATUS"; then
        log OK "$(t log_fw_active)"
    else
        log ALERT "$(t log_fw_inactive)" ""
        log_recommendation "$(t log_fw_enable)"
    fi

    local DEFAULT_IN
    DEFAULT_IN=$(grep "Default:" <<< "$UFW_STATUS" \
        | grep -oE "(deny|reject|allow)" | head -1 || echo "")

    if [[ "$DEFAULT_IN" == "deny" || "$DEFAULT_IN" == "reject" ]]; then
        log OK "$(t log_policy_ok)"
    elif [[ -z "$DEFAULT_IN" ]]; then
        log WARN "$(t log_policy_warn)" ""
    else
        log ALERT "$(t log_policy_alert)" ""
        log_recommendation "$(t log_policy_fix)"
    fi

    if $VERBOSE; then echo; echo "$UFW_STATUS"; echo; fi
    is_detailed && { { echo; echo "[UFW STATUS]"; echo "$UFW_STATUS"; echo; } >> "$LOGFILE"; }
}

# ==========================================================
# UFW RULE ANALYSIS — per port
# ==========================================================

get_ufw_rules_for_port() {
    local PORT="$1"
    ufw status numbered 2>/dev/null | grep -E "(^|\s)${PORT}(/tcp|/udp|$|\s)"
}

# Returns: open_world | open_local | deny | no_rule
analyze_port_exposure() {
    local PORT="$1"
    local RULES
    RULES=$(get_ufw_rules_for_port "$PORT")
    [[ -z "$RULES" ]] && { echo "no_rule"; return; }
    echo "$RULES" | grep -qi "DENY" && { echo "deny"; return; }
    if echo "$RULES" | grep -qi "ALLOW"; then
        if echo "$RULES" | grep -qE "from [0-9]+\.[0-9]|from [0-9a-fA-F]+:"; then
            echo "open_local"
        else
            echo "open_world"
        fi
        return
    fi
    echo "no_rule"
}

# ==========================================================
# SERVICE DETECTION
# ==========================================================

is_package_installed() {
    for PKG in $1; do
        dpkg -l "$PKG" 2>/dev/null | grep -q "^ii" && { echo "$PKG"; return; }
    done
    echo ""
}

# Returns: active_enabled | active_disabled | inactive_enabled | inactive_disabled | unknown
get_service_state() {
    for SVC in $1; do
        if systemctl list-units --all 2>/dev/null | grep -q "$SVC"; then
            local ACTIVE ENABLED
            ACTIVE=$(systemctl is-active  "$SVC" 2>/dev/null || echo "inactive")
            ENABLED=$(systemctl is-enabled "$SVC" 2>/dev/null || echo "disabled")
            if   [[ "$ACTIVE" == "active" && "$ENABLED" == "enabled" ]]; then echo "active_enabled"
            elif [[ "$ACTIVE" == "active"                             ]]; then echo "active_disabled"
            elif [[ "$ENABLED" == "enabled"                           ]]; then echo "inactive_enabled"
            else                                                              echo "inactive_disabled"
            fi
            return
        fi
    done
    echo "unknown"
}

# ==========================================================
# SERVICE AUDIT
# ==========================================================

audit_services() {
    log_section "$(t sec_services)"
    local FOUND_ANY=false

    for ENTRY in "${SERVICES[@]}"; do
        IFS='|' read -r LABEL PACKAGES SVCS DEFAULT_PORTS RISK CONFIG_KEY <<< "$ENTRY"

        local INSTALLED_PKG
        INSTALLED_PKG=$(is_package_installed "$PACKAGES")
        [[ -z "$INSTALLED_PKG" ]] && continue

        FOUND_ANY=true
        echo
        log_service_header "$LABEL"

        local SVC_STATE
        SVC_STATE=$(get_service_state "$SVCS")

        if [[ "$SVC_STATE" == "inactive_disabled" ]]; then
            local EXPL RECO
            EXPL=$(get_risk_explanation "$LABEL" "disabled")
            RECO=$(get_recommendation  "$LABEL" "disabled" "$DEFAULT_PORTS")
            log INFO "$EXPL"
            [[ -n "$RECO" ]] && log_recommendation "$RECO"
            continue
        fi

        case "$SVC_STATE" in
            active_enabled)   log OK   "$(t log_svc_active)" ;;
            active_disabled)  log WARN "$(t log_svc_nodaemon)" "" ;;
            inactive_enabled)
                local EXPL RECO
                EXPL=$(get_risk_explanation "$LABEL" "inactive")
                RECO=$(get_recommendation  "$LABEL" "inactive" "$DEFAULT_PORTS")
                log WARN "$EXPL" ""
                [[ -n "$RECO" ]] && log_recommendation "$RECO"
                continue ;;
            unknown) log INFO "$(t log_svc_unknown)" ;;
        esac

        local RESOLVED_PORTS
        RESOLVED_PORTS=$(resolve_ports "$LABEL" "$DEFAULT_PORTS" "$CONFIG_KEY")

        local DEFAULT_MAIN RESOLVED_MAIN
        DEFAULT_MAIN=$(echo "$DEFAULT_PORTS"   | awk '{print $1}')
        RESOLVED_MAIN=$(echo "$RESOLVED_PORTS" | awk '{print $1}')
        [[ "$RESOLVED_MAIN" != "$DEFAULT_MAIN" ]] && \
            log INFO "$(t log_svc_custom): $RESOLVED_MAIN ($(t log_svc_default): $DEFAULT_MAIN)"

        local WORST_EXPOSURE="no_rule"
        for PORT_PROTO in $RESOLVED_PORTS; do
            local PORT EXPOSURE
            PORT=$(echo "$PORT_PROTO" | cut -d'/' -f1)
            EXPOSURE=$(analyze_port_exposure "$PORT")
            log_detail "Port $PORT_PROTO: exposure = $EXPOSURE"
            case "$EXPOSURE" in
                open_world) WORST_EXPOSURE="open_world" ;;
                open_local) [[ "$WORST_EXPOSURE" != "open_world" ]] && WORST_EXPOSURE="open_local" ;;
                deny)       [[ "$WORST_EXPOSURE" == "no_rule" ]]   && WORST_EXPOSURE="deny" ;;
            esac
        done

        local EXPL RECO
        EXPL=$(get_risk_explanation "$LABEL" "$WORST_EXPOSURE")
        RECO=$(get_recommendation   "$LABEL" "$WORST_EXPOSURE" "$RESOLVED_PORTS")

        case "$WORST_EXPOSURE" in
            open_world)
                case "$RISK" in
                    critical|high) log ALERT "$EXPL" "$RECO" ;;
                    medium)        log WARN  "$EXPL" "$RECO" ;;
                    low)           log INFO  "$EXPL" ;;
                esac
                [[ -n "$RECO" ]] && log_recommendation "$RECO"
                ;;
            open_local)
                case "$RISK" in
                    critical|high) log WARN "$EXPL" "" ;;
                    *)             log OK   "$EXPL" ;;
                esac
                RECO=$(get_recommendation "$LABEL" "open_local" "$RESOLVED_PORTS")
                [[ -n "$RECO" ]] && log_recommendation "$RECO"
                ;;
            deny)    log OK   "$(t log_svc_blocked)" ;;
            no_rule) log INFO "$EXPL" ;;
        esac
    done

    echo
    $FOUND_ANY || log INFO "$(t log_no_services)"
}

# ==========================================================
# LISTENING PORTS (overview)
# ==========================================================

check_listening_ports() {
    log_section "$(t sec_ports)"

    if [[ -z "$PORT_TOOL" ]]; then
        log INFO "$(t log_ports_skip)"
        return
    fi

    local LISTEN=""
    [[ "$PORT_TOOL" == "ss" ]] \
        && LISTEN=$(ss -tulnH 2>/dev/null) \
        || LISTEN=$(netstat -tuln 2>/dev/null | awk 'NR>2')

    if [[ -z "$LISTEN" ]]; then
        log OK "$(t log_no_ports)"
        return
    fi

    local COUNT
    COUNT=$(echo "$LISTEN" | wc -l)
    log INFO "$COUNT $(t log_ports_count)"

    if $VERBOSE; then echo; echo "$LISTEN"; echo; fi
    is_detailed && { { echo; echo "[LISTENING PORTS]"; echo "$LISTEN"; echo; } >> "$LOGFILE"; }
}

# ==========================================================
# FINAL SUMMARY
# ==========================================================

show_summary() {
    (( SCORE < 0 )) && SCORE=0
    local RISK RISK_COLOR RISK_ICON
    if   (( SCORE <= 4 )); then RISK="$(t sum_risk_high)"; RISK_COLOR="$RED";    RISK_ICON="✖"
    elif (( SCORE <= 7 )); then RISK="$(t sum_risk_med)";  RISK_COLOR="$YELLOW"; RISK_ICON="⚠"
    else                        RISK="$(t sum_risk_low)";  RISK_COLOR="$GREEN";  RISK_ICON="✔"
    fi

    local W=58

    echo
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    banner_row "${BOLD}$(t sec_summary)${RESET}"   ""              $W
    echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
    banner_row "${GREEN}${BOLD}$(t sum_ok)${RESET}"    " $OK_COUNT"    $W
    banner_row "${YELLOW}${BOLD}$(t sum_warn)${RESET}" " $WARN_COUNT"  $W
    banner_row "${RED}${BOLD}$(t sum_alert)${RESET}"   " $ALERT_COUNT" $W
    echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
    banner_row "$(t sum_score)" " ${CYAN}${BOLD}${SCORE}/10${RESET}"                    $W
    banner_row "$(t sum_risk)"  " ${RISK_COLOR}${BOLD}${RISK_ICON} ${RISK}${RESET}"     $W
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo

    if   (( ALERT_COUNT > 0 )); then
        echo -e "  ${RED}${BOLD}$(t sum_msg_alert)${RESET}"
        echo -e "  ${RED}$(t sum_msg_alert2)${RESET}"
    elif (( WARN_COUNT  > 0 )); then
        echo -e "  ${YELLOW}${BOLD}$(t sum_msg_warn)${RESET}"
        echo -e "  ${YELLOW}$(t sum_msg_warn2)${RESET}"
    else
        echo -e "  ${GREEN}${BOLD}$(t sum_msg_ok)${RESET}"
        echo -e "  ${GREEN}$(t sum_msg_ok2)${RESET}"
    fi

    echo
    echo -e "  ${DIM}$(t sum_cfg_ports) $CONFIG_FILE${RESET}"
    use_logfile && echo -e "  ${DIM}$(t sum_cfg_report) $LOGFILE${RESET}"
    echo
}

# ==========================================================
# MAIN
# ==========================================================

main() {
    parse_arguments "$@"
    $VERSION_ONLY && { show_version; exit 0; }
    $HELP         && { show_help;    exit 0; }
    check_root

    if $AUDIT_REQUESTED; then
        detect_distro
        show_banner
        config_load

        if $RECONFIGURE; then
            echo -e "  ${YELLOW}[INFO]${RESET} $(t log_reconf)\n"
        elif [[ -f "$CONFIG_FILE" ]] \
          && grep -qv "^#" "$CONFIG_FILE" 2>/dev/null \
          && grep -q "=" "$CONFIG_FILE" 2>/dev/null; then
            echo -e "  ${CYAN}[INFO]${RESET} $(t log_cfg_found) ${CYAN}$CONFIG_FILE${RESET}"
            echo -e "         $(t log_cfg_reset) ${YELLOW}sudo $0 --reconfigure${RESET}\n"
        fi

        init_logfile
        log INFO "$(t log_start)"
        check_dependencies
        check_firewall_status
        audit_services
        check_listening_ports
        show_summary
        finalize_log
    fi
}

main "$@"
