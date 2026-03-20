#!/bin/bash
# ==========================================================
# UFW-audit v0.8
# UFW firewall security audit for Linux
# Target  : Debian/Ubuntu and derivatives
# Audience: regular user, non-system administrator
# ==========================================================

set -uo pipefail
export LC_ALL=C.UTF-8

VERSION="0.8"

OK_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0
SCORE=10

# Structured audit items for categorized summary and --fix mode
# Format: "level|nature|message|command"
# level   : WARN | ALERT
# nature  : action | improvement | structural
# command : UFW command to apply (empty = manual fix required)
AUDIT_ITEMS=()

FIX_MODE=false     # --fix       : show fix section after summary
FIX_YES=false      # --yes       : apply all fixes without confirmation (requires --fix)
NO_COLOR=false     # --no-color  : disable ANSI colour output
FW_INACTIVE=false  # set true when firewall is off — score capped at 3 in show_summary
JSON_MODE=false    # --json      : export summary as JSON (stdout, or file with -d)
JSON_FULL=false    # --json-full : export full audit details as JSON
LOG_DAYS=7         # --log-days=N : number of days to analyse in UFW log (default 7)
declare -A AUDITED_PORTS=()  # ports already audited in audit_services() — skip in port analysis
IMPLICIT_POLICY_SVCS=()      # high/critical services relying on default policy (no explicit UFW rule)

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

# --- Network context & scoring (v0.8) ---
PUBLIC_IP=""           # Public IP if detected via curl
HAS_PUBLIC_IP=false    # true if a public IP is confirmed
NETWORK_CONTEXT=""     # "public" | "local"
SCORE_BREAKDOWN=()     # Array of "reason|deduction" strings

GREEN=""
RED=""
YELLOW=""
CYAN=""
BLUE=""
BOLD=""
DIM=""
RESET=""

setup_colors() {
    if $NO_COLOR; then
        GREEN=""; RED=""; YELLOW=""; CYAN=""
        BLUE=""; BOLD=""; DIM=""; RESET=""
    else
        GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'
        BLUE=$'\e[34m';  BOLD=$'\e[1m'; DIM=$'\e[2m';     RESET=$'\e[0m'
    fi
}

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
            # --- ufw rules audit ---
            sec_rules)          echo "ANALYSE DES RÈGLES UFW" ;;
            dup_none)           echo "Aucune règle UFW en doublon détectée" ;;
            dup_found)          echo "Règle UFW en doublon détectée :" ;;
            dup_fix)            echo "Pour supprimer le doublon (règle numérotée en second) :" ;;
            any_none)           echo "Aucune règle \'allow from any\' sans restriction de port détectée" ;;
            any_found)          echo "Règle autorisant toutes les connexions entrantes sans restriction de port :" ;;
            any_fix)            echo "Pour restreindre ou supprimer cette règle :" ;;
            ipv6_ok)            echo "Configuration IPv6 cohérente avec les règles UFW" ;;
            ipv6_enabled_norules) echo "IPv6 activé dans UFW mais aucune règle (v6) présente" ;;
            ipv6_disabled_rules)  echo "IPv6 désactivé dans UFW mais des règles (v6) sont présentes" ;;
            ipv6_fix)           echo "Vérifiez votre configuration IPv6 : sudo ufw status verbose" ;;
            # --- listen addresses ---
            sec_listen)         echo "ADRESSES D\'ÉCOUTE DES SERVICES" ;;
            listen_exposed)     echo "exposé sur toutes les interfaces (0.0.0.0 / ::)" ;;
            listen_local)       echo "restreint à localhost uniquement" ;;
            # --- uncovered ports ---
            sec_uncovered)      echo "PORTS EN ÉCOUTE SANS RÈGLE UFW" ;;
            uncov_none)         echo "Tous les ports en écoute sur 0.0.0.0 sont couverts par une règle UFW" ;;
            uncov_alert)        echo "Port exposé sur toutes les interfaces sans aucune règle UFW :" ;;
            uncov_info)         echo "Port en écoute uniquement en local, sans règle UFW (pas de risque)" ;;
            uncov_fix)          echo "Pour bloquer ou créer une règle explicite :" ;;
            uncov_sysport)      echo "Port système interne — aucun danger (service OS légitime, pas de règle UFW nécessaire)" ;;
            uncov_ephemeral)    echo "Port éphémère ignoré (>32767) — port temporaire attribué par le noyau, pas un service" ;;
            sec_ports_analysis) echo "ANALYSE DES PORTS EN ÉCOUTE" ;;
            ports_exposed_norule) echo "exposé sur toutes les interfaces, aucune règle UFW" ;;
            ports_exposed_ruled) echo "exposé sur toutes les interfaces, couvert par UFW" ;;
            ports_local_norule) echo "restreint au réseau local, aucune règle UFW explicite" ;;
            ports_local_ruled)  echo "restreint au réseau local, couvert par UFW" ;;
            ports_netbios_warn) echo "NetBIOS/Samba écoute sur toutes les interfaces sans règle UFW explicite — risque faible derrière un NAT, envisagez de restreindre à votre réseau local" ;;
            ports_netbios_fix)  echo "Pour restreindre NetBIOS à votre réseau local (adaptez la plage) :" ;;
            # --- network context & score breakdown ---
            ctx_public)         echo "IP publique détectée" ;;
            ctx_local)          echo "Réseau local uniquement" ;;
            ctx_label)          echo "Contexte réseau     :" ;;
            score_breakdown)    echo "Détail du score" ;;
            score_deduct)       echo "points perdus" ;;
            score_pub_penalty)  echo "(contexte IP publique)" ;;
            score_cap_fw)       echo "score plafonné à 3 — pare-feu désactivé" ;;
            # --- categorized summary ---
            sum_cat_action)       echo "À corriger" ;;
            sum_cat_improvement)  echo "Améliorations possibles" ;;
            sum_cat_structural)   echo "Configuration normale" ;;
            sum_interp_clean)     echo "Votre configuration est saine. Aucune action requise." ;;
            sum_interp_structural) echo "Les avertissements reflètent une configuration normale pour ce type de système. Aucune action immédiate requise." ;;
            sum_interp_mixed)     echo "L'essentiel de votre configuration est normal. Traitez les points ci-dessus marqués \"À corriger\"." ;;
            sum_interp_action)    echo "Des corrections sont nécessaires. Traitez en priorité les points marqués \"À corriger\"." ;;
            # --- fix mode ---
            fix_title)          echo "CORRECTIONS DISPONIBLES" ;;
            fix_none)           echo "Aucune correction automatique disponible." ;;
            fix_applying)       echo "Application des corrections..." ;;
            fix_apply_prompt)   echo "Appliquer cette correction ?" ;;
            fix_applied)        echo "Appliqué" ;;
            fix_skipped)        echo "Ignoré" ;;
            fix_manual)         echo "manuel — appliquez la commande manuellement" ;;
            fix_done)           echo "Corrections terminées. Relancez l'audit pour vérifier." ;;
            fix_none_applied)   echo "Aucune correction appliquée." ;;
            fix_summary_auto)   echo "correction(s) automatique(s) disponible(s)" ;;
            fix_summary_manual) echo "correction(s) manuelle(s)" ;;
            # --- help additions ---
            help_fix)           echo "  --fix               Proposer les corrections après l'audit" ;;
            help_yes)           echo "  --yes               Appliquer toutes les corrections sans confirmation (avec --fix)" ;;
            help_nocolor)       echo "  --no-color          Désactiver les couleurs (utile pour redirection)" ;;
            help_json)          echo "  --json              Exporter le résumé au format JSON" ;;
            help_jsonfull)      echo "  --json-full         Exporter l'audit complet au format JSON" ;;
            # --- docker ---
            sec_docker)         echo "ANALYSE DOCKER" ;;
            docker_missing)     echo "Docker non installé — section ignorée" ;;
            docker_no_daemon)   echo "Docker installé mais le service n'est pas actif" ;;
            docker_bypass_warn) echo "Docker est installé et actif. Par défaut, Docker modifie directement iptables et contourne les règles UFW — les ports exposés via Docker (-p) sont accessibles même si UFW les bloque." ;;
            docker_bypass_fix)  echo "Pour désactiver le bypass iptables de Docker, ajoutez dans /etc/docker/daemon.json :\n  {\"iptables\": false}\npuis redémarrez Docker :\n  sudo systemctl restart docker\nAttention : ceci désactive la gestion réseau automatique de Docker." ;;
            docker_iptables_ok) echo "Docker est configuré avec iptables désactivé (daemon.json). Les règles UFW s'appliquent normalement." ;;
            docker_ports_title) echo "Ports exposés par Docker :" ;;
            docker_port_warn)   echo "Port Docker exposé sans règle UFW DENY explicite — potentiellement accessible malgré UFW" ;;
            docker_port_ok)     echo "Port Docker couvert par une règle UFW DENY" ;;
            docker_no_ports)    echo "Aucun container Docker en cours d'exécution avec ports exposés" ;;
            # --- json ---
            json_written)       echo "Export JSON :" ;;
            sum_implicit_note)  echo "Note : service(s) à risque élevé s'appuient sur la politique par défaut UFW plutôt que des règles explicites. C'est correct si la politique est deny, mais une règle explicite est plus robuste." ;;
            sum_implicit_svcs)  echo "Service(s) concerné(s) :" ;;
            # --- risk context ---
            risk_ctx_title)     echo "Contexte de risque" ;;
            risk_ctx_exposure)  echo "Exposition" ;;
            risk_ctx_threat)    echo "Menace potentielle" ;;
            risk_ctx_level)     echo "Niveau de risque" ;;
            risk_log_section)   echo "CONTEXTE DE RISQUE — SERVICES DÉTECTÉS" ;;
            # --- log analysis ---
            sec_logs)           echo "ANALYSE DES LOGS UFW" ;;
            log_no_logfile)     echo "Fichier de log UFW introuvable (/var/log/ufw.log) — journalisation désactivée ?" ;;
            log_empty)          echo "Aucun événement UFW BLOCK dans les logs sur la période analysée" ;;
            log_period)         echo "Période analysée" ;;
            log_days_unit)      echo "jour(s)" ;;
            log_available)      echo "jours de logs disponibles" ;;
            log_total_blocks)   echo "tentative(s) bloquée(s) détectée(s)" ;;
            log_top_ips)        echo "Top IPs sources" ;;
            log_top_ports)      echo "Top ports ciblés" ;;
            log_brute_title)    echo "Bruteforce détecté" ;;
            log_brute_none)     echo "Aucun bruteforce détecté sur la période" ;;
            log_brute_found)    echo "tentative(s) depuis" ;;
            log_brute_on)       echo "sur" ;;
            log_svc_hits)       echo "Tentatives sur services installés" ;;
            log_svc_hits_none)  echo "Aucune tentative sur les ports des services installés" ;;
            log_attempts)       echo "tentative(s)" ;;
            log_help_days)      echo "  --log-days=N        Analyser les N derniers jours de logs UFW (défaut : 7)" ;;
            geo_no_whois)       echo "whois non disponible — installez-le pour enrichir l'analyse avec la géolocalisation des IPs (sudo apt install whois)" ;;
            # --- ddns / external exposure ---
            sec_ddns)           echo "EXPOSITION EXTERNE (DDNS)" ;;
            ddns_none)          echo "Aucun client DDNS détecté — pas d'exposition externe via DDNS identifiée" ;;
            ddns_found)         echo "Client DDNS actif détecté" ;;
            ddns_domain)        echo "Domaine configuré" ;;
            ddns_no_domain)     echo "Domaine non extrait (vérifiez la configuration manuellement)" ;;
            ddns_no_ports)      echo "Aucun port UFW ouvert sans restriction de source détecté" ;;
            ddns_ports_title)   echo "Ports potentiellement exposés publiquement" ;;
            ddns_warn)          echo "DDNS actif avec port(s) ouverts sans restriction — vérifiez que l'exposition est intentionnelle" ;;
            ddns_high_warn)     echo "Service à risque élevé potentiellement exposé sur internet via DDNS" ;;
            ddns_advice)        echo "Si cette exposition est intentionnelle : maintenez les services à jour, activez l'authentification, et envisagez Fail2ban." ;;
            ddns_inactive)      echo "Client DDNS installé mais service inactif" ;;
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
            # --- ufw rules audit ---
            sec_rules)          echo "UFW RULES ANALYSIS" ;;
            dup_none)           echo "No duplicate UFW rules detected" ;;
            dup_found)          echo "Duplicate UFW rule detected:" ;;
            dup_fix)            echo "To remove the duplicate (the second numbered rule):" ;;
            any_none)           echo "No \'allow from any\' rule without port restriction detected" ;;
            any_found)          echo "Rule allowing all incoming connections without port restriction:" ;;
            any_fix)            echo "To restrict or remove this rule:" ;;
            ipv6_ok)            echo "IPv6 configuration is consistent with UFW rules" ;;
            ipv6_enabled_norules) echo "IPv6 enabled in UFW but no (v6) rules present" ;;
            ipv6_disabled_rules)  echo "IPv6 disabled in UFW but (v6) rules are present" ;;
            ipv6_fix)           echo "Check your IPv6 configuration: sudo ufw status verbose" ;;
            # --- listen addresses ---
            sec_listen)         echo "SERVICE LISTEN ADDRESSES" ;;
            listen_exposed)     echo "exposed on all interfaces (0.0.0.0 / ::)" ;;
            listen_local)       echo "restricted to localhost only" ;;
            # --- uncovered ports ---
            sec_uncovered)      echo "LISTENING PORTS WITHOUT UFW RULE" ;;
            uncov_none)         echo "All ports listening on 0.0.0.0 are covered by a UFW rule" ;;
            uncov_alert)        echo "Port exposed on all interfaces with no UFW rule:" ;;
            uncov_info)         echo "Port listening on localhost only, no UFW rule (no immediate risk):" ;;
            uncov_fix)          echo "To block or create an explicit rule:" ;;
            uncov_sysport)      echo "Internal system port — no danger (legitimate OS service, no UFW rule needed)" ;;
            uncov_ephemeral)    echo "Ephemeral port skipped (>32767) — temporary port assigned by the kernel, not a service" ;;
            sec_ports_analysis) echo "LISTENING PORTS ANALYSIS" ;;
            ports_exposed_norule) echo "exposed on all interfaces, no UFW rule" ;;
            ports_exposed_ruled) echo "exposed on all interfaces, covered by UFW" ;;
            ports_local_norule) echo "local network only, no explicit UFW rule" ;;
            ports_local_ruled)  echo "local network only, covered by UFW" ;;
            ports_netbios_warn) echo "NetBIOS/Samba listening on all interfaces with no explicit UFW rule — low risk behind NAT, consider restricting to your local network" ;;
            ports_netbios_fix)  echo "To restrict NetBIOS to your local network (adjust the range):" ;;
            # --- network context & score breakdown ---
            ctx_public)         echo "Public IP detected" ;;
            ctx_local)          echo "Local network only" ;;
            ctx_label)          echo "Network context     :" ;;
            score_breakdown)    echo "Score breakdown" ;;
            score_deduct)       echo "points lost" ;;
            score_pub_penalty)  echo "(public IP context)" ;;
            score_cap_fw)       echo "score capped at 3 — firewall disabled" ;;
            # --- categorized summary ---
            sum_cat_action)       echo "Action required" ;;
            sum_cat_improvement)  echo "Possible improvements" ;;
            sum_cat_structural)   echo "Normal configuration" ;;
            sum_interp_clean)     echo "Your configuration is healthy. No action required." ;;
            sum_interp_structural) echo "Warnings reflect normal configuration for this type of system. No immediate action required." ;;
            sum_interp_mixed)     echo "Most of your configuration is normal. Address the items marked \"Action required\" above." ;;
            sum_interp_action)    echo "Corrections are needed. Prioritize items marked \"Action required\"." ;;
            # --- fix mode ---
            fix_title)          echo "AVAILABLE FIXES" ;;
            fix_none)           echo "No automatic fix available." ;;
            fix_applying)       echo "Applying fixes..." ;;
            fix_apply_prompt)   echo "Apply this fix?" ;;
            fix_applied)        echo "Applied" ;;
            fix_skipped)        echo "Skipped" ;;
            fix_manual)         echo "manual — apply the command manually" ;;
            fix_done)           echo "Fixes complete. Re-run the audit to verify." ;;
            fix_none_applied)   echo "No fixes applied." ;;
            fix_summary_auto)   echo "automatic fix(es) available" ;;
            fix_summary_manual) echo "manual fix(es)" ;;
            # --- help additions ---
            help_fix)           echo "  --fix               Propose fixes after the audit" ;;
            help_yes)           echo "  --yes               Apply all fixes without confirmation (requires --fix)" ;;
            help_nocolor)       echo "  --no-color          Disable colours (useful for redirected output)" ;;
            help_json)          echo "  --json              Export summary as JSON" ;;
            help_jsonfull)      echo "  --json-full         Export full audit details as JSON" ;;
            # --- docker ---
            sec_docker)         echo "DOCKER ANALYSIS" ;;
            docker_missing)     echo "Docker not installed — section skipped" ;;
            docker_no_daemon)   echo "Docker installed but service is not active" ;;
            docker_bypass_warn) echo "Docker is installed and active. By default, Docker modifies iptables directly and bypasses UFW rules — ports exposed via Docker (-p) are reachable even if UFW blocks them." ;;
            docker_bypass_fix)  echo "To disable Docker iptables bypass, add to /etc/docker/daemon.json:\n  {\"iptables\": false}\nthen restart Docker:\n  sudo systemctl restart docker\nNote: this disables Docker's automatic network management." ;;
            docker_iptables_ok) echo "Docker is configured with iptables disabled (daemon.json). UFW rules apply normally." ;;
            docker_ports_title) echo "Ports exposed by Docker:" ;;
            docker_port_warn)   echo "Docker port exposed without explicit UFW DENY rule — potentially reachable despite UFW" ;;
            docker_port_ok)     echo "Docker port covered by a UFW DENY rule" ;;
            docker_no_ports)    echo "No running Docker containers with exposed ports" ;;
            # --- json ---
            json_written)       echo "JSON export:" ;;
            sum_implicit_note)  echo "Note: high-risk service(s) rely on UFW's default policy rather than explicit rules. This is correct if the policy is deny, but an explicit rule is more robust." ;;
            sum_implicit_svcs)  echo "Affected service(s):" ;;
            # --- risk context ---
            risk_ctx_title)     echo "Risk context" ;;
            risk_ctx_exposure)  echo "Exposure" ;;
            risk_ctx_threat)    echo "Potential threat" ;;
            risk_ctx_level)     echo "Risk level" ;;
            risk_log_section)   echo "RISK CONTEXT — DETECTED SERVICES" ;;
            # --- log analysis ---
            sec_logs)           echo "UFW LOG ANALYSIS" ;;
            log_no_logfile)     echo "UFW log file not found (/var/log/ufw.log) — logging disabled?" ;;
            log_empty)          echo "No UFW BLOCK events found in logs for the analysed period" ;;
            log_period)         echo "Period analysed" ;;
            log_days_unit)      echo "day(s)" ;;
            log_available)      echo "days of logs available" ;;
            log_total_blocks)   echo "blocked attempt(s) detected" ;;
            log_top_ips)        echo "Top source IPs" ;;
            log_top_ports)      echo "Top targeted ports" ;;
            log_brute_title)    echo "Bruteforce detected" ;;
            log_brute_none)     echo "No bruteforce detected in the analysed period" ;;
            log_brute_found)    echo "attempt(s) from" ;;
            log_brute_on)       echo "on" ;;
            log_svc_hits)       echo "Attempts on installed service ports" ;;
            log_svc_hits_none)  echo "No attempts on installed service ports" ;;
            log_attempts)       echo "attempt(s)" ;;
            log_help_days)      echo "  --log-days=N        Analyse the last N days of UFW logs (default: 7)" ;;
            geo_no_whois)       echo "whois not available — install it to enrich analysis with IP geolocation (sudo apt install whois)" ;;
            # --- ddns / external exposure ---
            sec_ddns)           echo "EXTERNAL EXPOSURE (DDNS)" ;;
            ddns_none)          echo "No DDNS client detected — no DDNS-based external exposure identified" ;;
            ddns_found)         echo "Active DDNS client detected" ;;
            ddns_domain)        echo "Configured domain" ;;
            ddns_no_domain)     echo "Domain not extracted (check configuration manually)" ;;
            ddns_no_ports)      echo "No UFW port open without source restriction detected" ;;
            ddns_ports_title)   echo "Ports potentially exposed to the internet" ;;
            ddns_warn)          echo "DDNS active with open port(s) without source restriction — verify exposure is intentional" ;;
            ddns_high_warn)     echo "High-risk service potentially internet-exposed via DDNS" ;;
            ddns_advice)        echo "If this exposure is intentional: keep services up to date, enable authentication, and consider Fail2ban." ;;
            ddns_inactive)      echo "DDNS client installed but service is inactive" ;;
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
    SYS_UFW="$(ufw version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "N/A")"

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
    "SSH Server|openssh-server|ssh|22/tcp|critical|ssh_port"
    "VNC Server|x11vnc tigervnc-standalone-server|x11vnc vncserver|5900/tcp|critical|ask"
    "Samba (Windows file sharing)|samba|smbd|445/tcp 139/tcp|critical|fixed"
    "FTP Server|vsftpd proftpd|vsftpd proftpd|21/tcp|critical|auto"
    "Apache Web Server|apache2|apache2|80/tcp 443/tcp|medium|ask"
    "Nginx Web Server|nginx|nginx|80/tcp 443/tcp|medium|ask"
    "MySQL / MariaDB|mysql-server mariadb-server|mysql mariadb|3306/tcp|critical|auto"
    "PostgreSQL|postgresql|postgresql|5432/tcp|critical|auto"
    "Transmission (web UI)|transmission-daemon|transmission-daemon|9091/tcp|medium|auto"
    "qBittorrent (web UI)|qbittorrent-nox|qbittorrent-nox|8080/tcp|medium|ask"
    "Avahi (local network discovery)|avahi-daemon|avahi-daemon|5353/udp|low|fixed"
    "CUPS (network printing)|cups|cups|631/tcp|low|auto"
    "Cockpit (web admin)|cockpit|cockpit|9090/tcp|high|auto"
    "WireGuard VPN|wireguard|wg-quick@|51820/udp|high|fixed"
    "Redis|redis-server|redis|6379/tcp|critical|fixed"
    "Jellyfin|jellyfin|jellyfin|8096/tcp|medium|fixed"
    "Plex Media Server|plexmediaserver|plexmediaserver|32400/tcp|medium|fixed"
    "Home Assistant|homeassistant python3-homeassistant|home-assistant homeassistant|8123/tcp|high|ask"
    "Nextcloud|nextcloud|nextcloud apache2 nginx|80/tcp 443/tcp|high|ask"
    "Gitea|gitea forgejo|gitea forgejo|3000/tcp|medium|auto"
    "Mosquitto (MQTT)|mosquitto|mosquitto|1883/tcp 8883/tcp|high|fixed"
    "Syncthing|syncthing|syncthing|8384/tcp 22000/tcp|medium|auto"
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
            "WireGuard VPN")
                case "$SITUATION" in
                    open_world) echo "WireGuard est exposé sur internet — c'est son fonctionnement normal en tant que VPN. Assurez-vous que la règle UFW autorise uniquement le port WireGuard et rien d'autre." ;;
                    open_local) echo "WireGuard est restreint au réseau local. Configuration correcte si vous ne l'utilisez qu'en local." ;;
                    deny)       echo "WireGuard est bloqué par UFW. Si vous utilisez le VPN depuis internet, cette règle l'empêchera de fonctionner." ;;
                    no_rule)    echo "WireGuard est actif mais aucune règle UFW ne couvre son port. Si la politique par défaut est deny, les clients VPN externes ne pourront pas se connecter." ;;
                    inactive)   echo "WireGuard est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "WireGuard est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Redis")
                case "$SITUATION" in
                    open_world) echo "Redis est accessible depuis internet. C'est un risque critique — Redis n'a pas d'authentification forte par défaut et ne devrait jamais être exposé publiquement." ;;
                    open_local) echo "Redis est restreint au réseau local. Idéalement, il ne devrait écouter que sur localhost." ;;
                    deny)       echo "L'accès à Redis est bloqué par UFW. Bonne configuration." ;;
                    no_rule)    echo "Redis est actif. Par défaut il écoute sur 127.0.0.1, ce qui est correct. Vérifiez que la configuration bind n'a pas été modifiée." ;;
                    inactive)   echo "Redis est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Redis est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Jellyfin")
                case "$SITUATION" in
                    open_world) echo "Jellyfin (media server) est accessible depuis internet. Assurez-vous que l'authentification est activée et que le service est à jour." ;;
                    open_local) echo "Jellyfin est restreint au réseau local. Configuration normale pour un usage domestique." ;;
                    deny)       echo "L'accès à Jellyfin est bloqué par UFW." ;;
                    no_rule)    echo "Jellyfin est actif. Vérifiez qu'il n'est pas accessible depuis internet si ce n'est pas intentionnel." ;;
                    inactive)   echo "Jellyfin est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Jellyfin est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Plex Media Server")
                case "$SITUATION" in
                    open_world) echo "Plex est accessible depuis internet. C'est souvent intentionnel pour le streaming distant — vérifiez que votre compte Plex est sécurisé et que le service est à jour." ;;
                    open_local) echo "Plex est restreint au réseau local. Configuration normale pour un usage domestique." ;;
                    deny)       echo "L'accès à Plex est bloqué par UFW." ;;
                    no_rule)    echo "Plex est actif. Vérifiez son niveau d'exposition selon votre usage." ;;
                    inactive)   echo "Plex est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Plex est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Home Assistant")
                case "$SITUATION" in
                    open_world) echo "Home Assistant est accessible depuis internet. Il contrôle vos équipements domotiques — assurez-vous que l'authentification à deux facteurs est activée et que le service est à jour." ;;
                    open_local) echo "Home Assistant est restreint au réseau local. Configuration normale pour un usage domestique." ;;
                    deny)       echo "L'accès à Home Assistant est bloqué par UFW." ;;
                    no_rule)    echo "Home Assistant est actif. Vérifiez qu'il n'est pas accessible depuis internet si ce n'est pas intentionnel." ;;
                    inactive)   echo "Home Assistant est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Home Assistant est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Nextcloud")
                case "$SITUATION" in
                    open_world) echo "Nextcloud est accessible depuis internet. Vérifiez que l'authentification à deux facteurs est activée, que le service est à jour et que HTTPS est configuré." ;;
                    open_local) echo "Nextcloud est restreint au réseau local. Configuration correcte pour un usage domestique." ;;
                    deny)       echo "L'accès à Nextcloud est bloqué par UFW." ;;
                    no_rule)    echo "Nextcloud est actif. Vérifiez son niveau d'exposition selon votre usage." ;;
                    inactive)   echo "Nextcloud est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Nextcloud est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Gitea")
                case "$SITUATION" in
                    open_world) echo "Gitea (forge Git) est accessible depuis internet. Désactivez les inscriptions publiques si non nécessaires et maintenez le service à jour." ;;
                    open_local) echo "Gitea est restreint au réseau local. Configuration adaptée pour un usage personnel." ;;
                    deny)       echo "L'accès à Gitea est bloqué par UFW." ;;
                    no_rule)    echo "Gitea est actif. Vérifiez qu'il n'est pas accessible depuis internet si ce n'est pas intentionnel." ;;
                    inactive)   echo "Gitea est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Gitea est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Mosquitto (MQTT)")
                case "$SITUATION" in
                    open_world) echo "Mosquitto (broker MQTT) est accessible depuis internet. MQTT sans authentification est un risque critique — n'importe qui peut publier ou s'abonner à vos topics domotiques." ;;
                    open_local) echo "Mosquitto est restreint au réseau local. Configuration normale pour la domotique locale." ;;
                    deny)       echo "L'accès à Mosquitto est bloqué par UFW." ;;
                    no_rule)    echo "Mosquitto est actif. Par défaut il écoute sur toutes les interfaces — vérifiez qu'il n'est pas accessible depuis internet." ;;
                    inactive)   echo "Mosquitto est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Mosquitto est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
                esac ;;
            "Syncthing")
                case "$SITUATION" in
                    open_world) echo "Syncthing est accessible depuis internet. L'interface web (8384) ne devrait pas être exposée publiquement — restreignez-la au réseau local." ;;
                    open_local) echo "Syncthing est restreint au réseau local. Configuration correcte pour la synchronisation domestique." ;;
                    deny)       echo "L'accès à Syncthing est bloqué par UFW." ;;
                    no_rule)    echo "Syncthing est actif. L'interface web écoute sur localhost par défaut, ce qui est correct." ;;
                    inactive)   echo "Syncthing est installé et actif, mais ne redémarrera pas automatiquement." ;;
                    disabled)   echo "Syncthing est installé mais arrêté et désactivé. Pas de risque immédiat." ;;
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
            "WireGuard VPN")
                case "$SITUATION" in
                    open_world) echo "WireGuard is exposed to the internet — this is its normal behaviour as a VPN. Make sure the UFW rule only allows the WireGuard port and nothing else." ;;
                    open_local) echo "WireGuard is restricted to the local network. Correct if you only use it locally." ;;
                    deny)       echo "WireGuard is blocked by UFW. If you use the VPN from the internet, this rule will prevent it from working." ;;
                    no_rule)    echo "WireGuard is active but no UFW rule covers its port. If the default policy is deny, external VPN clients will not be able to connect." ;;
                    inactive)   echo "WireGuard is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "WireGuard is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Redis")
                case "$SITUATION" in
                    open_world) echo "Redis is reachable from the internet. This is a critical risk — Redis has no strong authentication by default and should never be publicly exposed." ;;
                    open_local) echo "Redis is restricted to the local network. Ideally it should only listen on localhost." ;;
                    deny)       echo "Redis access is blocked by UFW. Good configuration." ;;
                    no_rule)    echo "Redis is active. By default it listens on 127.0.0.1, which is correct. Check the bind configuration has not been changed." ;;
                    inactive)   echo "Redis is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Redis is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Jellyfin")
                case "$SITUATION" in
                    open_world) echo "Jellyfin (media server) is reachable from the internet. Make sure authentication is enabled and the service is up to date." ;;
                    open_local) echo "Jellyfin is restricted to the local network. Normal setup for home use." ;;
                    deny)       echo "Jellyfin access is blocked by UFW." ;;
                    no_rule)    echo "Jellyfin is active. Check that it is not reachable from the internet if unintentional." ;;
                    inactive)   echo "Jellyfin is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Jellyfin is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Plex Media Server")
                case "$SITUATION" in
                    open_world) echo "Plex is reachable from the internet. This is often intentional for remote streaming — make sure your Plex account is secured and the service is up to date." ;;
                    open_local) echo "Plex is restricted to the local network. Normal setup for home use." ;;
                    deny)       echo "Plex access is blocked by UFW." ;;
                    no_rule)    echo "Plex is active. Check its exposure level based on your intended use." ;;
                    inactive)   echo "Plex is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Plex is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Home Assistant")
                case "$SITUATION" in
                    open_world) echo "Home Assistant is reachable from the internet. It controls your home automation devices — make sure two-factor authentication is enabled and the service is up to date." ;;
                    open_local) echo "Home Assistant is restricted to the local network. Normal setup for home use." ;;
                    deny)       echo "Home Assistant access is blocked by UFW." ;;
                    no_rule)    echo "Home Assistant is active. Check that it is not reachable from the internet if unintentional." ;;
                    inactive)   echo "Home Assistant is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Home Assistant is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Nextcloud")
                case "$SITUATION" in
                    open_world) echo "Nextcloud is reachable from the internet. Make sure two-factor authentication is enabled, the service is up to date, and HTTPS is configured." ;;
                    open_local) echo "Nextcloud is restricted to the local network. Suitable for home use." ;;
                    deny)       echo "Nextcloud access is blocked by UFW." ;;
                    no_rule)    echo "Nextcloud is active. Check its exposure level based on your intended use." ;;
                    inactive)   echo "Nextcloud is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Nextcloud is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Gitea")
                case "$SITUATION" in
                    open_world) echo "Gitea (Git forge) is reachable from the internet. Disable public registration if not needed and keep the service up to date." ;;
                    open_local) echo "Gitea is restricted to the local network. Suitable for personal use." ;;
                    deny)       echo "Gitea access is blocked by UFW." ;;
                    no_rule)    echo "Gitea is active. Check that it is not reachable from the internet if unintentional." ;;
                    inactive)   echo "Gitea is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Gitea is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Mosquitto (MQTT)")
                case "$SITUATION" in
                    open_world) echo "Mosquitto (MQTT broker) is reachable from the internet. MQTT without authentication is a critical risk — anyone can publish or subscribe to your home automation topics." ;;
                    open_local) echo "Mosquitto is restricted to the local network. Normal setup for local home automation." ;;
                    deny)       echo "Mosquitto access is blocked by UFW." ;;
                    no_rule)    echo "Mosquitto is active. By default it listens on all interfaces — check that it is not reachable from the internet." ;;
                    inactive)   echo "Mosquitto is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Mosquitto is installed but stopped and disabled. No immediate risk." ;;
                esac ;;
            "Syncthing")
                case "$SITUATION" in
                    open_world) echo "Syncthing is reachable from the internet. The web UI (8384) should not be publicly exposed — restrict it to the local network." ;;
                    open_local) echo "Syncthing is restricted to the local network. Suitable for home synchronisation." ;;
                    deny)       echo "Syncthing access is blocked by UFW." ;;
                    no_rule)    echo "Syncthing is active. The web UI listens on localhost by default, which is correct." ;;
                    inactive)   echo "Syncthing is installed and currently active, but will not restart automatically." ;;
                    disabled)   echo "Syncthing is installed but stopped and disabled. No immediate risk." ;;
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
                    "MySQL / MariaDB"|"PostgreSQL"|"Redis")
                        echo "Block internet access — a database must not be publicly exposed :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw deny $MAIN_PORT/tcp" ;;
                    "Transmission (web UI)"|"qBittorrent (web UI)"|"Cockpit (web admin)"|"Apache Web Server"|"Nginx Web Server"|"Jellyfin"|"Plex Media Server"|"Home Assistant"|"Nextcloud"|"Gitea"|"Syncthing")
                        echo "To restrict access to your local network (replace 192.168.1.0/24 with your network range) :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                    "Mosquitto (MQTT)")
                        echo "Restrict MQTT to your local network :\n  sudo ufw delete allow $MAIN_PORT/tcp\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT\nAlso enable authentication in /etc/mosquitto/mosquitto.conf" ;;
                    "WireGuard VPN")
                        echo "WireGuard is designed to be internet-facing. Make sure only the VPN port is open :\n  sudo ufw allow $MAIN_PORT/udp\n  sudo ufw deny $MAIN_PORT/tcp" ;;
                    "CUPS (network printing)"|"Avahi (local network discovery)")
                        echo "To block internet access :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw deny $MAIN_PORT" ;;
                    *)
                        echo "To restrict this service to your local network (replace 192.168.1.0/24) :\n  sudo ufw delete allow $MAIN_PORT\n  sudo ufw allow from 192.168.1.0/24 to any port $MAIN_PORT" ;;
                esac ;;
            open_local)
                case "$LABEL" in
                    "MySQL / MariaDB"|"PostgreSQL"|"Redis")
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
# RISK CONTEXT — two-axis classification per service
# Returns exposure and threat strings for display in audit
# and detailed report. Only called for high/critical services.
# ==========================================================

get_risk_context() {
    local LABEL="$1"
    local AXIS="$2"   # "exposure" | "threat" | "level"

    if $LANG_FR; then
        case "$LABEL" in
            "SSH Server")
                case "$AXIS" in
                    exposure) echo "Port très ciblé par les scans automatisés et attaques bruteforce — exposé sur internet par défaut" ;;
                    threat)   echo "Accès shell complet à la machine, escalade de privilèges, pivot vers d'autres systèmes du réseau" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "VNC Server")
                case "$AXIS" in
                    exposure) echo "Protocole souvent sans chiffrement natif, authentification faible ou absente sur les anciennes versions" ;;
                    threat)   echo "Contrôle visuel et interactif complet du bureau — équivalent à un accès physique à la machine" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "Samba (Windows file sharing)")
                case "$AXIS" in
                    exposure) echo "Conçu exclusivement pour les réseaux locaux — dangereux par nature si exposé sur internet" ;;
                    threat)   echo "Accès et chiffrement de fichiers (ransomware), mouvement latéral (EternalBlue/WannaCry), exfiltration de données" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "FTP Server")
                case "$AXIS" in
                    exposure) echo "Protocole non chiffré — identifiants et données transmis en clair sur le réseau" ;;
                    threat)   echo "Vol de credentials, accès et exfiltration de fichiers, potentiel pivot si les credentials sont réutilisés" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "MySQL / MariaDB")
                case "$AXIS" in
                    exposure) echo "Authentification par mot de passe, nombreuses CVE historiques d'accès non authentifié" ;;
                    threat)   echo "Exfiltration complète de la base de données, destruction de données, accès applicatif si credentials partagés" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "PostgreSQL")
                case "$AXIS" in
                    exposure) echo "Authentification par mot de passe ou méthodes configurables — exposition directe rarement intentionnelle" ;;
                    threat)   echo "Exfiltration complète de la base de données, exécution de commandes système via extensions (pg_execute_server_program)" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "Redis")
                case "$AXIS" in
                    exposure) echo "Pas d'authentification par défaut historiquement, très fréquemment mal configuré et exposé" ;;
                    threat)   echo "Lecture/écriture de toutes les données, exécution de code à distance (RCE) via configuration — vecteur d'attaque documenté et exploité activement" ;;
                    level)    echo "CRITIQUE" ;;
                esac ;;
            "Cockpit (web admin)")
                case "$AXIS" in
                    exposure) echo "Interface web d'administration système — authentification requise mais surface d'attaque significative" ;;
                    threat)   echo "Administration complète du système si compromis : gestion services, utilisateurs, réseau, terminal root" ;;
                    level)    echo "ÉLEVÉ" ;;
                esac ;;
            "WireGuard VPN")
                case "$AXIS" in
                    exposure) echo "Exposition intentionnelle sur internet pour fonction VPN — surface d'attaque limitée par conception" ;;
                    threat)   echo "Accès complet au réseau interne si tunnel compromis ou clés privées volées" ;;
                    level)    echo "ÉLEVÉ" ;;
                esac ;;
            "Home Assistant")
                case "$AXIS" in
                    exposure) echo "Interface web contrôlant des équipements physiques — authentification intégrée mais souvent exposée pour accès distant" ;;
                    threat)   echo "Contrôle d'équipements physiques (serrures, alarmes, prises), accès réseau local via automations, exfiltration de données domotiques" ;;
                    level)    echo "ÉLEVÉ" ;;
                esac ;;
            "Nextcloud")
                case "$AXIS" in
                    exposure) echo "Serveur de fichiers personnel exposé sur internet — authentification requise mais surface d'attaque importante selon les apps installées" ;;
                    threat)   echo "Accès à tous les fichiers personnels, contacts et calendriers stockés, potentiel pivot si credentials compromis" ;;
                    level)    echo "ÉLEVÉ" ;;
                esac ;;
            "Mosquitto (MQTT)")
                case "$AXIS" in
                    exposure) echo "Broker MQTT souvent sans authentification par défaut, écoute sur toutes les interfaces" ;;
                    threat)   echo "Publication/abonnement non autorisé aux topics domotiques, contrôle d'équipements, interception des données capteurs" ;;
                    level)    echo "ÉLEVÉ" ;;
                esac ;;
        esac
    else
        case "$LABEL" in
            "SSH Server")
                case "$AXIS" in
                    exposure) echo "Heavily targeted by automated scanners and brute-force attacks — internet-exposed by default" ;;
                    threat)   echo "Full shell access to the machine, privilege escalation, lateral movement to other network systems" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "VNC Server")
                case "$AXIS" in
                    exposure) echo "Often lacks native encryption; weak or absent authentication on older versions" ;;
                    threat)   echo "Full visual and interactive desktop control — equivalent to physical access to the machine" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "Samba (Windows file sharing)")
                case "$AXIS" in
                    exposure) echo "Designed exclusively for local networks — inherently dangerous if exposed to the internet" ;;
                    threat)   echo "File access and encryption (ransomware), lateral movement (EternalBlue/WannaCry), data exfiltration" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "FTP Server")
                case "$AXIS" in
                    exposure) echo "Unencrypted protocol — credentials and data transmitted in plain text over the network" ;;
                    threat)   echo "Credential theft, file access and exfiltration, potential pivot if credentials are reused" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "MySQL / MariaDB")
                case "$AXIS" in
                    exposure) echo "Password-based authentication, history of unauthenticated access CVEs" ;;
                    threat)   echo "Full database exfiltration, data destruction, application-level access if credentials are shared" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "PostgreSQL")
                case "$AXIS" in
                    exposure) echo "Password or configurable authentication — direct exposure is rarely intentional" ;;
                    threat)   echo "Full database exfiltration, system command execution via extensions (pg_execute_server_program)" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "Redis")
                case "$AXIS" in
                    exposure) echo "No authentication by default historically, very frequently misconfigured and exposed" ;;
                    threat)   echo "Read/write access to all data, remote code execution (RCE) via configuration — documented and actively exploited attack vector" ;;
                    level)    echo "CRITICAL" ;;
                esac ;;
            "Cockpit (web admin)")
                case "$AXIS" in
                    exposure) echo "Web-based system administration interface — authentication required but significant attack surface" ;;
                    threat)   echo "Full system administration if compromised: service management, users, network, root terminal" ;;
                    level)    echo "HIGH" ;;
                esac ;;
            "WireGuard VPN")
                case "$AXIS" in
                    exposure) echo "Intentionally internet-facing for VPN function — limited attack surface by design" ;;
                    threat)   echo "Full internal network access if tunnel is compromised or private keys are stolen" ;;
                    level)    echo "HIGH" ;;
                esac ;;
            "Home Assistant")
                case "$AXIS" in
                    exposure) echo "Web interface controlling physical devices — built-in authentication but often exposed for remote access" ;;
                    threat)   echo "Control of physical devices (locks, alarms, switches), local network access via automations, home automation data exfiltration" ;;
                    level)    echo "HIGH" ;;
                esac ;;
            "Nextcloud")
                case "$AXIS" in
                    exposure) echo "Personal file server exposed to the internet — authentication required but significant attack surface depending on installed apps" ;;
                    threat)   echo "Access to all personal files, contacts and calendars stored, potential pivot if credentials are compromised" ;;
                    level)    echo "HIGH" ;;
                esac ;;
            "Mosquitto (MQTT)")
                case "$AXIS" in
                    exposure) echo "MQTT broker often without authentication by default, listens on all interfaces" ;;
                    threat)   echo "Unauthorised publish/subscribe to home automation topics, device control, sensor data interception" ;;
                    level)    echo "HIGH" ;;
                esac ;;
        esac
    fi
}

# Helper: display risk context block for a service (terminal + log)
log_risk_context() {
    local LABEL="$1"
    local EXPOSURE THREAT LEVEL
    EXPOSURE=$(get_risk_context "$LABEL" "exposure")
    THREAT=$(get_risk_context  "$LABEL" "threat")
    LEVEL=$(get_risk_context   "$LABEL" "level")
    [[ -z "$EXPOSURE" ]] && return  # service not in context table

    local LEVEL_COLOR="$YELLOW"
    [[ "$LEVEL" == "CRITIQUE" || "$LEVEL" == "CRITICAL" ]] && LEVEL_COLOR="$RED"

    echo -e "    ${DIM}┄ $(t risk_ctx_title) — ${LEVEL_COLOR}${BOLD}${LEVEL}${RESET}"
    echo -e "    ${DIM}$(t risk_ctx_exposure) : ${RESET}${DIM}${EXPOSURE}${RESET}"
    echo -e "    ${DIM}$(t risk_ctx_threat)   : ${RESET}${DIM}${THREAT}${RESET}"
    echo

    if use_logfile; then
        {
            echo "  [$(t risk_ctx_title) — $LEVEL]"
            echo "  $(t risk_ctx_exposure) : $EXPOSURE"
            echo "  $(t risk_ctx_threat)   : $THREAT"
            echo
        } >> "$LOGFILE"
    fi
}

# ==========================================================
# HELPERS
# ==========================================================

use_logfile() { [[ -n "$LOGFILE" ]]; }
is_detailed() { [[ "$LOG_LEVEL" == "detailed" ]] && use_logfile; }

# ==========================================================
# NETWORK CONTEXT DETECTION
# ==========================================================

detect_network_context() {
    local HAS_LOCAL_PUBLIC=false

    # 1. Check local interfaces for non-RFC1918 addresses
    #    A public IP directly on an interface = machine is truly exposed
    local IFACE_IPS
    IFACE_IPS=$(ip addr show 2>/dev/null \
        | grep -oE 'inet ([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | awk '{print $2}')

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        # Skip loopback and RFC1918
        [[ "$ip" =~ ^127\. ]]       && continue
        [[ "$ip" =~ ^10\. ]]        && continue
        [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && continue
        [[ "$ip" =~ ^192\.168\. ]]  && continue
        # Skip link-local
        [[ "$ip" =~ ^169\.254\. ]]  && continue
        HAS_LOCAL_PUBLIC=true
        break
    done <<< "$IFACE_IPS"

    # 2. Try to fetch external IP via curl (timeout 3s)
    #    This confirms internet access but does NOT mean direct exposure —
    #    the machine may be behind a NAT/router (typical home setup)
    if command -v curl >/dev/null 2>&1; then
        PUBLIC_IP=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null || echo "")
        if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            HAS_PUBLIC_IP=true
        fi
    fi

    # Context = public ONLY if the machine has a public IP directly on a local
    # interface (VPS, dedicated server). If curl returns a public IP but no local
    # interface has one, the machine is behind NAT — treat as local.
    if $HAS_LOCAL_PUBLIC; then
        NETWORK_CONTEXT="public"
    else
        NETWORK_CONTEXT="local"
        # Still record the public IP for display if we found one (informational)
    fi
}

# ==========================================================
# CONTEXTUAL SCORE DEDUCTION
# ==========================================================

# score_deduct REASON BASE_DEDUCT [force_context]
# BASE_DEDUCT is the local penalty; public doubles it (except duplicates)
# Records the deduction in SCORE_BREAKDOWN for display
score_deduct() {
    local REASON="$1"
    local BASE="$2"
    local DEDUCT="$BASE"

    if [[ "$NETWORK_CONTEXT" == "public" ]]; then
        # Duplicate rules: no context multiplier
        if [[ "$REASON" != *"duplic"* && "$REASON" != *"doublon"* ]]; then
            DEDUCT=$(( BASE * 2 ))
            # Cap individual deduction at 4
            (( DEDUCT > 4 )) && DEDUCT=4
            SCORE_BREAKDOWN+=( "$REASON|$DEDUCT|public" )
        else
            SCORE_BREAKDOWN+=( "$REASON|$DEDUCT|" )
        fi
    else
        SCORE_BREAKDOWN+=( "$REASON|$DEDUCT|" )
    fi

    SCORE=$(( SCORE - DEDUCT ))
    (( SCORE < 0 )) && SCORE=0
}

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
        setup_colors
        return
    fi
    # First pass: detect --french and --no-color early
    for arg in "$@"; do
        [[ "$arg" == "--french" ]]   && LANG_FR=true
        [[ "$arg" == "--no-color" ]] && NO_COLOR=true
    done
    setup_colors
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)      VERBOSE=true;        AUDIT_REQUESTED=true ;;
            -h|--help)         HELP=true ;;
            -d|--detailed)     LOG_LEVEL="detailed"; AUDIT_REQUESTED=true ;;
            -V|--version)      VERSION_ONLY=true ;;
            -r|--reconfigure)  RECONFIGURE=true;     AUDIT_REQUESTED=true ;;
            --french)          LANG_FR=true;          AUDIT_REQUESTED=true ;;
            --fix)             FIX_MODE=true;         AUDIT_REQUESTED=true ;;
            --yes)             FIX_YES=true ;;
            --no-color)        NO_COLOR=true ;;
            --json)            JSON_MODE=true;         AUDIT_REQUESTED=true ;;
            --json-full)       JSON_MODE=true; JSON_FULL=true; AUDIT_REQUESTED=true ;;
            --log-days=*)      LOG_DAYS="${1#--log-days=}"
                               [[ "$LOG_DAYS" =~ ^[0-9]+$ ]] || { echo "$(t err_unknown_opt) $1"; exit 1; } ;;
            *)
                echo "${RED}[ERROR]${RESET} $(t err_unknown_opt) $1"
                echo "$(t err_use_help)"
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
    echo "$(t help_fix)"
    echo "$(t help_yes)"
    echo "$(t help_nocolor)"
    echo "$(t help_json)"
    echo "$(t help_jsonfull)"
    echo "$(t log_help_days)"
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
        log WARN "$(t log_distro_warn)" "" "--nature=improvement"
    fi
}

# ==========================================================
# LOGGING
# ==========================================================

log() {
    local LEVEL="$1"
    local MESSAGE="$2"
    local RECOMMENDATION="${3:-}"

    # Parse optional flags from arguments 4+
    # --no-score  : skip score deduction (intentionally configured services)
    # --nature=X  : override item nature in summary (action|improvement|structural)
    local NO_SCORE=false
    local NATURE=""
    local FIX_CMD=""
    local arg
    for arg in "${@:4}"; do
        [[ "$arg" == "--no-score" ]]    && NO_SCORE=true
        [[ "$arg" == --nature=* ]]      && NATURE="${arg#--nature=}"
        [[ "$arg" == --cmd=* ]]         && FIX_CMD="${arg#--cmd=}"
    done

    local TIMESTAMP
    TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    local COLOR="" PREFIX="" ICON=""

    case "$LEVEL" in
        INFO)  COLOR="$CYAN";   ICON="ℹ"
               $LANG_FR && PREFIX="[INFO]"    || PREFIX="[INFO]" ;;
        OK)    COLOR="$GREEN";  ICON="✔";  OK_COUNT=$(( OK_COUNT + 1 ))
               PREFIX="[OK]" ;;
        WARN)  COLOR="$YELLOW"; ICON="⚠";  WARN_COUNT=$(( WARN_COUNT + 1 ))
               $LANG_FR && PREFIX="[ATTENTION]" || PREFIX="[WARNING]"
               $NO_SCORE || score_deduct "$MESSAGE" 1
               local ITEM_NATURE="${NATURE:-improvement}"
               AUDIT_ITEMS+=( "WARN|${ITEM_NATURE}|${MESSAGE}|${FIX_CMD}" ) ;;
        ALERT) COLOR="$RED";    ICON="✖";  ALERT_COUNT=$(( ALERT_COUNT + 1 ))
               $LANG_FR && PREFIX="[ALERTE]"    || PREFIX="[ALERT]"
               $NO_SCORE || score_deduct "$MESSAGE" 2
               local ITEM_NATURE="${NATURE:-action}"
               AUDIT_ITEMS+=( "ALERT|${ITEM_NATURE}|${MESSAGE}|${FIX_CMD}" ) ;;
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
        echo "UFW         : $(ufw version 2>/dev/null | head -1 | grep -oE 'ufw [0-9.]+' || echo "N/A")"
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
        echo "Context : $NETWORK_CONTEXT${PUBLIC_IP:+ ($PUBLIC_IP)}"
        echo
        if [[ ${#SCORE_BREAKDOWN[@]} -gt 0 ]]; then
            echo "[SCORE BREAKDOWN]"
            for entry in "${SCORE_BREAKDOWN[@]}"; do
                local REASON DEDUCT CTX
                REASON=$(echo "$entry" | cut -d'|' -f1)
                DEDUCT=$(echo "$entry" | cut -d'|' -f2)
                CTX=$(echo "$entry"    | cut -d'|' -f3)
                local SUFFIX=""
                [[ "$CTX" == "public" ]] && SUFFIX=" (public IP context)"
                printf "  %-50s  -%s%s\n" "$REASON" "$DEDUCT" "$SUFFIX"
            done
            echo
        fi

        # Risk context section — all high/critical services detected on this machine
        local HAS_CTX=false
        for ENTRY in "${SERVICES[@]}"; do
            IFS='|' read -r LABEL PACKAGES SVCS DEFAULT_PORTS RISK CONFIG_KEY <<< "$ENTRY"
            [[ "$RISK" != "high" && "$RISK" != "critical" ]] && continue
            local INSTALLED_PKG
            INSTALLED_PKG=$(is_package_installed "$PACKAGES")
            [[ -z "$INSTALLED_PKG" ]] && continue
            # Skip services that are inactive and disabled — no immediate risk
            local SVC_STATE
            SVC_STATE=$(get_service_state "$SVCS")
            [[ "$SVC_STATE" == "inactive_disabled" ]] && continue
            local EXPOSURE THREAT LEVEL
            EXPOSURE=$(get_risk_context "$LABEL" "exposure")
            THREAT=$(get_risk_context   "$LABEL" "threat")
            LEVEL=$(get_risk_context    "$LABEL" "level")
            [[ -z "$EXPOSURE" ]] && continue
            if ! $HAS_CTX; then
                echo "=========================================================="
                echo "[$(t risk_log_section)]"
                echo
                HAS_CTX=true
            fi
            printf "  %-32s  [%s]\n" "$LABEL" "$LEVEL"
            echo "  $(t risk_ctx_exposure) : $EXPOSURE"
            echo "  $(t risk_ctx_threat)   : $THREAT"
            echo
        done

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
        chmod 600 "$CONFIG_FILE" 2>/dev/null || true
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
    chmod 600 "$CONFIG_FILE" 2>/dev/null || true
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
        "Redis")
            local P; P=$(grep -E "^port " /etc/redis/redis.conf 2>/dev/null | awk '{print $2}' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            echo "6379/tcp" && return ;;
        "Jellyfin")
            local P; P=$(grep -E "PublicPort|HttpServerPortNumber" /etc/jellyfin/network.xml 2>/dev/null | grep -oE '[0-9]+' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            echo "8096/tcp" && return ;;
        "Plex Media Server")
            echo "32400/tcp" && return ;;
        "Home Assistant")
            local P; P=$(grep -E "^http:" -A5 /etc/homeassistant/configuration.yaml 2>/dev/null | grep "server_port" | grep -oE '[0-9]+' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            echo "8123/tcp" && return ;;
        "Gitea")
            local P; P=$(grep -E "^HTTP_PORT\s*=" /etc/gitea/app.ini 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            # Forgejo uses same config structure
            P=$(grep -E "^HTTP_PORT\s*=" /etc/forgejo/app.ini 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | head -1)
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            echo "3000/tcp" && return ;;
        "Nextcloud")
            # Snap Nextcloud uses port 80/443 via its own nginx
            snap list nextcloud 2>/dev/null | grep -q "nextcloud" && { echo "80/tcp" && return; }
            ;;
        "Syncthing")
            local P; P=$(grep -rE "address.*:[0-9]+" /root/.config/syncthing/config.xml /home/*/.config/syncthing/config.xml 2>/dev/null \
                | grep -oE ':[0-9]+' | head -1 | tr -d ':')
            [[ -n "$P" ]] && echo "${P}/tcp" && return
            echo "8384/tcp" && return ;;
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

    # 'ask' means: prompt on first run, then save like any named key
    # Generate a stable key from the service label (lowercase, spaces→underscores)
    if [[ "$CONFIG_KEY" == "ask" ]]; then
        CONFIG_KEY=$(echo "$LABEL" | tr '[:upper:]' '[:lower:]' | tr ' /()' '_' | tr -s '_' | sed 's/_$//')_port
    fi

    if $RECONFIGURE && [[ "$CONFIG_KEY" != "auto" ]]; then
        config_delete_key "$CONFIG_KEY"
    fi

    local PROTO
    PROTO=$(echo "$DEFAULT_PORTS" | awk '{print $1}' | cut -d'/' -f2)

    # 1. From ~/.ufw_audit.conf
    if [[ "$CONFIG_KEY" != "auto" ]]; then
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
    local AUTO_PORT
    AUTO_PORT=$(detect_port_auto "$LABEL")
    if [[ -n "$AUTO_PORT" ]]; then
        $VERBOSE    && echo -e "    ${DIM}↳ $(t port_auto): $AUTO_PORT${RESET}" > /dev/tty
        is_detailed && echo    "    ↳ $(t port_auto): $AUTO_PORT" >> "$LOGFILE"
        [[ "$CONFIG_KEY" != "auto" ]] && config_set "$CONFIG_KEY" "$(echo "$AUTO_PORT" | cut -d'/' -f1)"
        echo "$AUTO_PORT"
        return
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

    [[ "$CONFIG_KEY" != "auto" ]] && config_set "$CONFIG_KEY" "$RESOLVED_PORT"
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
        log ALERT "$(t log_ufw_missing)" "$(t log_ufw_install)" "--nature=action" "--cmd=sudo apt install -y ufw"
        echo -e "\n  ${YELLOW}→ sudo apt install ufw${RESET}\n"
        log ERROR "$(t log_ufw_abort)"
        exit 1
    fi

    if command -v ss >/dev/null 2>&1; then
        PORT_TOOL="ss"
        log OK "$(t log_ss_ok)"
    elif command -v netstat >/dev/null 2>&1; then
        PORT_TOOL="netstat"
        log WARN "$(t log_netstat_warn)" "$(t log_netstat_fix)" "--nature=improvement"
    else
        PORT_TOOL=""
        log WARN "$(t log_notool_warn)" "$(t log_netstat_fix)" "--nature=improvement"
    fi
}

# ==========================================================
# UFW RULES ANALYSIS
# ==========================================================

# --- 1. Duplicate and redundant rules ---
check_ufw_duplicates() {
    local UFW_NUMBERED
    UFW_NUMBERED=$(ufw status numbered 2>/dev/null)

    # Extract rules stripping the number prefix: "[ 1] ..." -> "..."
    local RULES
    RULES=$(echo "$UFW_NUMBERED" | grep -E "^\[ *[0-9]+\]" | sed 's/^\[ *[0-9]*\] *//')

    local DUPLICATES=false
    declare -A SEEN

    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        if [[ -n "${SEEN[$rule]+_}" ]]; then
            DUPLICATES=true
            log WARN "$(t dup_found) $rule" "" "--nature=improvement"
            # Find the rule numbers for both occurrences
            local NUMS
            NUMS=$(echo "$UFW_NUMBERED" | grep -F "$rule" \
                | grep -oE "^\[ *[0-9]+" | grep -oE "[0-9]+" | tr '\n' ' ')
            local SECOND
            SECOND=$(echo "$NUMS" | awk '{print $2}')
            log_recommendation "$(t dup_fix)\n  sudo ufw delete $SECOND"
        fi
        SEEN[$rule]=1
    done <<< "$RULES"

    $DUPLICATES || log OK "$(t dup_none)"
}

# --- 2. allow from any without port restriction ---
check_ufw_allow_any() {
    local UFW_NUMBERED
    UFW_NUMBERED=$(ufw status numbered 2>/dev/null)

    # Match rules that ALLOW from Anywhere without a specific port (just "ALLOW IN" or "ALLOW")
    # These look like: "ALLOW IN    Anywhere" with no port on the left side
    local DANGEROUS
    DANGEROUS=$(echo "$UFW_NUMBERED" | grep -E "^\[ *[0-9]+\]" \
        | grep -iE "ALLOW (IN |FWD )?\s+Anywhere\s*$")

    if [[ -z "$DANGEROUS" ]]; then
        log OK "$(t any_none)"
        return
    fi

    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local NUM
        NUM=$(echo "$rule" | grep -oE "^\[ *[0-9]+" | grep -oE "[0-9]+")
        local RULE_TEXT
        RULE_TEXT=$(echo "$rule" | sed 's/^\[ *[0-9]*\] *//')
        log ALERT "$(t any_found) $RULE_TEXT" "" "--nature=action" "--cmd=sudo ufw --force delete $NUM"
        log_recommendation "$(t any_fix)\n  sudo ufw delete $NUM"
    done <<< "$DANGEROUS"
}

# --- 3. IPv6 consistency ---
check_ipv6_consistency() {
    local IPV6_SETTING
    IPV6_SETTING=$(grep -E "^IPV6=" /etc/default/ufw 2>/dev/null | cut -d'=' -f2 | tr -d '"' | tr '[:upper:]' '[:lower:]')

    local UFW_STATUS
    UFW_STATUS=$(ufw status verbose 2>/dev/null)

    local HAS_V6_RULES=false
    echo "$UFW_STATUS" | grep -q "(v6)" && HAS_V6_RULES=true

    # Check if any UFW rules exist at all (v4 or v6)
    local HAS_ANY_RULES=false
    ufw status numbered 2>/dev/null | grep -qE "^\[ *[0-9]+" && HAS_ANY_RULES=true

    if [[ "$IPV6_SETTING" == "yes" ]]; then
        if $HAS_V6_RULES; then
            log OK "$(t ipv6_ok)"
        else
            # Only penalise if user has configured some UFW rules — otherwise
            # IPv6 without rules on a fresh system is expected and harmless
            if $HAS_ANY_RULES; then
                log WARN "$(t ipv6_enabled_norules)" "" "--nature=improvement"
                log_recommendation "$(t ipv6_fix)"
            else
                log OK "$(t ipv6_ok)"
            fi
        fi
    else
        if $HAS_V6_RULES; then
            log WARN "$(t ipv6_disabled_rules)" "" "--nature=improvement"
            log_recommendation "$(t ipv6_fix)"
        else
            log OK "$(t ipv6_ok)"
        fi
    fi
}

# ==========================================================
# PORT MAP BUILDER + MERGED LISTENING PORTS ANALYSIS
# Single pass: builds exposure map, then logs once per port.
# "exposed" (0.0.0.0 / [::]) wins over "local" — worst-case kept.
# ==========================================================

# Known system ports — no UFW rule needed, informational only
declare -A _SYS_PORTS=(
    [53]="DNS (systemd-resolved / libvirt)"
    [67]="DHCP server (libvirt/virbr0)"
    [68]="DHCP client"
    [546]="DHCPv6 client"
    [631]="CUPS (localhost only)"
    [5353]="mDNS/Avahi (audited in services section)"
)
declare -A _SYS_PORTS_SHORT=(
    [53]="DNS" [67]="DHCP" [68]="DHCP client"
    [546]="DHCPv6" [631]="CUPS" [5353]="mDNS/Avahi"
)

# NetBIOS ports — Samba-managed, low risk behind NAT, WARN not ALERT
declare -A _NETBIOS_PORTS=( [137]="NetBIOS Name Service" [138]="NetBIOS Datagram" )

build_listen_map() {
    unset _LM_MAP _LM_ADDR
    declare -gA _LM_MAP=()
    declare -gA _LM_ADDR=()

    local LISTEN
    [[ "$PORT_TOOL" == "ss" ]] \
        && LISTEN=$(ss -tulnH 2>/dev/null) \
        || LISTEN=$(netstat -tuln 2>/dev/null | awk 'NR>2')
    [[ -z "$LISTEN" ]] && return

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local PROTO_RAW LOCAL_ADDR PORT PROTO
        if [[ "$PORT_TOOL" == "ss" ]]; then
            PROTO_RAW=$(echo "$line" | awk '{print $1}')
            LOCAL_ADDR=$(echo "$line" | awk '{print $5}')
        else
            PROTO_RAW=$(echo "$line" | awk '{print $1}')
            LOCAL_ADDR=$(echo "$line" | awk '{print $4}')
        fi
        PORT=$(echo "$LOCAL_ADDR" | grep -oE '[0-9]+$')
        [[ -z "$PORT" ]] && continue
        PROTO="tcp"; echo "$PROTO_RAW" | grep -qi "udp" && PROTO="udp"
        local KEY="${PROTO}:${PORT}"

        # Ephemeral
        if (( PORT > 32767 )); then
            [[ -z "${_LM_MAP[$KEY]+_}" ]] && _LM_MAP[$KEY]="ephemeral"
            continue
        fi
        # Known system ports
        if [[ -n "${_SYS_PORTS[$PORT]+_}" ]]; then
            [[ -z "${_LM_MAP[$KEY]+_}" ]] && {
                _LM_MAP[$KEY]="sysport:${_SYS_PORTS[$PORT]}"
                _LM_ADDR[$KEY]="$LOCAL_ADDR"
            }
            continue
        fi
        # Determine exposure — worst-case wins
        local LINE_EXPOSED=false
        echo "$LOCAL_ADDR" | grep -qE "^(0\.0\.0\.0|\*|\[::\]):" && LINE_EXPOSED=true
        if [[ -z "${_LM_MAP[$KEY]+_}" ]]; then
            _LM_ADDR[$KEY]="$LOCAL_ADDR"
            $LINE_EXPOSED && _LM_MAP[$KEY]="exposed" || _LM_MAP[$KEY]="local"
        elif [[ "${_LM_MAP[$KEY]}" == "local" ]] && $LINE_EXPOSED; then
            _LM_MAP[$KEY]="exposed"
            _LM_ADDR[$KEY]="$LOCAL_ADDR"
        fi
    done <<< "$LISTEN"
}

# Merged section: one log per port, score counted once
check_listening_ports_analysis() {
    log_section "$(t sec_ports_analysis)"

    if [[ -z "$PORT_TOOL" ]]; then
        log INFO "$(t log_ports_skip)"
        return
    fi

    build_listen_map

    if [[ ${#_LM_MAP[@]} -eq 0 ]]; then
        log OK "$(t log_no_ports)"
        return
    fi

    local FOUND_ISSUES=false

    for KEY in "${!_LM_MAP[@]}"; do
        local PROTO PORT STATUS
        PROTO="${KEY%%:*}"
        PORT="${KEY##*:}"
        STATUS="${_LM_MAP[$KEY]}"

        # Skip ports already covered by audit_services() — avoids duplicate reporting
        [[ -n "${AUDITED_PORTS[$KEY]+_}" ]] && continue

        # Silent: ephemeral and system ports — log_detail only
        case "$STATUS" in
            ephemeral)
                log_detail "$(t uncov_ephemeral): $PORT/$PROTO"
                continue ;;
            sysport:*)
                local DESC="${STATUS#sysport:}"
                log_detail "$(t uncov_sysport): $PORT/$PROTO (${_SYS_PORTS_SHORT[$PORT]:-$DESC})"
                continue ;;
        esac

        # Check UFW coverage for this port
        local UFW_EXPOSURE
        UFW_EXPOSURE=$(analyze_port_exposure "$PORT")

        if [[ "$STATUS" == "exposed" ]]; then
            if [[ "$UFW_EXPOSURE" == "no_rule" ]]; then
                FOUND_ISSUES=true
                # NetBIOS ports (137/138) — WARN, not ALERT (Samba-managed, low risk behind NAT)
                if [[ -n "${_NETBIOS_PORTS[$PORT]+_}" ]]; then
                    log WARN "$(t ports_netbios_warn)" "" "--nature=structural"
                    log_recommendation "$(t ports_netbios_fix)\n  sudo ufw allow from 192.168.1.0/24 to any port $PORT proto $PROTO\n  sudo ufw deny $PORT/$PROTO"
                else
                    log ALERT "$PORT/$PROTO — $(t ports_exposed_norule)" "" "--nature=action" "--cmd=sudo ufw deny $PORT/$PROTO"
                    log_recommendation "$(t uncov_fix)\n  sudo ufw deny $PORT/$PROTO"
                fi
            else
                # Has a UFW rule but binds on 0.0.0.0 — informational
                log_detail "$PORT/$PROTO — $(t ports_exposed_ruled)"
            fi
        else
            # Local bind
            if [[ "$UFW_EXPOSURE" == "no_rule" ]]; then
                log INFO "$PORT/$PROTO — $(t ports_local_norule)"
            else
                log_detail "$PORT/$PROTO — $(t ports_local_ruled)"
            fi
        fi
    done

    $FOUND_ISSUES || log OK "$(t uncov_none)"
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
        log ALERT "$(t log_fw_inactive)" "" "--nature=action"
        log_recommendation "$(t log_fw_enable)"
        # Mark firewall as inactive — score will be capped at 3 in show_summary()
        FW_INACTIVE=true
    fi

    local DEFAULT_IN
    DEFAULT_IN=$(grep "Default:" <<< "$UFW_STATUS" \
        | grep -oE "(deny|reject|allow)" | head -1 || echo "")

    if [[ "$DEFAULT_IN" == "deny" || "$DEFAULT_IN" == "reject" ]]; then
        log OK "$(t log_policy_ok)"
    elif [[ -z "$DEFAULT_IN" ]]; then
        log WARN "$(t log_policy_warn)" "" "--nature=improvement"
    else
        log ALERT "$(t log_policy_alert)" "" "--nature=action" "--no-score" "--cmd=sudo ufw default deny incoming"
        score_deduct "$(t log_policy_alert)" 3
        log_recommendation "$(t log_policy_fix)"
    fi

    if $VERBOSE; then echo; echo "$UFW_STATUS"; echo; fi
    is_detailed && { { echo; echo "[UFW STATUS]"; echo "$UFW_STATUS"; echo; } >> "$LOGFILE"; }

    # --- v0.5.0: UFW rules deep analysis ---
    log_section "$(t sec_rules)"
    check_ufw_duplicates
    check_ufw_allow_any
    check_ipv6_consistency
}

# ==========================================================
# UFW RULE ANALYSIS — per port
# ==========================================================

get_ufw_rules_for_port() {
    local PORT="$1"
    ufw status numbered 2>/dev/null | grep -E "(^|\s)${PORT}(/tcp|/udp|$|\s)"
}

# Returns: open_world | open_local | deny | no_rule
# ufw status numbered format: [ N] To/Port    Action    From
#   ALLOW IN    Anywhere       -> open_world
#   ALLOW IN    192.168.1.11   -> open_local (source IP in From column)
analyze_port_exposure() {
    local PORT="$1"
    local RULES
    RULES=$(get_ufw_rules_for_port "$PORT")
    [[ -z "$RULES" ]] && { echo "no_rule"; return; }

    # Check DENY first
    echo "$RULES" | grep -qi "DENY" && { echo "deny"; return; }

    if echo "$RULES" | grep -qi "ALLOW"; then
        local HAS_WORLD=false
        local HAS_LOCAL=false
        while IFS= read -r rule; do
            echo "$rule" | grep -qi "ALLOW" || continue
            # Extract From column: last whitespace-delimited token after stripping
            # the rule number prefix e.g. "[ 1] 445/tcp   ALLOW IN   192.168.1.11"
            # The From field is the last column
            local FROM_FIELD
            FROM_FIELD=$(echo "$rule" | awk '{print $NF}')
            # "Anywhere" (or v6 "Anywhere (v6)") = open to the world
            if echo "$FROM_FIELD" | grep -qiE "^Anywhere$|^\(v6\)$"; then
                HAS_WORLD=true
            elif echo "$FROM_FIELD" | grep -qE "^[0-9]+\.[0-9]|^[0-9a-fA-F:]+(/[0-9]+)?$"; then
                # Specific IPv4/IPv6 address or subnet = source-restricted
                HAS_LOCAL=true
            else
                # Unknown format — conservative: treat as world
                HAS_WORLD=true
            fi
        done <<< "$RULES"

        $HAS_WORLD && { echo "open_world"; return; }
        $HAS_LOCAL && { echo "open_local"; return; }
    fi

    echo "no_rule"
}

# ==========================================================
# SERVICE DETECTION
# ==========================================================

is_package_installed() {
    local PACKAGES="$1"
    for PKG in $PACKAGES; do
        # Standard dpkg check
        dpkg -l "$PKG" 2>/dev/null | grep -q "^ii" && { echo "$PKG"; return; }

        # Snap check — for packages like nextcloud installed via snap
        snap list "$PKG" 2>/dev/null | grep -q "^$PKG" && { echo "$PKG (snap)"; return; }

        # Binary check — for self-installed services like gitea
        case "$PKG" in
            gitea)
                for BIN in /usr/local/bin/gitea /usr/bin/gitea /opt/gitea/gitea; do
                    [[ -x "$BIN" ]] && { echo "$PKG (binary)"; return; }
                done
                systemctl list-units --all 2>/dev/null | grep -q "gitea" && { echo "$PKG (service)"; return; }
                ;;
            forgejo)
                for BIN in /usr/local/bin/forgejo /usr/bin/forgejo; do
                    [[ -x "$BIN" ]] && { echo "$PKG (binary)"; return; }
                done
                ;;
        esac
    done
    echo ""
}

# Returns: active_enabled | active_disabled | inactive_enabled | inactive_disabled | unknown
get_service_state() {
    for SVC in $1; do
        # Handle systemd template services (e.g. wg-quick@) — check for any instance
        local SVC_PATTERN="$SVC"
        [[ "$SVC" == *"@" ]] && SVC_PATTERN="${SVC}*"

        if systemctl list-units --all 2>/dev/null | grep -q "$SVC_PATTERN"; then
            # For template services, get the first active instance name
            local REAL_SVC="$SVC"
            if [[ "$SVC" == *"@" ]]; then
                REAL_SVC=$(systemctl list-units --all 2>/dev/null \
                    | grep "${SVC}" | awk '{print $1}' | head -1)
                [[ -z "$REAL_SVC" ]] && REAL_SVC="$SVC"
            fi
            local ACTIVE ENABLED
            ACTIVE=$(systemctl is-active  "$REAL_SVC" 2>/dev/null || echo "inactive")
            ENABLED=$(systemctl is-enabled "$REAL_SVC" 2>/dev/null || echo "disabled")
            if   [[ "$ACTIVE" == "active" && "$ENABLED" == "enabled" ]]; then echo "active_enabled"
            elif [[ "$ACTIVE" == "active"                             ]]; then echo "active_disabled"
            elif [[ "$ENABLED" == "enabled"                           ]]; then echo "inactive_enabled"
            else                                                              echo "inactive_disabled"
            fi
            return
        fi

        # Snap services — check snap service state
        if snap services "$SVC" 2>/dev/null | grep -q "active"; then
            echo "active_enabled"; return
        fi
        if snap list "$SVC" 2>/dev/null | grep -q "^$SVC"; then
            echo "inactive_disabled"; return
        fi

        # Also check if the package is installed even if no unit is loaded
        # For WireGuard: check for wg tool availability
        if [[ "$SVC" == *"@" ]]; then
            command -v wg >/dev/null 2>&1 && { echo "inactive_disabled"; return; }
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

        # Show risk context for high/critical active services only
        if [[ "$RISK" == "high" || "$RISK" == "critical" ]]; then
            log_risk_context "$LABEL"
        fi

        case "$SVC_STATE" in
            active_enabled)   log OK   "$(t log_svc_active)" ;;
            active_disabled)  log WARN "$(t log_svc_nodaemon)" "" "--nature=improvement" ;;
            inactive_enabled)
                local EXPL RECO
                EXPL=$(get_risk_explanation "$LABEL" "inactive")
                RECO=$(get_recommendation  "$LABEL" "inactive" "$DEFAULT_PORTS")
                log WARN "$EXPL" "" "--nature=improvement"
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
            PROTO_ONLY=$(echo "$PORT_PROTO" | cut -d'/' -f2)
            EXPOSURE=$(analyze_port_exposure "$PORT")
            log_detail "Port $PORT_PROTO: exposure = $EXPOSURE"
            # Register as audited so check_listening_ports_analysis skips it
            AUDITED_PORTS["${PROTO_ONLY}:${PORT}"]=1
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
                # Extract first sudo ufw command from recommendation for --fix mode
                local FIX_FIRST_CMD=""
                if [[ -n "$RECO" ]]; then
                    FIX_FIRST_CMD=$(echo -e "$RECO" | grep -m1 "sudo ufw" | sed 's/^[[:space:]]*//' || true)
                fi
                case "$RISK" in
                    critical|high)
                        log ALERT "$EXPL" "$RECO" "--nature=action" "--cmd=${FIX_FIRST_CMD}"
                        if [[ "$NETWORK_CONTEXT" == "public" ]]; then
                            score_deduct "$LABEL open_world high/critical (public IP extra)" 2
                        fi
                        ;;
                    medium) log WARN "$EXPL" "$RECO" "--nature=action" "--cmd=${FIX_FIRST_CMD}" ;;
                    low)    log INFO "$EXPL" ;;
                esac
                [[ -n "$RECO" ]] && log_recommendation "$RECO"
                ;;
            open_local)
                case "$RISK" in
                    critical|high) log WARN "$EXPL" "" "--no-score" "--nature=structural" ;;
                    *)             log OK   "$EXPL" ;;
                esac
                RECO=$(get_recommendation "$LABEL" "open_local" "$RESOLVED_PORTS")
                [[ -n "$RECO" ]] && log_recommendation "$RECO"
                ;;
            deny)    log OK   "$(t log_svc_blocked)" ;;
            no_rule)
                log INFO "$EXPL"
                # Track high/critical services with no explicit UFW rule
                # They rely on default policy — noted in summary without score penalty
                if [[ "$RISK" == "high" || "$RISK" == "critical" ]]; then
                    IMPLICIT_POLICY_SVCS+=( "$LABEL" )
                fi
                ;;
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
# UFW LOG ANALYSIS
# Parses /var/log/ufw.log for BLOCK events over LOG_DAYS days.
# Extracts: total blocks, top IPs, top ports, bruteforce
# detection, and attempts on installed service ports.
# Terminal: short summary. Detailed report: full tables.
# ==========================================================

# ==========================================================
# IP GEOLOCATION — via whois (no external dependency)
# Returns "CC, OrgName" or empty string if unavailable.
# IPs in private ranges are returned as "réseau local" / "local network".
# Results cached in GEO_CACHE[] to avoid duplicate lookups.
# ==========================================================

declare -A GEO_CACHE

get_ip_geo() {
    local IP="$1"

    # Return cached result if available
    if [[ -n "${GEO_CACHE[$IP]+_}" ]]; then
        echo "${GEO_CACHE[$IP]}"
        return
    fi

    # Private/loopback ranges — no lookup needed
    if echo "$IP" | grep -qE \
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1$|fc|fd)'; then
        local LABEL
        $LANG_FR && LABEL="réseau local" || LABEL="local network"
        GEO_CACHE[$IP]="$LABEL"
        echo "$LABEL"
        return
    fi

    # whois not available — return empty
    if ! command -v whois >/dev/null 2>&1; then
        GEO_CACHE[$IP]=""
        echo ""
        return
    fi

    # Query whois — extract country and org/netname
    local WHOIS_OUT
    WHOIS_OUT=$(whois "$IP" 2>/dev/null | head -40)

    local COUNTRY ORG
    COUNTRY=$(echo "$WHOIS_OUT" | grep -iE "^country:" \
        | head -1 | awk '{print $2}' | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    ORG=$(echo "$WHOIS_OUT" | grep -iE "^(org-name|orgname|netname|descr):" \
        | head -1 | sed 's/^[^:]*:[[:space:]]*//' | cut -c1-30 | tr -d '\n')

    local RESULT=""
    [[ -n "$COUNTRY" && -n "$ORG" ]] && RESULT="${COUNTRY}, ${ORG}"
    [[ -n "$COUNTRY" && -z "$ORG" ]] && RESULT="${COUNTRY}"
    [[ -z "$COUNTRY" && -n "$ORG" ]] && RESULT="${ORG}"

    GEO_CACHE[$IP]="$RESULT"
    echo "$RESULT"
}

audit_ufw_logs() {
    log_section "$(t sec_logs)"

    local LOGF="/var/log/ufw.log"
    if [[ ! -f "$LOGF" ]]; then
        log INFO "$(t log_no_logfile)"
        return
    fi

    # Count days actually available in log — handle both syslog and systemd ISO formats
    local DAYS_AVAILABLE
    DAYS_AVAILABLE=$(grep -oE '(^[A-Za-z]+ +[0-9]+|^[0-9]{4}-[0-9]{2}-[0-9]{2})' "$LOGF" 2>/dev/null \
        | sort -u | wc -l | tr -d '[:space:]')
    DAYS_AVAILABLE=$(( ${DAYS_AVAILABLE:-0} ))

    # Note once if whois unavailable
    if ! command -v whois >/dev/null 2>&1; then
        echo -e "  ${DIM}ℹ $(t geo_no_whois)${RESET}"
    fi

    # Extract BLOCK lines — fast awk-based date filtering
    # Supports ISO 8601 format: 2026-03-19T18:20:08.xxx+01:00
    # and syslog format: Mar 19 10:23:14
    local CUTOFF_DATE
    CUTOFF_DATE=$(date -d "-${LOG_DAYS} days" '+%Y-%m-%d' 2>/dev/null || \
                  date -v-${LOG_DAYS}d '+%Y-%m-%d' 2>/dev/null || \
                  date '+%Y-%m-%d')

    local BLOCKS
    BLOCKS=$(awk -v cutoff="$CUTOFF_DATE" '
        /\[UFW BLOCK\]/ {
            # ISO format: 2026-03-19T18:20:08... — use substr for mawk/gawk compat
            if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}/) {
                if (substr($1, 1, 10) >= cutoff) print $0
            }
            # Syslog format: Mar 19 10:23:14 — always include (year unknown)
            else if ($1 ~ /^[A-Za-z]+$/) {
                print $0
            }
        }
    ' "$LOGF" 2>/dev/null || true)

    local TOTAL
    if [[ -z "$BLOCKS" ]]; then
        TOTAL=0
    else
        TOTAL=$(printf '%s' "$BLOCKS" | grep -F "[UFW BLOCK]" | wc -l | tr -d '[:space:]')
        TOTAL=$(( ${TOTAL:-0} ))
    fi

    if [[ "${TOTAL:-0}" -eq 0 ]]; then
        log OK "$(t log_empty)"
        echo -e "  ${DIM}$(t log_period) : ${LOG_DAYS} $(t log_days_unit) — ${DAYS_AVAILABLE} $(t log_available)${RESET}"
        return
    fi

    # --- Extract fields ---
    local SRC_IPS DEST_PORTS
    SRC_IPS=$(echo "$BLOCKS"   | grep -oP 'SRC=\K[\d.]+' | sort | uniq -c | sort -rn | head -10)
    DEST_PORTS=$(echo "$BLOCKS" | grep -oP 'DPT=\K\d+'   | sort | uniq -c | sort -rn | head -10)

    # --- Bruteforce detection ---
    # Group by SRC+DPT, flag if >10 attempts within any 60s window
    local BRUTE_HITS
    BRUTE_HITS=$(echo "$BLOCKS" | awk '
    /\[UFW BLOCK\]/ {
        # Extract timestamp (seconds since epoch via date)
        ts_str = $1" "$2" "$3
        cmd = "date -d \""ts_str"\" +%s 2>/dev/null"
        cmd | getline ts; close(cmd)
        src=""; dpt=""
        for(i=1;i<=NF;i++){
            if($i~/^SRC=/) src=substr($i,5)
            if($i~/^DPT=/) dpt=substr($i,5)
        }
        if(src!="" && dpt!="" && ts!=""){
            key=src":"dpt
            n=split(times[key],arr,",")
            # Slide window: keep only last 60s
            new_times=""
            count=0
            for(j=1;j<=n;j++){
                if(ts-arr[j]<=60){ new_times=(new_times=="")?arr[j]:new_times","arr[j]; count++ }
            }
            times[key]=(new_times=="")?ts:new_times","ts
            count++
            if(count>10 && !flagged[key]){
                flagged[key]=1
                total[key]+=count
            }
            total[key]++
        }
    }
    END {
        for(key in flagged){
            split(key,parts,":")
            printf "%d %s %s\n", total[key], parts[1], parts[2]
        }
    }' | sort -rn | head -5)

    # --- Attempts on installed service ports ---
    local SVC_HITS=""
    for ENTRY in "${SERVICES[@]}"; do
        IFS='|' read -r LABEL PACKAGES SVCS DEFAULT_PORTS RISK CONFIG_KEY <<< "$ENTRY"
        local INSTALLED_PKG
        INSTALLED_PKG=$(is_package_installed "$PACKAGES")
        [[ -z "$INSTALLED_PKG" ]] && continue
        for PORT_PROTO in $DEFAULT_PORTS; do
            local PORT
            PORT=$(echo "$PORT_PROTO" | cut -d'/' -f1)
            local COUNT
            if [[ -z "$BLOCKS" ]]; then
                COUNT=0
            else
                COUNT=$(printf '%s' "$BLOCKS" | grep -F "DPT=${PORT}" | wc -l | tr -d '[:space:]')
                COUNT=$(( ${COUNT:-0} ))
            fi
            if [[ "$COUNT" -gt 0 ]]; then
                SVC_HITS="${SVC_HITS}${COUNT} ${LABEL} (${PORT_PROTO})\n"
            fi
        done
    done

    # --- Terminal: short summary ---
    echo -e "  ${DIM}$(t log_period) : ${LOG_DAYS} $(t log_days_unit) — ${DAYS_AVAILABLE} $(t log_available)${RESET}"
    echo

    # Total blocks
    if [[ "${TOTAL:-0}" -gt 0 ]]; then
        local BLOCK_COLOR="$CYAN"
        (( TOTAL > 1000 )) && BLOCK_COLOR="$YELLOW"
        (( TOTAL > 5000 )) && BLOCK_COLOR="$RED"
        echo -e "  ${BLOCK_COLOR}${BOLD}✖ ${TOTAL} $(t log_total_blocks)${RESET}"
    fi

    # Bruteforce
    if [[ -n "$BRUTE_HITS" ]]; then
        echo
        echo -e "  ${RED}${BOLD}⚠ $(t log_brute_title) :${RESET}"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local CNT IP PORT
            CNT=$(echo "$line" | awk '{print $1}')
            IP=$(echo "$line"  | awk '{print $2}')
            PORT=$(echo "$line" | awk '{print $3}')
            local GEO; GEO=$(get_ip_geo "$IP")
            local GEO_STR=""; [[ -n "$GEO" ]] && GEO_STR=" (${GEO})"
            echo -e "  ${RED}  → ${CNT} $(t log_brute_found) ${IP}${GEO_STR} $(t log_brute_on) ${PORT}/tcp${RESET}"
            log WARN "${CNT} $(t log_brute_found) ${IP}${GEO_STR} $(t log_brute_on) ${PORT}" \
                "" "--nature=improvement"
        done <<< "$BRUTE_HITS"
    else
        echo -e "  ${GREEN}✔ $(t log_brute_none)${RESET}"
    fi

    # Top IP (just the first one on terminal)
    local TOP_IP TOP_IP_COUNT
    TOP_IP=$(echo "$SRC_IPS" | head -1 | awk '{print $2}')
    TOP_IP_COUNT=$(echo "$SRC_IPS" | head -1 | awk '{print $1}')
    if [[ -n "$TOP_IP" ]]; then
        local GEO; GEO=$(get_ip_geo "$TOP_IP")
        local GEO_STR=""; [[ -n "$GEO" ]] && GEO_STR=" (${GEO})"
        echo -e "  ${DIM}ℹ $(t log_top_ips) : ${TOP_IP}${GEO_STR} — ${TOP_IP_COUNT} $(t log_attempts)${RESET}"
    fi

    # Top port (just the first one on terminal)
    local TOP_PORT TOP_PORT_COUNT
    TOP_PORT=$(echo "$DEST_PORTS" | head -1 | awk '{print $2}')
    TOP_PORT_COUNT=$(echo "$DEST_PORTS" | head -1 | awk '{print $1}')
    if [[ -n "$TOP_PORT" ]]; then
        echo -e "  ${DIM}ℹ $(t log_top_ports) : ${TOP_PORT}/tcp — ${TOP_PORT_COUNT} $(t log_attempts)${RESET}"
    fi

    # Service hits on terminal
    if [[ -n "$SVC_HITS" ]]; then
        echo
        echo -e "  ${YELLOW}⚠ $(t log_svc_hits) :${RESET}"
        echo -e "$SVC_HITS" | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local CNT SVC
            CNT=$(echo "$line" | awk '{print $1}')
            SVC=$(echo "$line" | cut -d' ' -f2-)
            echo -e "  ${YELLOW}  → ${SVC} — ${CNT} $(t log_attempts)${RESET}"
        done
    fi

    echo

    # --- Detailed report ---
    if is_detailed; then
        {
            echo
            echo "=== $(t sec_logs) — $(t log_period) : ${LOG_DAYS} $(t log_days_unit) ==="
            echo "$(t log_total_blocks) : $TOTAL"
            echo "$(t log_available)    : $DAYS_AVAILABLE"
            echo
            echo "--- $(t log_top_ips) ---"
            echo "$SRC_IPS" | while read -r cnt ip; do
                local geo; geo=$(get_ip_geo "$ip")
                local geo_str=""; [[ -n "$geo" ]] && geo_str=" (${geo})"
                printf "  %-20s%-32s %s $(t log_attempts)\n" "$ip" "$geo_str" "$cnt"
            done
            echo
            echo "--- $(t log_top_ports) ---"
            echo "$DEST_PORTS" | while read -r cnt port; do
                printf "  %-10s %s $(t log_attempts)\n" "${port}/tcp" "$cnt"
            done
            echo
            echo "--- $(t log_brute_title) ---"
            if [[ -n "$BRUTE_HITS" ]]; then
                echo "$BRUTE_HITS" | while read -r cnt ip port; do
                    local geo; geo=$(get_ip_geo "$ip")
                    local geo_str=""; [[ -n "$geo" ]] && geo_str=" (${geo})"
                    printf "  %-20s%-32s %-10s %s $(t log_attempts)\n" "$ip" "$geo_str" "${port}/tcp" "$cnt"
                done
            else
                echo "  $(t log_brute_none)"
            fi
            echo
            echo "--- $(t log_svc_hits) ---"
            if [[ -n "$SVC_HITS" ]]; then
                echo -e "$SVC_HITS" | while IFS= read -r line; do
                    [[ -z "$line" ]] && continue
                    echo "  $line $(t log_attempts)"
                done
            else
                echo "  $(t log_svc_hits_none)"
            fi
            echo
        } >> "$LOGFILE"
    fi
}

# ==========================================================
# DDNS / EXTERNAL EXPOSURE ANALYSIS
# Detects active DDNS clients, extracts configured domain,
# and crosses with unrestricted UFW ALLOW rules to identify
# ports potentially exposed to the internet.
# Score: -1 global if DDNS active + open ports (not per port)
# ==========================================================

audit_ddns() {
    log_section "$(t sec_ddns)"

    # --- DDNS client registry ---
    # Format: "label|packages|services|config_files"
    local DDNS_CLIENTS=(
        "ddclient|ddclient|ddclient|/etc/ddclient.conf"
        "inadyn|inadyn|inadyn|/etc/inadyn.conf /etc/inadyn/inadyn.conf"
        "No-IP DUC|noip2|noip2|/etc/no-ip2.conf"
        "DuckDNS (script)|duckdns||/etc/cron.d/duckdns /root/duckdns/duck.sh"
    )

    local FOUND_CLIENT=false
    local CLIENT_LABEL="" CLIENT_DOMAIN="" CLIENT_ACTIVE=false

    for ENTRY in "${DDNS_CLIENTS[@]}"; do
        IFS='|' read -r LABEL PACKAGES SERVICES CONFIG_FILES <<< "$ENTRY"

        # Check package installed
        local INSTALLED=false
        for PKG in $PACKAGES; do
            dpkg -l "$PKG" 2>/dev/null | grep -q "^ii" && INSTALLED=true && break
        done
        # Also check for script-based clients (DuckDNS)
        for CFG in $CONFIG_FILES; do
            [[ -f "$CFG" ]] && INSTALLED=true && break
        done
        $INSTALLED || continue

        FOUND_CLIENT=true
        CLIENT_LABEL="$LABEL"

        # Check service active
        CLIENT_ACTIVE=false
        for SVC in $SERVICES; do
            systemctl is-active "$SVC" >/dev/null 2>&1 && CLIENT_ACTIVE=true && break
        done
        # DuckDNS: check cron entry
        if [[ "$LABEL" == "DuckDNS (script)" ]]; then
            (crontab -l 2>/dev/null; cat /etc/cron.d/duckdns 2>/dev/null) \
                | grep -q "duckdns" && CLIENT_ACTIVE=true
        fi

        # Extract domain from config
        CLIENT_DOMAIN=""
        for CFG in $CONFIG_FILES; do
            [[ ! -f "$CFG" ]] && continue
            case "$LABEL" in
                "ddclient")
                    # Try standard host/hostname key first
                    CLIENT_DOMAIN=$(grep -E "^(host|hostname)\s*=" "$CFG" 2>/dev/null \
                        | head -1 | cut -d'=' -f2 | tr -d ' "' || true)
                    # DuckDNS format: domain on last non-comment line, may have http:// prefix
                    if [[ -z "$CLIENT_DOMAIN" ]]; then
                        CLIENT_DOMAIN=$(grep -vE "^\s*#|^\s*$|protocol=|use=|login=|password=" "$CFG" 2>/dev/null \
                            | tail -1 | tr -d ' \\' | sed 's|^http://||;s|^https://||' || true)
                    fi ;;
                "inadyn")
                    CLIENT_DOMAIN=$(grep -E "hostname\s*=" "$CFG" 2>/dev/null \
                        | head -1 | cut -d'=' -f2 | tr -d ' "' || true) ;;
                "No-IP DUC")
                    CLIENT_DOMAIN=$(grep -E "^hostname" "$CFG" 2>/dev/null \
                        | head -1 | awk '{print $2}' || true) ;;
                "DuckDNS (script)")
                    CLIENT_DOMAIN=$(grep -oE '[a-z0-9-]+\.duckdns\.org' "$CFG" 2>/dev/null \
                        | head -1 || true) ;;
            esac
            [[ -n "$CLIENT_DOMAIN" ]] && break
        done

        break  # Use first detected client
    done

    if ! $FOUND_CLIENT; then
        log OK "$(t ddns_none)"
        return
    fi

    # Display client info
    if $CLIENT_ACTIVE; then
        echo -e "  ${YELLOW}${BOLD}⚠ $(t ddns_found) : ${CLIENT_LABEL}${RESET}"
    else
        log INFO "$(t ddns_inactive) : ${CLIENT_LABEL}"
        return
    fi

    if [[ -n "$CLIENT_DOMAIN" ]]; then
        echo -e "  ${DIM}  $(t ddns_domain) : ${CLIENT_DOMAIN}${RESET}"
    else
        echo -e "  ${DIM}  $(t ddns_no_domain)${RESET}"
    fi
    echo

    # --- Cross with UFW open rules (ALLOW without source restriction) ---
    local OPEN_RULES
    OPEN_RULES=$(ufw status numbered 2>/dev/null \
        | grep -E "ALLOW IN" \
        | grep -v "from [0-9]\|from [0-9a-fA-F]*:" \
        | grep -v "Anywhere.*ALLOW IN.*Anywhere" || true)

    if [[ -z "$OPEN_RULES" ]]; then
        log OK "$(t ddns_no_ports)"
        return
    fi

    # List exposed ports + check for high/critical services
    echo -e "  ${YELLOW}${BOLD}$(t ddns_ports_title) :${RESET}"
    local HAS_HIGH_RISK=false

    while IFS= read -r rule; do
        [[ -z "$rule" ]] && continue
        local PORT_PROTO
        PORT_PROTO=$(echo "$rule" | grep -oE '[0-9]+/(tcp|udp)' | head -1)
        [[ -z "$PORT_PROTO" ]] && PORT_PROTO=$(echo "$rule" | grep -oE '[0-9]+' | head -1)

        # Check if port belongs to a high/critical service
        local MATCH_SVC="" MATCH_RISK=""
        for ENTRY in "${SERVICES[@]}"; do
            IFS='|' read -r LABEL PACKAGES SVCS DEFAULT_PORTS RISK CONFIG_KEY <<< "$ENTRY"
            for PP in $DEFAULT_PORTS; do
                local P; P=$(echo "$PP" | cut -d'/' -f1)
                if echo "$PORT_PROTO" | grep -q "^${P}"; then
                    INSTALLED_PKG=$(is_package_installed "$PACKAGES")
                    if [[ -n "$INSTALLED_PKG" ]]; then
                        MATCH_SVC="$LABEL"; MATCH_RISK="$RISK"; break 2
                    fi
                fi
            done
        done

        local LINE_COLOR="$DIM"
        local RISK_TAG=""
        if [[ "$MATCH_RISK" == "critical" || "$MATCH_RISK" == "high" ]]; then
            LINE_COLOR="$YELLOW"
            RISK_TAG=" ${RED}[${MATCH_RISK}]${RESET}"
            HAS_HIGH_RISK=true
        fi
        echo -e "  ${LINE_COLOR}  → ${PORT_PROTO}${MATCH_SVC:+ (${MATCH_SVC})}${RESET}${RISK_TAG}"
    done <<< "$OPEN_RULES"

    echo

    # Score — single -1 regardless of port count
    if $HAS_HIGH_RISK; then
        log WARN "$(t ddns_high_warn)" "" "--nature=action"
    else
        log WARN "$(t ddns_warn)" "" "--nature=improvement"
    fi

    echo -e "  ${DIM}ℹ $(t ddns_advice)${RESET}"
    echo

    # Detailed report
    if is_detailed; then
        {
            echo
            echo "--- $(t sec_ddns) ---"
            echo "Client   : $CLIENT_LABEL"
            echo "Active   : $CLIENT_ACTIVE"
            [[ -n "$CLIENT_DOMAIN" ]] && echo "Domain   : $CLIENT_DOMAIN"
            echo "$(t ddns_ports_title) :"
            echo "$OPEN_RULES" | while IFS= read -r r; do
                [[ -n "$r" ]] && echo "  $r"
            done
            echo "$(t ddns_advice)"
            echo
        } >> "$LOGFILE"
    fi
}

# ==========================================================
# DOCKER ANALYSIS
# Separate section — detects bypass of UFW via iptables,
# then lists exposed container ports and checks UFW DENY coverage.
# ==========================================================

audit_docker() {
    log_section "$(t sec_docker)"

    # Docker installed?
    if ! command -v docker >/dev/null 2>&1; then
        log INFO "$(t docker_missing)"
        return
    fi

    # Docker service active?
    if ! systemctl is-active docker >/dev/null 2>&1; then
        log INFO "$(t docker_no_daemon)"
        return
    fi

    # --- Check 1: iptables bypass ---
    local IPTABLES_DISABLED=false
    if [[ -f /etc/docker/daemon.json ]]; then
        grep -q '"iptables"[[:space:]]*:[[:space:]]*false' /etc/docker/daemon.json \
            && IPTABLES_DISABLED=true
    fi

    if $IPTABLES_DISABLED; then
        log OK "$(t docker_iptables_ok)"
    else
        log ALERT "$(t docker_bypass_warn)" "" "--nature=action" "--cmd="
        log_recommendation "$(t docker_bypass_fix)"
    fi

    # --- Check 2: exposed container ports ---
    echo
    echo -e "  ${BOLD}$(t docker_ports_title)${RESET}"

    local DOCKER_PORTS
    DOCKER_PORTS=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
        | grep -v '^$' || true)

    if [[ -z "$DOCKER_PORTS" ]]; then
        log OK "$(t docker_no_ports)"
        return
    fi

    local FOUND_ISSUE=false
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local CONTAINER_NAME
        CONTAINER_NAME=$(echo "$line" | awk '{print $1}')
        # Extract host ports — format: 0.0.0.0:PORT->CPORT/proto or :::PORT->...
        local HOST_PORTS
        HOST_PORTS=$(echo "$line" | grep -oE '(0\.0\.0\.0|:::|\[::\]):([0-9]+)' \
            | grep -oE '[0-9]+$' | sort -u || true)

        [[ -z "$HOST_PORTS" ]] && continue

        while IFS= read -r PORT; do
            [[ -z "$PORT" ]] && continue
            local EXPOSURE
            EXPOSURE=$(analyze_port_exposure "$PORT")
            if [[ "$EXPOSURE" == "deny" ]]; then
                log_detail "${CONTAINER_NAME}:${PORT} — $(t docker_port_ok)"
            else
                FOUND_ISSUE=true
                # --no-score: port already counted by check_listening_ports_analysis
                # --nature=improvement: contextual Docker warning, not a duplicate action
                log WARN "${CONTAINER_NAME} — $(t docker_port_warn): ${PORT}/tcp" \
                    "" "--no-score" "--nature=improvement"
                if ! $IPTABLES_DISABLED; then
                    log_detail "$(t docker_bypass_warn | cut -c1-80)…"
                fi
            fi
        done <<< "$HOST_PORTS"
    done <<< "$DOCKER_PORTS"

    $FOUND_ISSUE || log OK "$(t docker_no_ports)"
}

# ==========================================================
# FIX MODE
# Called at end of show_summary() when --fix is passed.
# Iterates AUDIT_ITEMS of nature "action", proposes each
# fix interactively (or applies all with --yes).
# Items with empty command are shown as manual.
# ==========================================================

run_fixes() {
    local W=58

    # Collect action items
    local AUTO_ITEMS=() MANUAL_ITEMS=()
    local item
    for item in "${AUDIT_ITEMS[@]}"; do
        local LVL NAT MSG CMD
        LVL=$(echo "$item" | cut -d'|' -f1)
        NAT=$(echo "$item" | cut -d'|' -f2)
        MSG=$(echo "$item" | cut -d'|' -f3)
        CMD=$(echo "$item" | cut -d'|' -f4-)
        [[ "$NAT" != "action" ]] && continue
        if [[ -n "$CMD" ]]; then
            AUTO_ITEMS+=( "$MSG|$CMD" )
        else
            MANUAL_ITEMS+=( "$MSG" )
        fi
    done

    # Sort ufw delete commands in descending rule number order
    # to avoid renumbering issues when deleting multiple rules
    local SORTED_ITEMS=()
    local UFW_DELETE_ITEMS=() OTHER_ITEMS=()
    for item in "${AUTO_ITEMS[@]}"; do
        local CMD="${item#*|}"
        if echo "$CMD" | grep -qE "ufw.*--force delete [0-9]+$"; then
            UFW_DELETE_ITEMS+=( "$item" )
        else
            OTHER_ITEMS+=( "$item" )
        fi
    done
    # Sort ufw delete items by rule number descending (last word of CMD)
    if [[ ${#UFW_DELETE_ITEMS[@]} -gt 0 ]]; then
        while IFS= read -r sorted_item; do
            [[ -n "$sorted_item" ]] && SORTED_ITEMS+=( "$sorted_item" )
        done < <(printf '%s\n' "${UFW_DELETE_ITEMS[@]}" | awk -F'|' '{
            cmd=$2; n=split(cmd,a," "); num=a[n]+0; print num, $0
        }' | sort -rn | cut -d' ' -f2-)
    fi
    SORTED_ITEMS+=( "${OTHER_ITEMS[@]}" )
    AUTO_ITEMS=( "${SORTED_ITEMS[@]}" )

    local TOTAL_AUTO=${#AUTO_ITEMS[@]}
    local TOTAL_MANUAL=${#MANUAL_ITEMS[@]}

    echo
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    banner_row "${BOLD}$(t fix_title)${RESET}" "" $W
    echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"

    if (( TOTAL_AUTO == 0 && TOTAL_MANUAL == 0 )); then
        banner_row "  $(t fix_none)" "" $W
        echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"
        return
    fi

    # Show counts
    (( TOTAL_AUTO   > 0 )) && banner_row "  ${GREEN}✔${RESET}  ${TOTAL_AUTO} $(t fix_summary_auto)"   "" $W
    (( TOTAL_MANUAL > 0 )) && banner_row "  ${YELLOW}⚠${RESET}  ${TOTAL_MANUAL} $(t fix_summary_manual)" "" $W
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    # ---- Manual items (display only) ----
    if (( TOTAL_MANUAL > 0 )); then
        echo
        echo -e "  ${YELLOW}${BOLD}[$(t fix_manual | tr '[:lower:]' '[:upper:]')]${RESET}"
        for item in "${MANUAL_ITEMS[@]}"; do
            local DISP="${item:0:56}"; [[ ${#item} -gt 56 ]] && DISP="${DISP}…"
            echo -e "  ${YELLOW}⚠${RESET}  ${DIM}${DISP}${RESET}"
        done
    fi

    # ---- Automatic items ----
    if (( TOTAL_AUTO == 0 )); then return; fi

    local APPLIED=0

    echo
    if $FIX_YES; then
        echo -e "  ${CYAN}${BOLD}$(t fix_applying)${RESET}"
    fi

    for item in "${AUTO_ITEMS[@]}"; do
        local MSG CMD
        MSG="${item%%|*}"
        CMD="${item#*|}"
        local DISP="${MSG:0:52}"; [[ ${#MSG} -gt 52 ]] && DISP="${DISP}…"

        echo
        echo -e "  ${RED}${BOLD}✖${RESET}  ${DISP}"
        echo -e "  ${DIM}→ ${CMD}${RESET}"

        local DO_APPLY=false

        if $FIX_YES; then
            DO_APPLY=true
        else
            # Interactive prompt — loop until valid input
            while true; do
                printf "  %s [y/N] " "$(t fix_apply_prompt)"
                local REPLY
                read -r REPLY < /dev/tty
                case "${REPLY,,}" in
                    y|yes|o|oui) DO_APPLY=true;  break ;;
                    n|no|"")     DO_APPLY=false; break ;;
                    *) echo -e "  ${YELLOW}y/n${RESET}" ;;
                esac
            done
        fi

        if $DO_APPLY; then
            if eval "$CMD" < /dev/null > /dev/null 2>&1; then
                echo -e "  ${GREEN}✔ $(t fix_applied)${RESET}"
                APPLIED=$(( APPLIED + 1 ))
                use_logfile && echo "  [FIX APPLIED] $CMD" >> "$LOGFILE"
            else
                echo -e "  ${RED}✖ $(t fix_manual)${RESET}"
                use_logfile && echo "  [FIX FAILED]  $CMD" >> "$LOGFILE"
            fi
        else
            echo -e "  ${DIM}$(t fix_skipped)${RESET}"
        fi
    done

    echo
    if (( APPLIED > 0 )); then
        echo -e "  ${GREEN}${BOLD}$(t fix_done)${RESET}"
    else
        echo -e "  ${DIM}$(t fix_none_applied)${RESET}"
    fi
    echo
}

# ==========================================================
# FINAL SUMMARY
# ==========================================================

show_summary() {
    (( SCORE < 0 )) && SCORE=0
    # Firewall inactive — cap score at 3 regardless of other checks
    # Applied here (after all score_deduct calls) so the cap always wins
    if $FW_INACTIVE && (( SCORE > 3 )); then
        SCORE=3
        SCORE_BREAKDOWN+=( "$(t score_cap_fw)|⚠|cap" )
    fi
    local RISK RISK_COLOR RISK_ICON
    if   (( SCORE <= 4 )); then RISK="$(t sum_risk_high)"; RISK_COLOR="$RED";    RISK_ICON="✖"
    elif (( SCORE <= 7 )); then RISK="$(t sum_risk_med)";  RISK_COLOR="$YELLOW"; RISK_ICON="⚠"
    else                        RISK="$(t sum_risk_low)";  RISK_COLOR="$GREEN";  RISK_ICON="✔"
    fi

    # Network context label and color
    local CTX_LABEL CTX_COLOR CTX_ICON
    if [[ "$NETWORK_CONTEXT" == "public" ]]; then
        CTX_LABEL="$(t ctx_public)"
        [[ -n "$PUBLIC_IP" ]] && CTX_LABEL="$CTX_LABEL ($PUBLIC_IP)"
        CTX_COLOR="$RED"; CTX_ICON="⚡"
    else
        CTX_LABEL="$(t ctx_local)"
        CTX_COLOR="$GREEN"; CTX_ICON="🏠"
    fi

    # Separate AUDIT_ITEMS into 3 buckets
    local ACTION_ITEMS=() IMPROVEMENT_ITEMS=() STRUCTURAL_ITEMS=()
    local item
    for item in "${AUDIT_ITEMS[@]}"; do
        local LVL NAT MSG
        LVL=$(echo "$item" | cut -d'|' -f1)
        NAT=$(echo "$item" | cut -d'|' -f2)
        MSG=$(echo "$item" | cut -d'|' -f3-)
        case "$NAT" in
            action)       ACTION_ITEMS+=( "$LVL|$MSG" ) ;;
            improvement)  IMPROVEMENT_ITEMS+=( "$LVL|$MSG" ) ;;
            structural)   STRUCTURAL_ITEMS+=( "$LVL|$MSG" ) ;;
        esac
    done

    # Determine interpretation phrase
    local HAS_ACTION=false HAS_IMPROVE=false HAS_STRUCT=false
    [[ ${#ACTION_ITEMS[@]}       -gt 0 ]] && HAS_ACTION=true
    [[ ${#IMPROVEMENT_ITEMS[@]}  -gt 0 ]] && HAS_IMPROVE=true
    [[ ${#STRUCTURAL_ITEMS[@]}   -gt 0 ]] && HAS_STRUCT=true

    local INTERP_KEY
    if   ! $HAS_ACTION && ! $HAS_IMPROVE && ! $HAS_STRUCT; then
        INTERP_KEY="sum_interp_clean"
    elif ! $HAS_ACTION && ! $HAS_IMPROVE && $HAS_STRUCT; then
        INTERP_KEY="sum_interp_structural"
    elif $HAS_ACTION && $HAS_STRUCT; then
        INTERP_KEY="sum_interp_mixed"
    elif $HAS_ACTION; then
        INTERP_KEY="sum_interp_action"
    else
        INTERP_KEY="sum_interp_structural"
    fi

    local W=58

    # --- Header ---
    echo
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}"
    banner_row "${BOLD}$(t sec_summary)${RESET}" "" $W
    echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
    banner_row "$(t sum_score)" " ${CYAN}${BOLD}${SCORE}/10${RESET}"                       $W
    banner_row "$(t sum_risk)"  " ${RISK_COLOR}${BOLD}${RISK_ICON} ${RISK}${RESET}"        $W
    banner_row "$(t ctx_label)" " ${CTX_COLOR}${BOLD}${CTX_ICON} ${CTX_LABEL}${RESET}"     $W

    # --- ACTION block ---
    if [[ ${#ACTION_ITEMS[@]} -gt 0 ]]; then
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        banner_row "${RED}${BOLD}✖ $(t sum_cat_action)${RESET}" "" $W
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        for entry in "${ACTION_ITEMS[@]}"; do
            local LVL MSG ICON_C
            LVL="${entry%%|*}"; MSG="${entry#*|}"
            [[ "$LVL" == "ALERT" ]] && ICON_C="${RED}✖${RESET}" || ICON_C="${YELLOW}⚠${RESET}"
            local DISP="${MSG:0:50}"; [[ ${#MSG} -gt 50 ]] && DISP="${DISP}…"
            banner_row "  ${ICON_C}  ${DIM}${DISP}${RESET}" "" $W
        done
    fi

    # --- IMPROVEMENT block ---
    if [[ ${#IMPROVEMENT_ITEMS[@]} -gt 0 ]]; then
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        banner_row "${YELLOW}${BOLD}⚠ $(t sum_cat_improvement)${RESET}" "" $W
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        for entry in "${IMPROVEMENT_ITEMS[@]}"; do
            local LVL MSG ICON_C
            LVL="${entry%%|*}"; MSG="${entry#*|}"
            [[ "$LVL" == "ALERT" ]] && ICON_C="${RED}✖${RESET}" || ICON_C="${YELLOW}⚠${RESET}"
            local DISP="${MSG:0:50}"; [[ ${#MSG} -gt 50 ]] && DISP="${DISP}…"
            banner_row "  ${ICON_C}  ${DIM}${DISP}${RESET}" "" $W
        done
    fi

    # --- STRUCTURAL block ---
    if [[ ${#STRUCTURAL_ITEMS[@]} -gt 0 ]]; then
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        banner_row "${GREEN}${BOLD}ℹ $(t sum_cat_structural)${RESET}" "" $W
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        for entry in "${STRUCTURAL_ITEMS[@]}"; do
            local LVL MSG
            LVL="${entry%%|*}"; MSG="${entry#*|}"
            local DISP="${MSG:0:50}"; [[ ${#MSG} -gt 50 ]] && DISP="${DISP}…"
            banner_row "  ${GREEN}ℹ${RESET}  ${DIM}${DISP}${RESET}" "" $W
        done
    fi

    # --- Score breakdown (context deductions) ---
    if [[ ${#SCORE_BREAKDOWN[@]} -gt 0 ]]; then
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        banner_row "${BOLD}$(t score_breakdown)${RESET}" "" $W
        echo -e "${BLUE}${BOLD}╠══════════════════════════════════════════════════════════════╣${RESET}"
        for entry in "${SCORE_BREAKDOWN[@]}"; do
            local REASON DEDUCT CTX
            REASON=$(echo "$entry" | cut -d'|' -f1)
            DEDUCT=$(echo "$entry" | cut -d'|' -f2)
            CTX=$(echo "$entry"    | cut -d'|' -f3)
            local DISP="${REASON:0:42}"; [[ ${#REASON} -gt 42 ]] && DISP="${DISP}…"
            local CTX_SUFFIX=""
            if [[ "$CTX" == "cap" ]]; then
                banner_row "${YELLOW}⚠  ${DIM}${DISP}${RESET}" "" $W
            else
                [[ "$CTX" == "public" ]] && CTX_SUFFIX=" ${DIM}$(t score_pub_penalty)${RESET}"
                banner_row "${RED}-${DEDUCT}${RESET}  ${DIM}${DISP}${RESET}" "${CTX_SUFFIX}" $W
            fi
        done
    fi

    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}"

    # Interpretation phrase
    echo
    local INTERP_COLOR="$GREEN"
    $HAS_ACTION  && INTERP_COLOR="$RED"
    ! $HAS_ACTION && $HAS_IMPROVE && INTERP_COLOR="$YELLOW"
    echo -e "  ${INTERP_COLOR}${BOLD}$(t $INTERP_KEY)${RESET}"

    # Implicit policy note — shown only when score is clean but high/critical
    # services have no explicit UFW rule (relying on default deny policy)
    if [[ ${#IMPLICIT_POLICY_SVCS[@]} -gt 0 ]] && ! $HAS_ACTION; then
        local DEFAULT_IN
        DEFAULT_IN=$(ufw status verbose 2>/dev/null | grep "Default:" \
            | grep -oE "(deny|reject|allow)" | head -1 || echo "")
        if [[ "$DEFAULT_IN" == "deny" || "$DEFAULT_IN" == "reject" ]]; then
            echo
            echo -e "  ${CYAN}ℹ $(t sum_implicit_note)${RESET}"
            local SVC_LIST
            SVC_LIST=$(IFS=", "; echo "${IMPLICIT_POLICY_SVCS[*]}")
            echo -e "  ${DIM}  $(t sum_implicit_svcs) ${SVC_LIST}${RESET}"
        fi
    fi

    echo
    echo -e "  ${DIM}$(t sum_cfg_ports) $CONFIG_FILE${RESET}"
    use_logfile && echo -e "  ${DIM}$(t sum_cfg_report) $LOGFILE${RESET}"
    echo

    # --fix mode: propose/apply corrections after summary
    $FIX_MODE && run_fixes
}

# ==========================================================
# JSON EXPORT
# --json      : summary only (score, risk, context, items)
# --json-full : full audit (adds ports, services, UFW rules)
# Output: stdout always; file alongside .log if -d is set.
# ==========================================================

export_json() {
    local TIMESTAMP
    TIMESTAMP="$(date '+%Y-%m-%dT%H:%M:%S')"

    # --- helpers ---
    json_str()  { local S="$1"; S="${S//\\/\\\\}"; S="${S//\"/\\\"}";
                  S="${S//$'\n'/\\n}"; echo "\"$S\""; }
    json_bool() { $1 && echo "true" || echo "false"; }

    # --- build items arrays ---
    local ACTION_JSON="" IMPROVE_JSON="" STRUCT_JSON=""
    local item
    for item in "${AUDIT_ITEMS[@]}"; do
        local LVL NAT MSG CMD
        LVL=$(echo "$item" | cut -d'|' -f1)
        NAT=$(echo "$item" | cut -d'|' -f2)
        MSG=$(echo "$item" | cut -d'|' -f3)
        CMD=$(echo "$item" | cut -d'|' -f4-)
        local ENTRY="{\"level\":$(json_str "$LVL"),\"message\":$(json_str "$MSG"),\"command\":$(json_str "$CMD")}"
        case "$NAT" in
            action)      ACTION_JSON="${ACTION_JSON:+$ACTION_JSON,}$ENTRY" ;;
            improvement) IMPROVE_JSON="${IMPROVE_JSON:+$IMPROVE_JSON,}$ENTRY" ;;
            structural)  STRUCT_JSON="${STRUCT_JSON:+$STRUCT_JSON,}$ENTRY" ;;
        esac
    done

    # --- score breakdown ---
    local BREAKDOWN_JSON=""
    for entry in "${SCORE_BREAKDOWN[@]}"; do
        local REASON DEDUCT CTX
        REASON=$(echo "$entry" | cut -d'|' -f1)
        DEDUCT=$(echo "$entry" | cut -d'|' -f2)
        CTX=$(echo "$entry"    | cut -d'|' -f3)
        local E="{\"reason\":$(json_str "$REASON"),\"deduct\":$(json_str "$DEDUCT"),\"context\":$(json_str "$CTX")}"
        BREAKDOWN_JSON="${BREAKDOWN_JSON:+$BREAKDOWN_JSON,}$E"
    done

    # --- summary block (always present) ---
    local RISK_STR
    (( SCORE <= 4 )) && RISK_STR="$(t sum_risk_high)" \
        || { (( SCORE <= 7 )) && RISK_STR="$(t sum_risk_med)" \
        || RISK_STR="$(t sum_risk_low)"; }

    local JSON
    JSON="{"
    JSON+="\"version\":$(json_str "$VERSION"),"
    JSON+="\"timestamp\":$(json_str "$TIMESTAMP"),"
    JSON+="\"host\":$(json_str "$(hostname)"),"
    JSON+="\"summary\":{"
    JSON+="\"score\":$SCORE,"
    JSON+="\"risk\":$(json_str "$RISK_STR"),"
    JSON+="\"network_context\":$(json_str "$NETWORK_CONTEXT"),"
    JSON+="\"fw_inactive\":$(json_bool $FW_INACTIVE),"
    JSON+="\"counts\":{\"ok\":$OK_COUNT,\"warn\":$WARN_COUNT,\"alert\":$ALERT_COUNT}"
    JSON+="},"
    JSON+="\"items\":{"
    JSON+="\"action\":[${ACTION_JSON}],"
    JSON+="\"improvement\":[${IMPROVE_JSON}],"
    JSON+="\"structural\":[${STRUCT_JSON}]"
    JSON+="},"
    JSON+="\"score_breakdown\":[${BREAKDOWN_JSON}]"

    # --- full mode: append ports + UFW rules ---
    if $JSON_FULL; then
        local UFW_RULES_JSON=""
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            UFW_RULES_JSON="${UFW_RULES_JSON:+$UFW_RULES_JSON,}$(json_str "$rule")"
        done <<< "$(ufw status numbered 2>/dev/null | grep -E '^\[' || true)"

        local PORTS_JSON=""
        for KEY in "${!_LM_MAP[@]}"; do
            local P_PROTO P_PORT P_STATUS
            P_PROTO="${KEY%%:*}"; P_PORT="${KEY##*:}"
            P_STATUS="${_LM_MAP[$KEY]}"
            local E="{\"port\":$(json_str "$P_PORT"),\"proto\":$(json_str "$P_PROTO"),\"status\":$(json_str "$P_STATUS")}"
            PORTS_JSON="${PORTS_JSON:+$PORTS_JSON,}$E"
        done

        JSON+=",\"ufw_rules\":[${UFW_RULES_JSON}]"
        JSON+=",\"listening_ports\":[${PORTS_JSON}]"
    fi

    JSON+="}"

    # Pretty-print if python3 available, else raw
    local PRETTY
    if command -v python3 >/dev/null 2>&1; then
        PRETTY=$(echo "$JSON" | python3 -m json.tool 2>/dev/null || echo "$JSON")
    else
        PRETTY="$JSON"
    fi

    # Always print to stdout
    echo "$PRETTY"

    # Write to file alongside .log if -d is set
    if use_logfile && [[ -n "$LOGFILE" ]]; then
        local JSONFILE="${LOGFILE%.log}.json"
        echo "$PRETTY" > "$JSONFILE"
        echo -e "  ${DIM}$(t json_written) $JSONFILE${RESET}"
    fi
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
        detect_network_context
        check_dependencies
        check_firewall_status
        audit_services
        check_listening_ports_analysis
        check_listening_ports
        audit_ufw_logs
        audit_ddns
        audit_docker
        show_summary
        finalize_log
        $JSON_MODE && export_json
    fi
}

main "$@"