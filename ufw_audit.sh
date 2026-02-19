#!/bin/bash
# ==========================================================
# UFW-audit v0.2
# UFW Firewall Audit Script for Linux
# ==========================================================

# ==========================================================
# GLOBAL VARIABLES
# ==========================================================

set -o pipefail

VERSION="0.2"

OK_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0
SCORE=10

VERBOSE=false
HELP=false
LOG_LEVEL="minimal"  # minimal par défaut
LOGFILE=""

# --- Colors ---
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# ==========================================================
# ARGUMENT PARSER
# ==========================================================

parse_arguments() {
    for ARG in "$@"; do
        case "$ARG" in
            -v|--verbose) VERBOSE=true ;;
            -h|--help) HELP=true ;;
            -d|--detailed) LOG_LEVEL="detailed" ;;
        esac
    done
}

# ==========================================================
# HELP MESSAGE
# ==========================================================

show_help() {
    echo -e "${BOLD}${GREEN}UFW-audit v$VERSION${RESET}"
    echo -e "${BOLD}${GREEN}UFW Firewall Audit Script for Linux${RESET}"
    echo
    echo "Usage: ./ufw_audit.sh [options]"
    echo
    echo "Options:"
    echo "  -v, --verbose     Show full audit details in terminal"
    echo "  -h, --help        Show help"
    echo "  -d, --detailed    Generate detailed log (full rules, listening ports, etc.)"
    echo
    exit 0
}

# ==========================================================
# ROOT CHECK
# ==========================================================

check_root() {
    if (( EUID != 0 )); then
        echo -e "${RED}[ERROR]${RESET} ${BOLD}${GREEN}UFW-audit v$VERSION${RESET}"
        echo "This script requires root privileges."
        echo -e "Run with: ${BOLD}sudo $0${RESET}"
        exit 1
    fi
}

# ==========================================================
# LOGGING SYSTEM
# ==========================================================

log() {
    local LEVEL="$1"
    local MESSAGE="$2"
    local TIMESTAMP
    TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    local COLOR=""
    local PREFIX=""

    case "$LEVEL" in
        INFO) COLOR="$CYAN"; PREFIX="[INFO]" ;;
        OK) COLOR="$GREEN"; PREFIX="[OK]"; ((OK_COUNT++)) ;;
        WARN) COLOR="$YELLOW"; PREFIX="[WARNING]"; ((WARN_COUNT++)); ((SCORE--)) ;;
        ALERT) COLOR="$RED"; PREFIX="[ALERT]"; ((ALERT_COUNT++)); ((SCORE-=2)) ;;
        ERROR) COLOR="$RED"; PREFIX="[ERROR]" ;;
    esac

    echo -e "${COLOR}${PREFIX}${RESET} $MESSAGE"
    echo "$TIMESTAMP $PREFIX $MESSAGE" >> "$LOGFILE"
}

# ==========================================================
# LOGFILE INITIALIZATION (INTERACTIVE)
# ==========================================================

init_logfile() {
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    DEFAULT_LOG_DIR="$SCRIPT_DIR"

    echo
    echo -e "${BOLD}Log file destination${RESET}"
    echo "Press ENTER to use default:"
    echo "$DEFAULT_LOG_DIR"
    echo

    while true; do
        read -r -p "Log directory: " USER_LOG_DIR
        LOG_DIR="${USER_LOG_DIR:-$DEFAULT_LOG_DIR}"
        LOG_DIR="$(eval echo "$LOG_DIR")"
        if mkdir -p "$LOG_DIR" 2>/dev/null; then
            break
        else
            echo -e "${RED}[ERROR]${RESET} Cannot create directory"
        fi
    done

    TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
    LOGFILE="$LOG_DIR/ufw_audit_$TIMESTAMP.log"

    echo
    echo -e "${GREEN}[OK]${RESET} Log file:"
    echo "$LOGFILE"
    echo
}

# ==========================================================
# LOG HEADER
# ==========================================================

init_log_header() {
    {
        echo "=========================================================="
        echo "UFW AUDIT REPORT v$VERSION - $(date)"
        echo "=========================================================="
        echo
        echo "[SYSTEM]"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "UFW Version: $(ufw version 2>/dev/null || echo "N/A")"
        echo
    } > "$LOGFILE"
}

# ==========================================================
# LOG SECTION HANDLER
# ==========================================================

log_section() {
    if $VERBOSE; then
        tee -a "$LOGFILE"
    else
        cat >> "$LOGFILE"
    fi
}

# ==========================================================
# HEADER DISPLAY
# ==========================================================

show_banner() {
    echo -e "${GREEN}==========================================================${RESET}"
    echo -e "${GREEN}UFW-audit v$VERSION${RESET}"
    echo -e "${GREEN}UFW Firewall Audit Script for Linux${RESET}"
    echo -e "${GREEN}==========================================================${RESET}"
    echo
}

# ==========================================================
# FIREWALL CHECK
# ==========================================================

check_firewall() {
    echo -e "\n${BOLD}=== FIREWALL CHECKLIST ===${RESET}\n"

    if command -v ufw &>/dev/null; then
        log OK "UFW installed"
        [[ "$LOG_LEVEL" == "detailed" ]] && echo "UFW version: $(ufw version)" >> "$LOGFILE"
    else
        log ALERT "UFW not installed"
        echo "[CRITICAL] Install UFW:" >> "$LOGFILE"
        if [ -f /etc/debian_version ]; then
            echo "sudo apt install ufw" >> "$LOGFILE"
        elif [ -f /etc/redhat-release ]; then
            echo "sudo dnf install ufw" >> "$LOGFILE"
        fi
        SCORE=0
        exit 1
    fi

    if ufw status | grep -q "inactive"; then
        log ALERT "Firewall inactive"
        [[ "$LOG_LEVEL" == "detailed" ]] && echo "[FIX] sudo ufw enable" >> "$LOGFILE"
    else
        log OK "Firewall active"
    fi

    [[ "$LOG_LEVEL" == "detailed" ]] && {
        echo "----- UFW STATUS -----" >> "$LOGFILE"
        ufw status verbose >> "$LOGFILE"
    }

    DEFAULTS=$(ufw status verbose | grep "Default:")
    [[ "$LOG_LEVEL" == "detailed" ]] && {
        echo "[POLICIES]" >> "$LOGFILE"
        echo "$DEFAULTS" >> "$LOGFILE"
    }

    if grep -q "deny (incoming)" <<< "$DEFAULTS"; then
        log OK "Incoming default = DENY"
    else
        log ALERT "Incoming default is NOT deny"
    fi

    if grep -q "allow (outgoing)" <<< "$DEFAULTS"; then
        log OK "Outgoing default = ALLOW"
    else
        log WARN "Outgoing default not standard"
    fi

    if grep -qi "^IPV6=yes" /etc/default/ufw 2>/dev/null; then
        log OK "IPv6 enabled"
    else
        log WARN "IPv6 not enabled"
    fi
}

# ==========================================================
# RULE ANALYSIS
# ==========================================================

check_rules() {
    echo -e "\n${BOLD}=== SECURITY ANALYSIS ===${RESET}\n"

    UFW_RULES=$(ufw status numbered 2>/dev/null)

    [[ "$LOG_LEVEL" == "detailed" ]] && {
        echo "[RULES]" >> "$LOGFILE"
        echo "$UFW_RULES" >> "$LOGFILE"
    }

    if grep -q "Anywhere" <<< "$UFW_RULES"; then
        log WARN "Rules allowing access from Anywhere detected"
        [[ "$LOG_LEVEL" == "detailed" ]] && grep "Anywhere" <<< "$UFW_RULES" >> "$LOGFILE"
    else
        log OK "No unrestricted Anywhere rules"
    fi

    SENSITIVE_PORTS="21 22 23 3389 5900 3306 5432"

    for PORT in $SENSITIVE_PORTS; do
        RULE=$(grep -E "\b$PORT(/tcp|/udp)?\b" <<< "$UFW_RULES")
        if [[ -n "$RULE" ]]; then
            if grep -q "Anywhere" <<< "$RULE"; then
                log ALERT "Sensitive port $PORT open to Anywhere"
            else
                log WARN "Sensitive port $PORT open (restricted)"
            fi
            [[ "$LOG_LEVEL" == "detailed" ]] && echo "$RULE" >> "$LOGFILE"
        fi
    done
}

# ==========================================================
# LISTENING PORTS
# ==========================================================

check_listening_ports() {
    LISTEN=$(ss -tuln | awk 'NR>1')
    COUNT=$(wc -l <<< "$LISTEN")

    [[ "$LOG_LEVEL" == "detailed" ]] && {
        echo "[LISTENING PORTS]" >> "$LOGFILE"
        echo "$LISTEN" >> "$LOGFILE"
    }

    if (( COUNT == 0 )); then
        log OK "No listening ports"
    else
        log WARN "$COUNT listening ports detected"
        if grep -q "0.0.0.0:" <<< "$LISTEN"; then
            log WARN "Services listening on all interfaces"
        fi
    fi
}

# ==========================================================
# FULL TOPOLOGY
# ==========================================================

show_topology() {
    [[ "$LOG_LEVEL" == "detailed" ]] && {
        {
            echo
            echo "=== FULL TOPOLOGY ==="
            echo
            ufw status numbered
            echo
            ss -tuln
            echo
            echo "=== AUDIT COMPLETED ==="
        } | log_section
    }
}

# ==========================================================
# SUMMARY
# ==========================================================

show_summary() {
    (( SCORE < 0 )) && SCORE=0

    RISK="LOW"
    if (( SCORE <= 4 )); then
        RISK="HIGH"
        COLOR="$RED"
    elif (( SCORE <= 7 )); then
        RISK="MEDIUM"
        COLOR="$YELLOW"
    else
        COLOR="$GREEN"
    fi

    echo -e "\n${BOLD}=== SUMMARY ===${RESET}"
    echo -e "OK: ${GREEN}$OK_COUNT${RESET}"
    echo -e "WARNING: ${YELLOW}$WARN_COUNT${RESET}"
    echo -e "ALERT: ${RED}$ALERT_COUNT${RESET}"
    echo -e "\nScore: ${CYAN}$SCORE/10${RESET}"
    echo -e "Risk: ${COLOR}$RISK${RESET}"
    echo
    echo "Log file:"
    echo "$LOGFILE"
    echo
}

# ==========================================================
# MAIN
# ==========================================================

main() {
    parse_arguments "$@"
    $HELP && show_help
    check_root
    init_logfile
    init_log_header
    show_banner
    log INFO "Starting audit"
    check_firewall
    check_rules
    check_listening_ports
    show_topology
    show_summary
}

main "$@"