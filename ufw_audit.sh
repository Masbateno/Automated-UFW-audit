#!/bin/bash
# ==========================================================
# UFW-audit v0.3.0 (stable)
# UFW Firewall Audit Script for Linux
# ==========================================================

set -uo pipefail
export LC_ALL=C.UTF-8

VERSION="0.3.0"

OK_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0
SCORE=10

VERBOSE=false
HELP=false
VERSION_ONLY=false
AUDIT_REQUESTED=false
LOG_LEVEL="minimal"
LOGFILE=""
PORT_TOOL=""

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# ==========================================================
# HELPERS
# ==========================================================

is_detailed() {
    [[ "$LOG_LEVEL" == "detailed" && -n "$LOGFILE" ]]
}

# ==========================================================
# ROOT CHECK
# ==========================================================

check_root() {
    if (( EUID != 0 )) && $AUDIT_REQUESTED; then
        echo -e "${RED}[ERROR]${RESET} ${GREEN}UFW-audit v$VERSION${RESET}"
        echo "This script requires root privileges for audit operations."
        echo -e "Run with: ${YELLOW}sudo $0${RESET}"
        exit 1
    fi
}

# ==========================================================
# ARGUMENT PARSER
# ==========================================================

parse_arguments() {
    AUDIT_REQUESTED=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                AUDIT_REQUESTED=true
                ;;
            -h|--help)
                HELP=true
                ;;
            -d|--detailed)
                LOG_LEVEL="detailed"
                AUDIT_REQUESTED=true
                ;;
            -V|--version)
                VERSION_ONLY=true
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done
}

# ==========================================================
# VERSION
# ==========================================================

show_version() {
    echo -e "${GREEN}UFW-audit v$VERSION${RESET}"
    exit 0
}

# ==========================================================
# HELP
# ==========================================================

show_help() {
    echo -e "${GREEN}UFW-audit v$VERSION${RESET}"
    echo -e "Usage: ${YELLOW}./ufw_audit.sh [options]${RESET}"
    echo
    echo "Options:"
    echo "  -v, --verbose     Show full audit details"
    echo "  -d, --detailed    Generate detailed log"
    echo "  -V, --version     Show version"
    echo "  -h, --help        Show help"
    echo
    exit 0
}

# ==========================================================
# LOGGING
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
    if [[ -n "$LOGFILE" ]]; then
        echo "$TIMESTAMP $PREFIX $MESSAGE" >> "$LOGFILE"
        if is_detailed; then
            case "$LEVEL" in
                WARN|ALERT)
                    echo "---" >> "$LOGFILE"
                    echo "[DETAILS] $MESSAGE" >> "$LOGFILE"
                    echo "[RECOMMENDATION] $(generate_recommendation "$LEVEL" "$MESSAGE")" >> "$LOGFILE"
                    echo "---" >> "$LOGFILE"
                    ;;
            esac
        fi
    fi
}

generate_recommendation() {
    local LEVEL="$1"
    local MESSAGE="$2"
    local RECOMMENDATION=""

    case "$LEVEL" in
        WARN)
            if [[ "$MESSAGE" == *"listening ports"* ]]; then
                RECOMMENDATION="Review open ports and close unnecessary services. Use 'sudo ufw deny <port>' to block unwanted traffic."
            elif [[ "$MESSAGE" == *"ss"* || "$MESSAGE" == *"netstat"* ]]; then
                RECOMMENDATION="Install 'ss' (iproute2) for better port analysis: 'sudo apt install iproute2'."
            else
                RECOMMENDATION="Investigate the warning and apply security best practices."
            fi
            ;;
        ALERT)
            if [[ "$MESSAGE" == *"Firewall inactive"* ]]; then
                RECOMMENDATION="Enable UFW immediately: 'sudo ufw enable'. Ensure rules are configured before enabling."
            elif [[ "$MESSAGE" == *"ufw command not found"* ]]; then
                RECOMMENDATION="Install UFW: 'sudo apt install ufw' (Debian/Ubuntu)."
            else
                RECOMMENDATION="Critical issue detected. Remediate immediately and review system security."
            fi
            ;;
    esac

    echo "$RECOMMENDATION"
}

init_logfile() {
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
    LOGFILE="$SCRIPT_DIR/ufw_audit_$TIMESTAMP.log"

    touch "$LOGFILE" 2>/dev/null || {
        echo -e "${RED}[ERROR] Cannot create log file in $SCRIPT_DIR${RESET}"
        exit 1
    }

    echo -e "${GREEN}[OK]${RESET} Log file created: $LOGFILE"
}

init_log_header() {
    {
        echo "=========================================================="
        echo "UFW AUDIT REPORT v$VERSION - $(date)"
        echo "=========================================================="
        echo
        echo "[SYSTEM INFORMATION]"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "UFW Version: $(ufw version 2>/dev/null || echo "N/A")"
        echo "Audit initiated by: $(whoami)"
        echo
        echo "[SUMMARY OF FINDINGS]"
        echo "(Will be populated during audit)"
        echo
        echo "=========================================================="
        echo
    } > "$LOGFILE"
}

finalize_log() {
    {
        echo
        echo "=========================================================="
        echo "[AUDIT SUMMARY]"
        echo "OK: $OK_COUNT | WARNING: $WARN_COUNT | ALERT: $ALERT_COUNT"
        echo "Score: $SCORE/10"
        echo "Risk Level: $(get_risk_level)"
        echo
        echo "[RECOMMENDED ACTIONS]"
        echo "1. Review all warnings and alerts above."
        echo "2. Apply recommended fixes for alerts."
        echo "3. Schedule regular firewall audits."
        echo "=========================================================="
    } >> "$LOGFILE"
}

get_risk_level() {
    if (( SCORE <= 4 )); then
        echo "HIGH"
    elif (( SCORE <= 7 )); then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# ==========================================================
# DEPENDENCY CHECK
# ==========================================================

check_dependencies() {

    local MISSING_UFW=0

    # --- UFW (mandatory) ---
    if command -v ufw >/dev/null 2>&1; then
        log OK "ufw command found"
    else
        log ALERT "ufw command not found"
        echo
        echo "UFW is required for this audit."
        echo
        echo "Install it with:"
        echo "  Debian/Ubuntu : sudo apt install ufw"
        echo "  Arch Linux    : sudo pacman -S ufw"
        echo "  Fedora        : sudo dnf install ufw"
        echo "  OpenSUSE      : sudo zypper install ufw"
        echo
        MISSING_UFW=1
    fi

    # --- Port tools (optional but recommended) ---
    if command -v ss >/dev/null 2>&1; then
        PORT_TOOL="ss"
        log OK "ss command found (iproute2)"
    elif command -v netstat >/dev/null 2>&1; then
        PORT_TOOL="netstat"
        log WARN "'ss' not found, falling back to 'netstat'"
    else
        PORT_TOOL=""
        log WARN "Neither 'ss' nor 'netstat' command found"
        echo
        echo "Listening port analysis will be skipped."
        echo
        echo "Install one of the following:"
        echo
        echo "  Debian/Ubuntu : sudo apt install iproute2"
        echo "                  (legacy alternative: sudo apt install net-tools)"
        echo "  Arch Linux    : sudo pacman -S iproute2"
        echo "  Fedora        : sudo dnf install iproute"
        echo "  OpenSUSE      : sudo zypper install iproute2"
        echo
    fi

    if (( MISSING_UFW == 1 )); then
        echo
        log ERROR "Missing required dependency. Audit aborted."
        exit 1
    fi
}

# ==========================================================
# FIREWALL CHECK
# ==========================================================

check_firewall() {

    echo -e "\n${BOLD}=== FIREWALL CHECKLIST ===${RESET}\n"

    log OK "UFW installed"

    local STATUS
    STATUS=$(ufw status 2>/dev/null)

    if grep -q "Status: active" <<< "$STATUS"; then
        log OK "Firewall active"
    else
        log ALERT "Firewall inactive"
        is_detailed && echo "[FIX] sudo ufw enable" >> "$LOGFILE"
    fi
}

# ==========================================================
# LISTENING PORTS
# ==========================================================

check_listening_ports() {

    echo -e "\n${BOLD}=== LISTENING PORT ANALYSIS ===${RESET}\n"

    if [[ -z "$PORT_TOOL" ]]; then
        log INFO "Listening port check skipped (no ss/netstat available)"
        return
    fi

    local LISTEN=""
    local COUNT=0

    if [[ "$PORT_TOOL" == "ss" ]]; then
        LISTEN=$(ss -tulnH 2>/dev/null)
    else
        LISTEN=$(netstat -tuln 2>/dev/null | awk 'NR>2')
    fi

    [[ -n "$LISTEN" ]] && COUNT=$(wc -l <<< "$LISTEN")

    if (( COUNT == 0 )); then
        log OK "No listening ports detected"
    else
        log WARN "$COUNT listening ports detected"

        if $VERBOSE; then
            echo
            echo "$LISTEN"
        fi

        if is_detailed; then
            {
                echo
                echo "[LISTENING PORTS]"
                echo "$LISTEN"
                echo
            } >> "$LOGFILE"
        fi
    fi
}

# ==========================================================
# SUMMARY
# ==========================================================

show_summary() {

    (( SCORE < 0 )) && SCORE=0

    local RISK="LOW"
    local RISK_COLOR="$GREEN"

    if (( SCORE <= 4 )); then
        RISK="HIGH"
        RISK_COLOR="$RED"
    elif (( SCORE <= 7 )); then
        RISK="MEDIUM"
        RISK_COLOR="$YELLOW"
    fi

    echo -e "\n${BOLD}=== SUMMARY ===${RESET}"
    echo -e "OK: ${GREEN}$OK_COUNT${RESET}"
    echo -e "WARNING: ${YELLOW}$WARN_COUNT${RESET}"
    echo -e "ALERT: ${RED}$ALERT_COUNT${RESET}"
    echo -e "\nScore: ${CYAN}$SCORE/10${RESET}"
    echo -e "Risk: ${RISK_COLOR}$RISK${RESET}"
}

# ==========================================================
# MAIN
# ==========================================================

main() {
    parse_arguments "$@"
    $VERSION_ONLY && show_version
    $HELP && show_help
    check_root

    if $AUDIT_REQUESTED; then
        init_logfile
        init_log_header
        log INFO "Starting UFW audit"
        check_dependencies
        check_firewall
        check_listening_ports
        show_summary
        finalize_log
    fi
}

main "$@"
