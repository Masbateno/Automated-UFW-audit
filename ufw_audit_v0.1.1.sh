#!/bin/bash
# ==========================================================
# UFW-audit v0.1.1
# UFW Firewall Audit Script for Linux
# ==========================================================

# --- Check for sudo privileges ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\e[31m[ERROR]\e[0m UFW-audit v0.1.1"
    echo -e "This script requires root privileges to run UFW commands."
    echo -e "Please run it with sudo: \e[1msudo $0\e[0m"
    exit 1
fi

# --- Setup log path ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGFILE="$SCRIPT_DIR/ufw_audit_$(date +%Y%m%d_%H%M%S).log"

# --- Colors ---
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# --- Counters ---
OK_COUNT=0
WARN_COUNT=0
ALERT_COUNT=0

# --- Security score ---
SCORE=10

# --- Options ---
VERBOSE=false
HELP=false

# --- Parse arguments ---
for ARG in "$@"; do
    case "$ARG" in
        -v|--verbose) VERBOSE=true ;;
        -h|--help) HELP=true ;;
        *) ;;
    esac
done

# --- Help message ---
if $HELP; then
    echo -e "${BOLD}UFW-audit v0.1.1${RESET}"
    echo -e "UFW Firewall Audit Script for Linux"
    echo
    echo "Usage: sudo ./UFW-audit.sh [options]"
    echo
    echo "Options:"
    echo "  -v, --verbose     Show full audit details in terminal"
    echo "  -h, --help        Show this help message"
    exit 0
fi

# --- Functions ---
ok() {
    echo -e "[${GREEN}OK${RESET}] $1"
    echo "[OK] $1" >> "$LOGFILE"
    ((OK_COUNT++))
}

warn() {
    echo -e "[${YELLOW}WARNING${RESET}] $1"
    echo "[WARNING] $1" >> "$LOGFILE"
    ((WARN_COUNT++))
    ((SCORE--))
}

alert() {
    echo -e "[${RED}NOT OK${RESET}] $1"
    echo "[ALERT] $1" >> "$LOGFILE"
    ((ALERT_COUNT++))
    ((SCORE-=2))
}

log_section() {
    if $VERBOSE; then
        tee -a "$LOGFILE"
    else
        cat >> "$LOGFILE"
    fi
}

# --- Start Log ---
{
echo "=========================================================="
echo "UFW AUDIT REPORT - $(date)"
echo "=========================================================="
echo
echo "[SYSTEM]"
echo "- Hostname: $(hostname)"
echo "- UFW Version: $(ufw version 2>/dev/null || echo "N/A")"
echo "- Kernel: $(uname -r)"
echo
} > "$LOGFILE"

# ==========================================================
# CHECKLIST (inchangé)
# ==========================================================

echo -e "\e[1;32m==========================================================\e[0m"
echo -e "\e[1;32mUFW-audit v0.1.1\e[0m"
echo -e "\e[1;32mUFW Firewall Audit Script for Linux\e[0m"
echo -e "\e[1;32m==========================================================\e[0m"
echo -e
echo -e "\n${BOLD}=== FIREWALL CHECKLIST ===${RESET}\n"

# UFW installed (inchangé)
if command -v ufw &>/dev/null; then
    ok "UFW installed"
    echo "UFW version: $(ufw version)" >> "$LOGFILE"
else
    alert "UFW not installed"
    echo "[CRITICAL] UFW is required. Install with:" >> "$LOGFILE"
    if [ -f /etc/debian_version ]; then
        echo "  sudo apt update && sudo apt install ufw" >> "$LOGFILE"
    elif [ -f /etc/redhat-release ]; then
        echo "  sudo dnf install ufw" >> "$LOGFILE"
    else
        echo "  Consult your distribution documentation" >> "$LOGFILE"
    fi
    SCORE=0
    exit 1
fi

# Firewall active (inchangé)
if ufw status | grep -q "Status: inactive"; then
    alert "Firewall inactive"
    echo "[FIX] Enable with: sudo ufw enable" >> "$LOGFILE"
else
    ok "Firewall active"
fi
echo "----- UFW STATUS -----" >> "$LOGFILE"
ufw status verbose >> "$LOGFILE"
echo "----------------------" >> "$LOGFILE"

# Default policies (inchangé)
DEFAULTS=$(ufw status verbose | grep "Default:")
echo "[POLICIES]" >> "$LOGFILE"
echo "$DEFAULTS" >> "$LOGFILE"

if echo "$DEFAULTS" | grep -q "deny (incoming)"; then
    ok "Incoming default = DENY"
else
    alert "Incoming default is NOT deny"
    echo "[RISK] Incoming traffic not blocked by default" >> "$LOGFILE"
fi

if echo "$DEFAULTS" | grep -q "allow (outgoing)"; then
    ok "Outgoing default = ALLOW"
else
    warn "Outgoing default not standard"
    echo "[NOTE] Outgoing traffic not allowed by default" >> "$LOGFILE"
fi

# IPv6 (inchangé)
if grep -qi "^IPV6=yes" /etc/default/ufw 2>/dev/null; then
    ok "IPv6 enabled"
    echo "[INFO] IPv6 is enabled" >> "$LOGFILE"
else
    warn "IPv6 not enabled"
    echo "[INFO] Enable IPv6 in /etc/default/ufw if needed" >> "$LOGFILE"
fi

# ==========================================================
# DANGEROUS RULE DETECTION (optimisé)
# ==========================================================

echo -e "\n${BOLD}=== SECURITY ANALYSIS ===${RESET}\n"
echo "[RULES ANALYSIS]" >> "$LOGFILE"

UFW_RULES=$(ufw status numbered 2>/dev/null)
echo "$UFW_RULES" >> "$LOGFILE"

# Analyse des règles Anywhere
if echo "$UFW_RULES" | grep -q "Anywhere"; then
    warn "Rules allowing access from Anywhere detected"
    echo "[DANGER] Unrestricted access rules:" >> "$LOGFILE"
    echo "$UFW_RULES" | grep "Anywhere" >> "$LOGFILE"
else
    ok "No unrestricted Anywhere allow rules"
    echo "[SAFE] No unrestricted Anywhere rules" >> "$LOGFILE"
fi

# Sensitive ports check (optimisé)
SENSITIVE_PORTS="21 22 23 3389 5900 3306 5432"
echo "[SENSITIVE PORTS]" >> "$LOGFILE"

for PORT in $SENSITIVE_PORTS; do
    RULE=$(echo "$UFW_RULES" | grep -E "\b$PORT(/tcp|/udp)?\b")
    if [[ -n "$RULE" ]]; then
        if echo "$RULE" | grep -q "Anywhere"; then
            alert "Sensitive port $PORT open to Anywhere"
            echo "[CRITICAL] Port $PORT exposed to Anywhere: $RULE" >> "$LOGFILE"
        else
            warn "Sensitive port $PORT open (restricted)"
            echo "[NOTE] Port $PORT restricted: $RULE" >> "$LOGFILE"
        fi
    fi
done

# Listening ports (optimisé)
LISTEN=$(ss -tuln | awk 'NR>1')
LISTEN_COUNT=$(echo "$LISTEN" | wc -l)
echo "[LISTENING PORTS]" >> "$LOGFILE"
echo "$LISTEN" >> "$LOGFILE"

if [ "$LISTEN_COUNT" -eq 0 ]; then
    ok "No listening ports"
    echo "[INFO] No listening ports detected" >> "$LOGFILE"
else
    warn "$LISTEN_COUNT listening ports detected"
    echo "[WARNING] $LISTEN_COUNT listening ports:" >> "$LOGFILE"
    if echo "$LISTEN" | grep -q "0.0.0.0:"; then
        warn "Services listening on all interfaces"
        echo "[DANGER] Services on 0.0.0.0:" >> "$LOGFILE"
        echo "$LISTEN" | grep "0.0.0.0:" >> "$LOGFILE"
    fi
fi

# ==========================================================
# FULL TOPOLOGY (optimisé)
# ==========================================================

{
echo
echo "=== FULL TOPOLOGY ==="
echo
echo "UFW STATUS:"
ufw status numbered
echo
echo "LISTENING PORTS:"
ss -tuln
echo
echo "=== AUDIT COMPLETED ==="
} | log_section

# ==========================================================
# FINAL SCORE (inchangé)
# ==========================================================

if (( SCORE < 0 )); then
    SCORE=0
fi

RISK="LOW"
if (( SCORE <= 4 )); then
    RISK="HIGH"
elif (( SCORE <= 7 )); then
    RISK="MEDIUM"
fi

COLOR=$GREEN
if [[ "$RISK" == "MEDIUM" ]]; then COLOR=$YELLOW; fi
if [[ "$RISK" == "HIGH" ]]; then COLOR=$RED; fi

# ==========================================================
# SUMMARY (inchangé)
# ==========================================================

echo -e "\n${BOLD}=== SUMMARY ===${RESET}"
echo -e "OK: ${GREEN}$OK_COUNT${RESET}"
echo -e "WARNING: ${YELLOW}$WARN_COUNT${RESET}"
echo -e "NOT OK: ${RED}$ALERT_COUNT${RESET}"
echo -e "\nSecurity score: ${CYAN}$SCORE/10${RESET}"
echo -e "Risk level: ${COLOR}${RISK}${RESET}"
echo -e "\nFull log saved at:"
echo -e "$LOGFILE\n"
