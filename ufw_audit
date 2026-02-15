#!/bin/bash
# ==========================================================
# UFW-audit v0.1
# UFW Firewall Audit Script for Linux
# ==========================================================

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
    echo -e "${BOLD}UFW-audit v0.1${RESET}"
    echo -e "UFW Firewall Audit Script for Linux"
    echo
    echo "Usage: ./UFW-audit.sh [options]"
    echo
    echo "Options:"
    echo "  -v, --verbose     Show full audit details in terminal"
    echo "  -h, --help        Show this help message"
    exit 0
fi

# --- Functions ---
ok() {
    echo -e "[${GREEN}OK${RESET}] $1"
    ((OK_COUNT++))
}

warn() {
    echo -e "[${YELLOW}WARNING${RESET}] $1"
    ((WARN_COUNT++))
    ((SCORE--))
}

alert() {
    echo -e "[${RED}NOT OK${RESET}] $1"
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
echo "UFW AUDIT FULL REPORT - $(date)"
echo "=========================================================="
} > "$LOGFILE"

# ==========================================================
# CHECKLIST
# ==========================================================

echo -e "\n${BOLD}=== FIREWALL CHECKLIST ===${RESET}\n"

# UFW installed
if command -v ufw &>/dev/null; then
    ok "UFW installed"
    echo "UFW version: $(ufw version)" >> "$LOGFILE"
else
    alert "UFW not installed"
    SCORE=0
    exit 1
fi

# Firewall active
if ufw status | grep -qi inactive; then
    alert "Firewall inactive"
else
    ok "Firewall active"
fi
ufw status >> "$LOGFILE"

# Default policies
DEFAULTS=$(ufw status verbose | grep "Default:")
echo "$DEFAULTS" >> "$LOGFILE"

if echo "$DEFAULTS" | grep -q "deny (incoming)"; then
    ok "Incoming default = DENY"
else
    alert "Incoming default is NOT deny"
fi

if echo "$DEFAULTS" | grep -q "allow (outgoing)"; then
    ok "Outgoing default = ALLOW"
else
    warn "Outgoing default not standard"
fi

# IPv6
if grep -qi "^IPV6=yes" /etc/default/ufw 2>/dev/null; then
    ok "IPv6 enabled"
else
    warn "IPv6 not enabled"
fi

# ==========================================================
# DANGEROUS RULE DETECTION
# ==========================================================

echo -e "\n${BOLD}=== SECURITY ANALYSIS ===${RESET}\n"

UFW_RULES=$(ufw status)

# Broad Anywhere rules
if echo "$UFW_RULES" | grep -q "ALLOW Anywhere"; then
    warn "Rules allowing access from Anywhere detected"
else
    ok "No unrestricted Anywhere allow rules"
fi

# Sensitive ports check
SENSITIVE_PORTS="21 22 23 3389 5900 3306 5432"

for PORT in $SENSITIVE_PORTS; do
    RULE=$(echo "$UFW_RULES" | grep -E "\b$PORT(/tcp|/udp)?\b")
    if [[ -n "$RULE" ]]; then
        if echo "$RULE" | grep -q "Anywhere"; then
            alert "Sensitive port $PORT open to Anywhere"
        else
            warn "Sensitive port $PORT open (restricted)"
        fi
    fi
done

# Listening ports
LISTEN=$(ss -tuln | awk 'NR>1')
LISTEN_COUNT=$(echo "$LISTEN" | wc -l)

echo "$LISTEN" >> "$LOGFILE"

if [ "$LISTEN_COUNT" -eq 0 ]; then
    ok "No listening ports"
else
    warn "$LISTEN_COUNT listening ports detected"
    if echo "$LISTEN" | grep -q "0.0.0.0:"; then
        warn "Services listening on all interfaces"
    fi
fi

# ==========================================================
# FULL TOPOLOGY
# ==========================================================

{
echo
echo "---------------- FULL TOPOLOGY ----------------"
echo
echo "----- UFW STATUS VERBOSE -----"
ufw status verbose
echo
echo "----- UFW NUMBERED RULES -----"
ufw status numbered
echo
echo "----- UFW RAW TABLES -----"
ufw show raw
echo
echo "----- LISTENING PORTS -----"
ss -tuln
echo
echo "=========================================================="
echo "Audit completed."
} | log_section

# ==========================================================
# FINAL SCORE
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
# SUMMARY
# ==========================================================

echo -e "\n${BOLD}=== SUMMARY ===${RESET}"
echo -e "OK: ${GREEN}$OK_COUNT${RESET}"
echo -e "WARNING: ${YELLOW}$WARN_COUNT${RESET}"
echo -e "NOT OK: ${RED}$ALERT_COUNT${RESET}"
echo -e "\nSecurity score: ${CYAN}$SCORE/10${RESET}"
echo -e "Risk level: ${COLOR}${RISK}${RESET}"
echo -e "\nFull log saved at:"
echo -e "$LOGFILE\n"
