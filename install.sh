#!/usr/bin/env bash
# =============================================================================
# ufw-audit installer
# =============================================================================
# Usage:
#   sudo ./install.sh              Install ufw-audit
#   sudo ./install.sh --dry-run    Show what would be done without doing it
#   sudo ./install.sh --uninstall  Remove ufw-audit (reads the manifest)
#
# Installation layout:
#   /usr/local/bin/ufw-audit                  Entry point
#   /usr/local/lib/ufw-audit/                 Python package
#   /usr/local/share/ufw-audit/               Data and locales
#   /usr/local/share/doc/ufw-audit/           Documentation
#   /usr/local/share/ufw-audit/install.manifest
#
# Uninstall removes exactly what the manifest lists.
# Directories are only removed if empty after file removal.
# User configuration (~/.config/ufw-audit/) is offered separately.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION="0.9"
PACKAGE_NAME="ufw-audit"

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
LIB_DIR="${PREFIX}/lib/ufw_audit"
SHARE_DIR="${PREFIX}/share/${PACKAGE_NAME}"
DOC_DIR="${PREFIX}/share/doc/${PACKAGE_NAME}"
COMPLETION_DIR="/etc/bash_completion.d"
MANIFEST="${SHARE_DIR}/install.manifest"

MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=8

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

DRY_RUN=false
UNINSTALL=false

for arg in "$@"; do
    case "$arg" in
        --dry-run)   DRY_RUN=true ;;
        --uninstall) UNINSTALL=true ;;
        --help|-h)
            echo "Usage: sudo ./install.sh [--dry-run] [--uninstall]"
            echo ""
            echo "  (no flag)     Install ${PACKAGE_NAME} v${VERSION}"
            echo "  --dry-run     Show what would be done without making changes"
            echo "  --uninstall   Remove ${PACKAGE_NAME} using the install manifest"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Run './install.sh --help' for usage."
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()    { echo -e "${BLUE}  →${RESET} $*"; }
ok()      { echo -e "${GREEN}  ✔${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
error()   { echo -e "${RED}  ✖${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}$*${RESET}"; }
dry()     { echo -e "${DIM}  [dry-run]${RESET} $*"; }

do_mkdir() {
    local dir="$1"
    if $DRY_RUN; then
        dry "mkdir -p ${dir}"
    else
        mkdir -p "$dir"
        ok "Created directory: ${dir}"
    fi
}

do_copy() {
    local src="$1" dst="$2"
    if $DRY_RUN; then
        dry "cp ${src} → ${dst}"
    else
        cp "$src" "$dst"
        ok "Copied: ${dst}"
    fi
}

do_copy_dir() {
    local src="$1" dst="$2"
    if $DRY_RUN; then
        dry "cp -r ${src}/ → ${dst}/"
    else
        cp -r "$src/." "$dst/"
        ok "Copied directory contents: ${src}/ → ${dst}/"
    fi
}

do_chmod() {
    local mode="$1" file="$2"
    if $DRY_RUN; then
        dry "chmod ${mode} ${file}"
    else
        chmod "$mode" "$file"
    fi
}

do_rm() {
    local file="$1"
    if $DRY_RUN; then
        dry "rm ${file}"
    else
        rm -f "$file"
        ok "Removed: ${file}"
    fi
}

do_rmdir_if_empty() {
    local dir="$1"
    if $DRY_RUN; then
        dry "rmdir (if empty): ${dir}"
        return
    fi
    if [[ -d "$dir" ]] && [[ -z "$(ls -A "$dir" 2>/dev/null)" ]]; then
        rmdir "$dir"
        ok "Removed empty directory: ${dir}"
    elif [[ -d "$dir" ]]; then
        warn "Directory not empty, left intact: ${dir}"
    fi
}

manifest_add() {
    # Only called during real install (not dry-run)
    echo "$1" >> "$MANIFEST"
}

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root: sudo ./install.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Source directory — where this script lives
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# UNINSTALL
# ---------------------------------------------------------------------------

if $UNINSTALL; then
    section "Uninstalling ${PACKAGE_NAME} v${VERSION}"

    if [[ ! -f "$MANIFEST" ]]; then
        error "Manifest not found: ${MANIFEST}"
        error "Cannot determine what was installed. Aborting."
        exit 1
    fi

    echo ""
    info "Reading manifest: ${MANIFEST}"
    echo ""

    # Collect files and dirs separately, maintaining manifest order
    declare -a FILES_TO_REMOVE=()
    declare -a DIRS_TO_REMOVE=()

    while IFS= read -r entry; do
        [[ -z "$entry" || "$entry" == \#* ]] && continue
        type="${entry%% *}"
        path="${entry#* }"
        case "$type" in
            FILE) FILES_TO_REMOVE+=("$path") ;;
            DIR)  DIRS_TO_REMOVE+=("$path") ;;
        esac
    done < "$MANIFEST"

    section "Removing files"
    for f in "${FILES_TO_REMOVE[@]}"; do
        if [[ -f "$f" ]]; then
            do_rm "$f"
        else
            warn "Already absent: ${f}"
        fi
    done

    section "Removing directories (only if empty)"
    # Reverse order — deepest directories first
    for (( i=${#DIRS_TO_REMOVE[@]}-1; i>=0; i-- )); do
        do_rmdir_if_empty "${DIRS_TO_REMOVE[$i]}"
    done

    echo ""
    section "User configuration"
    local_configs=()
    while IFS= read -r -d '' cfg; do
        local_configs+=("$cfg")
    done < <(find /home -name "ufw-audit" -type d -print0 2>/dev/null)
    [[ -d "/root/.config/ufw-audit" ]] && local_configs+=("/root/.config/ufw-audit")

    if [[ ${#local_configs[@]} -eq 0 ]]; then
        info "No user configuration directories found."
    else
        for cfg_dir in "${local_configs[@]}"; do
            echo ""
            warn "User configuration found: ${cfg_dir}"
            read -r -p "  Remove ${cfg_dir}? [y/N] " answer
            if [[ "${answer,,}" == "y" ]]; then
                if $DRY_RUN; then
                    dry "rm -rf ${cfg_dir}"
                else
                    rm -rf "$cfg_dir"
                    ok "Removed: ${cfg_dir}"
                fi
            else
                info "Kept: ${cfg_dir}"
            fi
        done
    fi

    echo ""
    ok "${PACKAGE_NAME} has been uninstalled."
    $DRY_RUN && echo -e "\n${DIM}  (dry-run — no changes were made)${RESET}"
    exit 0
fi

# ---------------------------------------------------------------------------
# INSTALL — pre-flight checks
# ---------------------------------------------------------------------------

section "ufw-audit v${VERSION} — Installer"
$DRY_RUN && echo -e "${YELLOW}  Dry-run mode — no changes will be made${RESET}"

section "Pre-flight checks"

# Python version
PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
        major="${ver%%.*}"
        minor="${ver##*.}"
        if [[ "$major" -ge "$MIN_PYTHON_MAJOR" && "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
            PYTHON_BIN="$candidate"
            ok "Python ${ver} found at $(command -v "$candidate")"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    error "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required but not found."
    error "Install it with: sudo apt install python3"
    exit 1
fi

# Source files present
# Detect layout: package (ufw_audit/) or flat (all files in same dir)
if [[ -d "${SCRIPT_DIR}/ufw_audit" ]]; then
    LAYOUT="package"
    SRC_MAIN="${SCRIPT_DIR}/ufw_audit"
    SRC_CHECKS="${SCRIPT_DIR}/ufw_audit/checks"
    SRC_LOCALES="${SCRIPT_DIR}/ufw_audit/locales"
    SRC_DATA="${SCRIPT_DIR}/ufw_audit/data"
else
    LAYOUT="flat"
    SRC_MAIN="${SCRIPT_DIR}"
    SRC_CHECKS="${SCRIPT_DIR}"
    SRC_LOCALES="${SCRIPT_DIR}"
    SRC_DATA="${SCRIPT_DIR}"
fi

required_files=(
    "${SRC_MAIN}/__main__.py"
    "${SRC_MAIN}/cli.py"
    "${SRC_MAIN}/i18n.py"
    "${SRC_LOCALES}/en.json"
    "${SRC_LOCALES}/fr.json"
    "${SRC_DATA}/services.json"
)

for f in "${required_files[@]}"; do
    if [[ ! -f "$f" ]]; then
        error "Required source file missing: ${f}"
        error "Run this installer from the ufw-audit source directory."
        exit 1
    fi
done
ok "Source files present"

# UFW installed
if ! command -v ufw &>/dev/null; then
    warn "UFW is not installed. ufw-audit requires UFW to function."
    warn "Install it after: sudo apt install ufw"
fi

# ---------------------------------------------------------------------------
# INSTALL — create directories
# ---------------------------------------------------------------------------

section "Creating directories"

do_mkdir "${BIN_DIR}"
do_mkdir "${LIB_DIR}"
do_mkdir "${LIB_DIR}/checks"
do_mkdir "${SHARE_DIR}"
do_mkdir "${SHARE_DIR}/locales"
do_mkdir "${SHARE_DIR}/data"
do_mkdir "${DOC_DIR}"
do_mkdir "${COMPLETION_DIR}"

# ---------------------------------------------------------------------------
# INSTALL — copy package files
# ---------------------------------------------------------------------------

section "Installing Python package"

# Core modules (excluding __init__.py — handled separately above)
for module in \
    __main__.py cli.py config.py i18n.py \
    output.py registry.py report.py scoring.py; do
    src="${SRC_MAIN}/${module}"
    if [[ -f "$src" ]]; then
        do_copy "$src" "${LIB_DIR}/${module}"
    fi
done

# checks/ subpackage
do_copy "${SRC_CHECKS}/__init__.py" "${LIB_DIR}/checks/__init__.py"
for check_module in firewall.py services.py ports.py logs.py ddns.py docker.py virtualization.py; do
    src="${SRC_CHECKS}/${check_module}"
    if [[ -f "$src" ]]; then
        do_copy "$src" "${LIB_DIR}/checks/${check_module}"
    fi
done

section "Installing data files"
do_copy "${SRC_LOCALES}/en.json" "${SHARE_DIR}/locales/en.json"
do_copy "${SRC_LOCALES}/fr.json" "${SHARE_DIR}/locales/fr.json"
do_copy "${SRC_DATA}/services.json" "${SHARE_DIR}/data/services.json"

section "Installing documentation"
for doc in README.md CHANGELOG.md LICENSE; do
    src="${SCRIPT_DIR}/${doc}"
    if [[ -f "$src" ]]; then
        do_copy "$src" "${DOC_DIR}/${doc}"
    fi
done

# ---------------------------------------------------------------------------
# INSTALL — entry point
# ---------------------------------------------------------------------------

section "Installing bash completion"

COMPLETION_SRC="${SCRIPT_DIR}/ufw-audit.bash-completion"
if [[ -f "${COMPLETION_SRC}" ]]; then
    do_copy "${COMPLETION_SRC}" "${COMPLETION_DIR}/ufw-audit"
    info "To activate immediately: source ${COMPLETION_DIR}/ufw-audit"
else
    warn "Bash completion file not found — skipping"
fi

section "Creating entry point"

ENTRY_POINT="${BIN_DIR}/ufw-audit"

if $DRY_RUN; then
    dry "Create entry point: ${ENTRY_POINT}"
else
    cat > "${ENTRY_POINT}" << ENTRYPOINT
#!/usr/bin/env ${PYTHON_BIN}
# ufw-audit entry point — generated by install.sh
import sys
import os

# The package ufw_audit/ lives inside LIB_DIR.
# We need the PARENT of LIB_DIR in sys.path so that
# "import ufw_audit" resolves correctly.
lib_parent = "${PREFIX}/lib"
if lib_parent not in sys.path:
    sys.path.insert(0, lib_parent)

# Point i18n and registry at the shared data directory
os.environ.setdefault("UFW_AUDIT_SHARE", "${SHARE_DIR}")

from ufw_audit.__main__ import main
sys.exit(main())
ENTRYPOINT
    do_chmod 755 "${ENTRY_POINT}"
    ok "Entry point created: ${ENTRY_POINT}"
fi

# ---------------------------------------------------------------------------
# INSTALL — write manifest
# ---------------------------------------------------------------------------

section "Writing install manifest"

if $DRY_RUN; then
    dry "Write manifest: ${MANIFEST}"
else
    # Start fresh
    : > "$MANIFEST"

    # Record all installed files
    echo "# ufw-audit install manifest — $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$MANIFEST"
    echo "# Do not edit this file manually." >> "$MANIFEST"
    echo "" >> "$MANIFEST"

    # Entry point
    manifest_add "FILE ${ENTRY_POINT}"

    # Python package
    for module in \
        __init__.py __main__.py cli.py config.py i18n.py \
        output.py registry.py report.py scoring.py; do
        [[ -f "${LIB_DIR}/${module}" ]] && manifest_add "FILE ${LIB_DIR}/${module}"
    done
    manifest_add "FILE ${LIB_DIR}/checks/__init__.py"
    for check_module in firewall.py services.py ports.py logs.py ddns.py docker.py virtualization.py; do
        [[ -f "${LIB_DIR}/checks/${check_module}" ]] && \
            manifest_add "FILE ${LIB_DIR}/checks/${check_module}"
    done

    # Data and locales
    manifest_add "FILE ${SHARE_DIR}/locales/en.json"
    manifest_add "FILE ${SHARE_DIR}/locales/fr.json"
    manifest_add "FILE ${SHARE_DIR}/data/services.json"

    # Documentation
    for doc in README.md CHANGELOG.md LICENSE; do
        [[ -f "${DOC_DIR}/${doc}" ]] && manifest_add "FILE ${DOC_DIR}/${doc}"
    done

    # Completion
    [[ -f "${COMPLETION_DIR}/ufw-audit" ]] && manifest_add "FILE ${COMPLETION_DIR}/ufw-audit"

    # Manifest itself (last file entry)
    manifest_add "FILE ${MANIFEST}"

    # Directories (shallowest first for removal reference, deepest removed first at uninstall)
    manifest_add "DIR ${LIB_DIR}/checks"
    manifest_add "DIR ${LIB_DIR}"
    manifest_add "DIR ${SHARE_DIR}/locales"
    manifest_add "DIR ${SHARE_DIR}/data"
    manifest_add "DIR ${SHARE_DIR}"
    manifest_add "DIR ${DOC_DIR}"
    # Note: /etc/bash_completion.d is a system dir — never removed

    ok "Manifest written: ${MANIFEST}"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo -e "${GREEN}${BOLD}  ✔ ufw-audit v${VERSION} installed successfully.${RESET}"
echo ""
echo -e "  Run the audit:  ${BOLD}sudo ufw-audit${RESET}"
echo -e "  French mode:    ${BOLD}sudo ufw-audit --french${RESET}"
echo -e "  Full report:    ${BOLD}sudo ufw-audit -v -d${RESET}"
echo -e "  Help:           ${BOLD}ufw-audit --help${RESET}"
echo -e "  Uninstall:      ${BOLD}sudo ./install.sh --uninstall${RESET}"
echo ""

$DRY_RUN && echo -e "${DIM}  (dry-run — no changes were made)${RESET}\n"

exit 0