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
#   /usr/local/lib/ufw_audit/                 Python package (underscore: Python import name)
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

VERSION="0.22"
PACKAGE_NAME="ufw-audit"
PY_PACKAGE_NAME="ufw_audit"   # Python import name (underscore); differs from CLI name (hyphen)

PREFIX="/usr/local"
BIN_DIR="${PREFIX}/bin"
LIB_DIR="${PREFIX}/lib/${PY_PACKAGE_NAME}"
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
# Rollback state (populated during install, used by cleanup_on_failure)
# ---------------------------------------------------------------------------

_INSTALLED_FILES=()
_INSTALLED_DIRS=()
INSTALL_SUCCESS=false

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
        _INSTALLED_DIRS+=("$dir")
        ok "Created directory: ${dir}"
    fi
}

do_copy() {
    local src="$1" dst="$2"
    if $DRY_RUN; then
        dry "install -m 644 ${src} → ${dst}"
    else
        if ! install -m 644 "$src" "$dst"; then
            error "Failed to copy: ${src} → ${dst}"
            exit 1
        fi
        _INSTALLED_FILES+=("$dst")
        ok "Copied: ${dst}"
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
    if [[ -d "$dir" ]] && [[ -z "$(find "$dir" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
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
# Rollback trap — runs on any non-zero exit during install
# ---------------------------------------------------------------------------

cleanup_on_failure() {
    $INSTALL_SUCCESS && return   # clean exit — nothing to do
    $DRY_RUN && return           # dry-run never touches the filesystem
    $UNINSTALL && return         # uninstall path handles its own errors

    [[ ${#_INSTALLED_FILES[@]} -eq 0 && ${#_INSTALLED_DIRS[@]} -eq 0 ]] && return

    echo ""
    error "Installation failed — rolling back partial install..."

    for f in "${_INSTALLED_FILES[@]}"; do
        [[ -f "$f" ]] && rm -f "$f" && warn "Rolled back: ${f}"
    done

    # Remove directories in reverse order (deepest first)
    for (( i=${#_INSTALLED_DIRS[@]}-1; i>=0; i-- )); do
        local d="${_INSTALLED_DIRS[$i]}"
        if [[ -d "$d" ]] && [[ -z "$(find "$d" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
            rmdir "$d" && warn "Rolled back directory: ${d}"
        fi
    done

    error "Rollback complete. No partial install left on disk."
}

trap cleanup_on_failure EXIT

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
        entry_type="${entry%% *}"
        entry_path="${entry#* }"
        case "$entry_type" in
            FILE) FILES_TO_REMOVE+=("$entry_path") ;;
            DIR)  DIRS_TO_REMOVE+=("$entry_path") ;;
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
    for home_dir in /home/*/; do
        [[ -d "$home_dir" ]] || continue
        cfg="${home_dir}.config/ufw-audit"
        [[ -d "$cfg" ]] && local_configs+=("$cfg")
    done
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
        if [[ "$major" -gt "$MIN_PYTHON_MAJOR" ]] || \
           [[ "$major" -eq "$MIN_PYTHON_MAJOR" && "$minor" -ge "$MIN_PYTHON_MINOR" ]]; then
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
    SRC_MAIN="${SCRIPT_DIR}/ufw_audit"
    SRC_CHECKS="${SCRIPT_DIR}/ufw_audit/checks"
    SRC_LOCALES="${SCRIPT_DIR}/ufw_audit/locales"
    SRC_DATA="${SCRIPT_DIR}/ufw_audit/data"
else
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
# Note: COMPLETION_DIR is a pre-existing system directory — not created or tracked

# ---------------------------------------------------------------------------
# INSTALL — copy package files
# ---------------------------------------------------------------------------

section "Installing Python package"

# Core modules
for module in \
    __init__.py __main__.py _paths.py cli.py config.py cron.py display.py fixes.py i18n.py \
    manage_logs.py output.py panorama.py registry.py report.py \
    report_markdown.py scoring.py sysinfo.py; do
    src="${SRC_MAIN}/${module}"
    if [[ -f "$src" ]]; then
        do_copy "$src" "${LIB_DIR}/${module}"
    fi
done

# checks/ subpackage
do_copy "${SRC_CHECKS}/__init__.py" "${LIB_DIR}/checks/__init__.py"
for check_module in _run.py firewall.py services.py ports.py logs.py ddns.py docker.py virtualization.py; do
    src="${SRC_CHECKS}/${check_module}"
    if [[ -f "$src" ]]; then
        do_copy "$src" "${LIB_DIR}/checks/${check_module}"
    fi
done

section "Installing data files"
for locale_file in "${SRC_LOCALES}"/*.json; do
    [[ -f "$locale_file" ]] && do_copy "$locale_file" "${SHARE_DIR}/locales/$(basename "$locale_file")"
done
do_copy "${SRC_DATA}/services.json" "${SHARE_DIR}/data/services.json"

section "Installing documentation"
for doc in README.md README_FR.md LICENSE; do
    src="${SCRIPT_DIR}/${doc}"
    [[ -f "$src" ]] && do_copy "$src" "${DOC_DIR}/${doc}"
done
if [[ -d "${SCRIPT_DIR}/DOCUMENTS" ]]; then
    for doc in "${SCRIPT_DIR}/DOCUMENTS/"*.md; do
        [[ -f "$doc" ]] && do_copy "$doc" "${DOC_DIR}/$(basename "$doc")"
    done
fi

# ---------------------------------------------------------------------------
# INSTALL — entry point
# ---------------------------------------------------------------------------

section "Installing bash completion"

COMPLETION_SRC="${SCRIPT_DIR}/ufw-audit.bash-completion"
if [[ ! -d "${COMPLETION_DIR}" ]]; then
    warn "Bash completion directory not found (${COMPLETION_DIR}) — skipping"
elif [[ ! -f "${COMPLETION_SRC}" ]]; then
    warn "Bash completion file not found — skipping"
else
    do_copy "${COMPLETION_SRC}" "${COMPLETION_DIR}/ufw-audit"
    info "To activate immediately: source ${COMPLETION_DIR}/ufw-audit"
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
    _INSTALLED_FILES+=("${ENTRY_POINT}")
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
    {
        echo "# ufw-audit install manifest — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "# Do not edit this file manually."
        echo ""
    } >> "$MANIFEST"

    # Entry point
    manifest_add "FILE ${ENTRY_POINT}"

    # Python package
    for module in \
        __init__.py __main__.py _paths.py cli.py config.py cron.py display.py fixes.py \
        i18n.py manage_logs.py output.py panorama.py registry.py report.py \
        report_markdown.py scoring.py sysinfo.py; do
        [[ -f "${LIB_DIR}/${module}" ]] && manifest_add "FILE ${LIB_DIR}/${module}"
    done
    manifest_add "FILE ${LIB_DIR}/checks/__init__.py"
    for check_module in _run.py firewall.py services.py ports.py logs.py ddns.py docker.py virtualization.py; do
        [[ -f "${LIB_DIR}/checks/${check_module}" ]] && \
            manifest_add "FILE ${LIB_DIR}/checks/${check_module}"
    done

    # Data and locales
    for f in "${SHARE_DIR}/locales/"*.json; do
        [[ -f "$f" ]] && manifest_add "FILE $f"
    done
    manifest_add "FILE ${SHARE_DIR}/data/services.json"

    # Documentation
    for f in "${DOC_DIR}/"*; do
        [[ -f "$f" ]] && manifest_add "FILE $f"
    done

    # Completion
    [[ -f "${COMPLETION_DIR}/ufw-audit" ]] && manifest_add "FILE ${COMPLETION_DIR}/ufw-audit"

    # Manifest itself (last file entry)
    manifest_add "FILE ${MANIFEST}"

    # Directories (shallowest first for removal reference, deepest removed first at uninstall)
    # Only package-owned directories are listed here.
    # System directories that pre-exist (BIN_DIR=/usr/local/bin,
    # COMPLETION_DIR=/etc/bash_completion.d) are intentionally omitted
    # — removing them would break other packages.
    manifest_add "DIR ${LIB_DIR}/checks"
    manifest_add "DIR ${LIB_DIR}"
    manifest_add "DIR ${SHARE_DIR}/locales"
    manifest_add "DIR ${SHARE_DIR}/data"
    manifest_add "DIR ${SHARE_DIR}"
    manifest_add "DIR ${DOC_DIR}"

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

INSTALL_SUCCESS=true
exit 0