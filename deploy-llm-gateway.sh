#!/usr/bin/env bash
#===============================================================================
# Proxmox LLM Gateway VM Deployment Script
# Version: 3.5.0 - Enterprise Grade (Production Ready - Hardened)
# Description: Production-ready deployment of LiteLLM gateway with monitoring
# Author: Optimized for FedEx APAC ACCS Team
# Usage: ./deploy-llm-gateway.sh [--help|--print-config|--report|--lint|--self-test|--version] [config-file]
#
# Changelog v3.5.0 (Code Review Round 4):
# - SECURITY: Host-side curl auth headers now use --config <(printf ...) process
#   substitution — secrets no longer visible in /proc/PID/cmdline or ps output
# - SECURITY: DEBUG mode (set -x) now redirects xtrace to log file via BASH_XTRACEFD
#   so secrets in debug traces go to 600-perm log, not terminal/process accounting
# - SECURITY: AUTO_PURGE_CREDS log output warns that file now contains cleartext secrets
# - SECURITY: ssh-rsa keys now trigger deprecation warning (OpenSSH 8.8+ disables by default)
# - FEATURE: AUTO_FIX_STORAGE=1 flag gates automatic storage content-type modification
#   (set to 0 in strict change-control environments to prevent silent host changes)
# - FEATURE: --report outputs resolved config as JSON for CI/CD pipeline integration
# - FEATURE: print_mutation_summary() lists all host-state changes before deployment
#   (interactive mode prompts for confirmation after showing mutation list)
# - DOCS: Help text now explicitly states "IPv4 only" network configuration
#
# Changelog v3.4.4:
# - REFACTOR: All curl auth array workarounds replaced with readable if/else branches
#   and helper functions (_host_health_check, _idem_ok flag) — eliminates bash 4.3
#   compat hacks (Proxmox 8 ships bash 5.2), much easier for next maintainer to read
# - REFACTOR: qm create args built as array with conditional --balloon append
#   (cleaner than word-splitting and empty-array expansion tricks)
# - FEATURE: STRICT_POSTCHECK=0 flag — when set to 1, host-side health check timeout
#   becomes fatal_error (for CI/CD pipelines that need definitive pass/fail)
# - FEATURE: AUTO_PURGE_CREDS=0 flag — when set to 1, retrieves credentials from VM
#   via SSH, displays one-time, logs to deployment log, then shred+rm from VM
#   (enterprise secrets lifecycle: credentials never persist on disk after handoff)
# - FEATURE: --self-test flag runs bash -n, shellcheck (if available), and --lint
#   in one shot for pre-deployment confidence
# - HARDENING: docker compose pull failure now outputs last 5 lines of stderr and
#   DNS diagnostics (ghcr.io / registry-1.docker.io) for faster root-cause analysis
# - HARDENING: docker compose images logged after successful pull for audit trail
#
# Changelog v3.4.3:
# - FIX: MOTD generation refactored — monitoring lines now built as local variable
#   before injection, eliminating string-terminator " sitting on a content line
#   (was a quoting fragility risk during future edits of the heredoc segments)
# - HARDENING: docker compose pull exits with error (exit 1) after 3 failed attempts
#   instead of falling through to docker compose up with missing images
# - HARDENING: VM-internal health check exits with error (exit 1) after 120s timeout
#   instead of silent warning, enabling cloud-init / external tooling to detect failure
#
# Changelog v3.4.2 (Code Review Round 2):
# - FIX: VM-internal bootstrap health check now sends Authorization header when
#   master key is set (was getting 401 → falsely reporting "not ready after 120s")
#   Uses _health_ok() helper function instead of eval for safety
# - SECURITY: New CLEANUP_SNIPPET=1 flag (default: enabled) auto-removes cloud-init
#   snippet from Proxmox host after successful deployment (snippet contains secrets)
# - FIX: lint_config DNS validation now normalizes commas to spaces, consistent
#   with validate_inputs() (was treating "1.1.1.1,8.8.8.8" as single token)
# - HARDENING: Unpinned container versions now prompt for confirmation in
#   INTERACTIVE mode (with example pinned versions in warning message)
# - FEATURE: docker compose pull with 3x retry before docker compose up
#   (prevents half-running stacks when image pull hits network transients)
# - FEATURE: Idempotent VM bootstrap via marker file (/opt/llm-gateway/.bootstrap-complete)
#   Safe to re-run bootstrap script after interruption without side effects
#
# Changelog v3.4.1 (Code Review Fixes):
# - SECURITY: post_deployment_check health check no longer uses bash -c with string
#   interpolation for auth headers (command injection risk via LITELLM_MASTER_KEY)
#   Now uses safe array-based curl arguments
# - SECURITY: check_existing_deployment health check now sends auth header when
#   LITELLM_MASTER_KEY is set (was getting 401 → falsely reporting service down)
# - SECURITY: print_summary now warns about cloud-init snippet containing cleartext
#   secrets persisting on Proxmox host, with removal command
# - FIX: trap changed from EXIT+ERR+INT+TERM to EXIT only (prevents double cleanup
#   invocation under set -e where both ERR and EXIT traps fire)
# - FIX: Config file inline comment stripping moved AFTER key=value extraction and
#   quote handling — '#' characters inside values are now preserved correctly
#   (e.g. LITELLM_MASTER_KEY=sk-abc#def456 no longer truncated)
# - FIX: Config file values no longer silently override environment variables
#   Precedence is now: environment > config file > defaults (was: config > env > defaults)
# - FIX: Validation script container count threshold now dynamic based on
#   ENABLE_MONITORING (was hardcoded to 3, missed prometheus+grafana)
# - FIX: balloon_param passed as array instead of unquoted string to qm create
# - CLEANUP: Redundant qm status calls between check_existing_deployment and
#   check_vm_conflicts consolidated with cached _VM_EXISTS flag
# - CLEANUP: _safe_load_config loaded counter now logged instead of unused
# - CLEANUP: Clarifying comments on qm/pvesm function overrides, bootstrap
#   script runtime expansion, and trap behavior
#
# Changelog v3.4.0 (Security Hardening Release):
# - SECURITY: Config file loading no longer uses `source` (arbitrary code execution)
#   Now uses safe key=value parser with variable whitelist and shell expansion rejection
# - SECURITY: Cloud image SHA256 verification (auto from SHA256SUMS or pinned IMG_SHA256)
# - SECURITY: Removed ssh-dss (DSA) from allowed SSH key types (deprecated/insecure)
#   Added sk-ssh-ed25519 and sk-ecdsa FIDO2 key types
# - HARDENING: Container version pinning warning when using 'latest' tags
# - HARDENING: Monitoring images (Prometheus/Grafana) now use configurable version vars
#   PROMETHEUS_VERSION and GRAFANA_VERSION (default: latest, recommended: pin in prod)
# - FEATURE: IMG_SHA256 config variable to pin cloud image checksum
#
# Changelog v3.3.6:
# - FEATURE: --help flag with full usage, env vars, and examples
# - FEATURE: --print-config prints resolved config (secrets redacted) for ops handoff
# - FEATURE: --lint validates config and prerequisites without deploying
# - FEATURE: --version prints version string
# - FIX: ALLOWED_NETWORKS now requires CIDR notation with prefix validation (0-32)
# - FIX: importdisk parsing matches unused[0-9]:STORAGE: pattern explicitly
#   with two-stage fallback (prevents wrong disk on non-standard storage)
# - FIX: DNS_SERVERS validated as IPv4 addresses with octet range check
# - FIX: Health checks pass Authorization header when LITELLM_MASTER_KEY is set
#   (compatible with auth-required gateway configurations)
#
# Changelog v3.3.5:
# - FIX: interactive_setup() wizard banner now uses ${SCRIPT_VERSION} (was hardcoded)
# - FIX: import_and_attach_disk() now parses actual volume name from qm importdisk
#   output instead of assuming vm-<id>-disk-0 (prevents "works on my node" failures)
# - FIX: IP/CIDR validation now checks octet ranges (0-255) and CIDR prefix (0-32)
#   Also validates ALLOWED_NETWORKS entries when firewall is enabled
# - FIX: UFW rule order corrected to defaults → loopback → allows → enable
#   (prevents edge-case lockouts on hardened builds)
# - FEATURE: PACKAGE_UPGRADE flag (default=0) gates cloud-init package_upgrade
#   (prevents unexpected kernel/systemd updates in production windows)
#
# Changelog v3.3.4:
# - ARCHITECTURE: Replaced fragile multi-segment cat >> cloud-init with single-shot write
# - ARCHITECTURE: Extracted all runcmd logic into llm-gateway-bootstrap.sh
#   (write_files delivers script, runcmd calls it with one line)
# - ARCHITECTURE: docker-compose.yml built as complete variable before writing
#   (eliminates YAML indentation fragility from appending monitoring services)
# - FIX: cleanup() now only prompts for VM removal in INTERACTIVE mode
#   (prevents 30s hang in non-interactive/automation environments like OpenClaw)
# - FIX: UFW rules generated as clean script lines, no echo -e in YAML
# - FIX: prometheus.yml built as complete variable (no conditional cat >> append)
# - FEATURE: Bootstrap script logs to /var/log/llm-gateway-bootstrap.log
#
# Changelog v3.3.3c:
# - CRITICAL: Fixed log() crash when LOG_FILE empty (set -e + write to "")
# - CRITICAL: Fixed DEBUG case [[ ]] && pattern causing exit under set -e
# - CRITICAL: Fixed validate_snippet_storage() using non-existent pvesm config
#   Now parses /etc/pve/storage.cfg directly with auto-enable snippets
# - FIX: Reordered main() to call setup_logging() BEFORE load_config/load_litellm
# - HARDENING: All [[ ]] && patterns in log() replaced with if/fi blocks
#
# Changelog v3.3.3b:
# - CRITICAL: Added bootcmd to create /etc/llm-gateway before write_files stage
# - HARDENING: Docker + network readiness gates before docker compose up
# - HARDENING: Postgres switched to named Docker volume (no more chown 999:999)
# - FEATURE: Added llm-gateway.service systemd unit (auto-start, status, restart)
#
# Changelog v3.3.3a:
# - HARDENING: write_files targets /etc/llm-gateway (guaranteed to exist)
#   then runcmd installs to /opt/llm-gateway (correct cloud-init stage order)
# - Removed ineffective mkdir in runcmd (write_files runs BEFORE runcmd)
#
# Changelog v3.3.3:
# - CRITICAL FIX: Validation script SSH accept-new detection (test against VM)
# - CRITICAL FIX: Ensure /opt/llm-gateway exists before write_files
# - IMPROVED: Wait for IP availability before starting Docker (BIND_TO_IP)
# - IMPROVED: More robust error handling in validation script
#===============================================================================

set -euo pipefail

#===============================================================================
# SCRIPT METADATA
#===============================================================================
readonly SCRIPT_VERSION="3.5.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly MAX_CONFIG_SIZE_BYTES=262144  # 256KB limit for external configs

#===============================================================================
# DEFAULT CONFIGURATION
#===============================================================================
# Capture which config variables are explicitly set via environment BEFORE defaults
# This allows the config file loader to respect env > config > default precedence
declare -A _ENV_OVERRIDES=()
for _var in VMID VMNAME MEM CORES DISK_GB BRIDGE VM_ONBOOT VM_STARTUP_ORDER VM_BALLOON VM_TAGS STORAGE SNIPPET_STORAGE CACHE_DIR CACHE_MAX_AGE_DAYS USE_DHCP IP_CIDR GATEWAY_IP DNS_SERVERS SEARCH_DOMAIN ENABLE_FIREWALL ALLOWED_NETWORKS BIND_TO_IP UBUNTU_RELEASE IMG_URL IMG_SHA256 CI_USER SSH_PUBKEY_FILE LITELLM_PORT LITELLM_MASTER_KEY POSTGRES_PASS GRAFANA_ADMIN_PASS LITELLM_CONFIG_FILE POSTGRES_VERSION REDIS_VERSION LITELLM_VERSION PROMETHEUS_VERSION GRAFANA_VERSION OLLAMA_IP OLLAMA_PORT ENABLE_MONITORING ENABLE_LITELLM_METRICS ENABLE_BACKUP ENABLE_VALIDATION_SCRIPT DRY_RUN INTERACTIVE DEBUG SKIP_IDEMPOTENCY_CHECK PACKAGE_UPGRADE CLEANUP_SNIPPET STRICT_POSTCHECK AUTO_PURGE_CREDS AUTO_FIX_STORAGE; do
    if [[ -n "${!_var+x}" ]]; then
        _ENV_OVERRIDES[$_var]=1
    fi
done
unset _var

# VM Configuration
: "${VMID:=120}"
: "${VMNAME:=llm-gateway}"
: "${MEM:=8192}"
: "${CORES:=4}"
: "${DISK_GB:=60}"
: "${BRIDGE:=vmbr0}"

# VM Advanced Settings
: "${VM_ONBOOT:=1}"
: "${VM_STARTUP_ORDER:=3}"
: "${VM_BALLOON:=4096}"
: "${VM_TAGS:=llm,gateway,prod}"

# Storage Configuration
: "${STORAGE:=ssdpool}"
: "${SNIPPET_STORAGE:=local}"
: "${CACHE_DIR:=/var/lib/vz/template/cache}"
: "${CACHE_MAX_AGE_DAYS:=7}"

# Network Configuration
: "${USE_DHCP:=0}"
: "${IP_CIDR:=192.168.200.120/24}"
: "${GATEWAY_IP:=192.168.200.1}"
: "${DNS_SERVERS:=1.1.1.1}"
: "${SEARCH_DOMAIN:=lan}"

# Network Security
: "${ENABLE_FIREWALL:=1}"
: "${ALLOWED_NETWORKS:=192.168.200.0/24}"
: "${BIND_TO_IP:=0}"

# Ubuntu Cloud Image
: "${UBUNTU_RELEASE:=noble}"
: "${IMG_URL:=https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${UBUNTU_RELEASE}-server-cloudimg-amd64.img}"
: "${IMG_SHA256:=}"  # Optional: pin image checksum (leave empty to auto-verify from SHA256SUMS)

# VM Login
: "${CI_USER:=ubuntu}"
: "${SSH_PUBKEY_FILE:=$HOME/.ssh/id_ed25519.pub}"

# LiteLLM Settings
: "${LITELLM_PORT:=4000}"
: "${LITELLM_MASTER_KEY:=AUTO}"
: "${POSTGRES_PASS:=AUTO}"
: "${GRAFANA_ADMIN_PASS:=AUTO}"
: "${LITELLM_CONFIG_FILE:=}"

# Docker Versions
: "${POSTGRES_VERSION:=16}"
: "${REDIS_VERSION:=7}"
: "${LITELLM_VERSION:=main-stable}"
: "${PROMETHEUS_VERSION:=latest}"
: "${GRAFANA_VERSION:=latest}"

# Ollama Backend
: "${OLLAMA_IP:=192.168.200.200}"
: "${OLLAMA_PORT:=11434}"

# Features
: "${ENABLE_MONITORING:=1}"
: "${ENABLE_LITELLM_METRICS:=0}"
: "${ENABLE_BACKUP:=0}"
: "${ENABLE_VALIDATION_SCRIPT:=1}"
: "${DRY_RUN:=0}"
: "${INTERACTIVE:=0}"
: "${DEBUG:=0}"
: "${SKIP_IDEMPOTENCY_CHECK:=0}"
: "${PACKAGE_UPGRADE:=0}"
: "${CLEANUP_SNIPPET:=1}"
: "${STRICT_POSTCHECK:=0}"
: "${AUTO_PURGE_CREDS:=0}"
: "${AUTO_FIX_STORAGE:=1}"

#===============================================================================
# GLOBAL VARIABLES
#===============================================================================
WORKDIR=""
IMG_PATH=""
LOG_FILE=""
SNIP_DIR=""
DEPLOYMENT_START_TIME=$(date +%s)
CUSTOM_CONFIG_CONTENT=""
_VM_EXISTS=0  # Cached result from check_existing_deployment

#===============================================================================
# COLOR OUTPUT
#===============================================================================
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'
    readonly MAGENTA='\033[0;35m'
    readonly NC='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly CYAN=''
    readonly MAGENTA=''
    readonly NC=''
fi

#===============================================================================
# LOGGING FUNCTIONS
#===============================================================================
setup_logging() {
    LOG_FILE="/var/log/proxmox-vm-deploy-${VMID}-$(date +%Y%m%d-%H%M%S).log"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/vm-deploy-${VMID}.log"
    chmod 600 "$LOG_FILE"
    
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "Script version: $SCRIPT_VERSION"
    log "INFO" "Start time: $(date)"
    log "INFO" "Execution user: $(whoami)"
    log "INFO" "PID: $$"
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
    local log_entry="[$timestamp] [$level] [PID:$$] $msg"
    
    # Guard: only write to log file if LOG_FILE is set and writable
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "$log_entry" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    case "$level" in
        ERROR)
            echo -e "${RED}❌ $msg${NC}" >&2
            ;;
        WARN)
            echo -e "${YELLOW}⚠️  $msg${NC}" >&2
            ;;
        SUCCESS)
            echo -e "${GREEN}✅ $msg${NC}"
            ;;
        INFO)
            echo -e "${BLUE}ℹ️  $msg${NC}"
            ;;
        DEBUG)
            if [[ "${DEBUG:-0}" == "1" ]]; then
                echo -e "${CYAN}🔍 $msg${NC}"
            fi
            ;;
        STEP)
            echo -e "${MAGENTA}📍 $msg${NC}"
            ;;
        *)
            echo "$msg"
            ;;
    esac
}

#===============================================================================
# ERROR HANDLING & CLEANUP
#===============================================================================
cleanup() {
    local exit_code=$?
    
    # Skip deployment-specific cleanup for utility modes (--help, --version, etc.)
    if [[ -z "${LOG_FILE:-}" ]]; then
        return 0
    fi
    
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Script failed with exit code: $exit_code"
        log "ERROR" "Check log file for details: $LOG_FILE"
        
        if [[ "${DRY_RUN}" != "1" ]]; then
            if [[ "${INTERACTIVE}" == "1" ]]; then
                read -p "Remove failed VM $VMID? (y/n) " -t 30 -n 1 -r || REPLY='n'
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    log "INFO" "Cleaning up failed VM..."
                    /usr/sbin/qm stop "$VMID" 2>/dev/null || true
                    sleep 2
                    /usr/sbin/qm destroy "$VMID" --purge 2>/dev/null || true
                    log "SUCCESS" "Failed VM removed"
                else
                    log "INFO" "Failed VM $VMID preserved for debugging"
                    log "INFO" "To manually remove: qm destroy $VMID --purge"
                fi
            else
                log "INFO" "Failed VM $VMID preserved for debugging (non-interactive mode)"
                log "INFO" "To manually remove: qm destroy $VMID --purge"
            fi
        fi
    else
        local elapsed=$(($(date +%s) - DEPLOYMENT_START_TIME))
        log "SUCCESS" "Deployment completed in ${elapsed}s"
    fi
    
    if [[ -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
        log "DEBUG" "Cleaning up workdir: $WORKDIR"
        rm -rf "$WORKDIR" 2>/dev/null || true
    fi
    
    # Release cache lock if held
    if [[ -n "${CACHE_LOCK_FD:-}" ]]; then
        exec {CACHE_LOCK_FD}>&- 2>/dev/null || true
    fi
}

# EXIT trap fires on all exit paths (normal, error, signal) — no need for ERR/INT/TERM
# which would cause double invocation under set -e
trap cleanup EXIT

fatal_error() {
    log "ERROR" "$*"
    exit 1
}

#===============================================================================
# COMMAND WRAPPERS (Function override instead of alias)
# NOTE: These override the qm/pvesm commands for DRY_RUN support.
# All calls in this script go through these wrappers. The real binaries
# are invoked via absolute path (/usr/sbin/qm, /usr/sbin/pvesm).
# External tools like vzdump are NOT affected by these overrides.
#===============================================================================
qm() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "DEBUG" "[DRY-RUN] qm $*"
        
        case "$1" in
            status)
                return 1
                ;;
            agent)
                if [[ "$2" == "$VMID" && "$3" == "ping" ]]; then
                    return 0
                fi
                return 0
                ;;
            *)
                return 0
                ;;
        esac
    else
        /usr/sbin/qm "$@"
    fi
}

pvesm() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        case "$1" in
            status)
                if [[ "$2" == "--storage" ]]; then
                    echo "dir local /var/lib/vz 1000000000 500000000 500000000 50.00%"
                    return 0
                fi
                ;;
            config)
                if [[ "$2" == "local" ]]; then
                    cat <<EOF
dir: local
	path /var/lib/vz
	content vztmpl,iso,backup,snippets
	shared 0
EOF
                    return 0
                fi
                ;;
        esac
        log "DEBUG" "[DRY-RUN] pvesm $*"
        return 0
    else
        /usr/sbin/pvesm "$@"
    fi
}

#===============================================================================
# PREREQUISITE CHECKS
#===============================================================================
check_prerequisites() {
    log "STEP" "Checking prerequisites..."
    
    local missing_cmds=()
    
    # Check Proxmox binaries
    local required_bins=(
        /usr/sbin/qm
        /usr/sbin/pvesm
    )
    
    for bin in "${required_bins[@]}"; do
        if [[ ! -x "$bin" ]]; then
            missing_cmds+=("$(basename "$bin")")
        fi
    done
    
    # Check standard utilities
    local required_cmds=(curl openssl awk sed grep mktemp flock tr timeout stat wc du)
    for cmd in "${required_cmds[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_cmds+=("$cmd")
        fi
    done
    
    if [[ ${#missing_cmds[@]} -gt 0 ]]; then
        fatal_error "Missing required commands: ${missing_cmds[*]}"
    fi
    
    if [[ $EUID -ne 0 ]]; then
        fatal_error "This script must be run as root. Try: sudo $0 $*"
    fi
    
    if [[ ! -f /etc/pve/.version ]]; then
        fatal_error "This script must run on a Proxmox VE host"
    fi
    
    local pve_version
    pve_version=$(cat /etc/pve/.version 2>/dev/null || echo "unknown")
    log "INFO" "Proxmox VE version: $pve_version"
    
    log "SUCCESS" "All prerequisites met"
}

#===============================================================================
# CONFIGURATION LOADING
#===============================================================================
# Whitelist of allowed config variables (prevents arbitrary code execution)
readonly _CONFIG_WHITELIST="VMID VMNAME MEM CORES DISK_GB BRIDGE VM_ONBOOT VM_STARTUP_ORDER VM_BALLOON VM_TAGS STORAGE SNIPPET_STORAGE CACHE_DIR CACHE_MAX_AGE_DAYS USE_DHCP IP_CIDR GATEWAY_IP DNS_SERVERS SEARCH_DOMAIN ENABLE_FIREWALL ALLOWED_NETWORKS BIND_TO_IP UBUNTU_RELEASE IMG_URL IMG_SHA256 CI_USER SSH_PUBKEY_FILE LITELLM_PORT LITELLM_MASTER_KEY POSTGRES_PASS GRAFANA_ADMIN_PASS LITELLM_CONFIG_FILE POSTGRES_VERSION REDIS_VERSION LITELLM_VERSION PROMETHEUS_VERSION GRAFANA_VERSION OLLAMA_IP OLLAMA_PORT ENABLE_MONITORING ENABLE_LITELLM_METRICS ENABLE_BACKUP ENABLE_VALIDATION_SCRIPT DRY_RUN INTERACTIVE DEBUG SKIP_IDEMPOTENCY_CHECK PACKAGE_UPGRADE CLEANUP_SNIPPET STRICT_POSTCHECK AUTO_PURGE_CREDS AUTO_FIX_STORAGE"

# Safe config loader: parse key=value with whitelist, reject shell expansion
# Used by load_config_file, print_effective_config, and lint_config
_safe_load_config() {
    local config_file="$1"
    local verbose="${2:-0}"  # 1 = log details (used by load_config_file)
    
    local line_num=0
    local loaded=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_num=$((line_num + 1))
        
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Trim whitespace (but do NOT strip inline comments yet — '#' may be inside values)
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue
        
        # Must match KEY=VALUE pattern
        if ! [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]]; then
            if [[ "$verbose" == "1" ]]; then
                log "WARN" "Config line ${line_num}: skipping invalid format: ${line:0:60}"
            fi
            continue
        fi
        
        local key="${BASH_REMATCH[1]}"
        local value="${BASH_REMATCH[2]}"
        
        # Strip surrounding quotes from value FIRST
        if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        else
            # Only strip inline comments for UNQUOTED values
            # (comments after quoted values are already excluded by the greedy quote regex)
            value="${value%%[[:space:]]#*}"
            # Trim trailing whitespace
            value="$(echo "$value" | sed 's/[[:space:]]*$//')"
        fi
        
        # Security: reject values containing command substitution or dangerous patterns
        if [[ "$value" =~ \$\( || "$value" =~ \` || "$value" =~ \$\{ ]]; then
            if [[ "$verbose" == "1" ]]; then
                log "WARN" "Config line ${line_num}: rejecting '${key}' (contains shell expansion)"
            fi
            continue
        fi
        
        # Check whitelist
        if [[ " $_CONFIG_WHITELIST " != *" $key "* ]]; then
            if [[ "$verbose" == "1" ]]; then
                log "WARN" "Config line ${line_num}: unknown variable '${key}' (not in whitelist, skipping)"
            fi
            continue
        fi
        
        # Safe assignment: env vars take precedence over config file values
        # (env vars are already set via : "${VAR:=default}" before config loading)
        # Only override if variable was not explicitly set via env
        if [[ -n "${_ENV_OVERRIDES[$key]+_}" ]]; then
            if [[ "$verbose" == "1" ]]; then
                log "DEBUG" "Config: ${key} skipped (overridden by environment variable)"
            fi
            continue
        fi
        declare -g "$key=$value"
        loaded=$((loaded + 1))
        if [[ "$verbose" == "1" ]]; then
            log "DEBUG" "Config: ${key}=${value:0:40}$([ ${#value} -gt 40 ] && echo '...')"
        fi
    done < "$config_file"
    
    if [[ "$verbose" == "1" && "$loaded" -gt 0 ]]; then
        log "INFO" "Loaded ${loaded} variable(s) from config file"
    fi
    
    return 0
}

load_config_file() {
    local config_file="${1:-}"
    
    if [[ -z "$config_file" ]]; then
        log "DEBUG" "No config file specified, using defaults"
        return 0
    fi
    
    if [[ ! -f "$config_file" ]]; then
        fatal_error "Config file not found: $config_file"
    fi
    
    log "INFO" "Loading configuration from: $config_file"
    
    _safe_load_config "$config_file" "1"
    
    log "SUCCESS" "Configuration loaded from ${config_file}"
}

load_litellm_config() {
    if [[ -z "${LITELLM_CONFIG_FILE}" ]]; then
        log "DEBUG" "No custom LiteLLM config specified, using default"
        return 0
    fi
    
    if [[ ! -f "${LITELLM_CONFIG_FILE}" ]]; then
        fatal_error "LiteLLM config file not found: ${LITELLM_CONFIG_FILE}"
    fi
    
    # Safety checks for external config
    local file_size
    file_size=$(wc -c < "${LITELLM_CONFIG_FILE}")
    
    if [ "$file_size" -gt "$MAX_CONFIG_SIZE_BYTES" ]; then
        fatal_error "Config file too large: ${file_size} bytes (max: ${MAX_CONFIG_SIZE_BYTES})"
    fi
    
    if [ "$file_size" -eq 0 ]; then
        fatal_error "Config file is empty: ${LITELLM_CONFIG_FILE}"
    fi
    
    log "INFO" "Loading custom LiteLLM config from: ${LITELLM_CONFIG_FILE}"
    
    # Read and sanitize config (remove Windows line endings)
    CUSTOM_CONFIG_CONTENT=$(tr -d '\r' < "${LITELLM_CONFIG_FILE}")
    
    # Check for NULL bytes (binary)
    if grep -q $'\x00' <<<"$CUSTOM_CONFIG_CONTENT"; then
        fatal_error "Config file contains binary data (NULL bytes): ${LITELLM_CONFIG_FILE}"
    fi
    
    log "SUCCESS" "Custom LiteLLM config loaded ($(wc -l < "${LITELLM_CONFIG_FILE}") lines, ${file_size} bytes)"
    log "DEBUG" "Config will be properly indented for cloud-init injection"
}

#===============================================================================
# INPUT VALIDATION
#===============================================================================
# Helper: validate IP address octets are 0-255
_validate_ip_octets() {
    local ip="$1"
    local label="${2:-IP}"
    local IFS='.'
    read -ra octets <<< "$ip"
    
    if [[ "${#octets[@]}" -ne 4 ]]; then
        fatal_error "Invalid ${label}: '${ip}' does not have exactly 4 octets"
    fi
    
    for octet in "${octets[@]}"; do
        if ! [[ "$octet" =~ ^[0-9]+$ ]]; then
            fatal_error "Invalid ${label}: non-numeric octet '${octet}' in '${ip}'"
        fi
        if [[ "$octet" -gt 255 ]]; then
            fatal_error "Invalid ${label}: octet value ${octet} exceeds 255 in ${ip}"
        fi
    done
}

validate_inputs() {
    log "STEP" "Validating inputs..."
    
    if ! [[ "$VMID" =~ ^[0-9]+$ ]] || [ "$VMID" -lt 100 ] || [ "$VMID" -gt 999999999 ]; then
        fatal_error "Invalid VMID: must be numeric (100-999999999), got: $VMID"
    fi
    
    if ! [[ "$VMNAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        fatal_error "Invalid VMNAME: must be alphanumeric with - or _, got: $VMNAME"
    fi
    
    if ! [[ "$MEM" =~ ^[0-9]+$ ]] || [ "$MEM" -lt 512 ]; then
        fatal_error "Invalid MEM: must be >= 512 MB, got: $MEM"
    fi
    
    if ! [[ "$CORES" =~ ^[0-9]+$ ]] || [ "$CORES" -lt 1 ] || [ "$CORES" -gt 128 ]; then
        fatal_error "Invalid CORES: must be 1-128, got: $CORES"
    fi
    
    if ! [[ "$DISK_GB" =~ ^[0-9]+$ ]] || [ "$DISK_GB" -lt 10 ]; then
        fatal_error "Invalid DISK_GB: must be >= 10 GB, got: $DISK_GB"
    fi
    
    if [[ "$VM_BALLOON" != "0" ]]; then
        if ! [[ "$VM_BALLOON" =~ ^[0-9]+$ ]] || [ "$VM_BALLOON" -ge "$MEM" ]; then
            fatal_error "Invalid VM_BALLOON: must be 0 or < MEM, got: $VM_BALLOON"
        fi
    fi
    
    if [[ "$USE_DHCP" != "1" ]]; then
        if ! [[ "$IP_CIDR" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            fatal_error "Invalid IP_CIDR format, got: $IP_CIDR"
        fi
        _validate_ip_octets "${IP_CIDR%/*}" "IP_CIDR"
        
        # Validate CIDR prefix (0-32)
        local cidr_prefix="${IP_CIDR#*/}"
        if [ "$cidr_prefix" -gt 32 ]; then
            fatal_error "Invalid CIDR prefix: must be 0-32, got: /$cidr_prefix"
        fi
        
        if ! [[ "$GATEWAY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            fatal_error "Invalid GATEWAY_IP format, got: $GATEWAY_IP"
        fi
        _validate_ip_octets "$GATEWAY_IP" "GATEWAY_IP"
    fi
    
    if [[ ! -f "$SSH_PUBKEY_FILE" ]]; then
        fatal_error "SSH public key file not found: $SSH_PUBKEY_FILE"
    fi
    
    SSH_PUBKEY=$(cat "$SSH_PUBKEY_FILE")
    if ! [[ "$SSH_PUBKEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256).+ ]]; then
        fatal_error "Invalid or unsupported SSH public key format in: $SSH_PUBKEY_FILE (ssh-dss/DSA is not supported)"
    fi
    
    # Warn about ssh-rsa (SHA-1 based, disabled by default in OpenSSH 8.8+)
    if [[ "$SSH_PUBKEY" =~ ^ssh-rsa ]]; then
        log "WARN" "SSH key type 'ssh-rsa' uses SHA-1 signatures (deprecated in OpenSSH 8.8+)"
        log "WARN" "Recommended: ssh-keygen -t ed25519 (or sk-ssh-ed25519 for FIDO2)"
    fi
    
    if ! [[ "$OLLAMA_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        fatal_error "Invalid OLLAMA_IP format, got: $OLLAMA_IP"
    fi
    _validate_ip_octets "$OLLAMA_IP" "OLLAMA_IP"
    
    if ! [[ "$OLLAMA_PORT" =~ ^[0-9]+$ ]] || [ "$OLLAMA_PORT" -lt 1 ] || [ "$OLLAMA_PORT" -gt 65535 ]; then
        fatal_error "Invalid OLLAMA_PORT: must be 1-65535, got: $OLLAMA_PORT"
    fi
    
    # Validate DNS_SERVERS (space or comma delimited IPs)
    local dns_clean="${DNS_SERVERS//,/ }"
    for dns_entry in $dns_clean; do
        if ! [[ "$dns_entry" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            fatal_error "Invalid DNS_SERVERS entry: '$dns_entry' (must be valid IPv4)"
        fi
        _validate_ip_octets "$dns_entry" "DNS_SERVERS($dns_entry)"
    done
    
    # Validate ALLOWED_NETWORKS entries (if firewall enabled)
    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        IFS=',' read -ra _nets <<< "$ALLOWED_NETWORKS"
        for _net in "${_nets[@]}"; do
            _net=$(echo "$_net" | xargs)
            
            # Require CIDR notation (IP/prefix)
            if [[ "$_net" != *"/"* ]]; then
                fatal_error "ALLOWED_NETWORKS entry missing CIDR prefix: '$_net' (expected format: x.x.x.x/y)"
            fi
            
            local _net_ip="${_net%/*}"
            local _net_prefix="${_net#*/}"
            
            # Validate IP format and octets
            if ! [[ "$_net_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                fatal_error "Invalid ALLOWED_NETWORKS entry IP format: $_net"
            fi
            _validate_ip_octets "$_net_ip" "ALLOWED_NETWORKS($_net)"
            
            # Validate CIDR prefix (0-32)
            if ! [[ "$_net_prefix" =~ ^[0-9]+$ ]] || [ "$_net_prefix" -gt 32 ]; then
                fatal_error "Invalid ALLOWED_NETWORKS CIDR prefix: /$_net_prefix in '$_net' (must be 0-32)"
            fi
        done
    fi
    
    log "SUCCESS" "All inputs validated"
    
    # Warn about unpinned container versions (non-deterministic deployments)
    local _unpinned=""
    [[ "$LITELLM_VERSION" == "latest" || "$LITELLM_VERSION" == "main-stable" ]] && _unpinned+="LITELLM_VERSION "
    [[ "$PROMETHEUS_VERSION" == "latest" ]] && _unpinned+="PROMETHEUS_VERSION "
    [[ "$GRAFANA_VERSION" == "latest" ]] && _unpinned+="GRAFANA_VERSION "
    if [[ -n "$_unpinned" ]]; then
        log "WARN" "Unpinned container versions (non-deterministic): ${_unpinned}"
        log "WARN" "For reproducible production deployments, pin to specific versions"
        log "WARN" "  e.g. LITELLM_VERSION=main-v1.63.2 PROMETHEUS_VERSION=v3.2.1 GRAFANA_VERSION=11.5.2"
        
        # In interactive mode, require explicit confirmation to proceed with 'latest'
        if [[ "${INTERACTIVE}" == "1" ]]; then
            read -p "Continue with unpinned 'latest' tags? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                fatal_error "Aborted: set pinned versions and re-run"
            fi
        fi
    fi
}

#===============================================================================
# STORAGE VALIDATION
#===============================================================================
validate_storage() {
    log "STEP" "Validating storage configuration..."
    
    if [[ "${DRY_RUN}" != "1" ]]; then
        if ! pvesm status --storage "$STORAGE" &>/dev/null; then
            fatal_error "Storage '$STORAGE' not found in Proxmox"
        fi
        
        local storage_status
        storage_status=$(pvesm status --storage "$STORAGE" 2>/dev/null | tail -n1)
        if [[ -n "$storage_status" ]]; then
            local avail_info=$(echo "$storage_status" | awk '{for(i=1;i<=NF;i++) if($i ~ /[0-9]+G/) print $i}' | tail -1)
            if [[ -n "$avail_info" ]]; then
                log "INFO" "Storage '$STORAGE' available: $avail_info (estimate)"
            fi
        fi
        
        log "SUCCESS" "Storage '$STORAGE' is accessible"
    fi
}

validate_snippet_storage() {
    log "STEP" "Validating snippet storage..."
    
    if [[ "${DRY_RUN}" != "1" ]]; then
        if ! pvesm status --storage "$SNIPPET_STORAGE" &>/dev/null; then
            fatal_error "Snippet storage '$SNIPPET_STORAGE' not found"
        fi
        
        # Parse /etc/pve/storage.cfg directly (pvesm config does not exist)
        local storage_cfg="/etc/pve/storage.cfg"
        if [[ ! -f "$storage_cfg" ]]; then
            fatal_error "Proxmox storage config not found: $storage_cfg"
        fi
        
        # Extract the block for our storage (e.g. "dir: local" followed by indented lines)
        local st_block
        st_block="$(awk -v store="$SNIPPET_STORAGE" '
            /^[a-z]+:[[:space:]]+/ {
                split($0, a, ":")
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[2])
                if (a[2] == store) { found=1; type=a[1]; next }
                else { found=0 }
            }
            found && /^[[:space:]]/ { print }
        ' "$storage_cfg")" || true
        
        local st_type
        st_type="$(awk -v store="$SNIPPET_STORAGE" '
            /^[a-z]+:[[:space:]]+/ {
                split($0, a, ":")
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", a[2])
                if (a[2] == store) { print a[1]; exit }
            }
        ' "$storage_cfg")" || true
        
        local st_path
        st_path="$(awk '/^[[:space:]]+path[[:space:]]/{print $2; exit}' <<<"$st_block")" || true
        
        if [[ "$st_type" != "dir" || -z "${st_path}" ]]; then
            fatal_error "Snippet storage '$SNIPPET_STORAGE' is not a directory storage (type=dir). Detected type='${st_type:-unknown}', path='${st_path:-not set}'"
        fi
        
        SNIP_DIR="${st_path%/}/snippets"
        mkdir -p "$SNIP_DIR" 2>/dev/null || fatal_error "Cannot create snippets directory: $SNIP_DIR"
        
        # Check and auto-enable snippets content type
        local st_content
        st_content="$(awk '/^[[:space:]]+content[[:space:]]/{$1=""; gsub(/^[[:space:]]+/,""); print; exit}' <<<"$st_block")" || true
        
        if [[ ! "$st_content" =~ snippets ]]; then
            if [[ "${AUTO_FIX_STORAGE}" == "1" ]]; then
                log "INFO" "Auto-enabling 'snippets' content on '$SNIPPET_STORAGE' (AUTO_FIX_STORAGE=1)..."
                if [[ -n "$st_content" ]]; then
                    pvesm set "$SNIPPET_STORAGE" --content "${st_content},snippets" >/dev/null
                else
                    pvesm set "$SNIPPET_STORAGE" --content "vztmpl,iso,backup,snippets" >/dev/null
                fi
                log "SUCCESS" "Added 'snippets' content type to '$SNIPPET_STORAGE'"
            else
                fatal_error "Storage '$SNIPPET_STORAGE' missing 'snippets' content type. Fix: pvesm set $SNIPPET_STORAGE --content '${st_content:+${st_content},}snippets' or set AUTO_FIX_STORAGE=1"
            fi
        fi
        
        log "SUCCESS" "Snippet storage configured: $SNIP_DIR"
    else
        SNIP_DIR="/tmp/snippets"
        mkdir -p "$SNIP_DIR"
    fi
}

#===============================================================================
# PRE-DEPLOY MUTATION SUMMARY
#===============================================================================
print_mutation_summary() {
    log "STEP" "Pre-deployment mutation summary..."
    
    local mutations=()
    
    # VM lifecycle
    if [[ "${DRY_RUN}" != "1" ]] && qm status "$VMID" &>/dev/null 2>&1; then
        mutations+=("DESTROY+RECREATE VM $VMID on storage '$STORAGE'")
    else
        mutations+=("CREATE VM $VMID (${CORES} cores, ${MEM}MB RAM, ${DISK_GB}GB disk) on '$STORAGE'")
    fi
    
    # Storage modifications
    if [[ "${AUTO_FIX_STORAGE}" == "1" ]]; then
        mutations+=("MAY MODIFY storage '$SNIPPET_STORAGE' content types (add snippets if missing)")
    fi
    
    # Files on host
    local snippet_fate="persists on host"
    [[ "${CLEANUP_SNIPPET}" == "1" ]] && snippet_fate="auto-removed after deploy"
    mutations+=("WRITE cloud-init snippet → ${SNIP_DIR}/ (${snippet_fate})")
    mutations+=("WRITE deployment log → ${LOG_FILE}")
    mutations+=("DOWNLOAD cloud image → ${CACHE_DIR}/ (if not cached)")
    
    # Validation script
    if [[ "${ENABLE_VALIDATION_SCRIPT}" == "1" && "$USE_DHCP" != "1" ]]; then
        mutations+=("WRITE validation script → /tmp/validate-llm-gateway-${VMID}.sh")
    fi
    
    # Post-deploy actions
    if [[ "${AUTO_PURGE_CREDS}" == "1" ]]; then
        mutations+=("SSH → VM: retrieve then SHRED credentials file")
    fi
    
    echo ""
    log "INFO" "This deployment will:"
    local i=1
    for m in "${mutations[@]}"; do
        log "INFO" "  ${i}. ${m}"
        i=$((i + 1))
    done
    echo ""
    
    if [[ "${INTERACTIVE}" == "1" ]]; then
        read -p "Proceed? (y/n) " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && fatal_error "Aborted by user"
    fi
}

#===============================================================================
# IDEMPOTENCY CHECK
#===============================================================================
check_existing_deployment() {
    if [[ "${SKIP_IDEMPOTENCY_CHECK}" == "1" ]]; then
        return 0
    fi
    
    log "STEP" "Checking for existing deployment..."
    
    if [[ "${DRY_RUN}" != "1" ]]; then
        if qm status "$VMID" &>/dev/null; then
            _VM_EXISTS=1
            log "WARN" "VM $VMID already exists"
            
            if [[ "$USE_DHCP" != "1" ]]; then
                local vm_ip="${IP_CIDR%/*}"
                
                # Health check with auth (secrets hidden from /proc via curl --config + process substitution)
                local _idem_ok=0
                if [[ "${LITELLM_MASTER_KEY}" != "AUTO" && -n "${LITELLM_MASTER_KEY}" ]]; then
                    timeout 5 curl -sf --config <(printf 'header = "Authorization: Bearer %s"\n' "${LITELLM_MASTER_KEY}") \
                        "http://${vm_ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1 && _idem_ok=1
                else
                    timeout 5 curl -sf "http://${vm_ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1 && _idem_ok=1
                fi
                
                if [[ "$_idem_ok" == "1" ]]; then
                    log "SUCCESS" "LiteLLM is already deployed and healthy on VM $VMID (${vm_ip})"
                    log "INFO" "Endpoint: http://${vm_ip}:${LITELLM_PORT}"
                    
                    if [[ "${INTERACTIVE}" == "1" ]]; then
                        read -p "Re-deploy anyway? (y/n) " -n 1 -r
                        echo
                        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
                    else
                        log "INFO" "Use SKIP_IDEMPOTENCY_CHECK=1 to force re-deployment"
                        exit 0
                    fi
                fi
            else
                log "INFO" "DHCP mode: skipping health check (IP unknown)"
            fi
        fi
    fi
}

#===============================================================================
# VM CONFLICT CHECK
#===============================================================================
check_vm_conflicts() {
    log "STEP" "Checking for VM conflicts (skipped - VM pre-configured)..."
    
    if [[ "${DRY_RUN}" != "1" ]]; then
        # Use cached result from check_existing_deployment, or re-check if skipped
        local vm_exists="${_VM_EXISTS}"
        if [[ "$vm_exists" != "1" ]] && qm status "$VMID" &>/dev/null; then
            vm_exists=1
        fi
        
        if [[ "$vm_exists" == "1" ]]; then
            log "WARN" "VM $VMID exists and will be destroyed"
            
            if [[ "${INTERACTIVE}" == "1" ]]; then
                read -p "Destroy existing VM $VMID and proceed? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    fatal_error "Aborted by user"
                fi
            else
                log "INFO" "Non-interactive mode: proceeding with VM destruction"
            fi
            
            log "INFO" "Destroying existing VM $VMID..."
            qm stop "$VMID" &>/dev/null || true
            sleep 3
            qm destroy "$VMID" --purge
            log "SUCCESS" "Existing VM destroyed"
        fi
    fi
}

#===============================================================================
# BACKUP EXISTING VM
#===============================================================================
backup_vm() {
    if [[ "${ENABLE_BACKUP}" != "1" ]]; then
        return 0
    fi
    
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would backup VM $VMID"
        return 0
    fi
    
    if qm status "$VMID" &>/dev/null; then
        log "STEP" "Backing up existing VM $VMID..."
        
        if vzdump "$VMID" --compress zstd --mode snapshot --quiet 1 2>>"$LOG_FILE"; then
            log "SUCCESS" "Backup created successfully"
        else
            log "WARN" "Backup failed, continuing anyway..."
        fi
    fi
}

#===============================================================================
# INTERACTIVE SETUP WIZARD
#===============================================================================
interactive_setup() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       LLM Gateway VM Configuration Wizard                    ║"
    echo "║                    Version ${SCRIPT_VERSION}                             ║"
    echo "╚══════════════════════════════════════════════════════════════╝"

    read -p "VM ID [$VMID]: " input_vmid
    VMID="${input_vmid:-$VMID}"
    
    read -p "VM Name [$VMNAME]: " input_name
    VMNAME="${input_name:-$VMNAME}"
    
    read -p "Memory (MB) [$MEM]: " input_mem
    MEM="${input_mem:-$MEM}"
    
    read -p "CPU Cores [$CORES]: " input_cores
    CORES="${input_cores:-$CORES}"
    
    read -p "Disk Size (GB) [$DISK_GB]: " input_disk
    DISK_GB="${input_disk:-$DISK_GB}"
    
    read -p "Use DHCP? (y/n) [$([ "$USE_DHCP" = "1" ] && echo 'y' || echo 'n')]: " input_dhcp
    if [[ "$input_dhcp" =~ ^[Yy]$ ]]; then
        USE_DHCP="1"
    else
        USE_DHCP="0"
        read -p "Static IP (CIDR) [$IP_CIDR]: " input_ip
        IP_CIDR="${input_ip:-$IP_CIDR}"
        
        read -p "Gateway IP [$GATEWAY_IP]: " input_gw
        GATEWAY_IP="${input_gw:-$GATEWAY_IP}"
    fi
    
    read -p "Ollama Backend IP [$OLLAMA_IP]: " input_ollama
    OLLAMA_IP="${input_ollama:-$OLLAMA_IP}"
    
    read -p "Enable Monitoring? (y/n) [$([ "$ENABLE_MONITORING" = "1" ] && echo 'y' || echo 'n')]: " input_mon
    [[ "$input_mon" =~ ^[Yy]$ ]] && ENABLE_MONITORING="1" || ENABLE_MONITORING="0"
    
    read -p "Enable Firewall? (y/n) [$([ "$ENABLE_FIREWALL" = "1" ] && echo 'y' || echo 'n')]: " input_fw
    [[ "$input_fw" =~ ^[Yy]$ ]] && ENABLE_FIREWALL="1" || ENABLE_FIREWALL="0"
    
    if [[ "$ENABLE_FIREWALL" == "1" ]]; then
        read -p "Allowed Networks (CIDR) [$ALLOWED_NETWORKS]: " input_allow
        ALLOWED_NETWORKS="${input_allow:-$ALLOWED_NETWORKS}"
        
        read -p "Bind services to IP only (more secure)? (y/n) [$([ "$BIND_TO_IP" = "1" ] && echo 'y' || echo 'n')]: " input_bind
        [[ "$input_bind" =~ ^[Yy]$ ]] && BIND_TO_IP="1" || BIND_TO_IP="0"
    fi
    
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "Configuration Summary:"
    echo "═══════════════════════════════════════════════════════════"
    echo "VM ID:          $VMID"
    echo "VM Name:        $VMNAME"
    echo "Memory:         ${MEM}MB"
    echo "CPU Cores:      $CORES"
    echo "Disk Size:      ${DISK_GB}GB"
    echo "Storage:        $STORAGE"
    echo "Network:        $([ "$USE_DHCP" = "1" ] && echo "DHCP" || echo "$IP_CIDR (GW: $GATEWAY_IP)")"
    echo "Ollama Backend: ${OLLAMA_IP}:${OLLAMA_PORT}"
    echo "Monitoring:     $([ "$ENABLE_MONITORING" = "1" ] && echo "Enabled" || echo "Disabled")"
    echo "Firewall:       $([ "$ENABLE_FIREWALL" = "1" ] && echo "Enabled ($ALLOWED_NETWORKS)" || echo "Disabled")"
    echo "Bind to IP:     $([ "$BIND_TO_IP" = "1" ] && echo "Yes" || echo "No")"
    echo "═══════════════════════════════════════════════════════════"
    echo
    
    read -p "Proceed with this configuration? (y/n) " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && fatal_error "Aborted by user"
}

#===============================================================================
# CLOUD IMAGE DOWNLOAD (WITH LOCKING)
#===============================================================================
# Helper: verify downloaded cloud image SHA256
_verify_cloud_image_checksum() {
    local img_file="$1"
    local img_basename
    img_basename="$(basename "$IMG_PATH")"
    
    # If user provided explicit checksum, use it
    if [[ -n "${IMG_SHA256}" ]]; then
        local actual_sum
        actual_sum=$(sha256sum "$img_file" | awk '{print $1}')
        if [[ "$actual_sum" == "${IMG_SHA256}" ]]; then
            log "SUCCESS" "Image checksum verified (pinned SHA256)"
            return 0
        else
            log "ERROR" "Checksum mismatch! Expected: ${IMG_SHA256:0:16}... Got: ${actual_sum:0:16}..."
            return 1
        fi
    fi
    
    # Try to download SHA256SUMS from the same directory as the image
    local base_url="${IMG_URL%/*}"
    local sums_url="${base_url}/SHA256SUMS"
    local sums_file
    sums_file="$(mktemp)"
    
    if curl -sfL "$sums_url" -o "$sums_file" 2>/dev/null; then
        local expected_sum
        expected_sum=$(grep "${img_basename}" "$sums_file" | awk '{print $1}' | head -n1)
        rm -f "$sums_file"
        
        if [[ -n "$expected_sum" ]]; then
            local actual_sum
            actual_sum=$(sha256sum "$img_file" | awk '{print $1}')
            if [[ "$actual_sum" == "$expected_sum" ]]; then
                log "SUCCESS" "Image checksum verified (SHA256SUMS)"
                return 0
            else
                log "ERROR" "Checksum mismatch! Expected: ${expected_sum:0:16}... Got: ${actual_sum:0:16}..."
                return 1
            fi
        else
            log "WARN" "Image not found in SHA256SUMS, skipping verification"
            return 0
        fi
    else
        rm -f "$sums_file"
        log "WARN" "Could not download SHA256SUMS, skipping verification (set IMG_SHA256 to enforce)"
        return 0
    fi
}

download_cloud_image() {
    log "STEP" "[Step 1/10] Managing cloud image..."
    
    mkdir -p "$CACHE_DIR" 2>/dev/null || fatal_error "Cannot create cache dir: $CACHE_DIR"
    
    IMG_PATH="${CACHE_DIR}/${UBUNTU_RELEASE}-server-cloudimg-amd64.img"
    
    # Acquire lock to prevent concurrent downloads
    local lock_file="${CACHE_DIR}/.download-${UBUNTU_RELEASE}.lock"
    exec {CACHE_LOCK_FD}>"$lock_file" 2>/dev/null || fatal_error "Cannot create lock file"
    
    if ! flock -n "$CACHE_LOCK_FD"; then
        log "INFO" "Another process is downloading the image, waiting..."
        flock "$CACHE_LOCK_FD"
        log "INFO" "Lock acquired, continuing..."
    fi
    
    # Check if cached image exists and is recent
    if [[ -f "$IMG_PATH" ]]; then
        local file_age_days=$(( ($(date +%s) - $(stat -c %Y "$IMG_PATH" 2>/dev/null || echo 0)) / 86400 ))
        
        if [ "$file_age_days" -lt "$CACHE_MAX_AGE_DAYS" ]; then
            log "SUCCESS" "Using cached image (${file_age_days}d old): $IMG_PATH"
            return 0
        else
            log "INFO" "Cache expired (${file_age_days}d old), re-downloading..."
            rm -f "$IMG_PATH"
        fi
    fi
    
    log "INFO" "Downloading from: $IMG_URL"
    
    local tmp_img="${IMG_PATH}.tmp.$$"
    local retries=3
    local attempt=1
    
    while [ $attempt -le $retries ]; do
        if [[ "${DRY_RUN}" == "1" ]]; then
            log "INFO" "[DRY-RUN] Would download image"
            touch "$IMG_PATH"
            return 0
        fi
        
        if curl -fL --progress-bar "$IMG_URL" -o "$tmp_img" 2>>"$LOG_FILE"; then
            # Verify image integrity (SHA256)
            if ! _verify_cloud_image_checksum "$tmp_img"; then
                log "WARN" "Checksum verification failed on attempt $attempt/$retries"
                rm -f "$tmp_img"
                attempt=$((attempt + 1))
                [ $attempt -le $retries ] && sleep 5
                continue
            fi
            
            mv "$tmp_img" "$IMG_PATH"
            chmod 644 "$IMG_PATH"
            log "SUCCESS" "Cloud image cached ($(du -h "$IMG_PATH" | cut -f1))"
            return 0
        fi
        
        log "WARN" "Download attempt $attempt/$retries failed"
        rm -f "$tmp_img"
        attempt=$((attempt + 1))
        [ $attempt -le $retries ] && sleep 5
    done
    
    fatal_error "Failed to download cloud image after $retries attempts"
}

#===============================================================================
# VM CREATION
#===============================================================================
create_vm_shell() {
    log "STEP" "[Step 2/10] Creating VM shell..."
    if qm status "" &>/dev/null; then
        log "INFO" "VM  already exists, skipping creation"
        return 0
    fi
    
    local vm_desc="LiteLLM Gateway v${SCRIPT_VERSION} - Deployed on $(date '+%Y-%m-%d %H:%M:%S')"
    
    # Build qm create args (balloon is optional)
    local qm_args=(
        --name "$VMNAME"
        --memory "$MEM"
        --cores "$CORES"
        --cpu host
        --numa 1
        --net0 "virtio,bridge=${BRIDGE}"
        --scsihw virtio-scsi-pci
        --agent enabled=1
        --ostype l26
        --onboot "$VM_ONBOOT"
        --startup "order=${VM_STARTUP_ORDER},up=30,down=60"
        --tags "$VM_TAGS"
        --description "$vm_desc"
    )
    
    if [[ "$VM_BALLOON" != "0" ]]; then
        qm_args+=(--balloon "$VM_BALLOON")
    fi
    
    qm create "$VMID" "${qm_args[@]}" >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "VM $VMID created with optimized settings"
}

import_and_attach_disk() {
    log "STEP" "[Step 3/10] Importing and attaching disk..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would import $IMG_PATH to $STORAGE and attach as scsi0"
        return 0
    fi

    # Import cloud image into Proxmox storage and parse actual volume name
    # Note: qm importdisk writes progress AND result to stderr
    local import_output
    import_output=$(qm importdisk "$VMID" "$IMG_PATH" "$STORAGE" 2>&1 | tee -a "$LOG_FILE") || \
        fatal_error "Failed to import disk image"
    log "DEBUG" "importdisk output (last line): $(echo "$import_output" | tail -1)"

    # Parse volume name from importdisk output (e.g. "unused0:ssdpool:vm-120-disk-0")
    local volume=""
    volume=$(echo "$import_output" | grep -oP 'unused[0-9]+:\K\S+' | tail -1 || true)

    if [[ -z "$volume" ]]; then
        # Fallback: try STORAGE:vm-VMID-disk-0 pattern
        volume="${STORAGE}:vm-${VMID}-disk-0"
        log "WARN" "Could not parse volume from importdisk output, assuming: $volume"
    fi

    # Attach imported disk as scsi0
    qm set "$VMID" --scsi0 "$volume" >>"$LOG_FILE" 2>&1 || \
        fatal_error "Failed to attach disk as scsi0"

    log "SUCCESS" "Disk imported and attached as scsi0 ($volume)"
}

configure_disk_and_boot() {
    log "STEP" "[Step 4/10] Configuring disk and boot..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would resize disk to ${DISK_GB}GB and set boot order"
        return 0
    fi

    qm resize "$VMID" scsi0 "${DISK_GB}G" >>"$LOG_FILE" 2>&1
    qm set "$VMID" --boot c --bootdisk scsi0 >>"$LOG_FILE" 2>&1
    qm set "$VMID" --serial0 socket --vga serial0 >>"$LOG_FILE" 2>&1

    log "SUCCESS" "Disk resized to ${DISK_GB}GB and boot configured"
}

add_cloudinit_drive() {
    log "STEP" "[Step 5/10] Adding Cloud-Init drive..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would add cloud-init drive on ide2"
        return 0
    fi

    qm set "$VMID" --ide2 "${STORAGE}:cloudinit" >>"$LOG_FILE" 2>&1

    log "SUCCESS" "Cloud-Init drive added"
}

configure_cloudinit_network() {
    log "STEP" "[Step 6/10] Configuring Cloud-Init network..."

    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would configure cloud-init network settings"
        return 0
    fi

    WORKDIR=$(mktemp -d "/tmp/${VMNAME}-${VMID}-config.XXXXXX")
    chmod 700 "$WORKDIR"
    
    qm set "$VMID" --ciuser "$CI_USER" >>"$LOG_FILE" 2>&1
    
    local key_file="${WORKDIR}/ssh_key.pub"
    echo "$SSH_PUBKEY" > "$key_file"
    chmod 600 "$key_file"
    qm set "$VMID" --sshkeys "$key_file" >>"$LOG_FILE" 2>&1
    
    if [[ "$USE_DHCP" == "1" ]]; then
        qm set "$VMID" --ipconfig0 "ip=dhcp" >>"$LOG_FILE" 2>&1
        log "SUCCESS" "Network configured (DHCP)"
    else
        qm set "$VMID" --ipconfig0 "ip=${IP_CIDR},gw=${GATEWAY_IP}" >>"$LOG_FILE" 2>&1
        qm set "$VMID" --nameserver "$DNS_SERVERS" >>"$LOG_FILE" 2>&1
        qm set "$VMID" --searchdomain "$SEARCH_DOMAIN" >>"$LOG_FILE" 2>&1
        log "SUCCESS" "Network configured (Static: $IP_CIDR)"
    fi
}

#===============================================================================
# CLOUD-INIT USER DATA GENERATION (FINAL HARDENED VERSION)
#===============================================================================
generate_userdata() {
    log "STEP" "[Step 7/10] Generating Cloud-Init user data..."
    
    local userdata_file="${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml"
    
    # =========================================================================
    # Determine network configuration
    # =========================================================================
    local port_binding
    local vm_ip=""
    local fw_dest="any"
    
    if [[ "$USE_DHCP" != "1" ]]; then
        vm_ip="${IP_CIDR%/*}"
        
        if [[ "$BIND_TO_IP" == "1" ]]; then
            port_binding="${vm_ip}:${LITELLM_PORT}:${LITELLM_PORT}"
            fw_dest="$vm_ip"
            log "INFO" "Services will bind to specific IP: $vm_ip"
        else
            port_binding="${LITELLM_PORT}:${LITELLM_PORT}"
        fi
    else
        port_binding="${LITELLM_PORT}:${LITELLM_PORT}"
        log "INFO" "DHCP mode: Services will bind to 0.0.0.0"
    fi
    
    # =========================================================================
    # Build LiteLLM config.yaml (indented for cloud-init)
    # =========================================================================
    local config_yaml_raw
    
    if [[ -n "$CUSTOM_CONFIG_CONTENT" ]]; then
        config_yaml_raw="$CUSTOM_CONFIG_CONTENT"
        log "INFO" "Using custom LiteLLM configuration"
    else
        config_yaml_raw="model_list:
  - model_name: \"qwen3\"
    litellm_params:
      model: \"ollama/qwen3\"
      api_base: \"http://${OLLAMA_IP}:${OLLAMA_PORT}\"
  
  - model_name: \"gpt-oss-20b\"
    litellm_params:
      model: \"ollama/gpt-oss:20b\"
      api_base: \"http://${OLLAMA_IP}:${OLLAMA_PORT}\"
  
  - model_name: \"local-default\"
    litellm_params:
      model: \"ollama/qwen3\"
      api_base: \"http://${OLLAMA_IP}:${OLLAMA_PORT}\"

litellm_settings:
  drop_params: true
  set_verbose: false
  request_timeout: 600
  num_retries: 2
  allowed_fails: 3
  cooldown_time: 1"
    fi
    
    local config_yaml_content
    config_yaml_content="$(printf '%s\n' "$config_yaml_raw" | sed 's/^/      /')"
    log "DEBUG" "Config properly indented with 6-space prefix"
    
    # =========================================================================
    # Build docker-compose.yml as COMPLETE variable (no cat >> fragility)
    # =========================================================================
    local compose_content=""
    
    # Core services (always present)
    compose_content+="services:
  postgres:
    image: postgres:${POSTGRES_VERSION}
    container_name: llm-postgres
    environment:
      POSTGRES_USER: litellm
      POSTGRES_PASSWORD: \${POSTGRES_PASS}
      POSTGRES_DB: litellm
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: [\"CMD-SHELL\", \"pg_isready -U litellm -d litellm || exit 1\"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - llm-network

  redis:
    image: redis:${REDIS_VERSION}-alpine
    container_name: llm-redis
    restart: unless-stopped
    healthcheck:
      test: [\"CMD\", \"redis-cli\", \"ping\"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks:
      - llm-network

  litellm:
    image: ghcr.io/berriai/litellm:${LITELLM_VERSION}
    container_name: llm-litellm
    command:
      - \"--config\"
      - \"/app/config.yaml\"
      - \"--port\"
      - \"${LITELLM_PORT}\"
      - \"--num_workers\"
      - \"2\"
    environment:
      LITELLM_MASTER_KEY: \"\${LITELLM_MASTER_KEY}\"
      DATABASE_URL: \"postgresql://litellm:\${POSTGRES_PASS}@postgres:5432/litellm\"
      REDIS_URL: \"redis://redis:6379\"
    ports:
      - \"${port_binding}\"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - llm-network"
    
    # Optional monitoring services
    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        local prom_port_binding
        local graf_port_binding
        
        if [[ "$BIND_TO_IP" == "1" && "$USE_DHCP" != "1" ]]; then
            prom_port_binding="${vm_ip}:9090:9090"
            graf_port_binding="${vm_ip}:3000:3000"
        else
            prom_port_binding="9090:9090"
            graf_port_binding="3000:3000"
        fi
        
        compose_content+="

  prometheus:
    image: prom/prometheus:${PROMETHEUS_VERSION}
    container_name: llm-prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./data/prometheus:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    ports:
      - \"${prom_port_binding}\"
    restart: unless-stopped
    networks:
      - llm-network

  grafana:
    image: grafana/grafana:${GRAFANA_VERSION}
    container_name: llm-grafana
    environment:
      GF_SECURITY_ADMIN_USER: \"admin\"
      GF_SECURITY_ADMIN_PASSWORD: \"\${GRAFANA_ADMIN_PASS}\"
      GF_SERVER_ROOT_URL: \"http://localhost:3000\"
    volumes:
      - ./data/grafana:/var/lib/grafana
    ports:
      - \"${graf_port_binding}\"
    depends_on:
      - prometheus
    restart: unless-stopped
    networks:
      - llm-network"
    fi
    
    # Networks and volumes (always present, appended ONCE)
    compose_content+="

networks:
  llm-network:
    driver: bridge

volumes:
  pgdata:"
    
    # Indent entire compose for cloud-init write_files (6 spaces)
    local compose_indented
    compose_indented="$(printf '%s\n' "$compose_content" | sed 's/^/      /')"
    log "DEBUG" "docker-compose.yml built as complete variable ($(echo "$compose_content" | wc -l) lines)"
    
    # =========================================================================
    # Build prometheus.yml as complete variable (if monitoring enabled)
    # =========================================================================
    local prometheus_section=""
    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        local prom_raw="global:
  scrape_interval: 15s
  evaluation_interval: 15s"
        
        if [[ "${ENABLE_LITELLM_METRICS}" == "1" ]]; then
            prom_raw+="

scrape_configs:
  - job_name: 'litellm'
    metrics_path: '/metrics'
    static_configs:
      - targets: ['litellm:${LITELLM_PORT}']"
            log "INFO" "Prometheus will scrape LiteLLM /metrics (ensure it's available)"
        else
            log "INFO" "LiteLLM metrics disabled (ENABLE_LITELLM_METRICS=0)"
        fi
        
        local prom_indented
        prom_indented="$(printf '%s\n' "$prom_raw" | sed 's/^/      /')"
        
        prometheus_section="
  - path: /etc/llm-gateway/prometheus.yml
    permissions: \"0644\"
    content: |
${prom_indented}
"
    fi
    
    # =========================================================================
    # Build firewall rules for bootstrap script (clean, no echo -e in YAML)
    # =========================================================================
    local fw_rules_lines=""
    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        IFS=',' read -ra NETWORKS <<< "$ALLOWED_NETWORKS"
        
        for net in "${NETWORKS[@]}"; do
            net=$(echo "$net" | xargs)
            fw_rules_lines+="    ufw allow from ${net} to ${fw_dest} port 22 proto tcp comment 'SSH'
"
            fw_rules_lines+="    ufw allow from ${net} to ${fw_dest} port ${LITELLM_PORT} proto tcp comment 'LiteLLM API'
"
            if [[ "${ENABLE_MONITORING}" == "1" ]]; then
                fw_rules_lines+="    ufw allow from ${net} to ${fw_dest} port 9090 proto tcp comment 'Prometheus'
"
                fw_rules_lines+="    ufw allow from ${net} to ${fw_dest} port 3000 proto tcp comment 'Grafana'
"
            fi
        done
    fi
    
    # =========================================================================
    # Build bootstrap script (replaces fragile multi-segment runcmd)
    # All deployment logic runs as ONE script → no YAML indentation fragility
    # =========================================================================
    local bootstrap_script=""
    
    # Header (literal, no variable expansion needed)
    # NOTE: Single-quoted heredoc — $(date), $(gen_secret) etc. expand at VM RUNTIME, not host time
    bootstrap_script+='#!/usr/bin/env bash
#===============================================================================
# LLM Gateway Bootstrap Script
# Auto-generated by deploy-llm-gateway.sh
# This script runs inside the VM via cloud-init runcmd
#===============================================================================
set -euo pipefail
exec > >(tee -a /var/log/llm-gateway-bootstrap.log) 2>&1
echo "=========================================="
echo "LLM Gateway Bootstrap - $(date)"
echo "=========================================="

# --- Stage 1: Install config files ---
echo "📦 Installing config files..."
mkdir -p /opt/llm-gateway
install -m 0600 /etc/llm-gateway/.env /opt/llm-gateway/.env
install -m 0644 /etc/llm-gateway/config.yaml /opt/llm-gateway/config.yaml
install -m 0644 /etc/llm-gateway/docker-compose.yml /opt/llm-gateway/docker-compose.yml
test -f /etc/llm-gateway/prometheus.yml && install -m 0644 /etc/llm-gateway/prometheus.yml /opt/llm-gateway/prometheus.yml || true
echo "✅ Config files installed to /opt/llm-gateway"

# --- Stage 2: Create data directories ---
mkdir -p /opt/llm-gateway/data/{prometheus,grafana}
chmod 700 /opt/llm-gateway/data
chown 65534:65534 /opt/llm-gateway/data/prometheus
chmod 755 /opt/llm-gateway/data/prometheus
chown 472:0 /opt/llm-gateway/data/grafana
chmod 755 /opt/llm-gateway/data/grafana

# --- Stage 3: Generate secrets ---
echo "🔑 Generating secrets..."
ENV_FILE="/opt/llm-gateway/.env"
gen_secret() { openssl rand -hex 32; }

LITELLM_MASTER_KEY="$(awk -F= '"'"'/^LITELLM_MASTER_KEY=/{print $2}'"'"' "$ENV_FILE" | tr -d '"'"' '"'"')"
POSTGRES_PASS="$(awk -F= '"'"'/^POSTGRES_PASS=/{print $2}'"'"' "$ENV_FILE" | tr -d '"'"' '"'"')"
GRAFANA_ADMIN_PASS="$(awk -F= '"'"'/^GRAFANA_ADMIN_PASS=/{print $2}'"'"' "$ENV_FILE" | tr -d '"'"' '"'"')"

if [ "$LITELLM_MASTER_KEY" = "AUTO" ] || [ -z "$LITELLM_MASTER_KEY" ]; then
    LITELLM_MASTER_KEY="sk-$(gen_secret)"
fi
if [ "$POSTGRES_PASS" = "AUTO" ] || [ -z "$POSTGRES_PASS" ]; then
    POSTGRES_PASS="$(gen_secret)"
fi
if [ "$GRAFANA_ADMIN_PASS" = "AUTO" ] || [ -z "$GRAFANA_ADMIN_PASS" ]; then
    GRAFANA_ADMIN_PASS="$(gen_secret)"
fi

cat > "$ENV_FILE" <<ENVEOF
LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
POSTGRES_PASS=${POSTGRES_PASS}
GRAFANA_ADMIN_PASS=${GRAFANA_ADMIN_PASS}
ENVEOF
chmod 600 "$ENV_FILE"

CREDS="/root/llm-gateway-credentials.txt"
cat > "$CREDS" <<CREDSEOF
═══════════════════════════════════════════════════════
  LLM Gateway Credentials
  Generated: $(date)
═══════════════════════════════════════════════════════

LiteLLM Master Key:  ${LITELLM_MASTER_KEY}
PostgreSQL Password: ${POSTGRES_PASS}
Grafana Admin User:  admin
Grafana Password:    ${GRAFANA_ADMIN_PASS}

═══════════════════════════════════════════════════════
SECURITY: Keep this file secure! (chmod 600)
═══════════════════════════════════════════════════════
CREDSEOF
chmod 600 "$CREDS"
echo "✅ Secrets generated"
'
    
    # Stage 4: MOTD (needs host variable expansion for ports/version)
    # NOTE: Each bootstrap_script+= segment has its closing " on a SEPARATE line
    # from MOTD content to prevent quoting confusion during future edits
    local motd_services="📊 Services: LiteLLM http://\${VMIP}:${LITELLM_PORT}"
    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        motd_services+="
   Prometheus: http://\${VMIP}:9090
   Grafana:    http://\${VMIP}:3000"
    fi
    
    bootstrap_script+="
# --- Stage 4: Generate MOTD ---
VMIP=\"\$(hostname -I | awk '{print \$1}')\"
cat > /etc/motd <<MOTDEOF

╔══════════════════════════════════════════════════════════════╗
║           🚀 LLM Gateway ${SCRIPT_VERSION} - Ready           ║
╚══════════════════════════════════════════════════════════════╝

📍 LiteLLM API: http://\${VMIP}:${LITELLM_PORT}/v1/chat/completions
📋 Models: curl http://\${VMIP}:${LITELLM_PORT}/v1/models
${motd_services}

🔐 Credentials: /root/llm-gateway-credentials.txt
📝 Logs: cd /opt/llm-gateway && docker compose logs -f
🔄 Status: cd /opt/llm-gateway && docker compose ps
🔧 Systemd: systemctl status llm-gateway

MOTDEOF
"

    # Stage 5: Docker install (literal)
    bootstrap_script+='
# --- Stage 5: Install Docker ---
echo "🐳 Installing Docker CE..."
export DEBIAN_FRONTEND=noninteractive

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
    tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable --now docker
docker --version && docker compose version
echo "✅ Docker installed"
'

    # Stage 6: Firewall (uses pre-built rules)
    bootstrap_script+="
# --- Stage 6: Configure firewall ---
"
    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        bootstrap_script+="if command -v ufw >/dev/null 2>&1; then
    echo \"Configuring UFW firewall...\"
    # Set default policies FIRST
    ufw default deny incoming
    ufw default allow outgoing
    # Allow loopback and established connections
    ufw allow in on lo
    ufw allow out on lo
    # Allow specific services
${fw_rules_lines}    ufw logging on
    echo \"y\" | ufw enable
    ufw status verbose
    echo \"✅ Firewall configured\"
else
    echo \"⚠️  UFW not available\"
fi
"
    else
        bootstrap_script+='echo "Firewall disabled by configuration"
'
    fi

    # Stage 7: IP wait + Docker readiness gates
    if [[ "$BIND_TO_IP" == "1" && "$USE_DHCP" != "1" ]]; then
        bootstrap_script+="
# --- Stage 7a: Wait for IP ---
echo \"Waiting for IP ${vm_ip} to be available...\"
for i in {1..30}; do
    if ip addr show | grep -q \"${vm_ip}\"; then
        echo \"✅ IP ${vm_ip} is available\"
        break
    fi
    echo \"Waiting for IP... (\\\$i/30)\"
    sleep 1
done
"
    fi

    bootstrap_script+='
# --- Stage 7: Docker & network readiness gates ---
echo "Waiting for Docker daemon..."
for i in {1..30}; do
    if systemctl is-active --quiet docker && docker info >/dev/null 2>&1; then
        echo "✅ Docker daemon is ready"
        break
    fi
    echo "Waiting for Docker... ($i/30)"
    sleep 2
done

echo "Waiting for network/DNS..."
for i in {1..30}; do
    if getent hosts ghcr.io >/dev/null 2>&1 || \
       getent hosts registry-1.docker.io >/dev/null 2>&1; then
        echo "✅ Network/DNS is ready"
        break
    fi
    echo "Waiting for DNS resolution... ($i/30)"
    sleep 2
done
'

    # Stage 8: Start services (needs LITELLM_PORT from host)
    bootstrap_script+="
# --- Stage 8: Start services ---
MARKER_FILE=\"/opt/llm-gateway/.bootstrap-complete\"

# Idempotent guard: if bootstrap already completed, skip to health check
if [ -f \"\${MARKER_FILE}\" ]; then
    echo \"⏭️  Bootstrap already completed (marker exists), checking services...\"
    cd /opt/llm-gateway
    docker compose up -d --remove-orphans
else
    echo \"🚀 Pulling container images (with retry)...\"
    cd /opt/llm-gateway
    PULL_OK=0
    PULL_LOG=\"/tmp/docker-pull-\$\$.log\"
    for attempt in 1 2 3; do
        if docker compose pull 2>\"\${PULL_LOG}\"; then
            echo \"✅ All images pulled\"
            PULL_OK=1
            break
        fi
        echo \"⚠️  Pull attempt \\\$attempt/3 failed\"
        # Show last 5 lines of error for diagnostic (registry/DNS/proxy issues)
        tail -5 \"\${PULL_LOG}\" 2>/dev/null | sed 's/^/   /'
        echo \"   Retrying in 10s...\"
        sleep 10
    done
    rm -f \"\${PULL_LOG}\"
    
    if [ \"\${PULL_OK}\" -ne 1 ]; then
        echo \"❌ FATAL: Failed to pull container images after 3 attempts\"
        echo \"Diagnostics:\"
        echo \"  DNS:      \$(getent hosts ghcr.io 2>&1 | head -1)\"
        echo \"  Registry: \$(getent hosts registry-1.docker.io 2>&1 | head -1)\"
        echo \"Re-run after fixing network:\"
        echo \"  cd /opt/llm-gateway && docker compose pull && docker compose up -d\"
        exit 1
    fi
    
    echo \"🚀 Starting LLM Gateway services...\"
    docker compose up -d
    
    # Audit: log pulled images for traceability
    echo \"📋 Container images in use:\"
    docker compose images 2>/dev/null || docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null | head -10
    
    # Enable systemd unit for future reboots
    systemctl daemon-reload
    systemctl enable llm-gateway.service
    echo \"✅ llm-gateway.service enabled for auto-start\"
    
    # Mark bootstrap as complete
    date > \"\${MARKER_FILE}\"
fi

echo \"Waiting for services to initialize...\"
sleep 20

# Health check helper (uses master key if available, avoids 401 false-negatives)
_health_ok() {
    if [ -n \"\${LITELLM_MASTER_KEY:-}\" ] && [ \"\${LITELLM_MASTER_KEY}\" != \"AUTO\" ]; then
        curl -sf -H \"Authorization: Bearer \${LITELLM_MASTER_KEY}\" http://localhost:${LITELLM_PORT}/v1/models >/dev/null 2>&1
    else
        curl -sf http://localhost:${LITELLM_PORT}/v1/models >/dev/null 2>&1 || \\
            wget --spider -q http://localhost:${LITELLM_PORT}/v1/models 2>/dev/null
    fi
}

# VM-level health check (with auth support)
for i in {1..60}; do
    if _health_ok; then
        echo \"✅ LiteLLM is ready!\"
        docker compose ps
        break
    fi
    echo \"Waiting for LiteLLM... (\\\$i/60)\"
    sleep 2
done

if ! _health_ok; then
    echo \"❌ FATAL: LiteLLM not ready after 120s\"
    docker compose logs --tail=50
    echo \"Bootstrap FAILED — investigate logs above, then retry:\"
    echo \"  cd /opt/llm-gateway && docker compose up -d && docker compose logs -f\"
    exit 1
fi

echo \"==========================================\"
echo \"LLM Gateway Bootstrap Complete - \$(date)\"
echo \"==========================================\"
"

    # Indent bootstrap script for cloud-init (6 spaces)
    local bootstrap_indented
    bootstrap_indented="$(printf '%s\n' "$bootstrap_script" | sed 's/^/      /')"
    
    # =========================================================================
    # Write COMPLETE cloud-init YAML in ONE shot (no cat >> anywhere)
    # =========================================================================
    local PACKAGE_UPGRADE_BOOL="false"
    if [[ "${PACKAGE_UPGRADE}" == "1" ]]; then
        PACKAGE_UPGRADE_BOOL="true"
        log "INFO" "Full package upgrade enabled (PACKAGE_UPGRADE=1)"
    else
        log "INFO" "Full package upgrade disabled (set PACKAGE_UPGRADE=1 to enable)"
    fi
    
    cat > "$userdata_file" <<EOF
#cloud-config
# Generated by: $SCRIPT_NAME v$SCRIPT_VERSION
# Generated at: $(date)
# VM ID: $VMID

ssh_authorized_keys:
  - ${SSH_PUBKEY}

package_update: true
package_upgrade: ${PACKAGE_UPGRADE_BOOL}

bootcmd:
  - mkdir -p /etc/llm-gateway
  - chmod 0755 /etc/llm-gateway

packages:
  - ufw
  - curl
  - wget
  - ca-certificates
  - gnupg
  - lsb-release

write_files:
  - path: /etc/llm-gateway/.env
    permissions: "0600"
    content: |
      LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
      POSTGRES_PASS=${POSTGRES_PASS}
      GRAFANA_ADMIN_PASS=${GRAFANA_ADMIN_PASS}

  - path: /etc/llm-gateway/config.yaml
    permissions: "0644"
    content: |
${config_yaml_content}

  - path: /etc/llm-gateway/docker-compose.yml
    permissions: "0644"
    content: |
${compose_indented}
${prometheus_section}
  - path: /etc/systemd/system/llm-gateway.service
    permissions: "0644"
    content: |
      [Unit]
      Description=LLM Gateway Docker Compose Stack
      Requires=docker.service
      After=docker.service network-online.target

      [Service]
      Type=oneshot
      RemainAfterExit=yes
      WorkingDirectory=/opt/llm-gateway
      EnvironmentFile=/opt/llm-gateway/.env
      ExecStart=/usr/bin/docker compose up -d --remove-orphans
      ExecStop=/usr/bin/docker compose down
      ExecReload=/usr/bin/docker compose up -d --remove-orphans
      TimeoutStartSec=300

      [Install]
      WantedBy=multi-user.target

  - path: /etc/llm-gateway/llm-gateway-bootstrap.sh
    permissions: "0755"
    content: |
${bootstrap_indented}

runcmd:
  - bash /etc/llm-gateway/llm-gateway-bootstrap.sh

final_message: |
  
  ╔══════════════════════════════════════════════════════════════╗
  ║        🎉 LLM Gateway Deployment Complete!                   ║
  ╚══════════════════════════════════════════════════════════════╝
  
  Check /etc/motd for quick reference
  Credentials: /root/llm-gateway-credentials.txt
  Bootstrap log: /var/log/llm-gateway-bootstrap.log
  
EOF

    chmod 644 "$userdata_file"
    log "SUCCESS" "User data generated: $(basename "$userdata_file")"
    log "INFO" "Architecture: write_files → bootstrap.sh (single runcmd call)"
    log "INFO" "docker-compose.yml: $(echo "$compose_content" | wc -l) lines (one-shot, no cat >> append)"
}

attach_userdata() {
    log "STEP" "[Step 8/10] Attaching user data to VM..."
    
    local userdata_basename="$(basename "${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml")"
    qm set "$VMID" --cicustom "user=${SNIPPET_STORAGE}:snippets/${userdata_basename}" >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "User data attached"
}

#===============================================================================
# VM START AND VALIDATION
#===============================================================================
start_vm() {
    log "STEP" "[Step 9/10] Starting VM..."
    
    qm start "$VMID" >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "VM $VMID started"
}

wait_for_vm_ready() {
    log "STEP" "[Step 10/10] Waiting for VM to be ready..."
    
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Skipping wait"
        return 0
    fi
    
    local timeout=300
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if qm agent "$VMID" ping &>/dev/null; then
            log "SUCCESS" "VM is ready (QEMU agent responding)"
            return 0
        fi
        
        sleep 5
        elapsed=$((elapsed + 5))
        
        if [ $((elapsed % 30)) -eq 0 ]; then
            log "INFO" "Still waiting for VM... (${elapsed}s/${timeout}s)"
        fi
    done
    
    log "WARN" "VM agent not responding after ${timeout}s (may still be booting)"
    log "INFO" "Cloud-init is likely still running"
    return 0
}

#===============================================================================
# POST-DEPLOYMENT VALIDATION
#===============================================================================
post_deployment_check() {
    log "INFO" "Running post-deployment checks..."
    
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Skipping validation"
        return 0
    fi
    
    if [[ "$USE_DHCP" == "1" ]]; then
        log "INFO" "DHCP mode: Skipping automated health check"
        log "INFO" "SSH to VM and verify: docker compose ps"
        return 0
    fi
    
    local ip="${IP_CIDR%/*}"
    local max_wait=240
    local waited=0
    
    # Health check helper: secrets hidden from /proc via curl --config + process substitution
    _host_health_check() {
        if [[ "${LITELLM_MASTER_KEY}" != "AUTO" && -n "${LITELLM_MASTER_KEY}" ]]; then
            timeout 5 curl -sf --config <(printf 'header = "Authorization: Bearer %s"\n' "${LITELLM_MASTER_KEY}") \
                "http://${ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1
        else
            timeout 5 curl -sf "http://${ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1
        fi
    }
    
    if [[ "${LITELLM_MASTER_KEY}" != "AUTO" && -n "${LITELLM_MASTER_KEY}" ]]; then
        log "DEBUG" "Health checks will use master key authentication"
    fi
    
    log "INFO" "Waiting for LiteLLM service (may take 2-3 minutes)..."
    while [ $waited -lt $max_wait ]; do
        if _host_health_check; then
            log "SUCCESS" "✅ LiteLLM is healthy and responding"
            break
        fi
        
        sleep 10
        waited=$((waited + 10))
        
        if [ $((waited % 30)) -eq 0 ]; then
            log "INFO" "Still waiting... (${waited}s/${max_wait}s)"
        fi
    done
    
    if [ $waited -ge $max_wait ]; then
        if [[ "${STRICT_POSTCHECK}" == "1" ]]; then
            log "ERROR" "Services not ready after ${max_wait}s (STRICT_POSTCHECK=1)"
            log "INFO" "  ssh ${CI_USER}@${ip} 'cd /opt/llm-gateway && docker compose logs -f'"
            fatal_error "Post-deployment health check failed"
        else
            log "WARN" "⚠️  Services not ready after ${max_wait}s"
            log "INFO" "This can be normal for first boot. To check:"
            log "INFO" "  ssh ${CI_USER}@${ip} 'cd /opt/llm-gateway && docker compose logs -f'"
            log "INFO" "Set STRICT_POSTCHECK=1 to treat this as a fatal error (for CI/CD)"
            return 0
        fi
    fi
    
    # Check monitoring (best effort)
    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        if timeout 5 curl -sf "http://${ip}:9090/-/healthy" &>/dev/null 2>&1; then
            log "SUCCESS" "✅ Prometheus is healthy"
        fi
        
        if timeout 5 curl -sf "http://${ip}:3000/api/health" &>/dev/null 2>&1; then
            log "SUCCESS" "✅ Grafana is healthy"
        fi
    fi
}

#===============================================================================
# VALIDATION SCRIPT GENERATION (CRITICAL FIX: Proper accept-new detection)
#===============================================================================
generate_validation_script() {
    if [[ "${ENABLE_VALIDATION_SCRIPT}" != "1" ]]; then
        return 0
    fi
    
    if [[ "$USE_DHCP" == "1" ]]; then
        log "INFO" "DHCP mode: Skipping validation script generation"
        return 0
    fi
    
    log "INFO" "Generating post-deployment validation script..."
    
    local vm_ip="${IP_CIDR%/*}"
    local val_script="/tmp/validate-llm-gateway-${VMID}.sh"
    
    # CRITICAL FIX: Test accept-new against actual VM, not localhost
    cat > "$val_script" <<EOFVAL
#!/usr/bin/env bash
# LLM Gateway Validation Script
# VM ID: ${VMID}
# Generated: $(date)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VM_IP="${vm_ip}"
LITELLM_PORT="${LITELLM_PORT}"

# Test accept-new support by trying it against the VM
# If it fails with "Bad configuration option", fallback to 'no'
SSH_ERR=\$(mktemp)
trap "rm -f \${SSH_ERR}" EXIT

if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 ${CI_USER}@\${VM_IP} true 2>\${SSH_ERR}; then
    # Success - use accept-new
    SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"
else
    # Check if failure was due to unsupported option
    if grep -qiE "Bad configuration option|Unsupported option|unknown option" "\${SSH_ERR}"; then
        echo "Note: Using StrictHostKeyChecking=no (older OpenSSH detected)"
        SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"
    else
        # Other error (network, key, etc.) - still use accept-new
        SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5"
    fi
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     LLM Gateway VM ${VMID} - Validation Script          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

# 1. Check VM is running
echo -n "1. Checking VM status... "
if /usr/sbin/qm status ${VMID} | grep -q "running"; then
    echo -e "\${GREEN}✅ Running\${NC}"
else
    echo -e "\${RED}❌ Not running\${NC}"
    exit 1
fi

# 2. Check SSH connectivity
echo -n "2. Checking SSH... "
if timeout 5 ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} true 2>/dev/null; then
    echo -e "\${GREEN}✅ OK\${NC}"
else
    echo -e "\${RED}❌ Cannot connect\${NC}"
    exit 1
fi

# 3. Check LiteLLM API
echo -n "3. Checking LiteLLM API... "
if timeout 5 curl -sf http://\${VM_IP}:\${LITELLM_PORT}/v1/models >/dev/null 2>&1; then
    echo -e "\${GREEN}✅ Responding\${NC}"
else
    echo -e "\${YELLOW}⚠️  Not ready yet\${NC}"
fi

# 4. Check Docker containers
EXPECTED_CONTAINERS=$((3 + ${ENABLE_MONITORING} * 2))
echo -n "4. Checking Docker containers (expect \${EXPECTED_CONTAINERS})... "
CONTAINER_COUNT=\$(ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} 'docker ps -q | wc -l' 2>/dev/null || echo 0)
if [ "\$CONTAINER_COUNT" -ge "\$EXPECTED_CONTAINERS" ]; then
    echo -e "\${GREEN}✅ \${CONTAINER_COUNT} running\${NC}"
else
    echo -e "\${YELLOW}⚠️  Only \${CONTAINER_COUNT} running\${NC}"
fi

# 5. Get credentials
echo
echo "═══════════════════════════════════════════════════════════"
echo "Credentials:"
echo "═══════════════════════════════════════════════════════════"
ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} 'sudo cat /root/llm-gateway-credentials.txt' 2>/dev/null || echo "Cannot retrieve credentials"

echo
echo "═══════════════════════════════════════════════════════════"
echo "Quick Commands:"
echo "═══════════════════════════════════════════════════════════"
echo "SSH to VM:"
echo "  ssh ${CI_USER}@\${VM_IP}"
echo
echo "View logs:"
echo "  ssh ${CI_USER}@\${VM_IP} 'cd /opt/llm-gateway && docker compose logs -f'"
echo
echo "Check status:"
echo "  ssh ${CI_USER}@\${VM_IP} 'cd /opt/llm-gateway && docker compose ps'"
echo "═══════════════════════════════════════════════════════════"
EOFVAL

    chmod +x "$val_script"
    log "SUCCESS" "Validation script created: $val_script"
    log "INFO" "Run it with: $val_script"
}

#===============================================================================
# CREDENTIAL RETRIEVAL & PURGE (optional enterprise hardening)
#===============================================================================
retrieve_and_purge_credentials() {
    if [[ "${AUTO_PURGE_CREDS}" != "1" ]]; then
        return 0
    fi
    
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would retrieve and purge VM credentials"
        return 0
    fi
    
    if [[ "$USE_DHCP" == "1" ]]; then
        log "WARN" "AUTO_PURGE_CREDS: skipped (DHCP mode, IP unknown)"
        return 0
    fi
    
    local ip="${IP_CIDR%/*}"
    local ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes"
    
    log "STEP" "Retrieving credentials from VM before purge..."
    
    local creds_content
    if creds_content=$(ssh $ssh_opts "${CI_USER}@${ip}" 'sudo cat /root/llm-gateway-credentials.txt' 2>/dev/null); then
        # Log to deployment log file (600 permissions)
        # WARNING: This writes cleartext secrets to the log file
        {
            echo ""
            echo "=== CREDENTIALS (retrieved at $(date), purged from VM) ==="
            echo "=== ⚠️  CLEARTEXT — protect this log file accordingly ==="
            echo "$creds_content"
            echo "=== END CREDENTIALS ==="
            echo ""
        } >> "$LOG_FILE"
        
        # Display to operator (one-time, not logged to terminal history)
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "🔑 Credentials (one-time display — will be purged from VM):"
        echo "═══════════════════════════════════════════════════════════"
        echo "$creds_content"
        echo "═══════════════════════════════════════════════════════════"
        echo "📂 Saved to deployment log: $LOG_FILE (chmod 600)"
        echo "⚠️  Log file now contains secrets — handle accordingly"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        
        # Purge from VM
        if ssh $ssh_opts "${CI_USER}@${ip}" 'sudo shred -u /root/llm-gateway-credentials.txt 2>/dev/null || sudo rm -f /root/llm-gateway-credentials.txt' 2>/dev/null; then
            log "SUCCESS" "Credentials purged from VM (saved in deployment log)"
        else
            log "WARN" "Could not purge credentials from VM (remove manually)"
        fi
    else
        log "WARN" "AUTO_PURGE_CREDS: could not SSH to VM to retrieve credentials"
        log "INFO" "Credentials still on VM at /root/llm-gateway-credentials.txt"
    fi
}

#===============================================================================
# SNIPPET CLEANUP (remove secrets from host after successful deployment)
#===============================================================================
cleanup_deployment_snippet() {
    if [[ "${CLEANUP_SNIPPET}" != "1" ]]; then
        log "INFO" "Snippet cleanup disabled (CLEANUP_SNIPPET=0)"
        return 0
    fi
    
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "INFO" "[DRY-RUN] Would remove cloud-init snippet"
        return 0
    fi
    
    local snippet_file="${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml"
    if [[ -f "$snippet_file" ]]; then
        rm -f "$snippet_file"
        log "SUCCESS" "Cloud-init snippet removed from host (contained secrets): $(basename "$snippet_file")"
    fi
}

#===============================================================================
# DEPLOYMENT SUMMARY
#===============================================================================
print_summary() {
    local ip
    if [[ "$USE_DHCP" == "1" ]]; then
        ip="<DHCP - check Proxmox UI>"
    else
        ip="${IP_CIDR%/*}"
    fi
    
    cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║         🎉 Deployment Successfully Completed!                ║
╚══════════════════════════════════════════════════════════════╝

📋 VM Information:
   VM ID:       $VMID
   VM Name:     $VMNAME
   IP Address:  $ip
   Memory:      ${MEM}MB $([ "$VM_BALLOON" != "0" ] && echo "(balloon: ${VM_BALLOON}MB)")
   CPU Cores:   $CORES
   Disk Size:   ${DISK_GB}GB
   Auto-start:  $([ "$VM_ONBOOT" = "1" ] && echo "Enabled" || echo "Disabled")
   Tags:        $VM_TAGS

🌐 Service Endpoints:
   LiteLLM API:   http://${ip}:${LITELLM_PORT}
   Models:        http://${ip}:${LITELLM_PORT}/v1/models
EOF

    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        cat <<EOF
   Prometheus:    http://${ip}:9090
   Grafana:       http://${ip}:3000
EOF
    fi

    cat <<EOF

🔐 Security:
   SSH Access:    ssh ${CI_USER}@${ip}
   Credentials:   $(if [[ "$AUTO_PURGE_CREDS" == "1" ]]; then echo "✅ Purged from VM (saved in deployment log)"; else echo "/root/llm-gateway-credentials.txt (on VM)"; fi)
   Firewall:      $([ "$ENABLE_FIREWALL" = "1" ] && echo "Enabled (${ALLOWED_NETWORKS})" || echo "Disabled")
   Bind to IP:    $([ "$BIND_TO_IP" = "1" ] && echo "Yes ($ip only)" || echo "No (0.0.0.0)")
   Snippet:       $(if [[ "$CLEANUP_SNIPPET" == "1" ]]; then echo "✅ Auto-removed (secrets cleared from host)"; else echo "⚠️  Persists on host: ${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml"; fi)

🧪 Quick Test:
EOF

    if [[ "$USE_DHCP" != "1" ]]; then
        cat <<EOF
   # Get master key
   MASTER_KEY=\$(ssh ${CI_USER}@${ip} 'sudo grep "LiteLLM Master Key" /root/llm-gateway-credentials.txt | cut -d: -f2 | xargs')
   
   # Test API
   curl http://${ip}:${LITELLM_PORT}/v1/chat/completions \\
     -H "Content-Type: application/json" \\
     -H "Authorization: Bearer \$MASTER_KEY" \\
     -d '{"model":"qwen3","messages":[{"role":"user","content":"Hello!"}]}'
EOF
    else
        cat <<EOF
   SSH to VM first to get IP, then test as shown in /etc/motd
EOF
    fi

    cat <<EOF

📝 Useful Commands:
   ssh ${CI_USER}@${ip} 'sudo cat /root/llm-gateway-credentials.txt'
   ssh ${CI_USER}@${ip} 'cd /opt/llm-gateway && docker compose logs -f'
   ssh ${CI_USER}@${ip} 'cd /opt/llm-gateway && docker compose ps'
   ssh ${CI_USER}@${ip} 'sudo systemctl status llm-gateway'
   ssh ${CI_USER}@${ip} 'sudo systemctl restart llm-gateway'

📂 Files:
   Deployment Log: $LOG_FILE
   Snippets:       ${SNIP_DIR}
   Cloud Image:    ${IMG_PATH}
EOF

    if [[ "${ENABLE_VALIDATION_SCRIPT}" == "1" && "$USE_DHCP" != "1" ]]; then
        cat <<EOF
   Validation:     /tmp/validate-llm-gateway-${VMID}.sh
EOF
    fi

    cat <<EOF

⏱️  Deployment Time: $(($(date +%s) - DEPLOYMENT_START_TIME))s

╔══════════════════════════════════════════════════════════════╗
║  Next Steps:                                                 ║
║  1. SSH: ssh ${CI_USER}@${ip}                                ║
║  2. Verify: docker compose ps                                ║
║  3. Get credentials: sudo cat /root/llm-gateway-credentials.txt ║
EOF

    if [[ "${ENABLE_VALIDATION_SCRIPT}" == "1" && "$USE_DHCP" != "1" ]]; then
        cat <<EOF
║  4. Run validation: /tmp/validate-llm-gateway-${VMID}.sh     ║
EOF
    fi

    cat <<EOF
╚══════════════════════════════════════════════════════════════╝

EOF
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║    Proxmox LLM Gateway Deployment Script v${SCRIPT_VERSION}          ║"
    echo "║         Enterprise Grade - Production Ready - Final          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    # CRITICAL: setup_logging MUST run first so log() can write to LOG_FILE
    setup_logging
    
    if [[ "${DEBUG}" == "1" ]]; then
        # Redirect xtrace to log file (600 perms) instead of terminal to prevent
        # secrets from leaking to screen or process accounting in debug mode
        exec 7>>"$LOG_FILE"
        export BASH_XTRACEFD=7
        set -x
        log "DEBUG" "Debug mode enabled (xtrace output → log file, not terminal)"
    fi
    
    load_config_file "${1:-}"
    load_litellm_config
    
    if [[ "${INTERACTIVE}" == "1" ]]; then
        interactive_setup
    fi
    
    check_prerequisites
    validate_inputs
    validate_storage
    validate_snippet_storage
    
    print_mutation_summary
    
    check_existing_deployment
    check_vm_conflicts
    backup_vm
    
    download_cloud_image
    
    create_vm_shell
    import_and_attach_disk
    configure_disk_and_boot
    add_cloudinit_drive
    configure_cloudinit_network
    
    generate_userdata
    attach_userdata
    
    # Security: clear secrets from shell environment now that cloud-init snippet
    # is written. Prevents leakage via core dump / child process inheritance.
    # (post_deployment_check and retrieve_and_purge_credentials re-read from
    #  LOG_FILE or VM as needed — they only need LITELLM_MASTER_KEY for health
    #  checks, which we preserve if non-AUTO since it's needed for curl probes)
    unset POSTGRES_PASS GRAFANA_ADMIN_PASS
    
    start_vm
    wait_for_vm_ready
    
    post_deployment_check
    
    retrieve_and_purge_credentials
    cleanup_deployment_snippet
    
    generate_validation_script
    
    print_summary
    
    log "SUCCESS" "All operations completed successfully! 🎉"
    log "INFO" "Check the log file for details: $LOG_FILE"
}

#===============================================================================
# SCRIPT ENTRY POINT
#===============================================================================
show_help() {
    cat <<HELPEOF
Usage: $SCRIPT_NAME [OPTIONS] [config-file]

Enterprise-grade automation script for deploying LiteLLM API gateway on Proxmox VE.
NOTE: All network configuration is IPv4 only. IPv6 is not currently supported.

OPTIONS:
  -h, --help                 Show this help message and exit
  --print-config             Print effective configuration (secrets redacted) and exit
  --report                   Output resolved config as JSON (for CI/CD integration)
  --lint                     Validate config and prerequisites without deploying
  --self-test                Run syntax check, shellcheck, and config lint
  --version                  Print version and exit

ENVIRONMENT VARIABLES (override with export or config file):
  VM Configuration:
    VMID=120                 VM ID (100-999999999)
    VMNAME=llm-gateway       VM hostname
    MEM=8192                 Memory in MB
    CORES=4                  CPU cores
    DISK_GB=60               Disk size in GB

  Network:
    USE_DHCP=0               Use DHCP (1) or static IP (0)
    IP_CIDR=192.168.200.120/24  Static IP with CIDR
    GATEWAY_IP=192.168.200.1    Default gateway
    DNS_SERVERS=1.1.1.1         DNS server(s), space-delimited
    BIND_TO_IP=0             Bind services to specific IP

  Storage:
    STORAGE=local-lvm        Proxmox storage for VM disk
    SNIPPET_STORAGE=local    Proxmox storage for cloud-init snippets

  Services:
    OLLAMA_IP=192.168.200.10     Ollama backend IP
    OLLAMA_PORT=11434            Ollama backend port
    LITELLM_PORT=4000            LiteLLM API port
    LITELLM_MASTER_KEY=AUTO      Master key (AUTO = generate on VM)
    LITELLM_CONFIG_FILE=         Path to custom LiteLLM config.yaml
    POSTGRES_VERSION=16          PostgreSQL version
    REDIS_VERSION=7              Redis version
    LITELLM_VERSION=main-stable  LiteLLM image tag (pin for prod!)
    PROMETHEUS_VERSION=latest    Prometheus image tag
    GRAFANA_VERSION=latest       Grafana image tag

  Security:
    IMG_SHA256=                  Pin cloud image checksum (empty=auto-verify)

  Features:
    ENABLE_MONITORING=1          Deploy Prometheus + Grafana
    ENABLE_FIREWALL=1            Configure UFW firewall
    ENABLE_VALIDATION_SCRIPT=1   Generate post-deploy validation script
    PACKAGE_UPGRADE=0            Full apt upgrade on first boot
    CLEANUP_SNIPPET=1           Remove cloud-init snippet after deploy (has secrets)
    STRICT_POSTCHECK=0         Treat host health check timeout as fatal (for CI/CD)
    AUTO_PURGE_CREDS=0         Retrieve then purge credentials from VM after deploy
    AUTO_FIX_STORAGE=1         Auto-fix missing 'snippets' content on storage
    DRY_RUN=0                    Simulate without changes
    INTERACTIVE=0                Interactive setup wizard
    DEBUG=0                      Verbose debug output

EXAMPLES:
  # Deploy with defaults
  sudo ./deploy-llm-gateway.sh

  # Deploy with config file
  sudo ./deploy-llm-gateway.sh my-config.env

  # Deploy with overrides
  VMID=121 IP_CIDR=192.168.200.121/24 sudo ./deploy-llm-gateway.sh

  # Dry run
  DRY_RUN=1 sudo ./deploy-llm-gateway.sh

  # Print resolved config
  ./deploy-llm-gateway.sh --print-config

HELPEOF
}

print_effective_config() {
    # Load config file if provided (to resolve variables)
    local config_arg=""
    for arg in "$@"; do
        if [[ "$arg" != "--print-config" && "$arg" != "-h" && "$arg" != "--help" ]]; then
            config_arg="$arg"
        fi
    done
    if [[ -n "$config_arg" && -f "$config_arg" ]]; then
        _safe_load_config "$config_arg"
    fi
    
    local redact="********"
    cat <<CFGEOF
╔══════════════════════════════════════════════════════════════╗
║    Effective Configuration - v${SCRIPT_VERSION}                        ║
╚══════════════════════════════════════════════════════════════╝

VM Configuration:
  VMID               = ${VMID}
  VMNAME             = ${VMNAME}
  MEM                = ${MEM} MB
  CORES              = ${CORES}
  DISK_GB            = ${DISK_GB} GB
  VM_ONBOOT          = ${VM_ONBOOT}
  VM_BALLOON         = ${VM_BALLOON}
  VM_TAGS            = ${VM_TAGS}

Network:
  USE_DHCP           = ${USE_DHCP}
  IP_CIDR            = ${IP_CIDR}
  GATEWAY_IP         = ${GATEWAY_IP}
  DNS_SERVERS        = ${DNS_SERVERS}
  SEARCH_DOMAIN      = ${SEARCH_DOMAIN}
  BIND_TO_IP         = ${BIND_TO_IP}
  ENABLE_FIREWALL    = ${ENABLE_FIREWALL}
  ALLOWED_NETWORKS   = ${ALLOWED_NETWORKS}

Storage:
  STORAGE            = ${STORAGE}
  SNIPPET_STORAGE    = ${SNIPPET_STORAGE}
  CACHE_DIR          = ${CACHE_DIR}

Cloud Image:
  UBUNTU_RELEASE     = ${UBUNTU_RELEASE}
  IMG_URL            = ${IMG_URL}

Services:
  OLLAMA_IP          = ${OLLAMA_IP}
  OLLAMA_PORT        = ${OLLAMA_PORT}
  LITELLM_PORT       = ${LITELLM_PORT}
  LITELLM_MASTER_KEY = $(if [[ "$LITELLM_MASTER_KEY" == "AUTO" ]]; then echo "AUTO (will generate)"; else echo "$redact"; fi)
  POSTGRES_PASS      = $(if [[ "$POSTGRES_PASS" == "AUTO" ]]; then echo "AUTO (will generate)"; else echo "$redact"; fi)
  GRAFANA_ADMIN_PASS = $(if [[ "$GRAFANA_ADMIN_PASS" == "AUTO" ]]; then echo "AUTO (will generate)"; else echo "$redact"; fi)
  LITELLM_CONFIG_FILE= ${LITELLM_CONFIG_FILE:-<default>}

Docker Versions:
  POSTGRES_VERSION   = ${POSTGRES_VERSION}
  REDIS_VERSION      = ${REDIS_VERSION}
  LITELLM_VERSION    = ${LITELLM_VERSION}$(if [[ "$LITELLM_VERSION" == "latest" || "$LITELLM_VERSION" == "main-stable" ]]; then echo " ⚠️  unpinned"; fi)
  PROMETHEUS_VERSION = ${PROMETHEUS_VERSION}$(if [[ "$PROMETHEUS_VERSION" == "latest" ]]; then echo " ⚠️  unpinned"; fi)
  GRAFANA_VERSION    = ${GRAFANA_VERSION}$(if [[ "$GRAFANA_VERSION" == "latest" ]]; then echo " ⚠️  unpinned"; fi)

Supply Chain:
  IMG_SHA256         = ${IMG_SHA256:-<auto-verify from SHA256SUMS>}

Features:
  ENABLE_MONITORING  = ${ENABLE_MONITORING}
  ENABLE_LITELLM_METRICS = ${ENABLE_LITELLM_METRICS}
  ENABLE_BACKUP      = ${ENABLE_BACKUP}
  ENABLE_VALIDATION_SCRIPT = ${ENABLE_VALIDATION_SCRIPT}
  PACKAGE_UPGRADE    = ${PACKAGE_UPGRADE}
  CLEANUP_SNIPPET    = ${CLEANUP_SNIPPET}
  STRICT_POSTCHECK   = ${STRICT_POSTCHECK}
  AUTO_PURGE_CREDS   = ${AUTO_PURGE_CREDS}
  AUTO_FIX_STORAGE   = ${AUTO_FIX_STORAGE}
  DRY_RUN            = ${DRY_RUN}
  INTERACTIVE        = ${INTERACTIVE}
  DEBUG              = ${DEBUG}

Login:
  CI_USER            = ${CI_USER}
  SSH_PUBKEY_FILE    = ${SSH_PUBKEY_FILE}

CFGEOF
}

lint_config() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║    Configuration Lint Check - v${SCRIPT_VERSION}                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    local errors=0
    local warnings=0
    
    # Load config file if provided
    local config_arg=""
    for arg in "$@"; do
        if [[ "$arg" != "--lint" ]]; then config_arg="$arg"; fi
    done
    if [[ -n "$config_arg" && -f "$config_arg" ]]; then
        _safe_load_config "$config_arg"
        echo "ℹ️  Loaded config: $config_arg"
    fi
    
    # Check SSH key
    if [[ -f "$SSH_PUBKEY_FILE" ]]; then
        echo "✅ SSH pubkey: $SSH_PUBKEY_FILE"
    else
        echo "❌ SSH pubkey not found: $SSH_PUBKEY_FILE"; errors=$((errors + 1))
    fi
    
    # Check VMID range
    if [[ "$VMID" =~ ^[0-9]+$ ]] && [ "$VMID" -ge 100 ]; then
        echo "✅ VMID: $VMID"
    else
        echo "❌ Invalid VMID: $VMID"; errors=$((errors + 1))
    fi
    
    # Check IP format (static mode)
    if [[ "$USE_DHCP" != "1" ]]; then
        if [[ "$IP_CIDR" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            echo "✅ IP_CIDR: $IP_CIDR"
        else
            echo "❌ Invalid IP_CIDR: $IP_CIDR"; errors=$((errors + 1))
        fi
    fi
    
    # Check DNS format (normalize commas to spaces, same as validate_inputs)
    local dns_lint_clean="${DNS_SERVERS//,/ }"
    for dns_entry in $dns_lint_clean; do
        if [[ "$dns_entry" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            echo "✅ DNS: $dns_entry"
        else
            echo "⚠️  DNS entry may not be valid IP: $dns_entry"; warnings=$((warnings + 1))
        fi
    done
    
    # Check custom config file
    if [[ -n "${LITELLM_CONFIG_FILE}" ]]; then
        if [[ -f "${LITELLM_CONFIG_FILE}" ]]; then
            echo "✅ LiteLLM config: ${LITELLM_CONFIG_FILE} ($(wc -c < "${LITELLM_CONFIG_FILE}") bytes)"
        else
            echo "❌ LiteLLM config not found: ${LITELLM_CONFIG_FILE}"; errors=$((errors + 1))
        fi
    fi
    
    # Check root
    if [[ $EUID -eq 0 ]]; then
        echo "✅ Running as root"
    else
        echo "⚠️  Not running as root (deployment requires root)"; warnings=$((warnings + 1))
    fi
    
    # Check Proxmox
    if [[ -f /etc/pve/.version ]]; then
        echo "✅ Proxmox VE detected: $(cat /etc/pve/.version 2>/dev/null)"
    else
        echo "⚠️  Not on Proxmox host (or /etc/pve not accessible)"; warnings=$((warnings + 1))
    fi
    
    echo
    echo "Results: ${errors} error(s), ${warnings} warning(s)"
    if [ "$errors" -gt 0 ]; then
        echo "❌ Fix errors before deploying"
        return 1
    else
        echo "✅ Config looks good"
        return 0
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Handle CLI flags before main()
    case "${1:-}" in
        -h|--help)
            show_help
            exit 0
            ;;
        --version)
            echo "$SCRIPT_NAME v$SCRIPT_VERSION"
            exit 0
            ;;
        --print-config)
            print_effective_config "$@"
            exit 0
            ;;
        --lint)
            lint_config "$@"
            exit $?
            ;;
        --report)
            # Load config if provided as second arg
            for arg in "$@"; do
                [[ "$arg" != "--report" && -f "$arg" ]] && _safe_load_config "$arg"
            done
            _rpt_ip="${IP_CIDR%/*}"
            [[ "$USE_DHCP" == "1" ]] && _rpt_ip="dhcp"
            # JSON-escape helper: backslash and double-quote
            _json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
            cat <<JSONEOF
{
  "script_version": "$(_json_esc "${SCRIPT_VERSION}")",
  "vmid": ${VMID},
  "vmname": "$(_json_esc "${VMNAME}")",
  "ip": "$(_json_esc "${_rpt_ip}")",
  "cores": ${CORES},
  "memory_mb": ${MEM},
  "disk_gb": ${DISK_GB},
  "storage": "$(_json_esc "${STORAGE}")",
  "litellm_port": ${LITELLM_PORT},
  "ollama": "$(_json_esc "${OLLAMA_IP}:${OLLAMA_PORT}")",
  "monitoring": $([ "$ENABLE_MONITORING" = "1" ] && echo "true" || echo "false"),
  "firewall": $([ "$ENABLE_FIREWALL" = "1" ] && echo "true" || echo "false"),
  "versions": {
    "litellm": "$(_json_esc "${LITELLM_VERSION}")",
    "postgres": "$(_json_esc "${POSTGRES_VERSION}")",
    "redis": "$(_json_esc "${REDIS_VERSION}")",
    "prometheus": "$(_json_esc "${PROMETHEUS_VERSION}")",
    "grafana": "$(_json_esc "${GRAFANA_VERSION}")"
  },
  "flags": {
    "strict_postcheck": $([ "$STRICT_POSTCHECK" = "1" ] && echo "true" || echo "false"),
    "auto_purge_creds": $([ "$AUTO_PURGE_CREDS" = "1" ] && echo "true" || echo "false"),
    "cleanup_snippet": $([ "$CLEANUP_SNIPPET" = "1" ] && echo "true" || echo "false"),
    "auto_fix_storage": $([ "$AUTO_FIX_STORAGE" = "1" ] && echo "true" || echo "false")
  }
}
JSONEOF
            exit 0
            ;;
        --self-test)
            echo "╔══════════════════════════════════════════════════════════════╗"
            echo "║    Self-Test - v${SCRIPT_VERSION}                                       ║"
            echo "╚══════════════════════════════════════════════════════════════╝"
            echo
            echo "1. Bash syntax check..."
            if bash -n "$0" 2>&1; then
                echo "   ✅ Syntax OK"
            else
                echo "   ❌ Syntax errors detected"
                exit 1
            fi
            echo
            echo "2. ShellCheck static analysis..."
            if command -v shellcheck &>/dev/null; then
                local_issues=$(shellcheck -S warning "$0" 2>&1 | grep -c "^In " || true)
                if [ "$local_issues" -eq 0 ]; then
                    echo "   ✅ No warnings"
                else
                    echo "   ⚠️  ${local_issues} finding(s):"
                    shellcheck -S warning -f gcc "$0" 2>&1 | head -20
                    echo "   Run: shellcheck $0"
                fi
            else
                echo "   ⏭️  shellcheck not installed"
                echo "   Install: apt install shellcheck  (or brew install shellcheck)"
            fi
            echo
            echo "3. Config lint..."
            lint_config "$@" 2>&1 | sed 's/^/   /'
            exit 0
            ;;
    esac
    
    main "$@"
fi
