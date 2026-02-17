#!/usr/bin/env bash
#===============================================================================
# Proxmox LLM Gateway VM Deployment Script
# Version: 3.3.3c - Enterprise Grade (Production Ready - Final)
# Description: Production-ready deployment of LiteLLM gateway with monitoring
# Usage: ./deploy-llm-gateway.sh [config-file]
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
readonly SCRIPT_VERSION="3.3.3c"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly MAX_CONFIG_SIZE_BYTES=262144  # 256KB limit for external configs

#===============================================================================
# DEFAULT CONFIGURATION
#===============================================================================
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
: "${STORAGE:=local-lvm}"
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
: "${LITELLM_VERSION:=latest}"

# Ollama Backend
: "${OLLAMA_IP:=192.168.200.10}"
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

#===============================================================================
# GLOBAL VARIABLES
#===============================================================================
WORKDIR=""
IMG_PATH=""
LOG_FILE=""
SNIP_DIR=""
DEPLOYMENT_START_TIME=$(date +%s)
CUSTOM_CONFIG_CONTENT=""

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
    
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Script failed with exit code: $exit_code"
        log "ERROR" "Check log file for details: $LOG_FILE"
        
        if [[ "${DRY_RUN}" != "1" ]]; then
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

trap cleanup EXIT ERR INT TERM

fatal_error() {
    log "ERROR" "$*"
    exit 1
}

#===============================================================================
# COMMAND WRAPPERS (Function override instead of alias)
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
    # shellcheck source=/dev/null
    source "$config_file"
    
    log "SUCCESS" "Configuration loaded"
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
        
        if ! [[ "$GATEWAY_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            fatal_error "Invalid GATEWAY_IP format, got: $GATEWAY_IP"
        fi
    fi
    
    if [[ ! -f "$SSH_PUBKEY_FILE" ]]; then
        fatal_error "SSH public key file not found: $SSH_PUBKEY_FILE"
    fi
    
    SSH_PUBKEY=$(cat "$SSH_PUBKEY_FILE")
    if ! [[ "$SSH_PUBKEY" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss).+ ]]; then
        fatal_error "Invalid SSH public key format in: $SSH_PUBKEY_FILE"
    fi
    
    if ! [[ "$OLLAMA_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        fatal_error "Invalid OLLAMA_IP format, got: $OLLAMA_IP"
    fi
    
    if ! [[ "$OLLAMA_PORT" =~ ^[0-9]+$ ]] || [ "$OLLAMA_PORT" -lt 1 ] || [ "$OLLAMA_PORT" -gt 65535 ]; then
        fatal_error "Invalid OLLAMA_PORT: must be 1-65535, got: $OLLAMA_PORT"
    fi
    
    log "SUCCESS" "All inputs validated"
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
            log "INFO" "Enabling 'snippets' content on storage '$SNIPPET_STORAGE'..."
            if [[ -n "$st_content" ]]; then
                pvesm set "$SNIPPET_STORAGE" --content "${st_content},snippets" >/dev/null
            else
                pvesm set "$SNIPPET_STORAGE" --content "vztmpl,iso,backup,snippets" >/dev/null
            fi
            log "SUCCESS" "Added 'snippets' content type to '$SNIPPET_STORAGE'"
        fi
        
        log "SUCCESS" "Snippet storage configured: $SNIP_DIR"
    else
        SNIP_DIR="/tmp/snippets"
        mkdir -p "$SNIP_DIR"
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
            log "WARN" "VM $VMID already exists"
            
            if [[ "$USE_DHCP" != "1" ]]; then
                local vm_ip="${IP_CIDR%/*}"
                
                if timeout 5 curl -sf "http://${vm_ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1; then
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
    log "STEP" "Checking for VM conflicts..."
    
    if [[ "${DRY_RUN}" != "1" ]]; then
        if qm status "$VMID" &>/dev/null; then
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
    cat <<'EOF'
╔══════════════════════════════════════════════════════════════╗
║         LLM Gateway VM Configuration Wizard                  ║
║                      Version 3.3.3                           ║
╚══════════════════════════════════════════════════════════════╝
EOF

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
    
    local vm_desc="LiteLLM Gateway v${SCRIPT_VERSION} - Deployed on $(date '+%Y-%m-%d %H:%M:%S')"
    local balloon_param=""
    
    if [[ "$VM_BALLOON" != "0" ]]; then
        balloon_param="--balloon $VM_BALLOON"
    fi
    
    qm create "$VMID" \
        --name "$VMNAME" \
        --memory "$MEM" \
        $balloon_param \
        --cores "$CORES" \
        --cpu host \
        --numa 1 \
        --net0 "virtio,bridge=${BRIDGE}" \
        --scsihw virtio-scsi-pci \
        --agent enabled=1 \
        --ostype l26 \
        --onboot "$VM_ONBOOT" \
        --startup "order=${VM_STARTUP_ORDER},up=30,down=60" \
        --tags "$VM_TAGS" \
        --description "$vm_desc" \
        >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "VM $VMID created with optimized settings"
}

import_and_attach_disk() {
    log "STEP" "[Step 3/10] Importing and attaching disk..."
    
    qm importdisk "$VMID" "$IMG_PATH" "$STORAGE" >>"$LOG_FILE" 2>&1
    
    local imported_disk="vm-${VMID}-disk-0"
    qm set "$VMID" --scsi0 "${STORAGE}:${imported_disk}" >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "Disk imported and attached"
}

configure_disk_and_boot() {
    log "STEP" "[Step 4/10] Configuring disk and boot..."
    
    qm resize "$VMID" scsi0 "${DISK_GB}G" >>"$LOG_FILE" 2>&1
    qm set "$VMID" --boot c --bootdisk scsi0 >>"$LOG_FILE" 2>&1
    qm set "$VMID" --serial0 socket --vga serial0 >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "Disk resized to ${DISK_GB}GB and boot configured"
}

add_cloudinit_drive() {
    log "STEP" "[Step 5/10] Adding Cloud-Init drive..."
    
    qm set "$VMID" --ide2 "${STORAGE}:cloudinit" >>"$LOG_FILE" 2>&1
    
    log "SUCCESS" "Cloud-Init drive added"
}

configure_cloudinit_network() {
    log "STEP" "[Step 6/10] Configuring Cloud-Init network..."
    
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
    
    # Determine network configuration
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
    
    # Unified config indentation pipeline
    local config_yaml_raw
    
    if [[ -n "$CUSTOM_CONFIG_CONTENT" ]]; then
        config_yaml_raw="$CUSTOM_CONFIG_CONTENT"
        log "INFO" "Using custom LiteLLM configuration"
    else
        # Default config (zero-indented YAML)
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
    
    # Add 6-space indentation for cloud-init YAML nesting
    local config_yaml_content
    config_yaml_content="$(printf '%s\n' "$config_yaml_raw" | sed 's/^/      /')"
    log "DEBUG" "Config properly indented with 6-space prefix"
    
    cat > "$userdata_file" <<EOF
#cloud-config
# Generated by: $SCRIPT_NAME v$SCRIPT_VERSION
# Generated at: $(date)
# VM ID: $VMID

package_update: true
package_upgrade: true

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
      services:
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
            test: ["CMD-SHELL", "pg_isready -U litellm -d litellm || exit 1"]
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
            test: ["CMD", "redis-cli", "ping"]
            interval: 5s
            timeout: 3s
            retries: 5
          networks:
            - llm-network

        litellm:
          image: ghcr.io/berriai/litellm:${LITELLM_VERSION}
          container_name: llm-litellm
          command: 
            - "--config"
            - "/app/config.yaml"
            - "--port"
            - "${LITELLM_PORT}"
            - "--num_workers"
            - "2"
          environment:
            LITELLM_MASTER_KEY: "\${LITELLM_MASTER_KEY}"
            DATABASE_URL: "postgresql://litellm:\${POSTGRES_PASS}@postgres:5432/litellm"
            REDIS_URL: "redis://redis:6379"
          ports:
            - "${port_binding}"
          volumes:
            - ./config.yaml:/app/config.yaml:ro
          depends_on:
            postgres:
              condition: service_healthy
            redis:
              condition: service_healthy
          restart: unless-stopped
          networks:
            - llm-network
EOF

    # No container healthcheck for LiteLLM (VM-level check is reliable)
    log "INFO" "LiteLLM container healthcheck omitted (VM-level check is reliable)"

    # Add systemd unit for the stack (auto-start, status, restart)
    cat >> "$userdata_file" <<'EOFSYS'

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
EOFSYS
    log "INFO" "Systemd unit llm-gateway.service will be created"

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
        
        cat >> "$userdata_file" <<EOF

        prometheus:
          image: prom/prometheus:latest
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
            - "${prom_port_binding}"
          restart: unless-stopped
          networks:
            - llm-network

        grafana:
          image: grafana/grafana:latest
          container_name: llm-grafana
          environment:
            GF_SECURITY_ADMIN_USER: "admin"
            GF_SECURITY_ADMIN_PASSWORD: "\${GRAFANA_ADMIN_PASS}"
            GF_SERVER_ROOT_URL: "http://localhost:3000"
          volumes:
            - ./data/grafana:/var/lib/grafana
          ports:
            - "${graf_port_binding}"
          depends_on:
            - prometheus
          restart: unless-stopped
          networks:
            - llm-network

      networks:
        llm-network:
          driver: bridge

      volumes:
        pgdata:

  - path: /etc/llm-gateway/prometheus.yml
    permissions: "0644"
    content: |
      global:
        scrape_interval: 15s
        evaluation_interval: 15s
EOF

        if [[ "${ENABLE_LITELLM_METRICS}" == "1" ]]; then
            cat >> "$userdata_file" <<EOF
      
      scrape_configs:
        - job_name: 'litellm'
          metrics_path: '/metrics'
          static_configs:
            - targets: ['litellm:${LITELLM_PORT}']
EOF
            log "INFO" "Prometheus will scrape LiteLLM /metrics (ensure it's available)"
        else
            log "INFO" "LiteLLM metrics disabled (ENABLE_LITELLM_METRICS=0)"
        fi
    else
        cat >> "$userdata_file" <<EOF

      networks:
        llm-network:
          driver: bridge

      volumes:
        pgdata:
EOF
    fi

    # Generate firewall rules
    local fw_rules=""
    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        IFS=',' read -ra NETWORKS <<< "$ALLOWED_NETWORKS"
        
        for net in "${NETWORKS[@]}"; do
            net=$(echo "$net" | xargs)
            fw_rules+="      ufw allow from ${net} to ${fw_dest} port 22 proto tcp comment 'SSH'\n"
            fw_rules+="      ufw allow from ${net} to ${fw_dest} port ${LITELLM_PORT} proto tcp comment 'LiteLLM API'\n"
            if [[ "${ENABLE_MONITORING}" == "1" ]]; then
                fw_rules+="      ufw allow from ${net} to ${fw_dest} port 9090 proto tcp comment 'Prometheus'\n"
                fw_rules+="      ufw allow from ${net} to ${fw_dest} port 3000 proto tcp comment 'Grafana'\n"
            fi
        done
    fi

    cat >> "$userdata_file" <<'EOFX'

runcmd:
  # Stage 1: Install config files from /etc/llm-gateway → /opt/llm-gateway
  # (write_files writes to /etc/llm-gateway which is guaranteed to exist;
  #  runcmd runs AFTER write_files, so files are ready to install here)
  - mkdir -p /opt/llm-gateway
  - install -m 0600 /etc/llm-gateway/.env /opt/llm-gateway/.env
  - install -m 0644 /etc/llm-gateway/config.yaml /opt/llm-gateway/config.yaml
  - install -m 0644 /etc/llm-gateway/docker-compose.yml /opt/llm-gateway/docker-compose.yml
  - test -f /etc/llm-gateway/prometheus.yml && install -m 0644 /etc/llm-gateway/prometheus.yml /opt/llm-gateway/prometheus.yml || true
  - rm -rf /etc/llm-gateway
  
  # Create data directories (postgres uses named Docker volume)
  - mkdir -p /opt/llm-gateway/data/{prometheus,grafana}
  - chmod 700 /opt/llm-gateway/data
  - chmod 755 /opt/llm-gateway/data/prometheus
  - chmod 755 /opt/llm-gateway/data/grafana

  # Generate secrets
  - |
    set -e
    ENV_FILE="/opt/llm-gateway/.env"
    gen_secret() { openssl rand -hex 32; }
    
    LITELLM_MASTER_KEY="$(awk -F= '/^LITELLM_MASTER_KEY=/{print $2}' "$ENV_FILE" | tr -d ' ')"
    POSTGRES_PASS="$(awk -F= '/^POSTGRES_PASS=/{print $2}' "$ENV_FILE" | tr -d ' ')"
    GRAFANA_ADMIN_PASS="$(awk -F= '/^GRAFANA_ADMIN_PASS=/{print $2}' "$ENV_FILE" | tr -d ' ')"
    
    if [ "$LITELLM_MASTER_KEY" = "AUTO" ] || [ -z "$LITELLM_MASTER_KEY" ]; then
      LITELLM_MASTER_KEY="sk-$(gen_secret)"
    fi
    if [ "$POSTGRES_PASS" = "AUTO" ] || [ -z "$POSTGRES_PASS" ]; then
      POSTGRES_PASS="$(gen_secret)"
    fi
    if [ "$GRAFANA_ADMIN_PASS" = "AUTO" ] || [ -z "$GRAFANA_ADMIN_PASS" ]; then
      GRAFANA_ADMIN_PASS="$(gen_secret)"
    fi
    
    cat > "$ENV_FILE" <<ENV
LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
POSTGRES_PASS=${POSTGRES_PASS}
GRAFANA_ADMIN_PASS=${GRAFANA_ADMIN_PASS}
ENV
    chmod 600 "$ENV_FILE"
    
    CREDS="/root/llm-gateway-credentials.txt"
    cat > "$CREDS" <<CREDS
═══════════════════════════════════════════════════════
  LLM Gateway Credentials
  Generated: $(date)
  VM ID: ${VMID}
  VM Name: ${VMNAME}
  Script Version: ${SCRIPT_VERSION}
═══════════════════════════════════════════════════════

LiteLLM Master Key:  ${LITELLM_MASTER_KEY}
PostgreSQL Password: ${POSTGRES_PASS}
Grafana Admin User:  admin
Grafana Password:    ${GRAFANA_ADMIN_PASS}

═══════════════════════════════════════════════════════
SECURITY: Keep this file secure! (chmod 600)
═══════════════════════════════════════════════════════
CREDS
    chmod 600 "$CREDS"
    
    VMIP="$(hostname -I | awk '{print $1}')"
    cat > /etc/motd <<MOTD

╔══════════════════════════════════════════════════════════════╗
║           🚀 LLM Gateway ${SCRIPT_VERSION} - Ready           ║
╚══════════════════════════════════════════════════════════════╝

📍 LiteLLM API: http://\${VMIP}:${LITELLM_PORT}/v1/chat/completions
📋 Models: curl http://\${VMIP}:${LITELLM_PORT}/v1/models
📊 Services: LiteLLM http://\${VMIP}:${LITELLM_PORT}
MOTD
EOFX

    if [[ "${ENABLE_MONITORING}" == "1" ]]; then
        cat >> "$userdata_file" <<'EOFX'
    cat >> /etc/motd <<MOTD2
   Prometheus: http://${VMIP}:9090
   Grafana:    http://${VMIP}:3000
MOTD2
EOFX
    fi

    cat >> "$userdata_file" <<'EOFX'

    cat >> /etc/motd <<MOTD3

🔐 Credentials: /root/llm-gateway-credentials.txt
📝 Logs: docker compose logs -f
🔄 Status: docker compose ps
🔧 Systemd: systemctl status llm-gateway

MOTD3

  # Install Docker
  - |
    set -e
    echo "Installing Docker CE..."
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

  # Configure firewall
  - |
EOFX

    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        cat >> "$userdata_file" <<EOFX
    if command -v ufw >/dev/null 2>&1; then
      echo "Configuring UFW firewall..."
$(echo -e "$fw_rules")
      ufw default deny incoming
      ufw default allow outgoing
      ufw logging on
      echo "y" | ufw enable
      ufw status verbose
      echo "✅ Firewall configured"
    else
      echo "⚠️  UFW not available"
    fi
EOFX
    else
        cat >> "$userdata_file" <<EOFX
    echo "Firewall disabled by configuration"
EOFX
    fi

    # IMPROVEMENT: Wait for IP availability if BIND_TO_IP is enabled
    if [[ "$BIND_TO_IP" == "1" && "$USE_DHCP" != "1" ]]; then
        cat >> "$userdata_file" <<EOFX

  # Wait for IP to be available (BIND_TO_IP enabled)
  - |
    echo "Waiting for IP ${vm_ip} to be available..."
    for i in {1..30}; do
      if ip addr show | grep -q "${vm_ip}"; then
        echo "✅ IP ${vm_ip} is available"
        break
      fi
      echo "Waiting for IP... (\$i/30)"
      sleep 1
    done
EOFX
    fi

    cat >> "$userdata_file" <<'EOFX'

  # Start Docker services
  - |
    set -e
    cd /opt/llm-gateway
    
    # Gate 1: Wait for Docker daemon to be fully ready
    echo "Waiting for Docker daemon..."
    for i in {1..30}; do
      if systemctl is-active --quiet docker && docker info >/dev/null 2>&1; then
        echo "✅ Docker daemon is ready"
        break
      fi
      echo "Waiting for Docker... ($i/30)"
      sleep 2
    done
    
    # Gate 2: Wait for DNS/network (needed for image pulls)
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
    
    echo "Starting LLM Gateway services..."
    docker compose up -d
    
    # Enable systemd unit for future reboots
    systemctl daemon-reload
    systemctl enable llm-gateway.service
    echo "✅ llm-gateway.service enabled for auto-start"
    
    echo "Waiting for services..."
    sleep 20
    
    # VM-level health check (reliable)
    for i in {1..60}; do
      if curl -sf http://localhost:4000/v1/models >/dev/null 2>&1 || \
         wget --spider -q http://localhost:4000/v1/models 2>/dev/null; then
        echo "✅ LiteLLM is ready!"
        docker compose ps
        break
      fi
      echo "Waiting for LiteLLM... ($i/60)"
      sleep 2
    done
    
    if ! curl -sf http://localhost:4000/v1/models >/dev/null 2>&1 && \
       ! wget --spider -q http://localhost:4000/v1/models 2>/dev/null; then
      echo "⚠️  LiteLLM not ready after 120s"
      docker compose logs --tail=50
    fi

final_message: |
  
  ╔══════════════════════════════════════════════════════════════╗
  ║        🎉 LLM Gateway Deployment Complete!                   ║
  ╚══════════════════════════════════════════════════════════════╝
  
  Check /etc/motd for quick reference
  Credentials: /root/llm-gateway-credentials.txt
  
EOFX

    chmod 644 "$userdata_file"
    log "SUCCESS" "User data generated: $(basename "$userdata_file")"
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
    
    log "INFO" "Waiting for LiteLLM service (may take 2-3 minutes)..."
    while [ $waited -lt $max_wait ]; do
        if timeout 5 curl -sf "http://${ip}:${LITELLM_PORT}/v1/models" &>/dev/null 2>&1; then
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
        log "WARN" "⚠️  Services not ready after ${max_wait}s"
        log "INFO" "This can be normal for first boot. To check:"
        log "INFO" "  ssh ${CI_USER}@${ip} 'cd /opt/llm-gateway && docker compose logs -f'"
        return 0
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
echo -n "4. Checking Docker containers... "
CONTAINER_COUNT=\$(ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} 'docker ps -q | wc -l' 2>/dev/null || echo 0)
if [ "\$CONTAINER_COUNT" -ge 3 ]; then
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
   Credentials:   /root/llm-gateway-credentials.txt (on VM)
   Firewall:      $([ "$ENABLE_FIREWALL" = "1" ] && echo "Enabled (${ALLOWED_NETWORKS})" || echo "Disabled")
   Bind to IP:    $([ "$BIND_TO_IP" = "1" ] && echo "Yes ($ip only)" || echo "No (0.0.0.0)")

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
        set -x
        log "DEBUG" "Debug mode enabled"
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
    
    start_vm
    wait_for_vm_ready
    
    post_deployment_check
    
    generate_validation_script
    
    print_summary
    
    log "SUCCESS" "All operations completed successfully! 🎉"
    log "INFO" "Check the log file for details: $LOG_FILE"
}

#===============================================================================
# SCRIPT ENTRY POINT
#===============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
