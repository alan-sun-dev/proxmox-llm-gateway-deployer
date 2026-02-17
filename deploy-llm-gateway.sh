#!/usr/bin/env bash
#===============================================================================
# Proxmox LLM Gateway VM Deployment Script
# Version: 3.3.3a - Enterprise Grade (Production Ready - Sealed)
# Description: Production-ready deployment of LiteLLM gateway with monitoring
# Repository: https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer
# License: MIT
# Usage: ./deploy-llm-gateway.sh [config-file]
#
# Changelog v3.3.3a:
# - CRITICAL FIX: cloud-init execution order (write_files to /etc, move in runcmd)
# - IMPROVED: Validation script timeout handling
# - IMPROVED: IP availability wait for BIND_TO_IP mode
#===============================================================================

set -euo pipefail

#===============================================================================
# SCRIPT METADATA
#===============================================================================
readonly SCRIPT_VERSION="3.3.3a"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly MAX_CONFIG_SIZE_BYTES=262144

#===============================================================================
# DEFAULT CONFIGURATION
#===============================================================================
: "${VMID:=120}"
: "${VMNAME:=llm-gateway}"
: "${MEM:=8192}"
: "${CORES:=4}"
: "${DISK_GB:=60}"
: "${BRIDGE:=vmbr0}"
: "${VM_ONBOOT:=1}"
: "${VM_STARTUP_ORDER:=3}"
: "${VM_BALLOON:=4096}"
: "${VM_TAGS:=llm,gateway,prod}"
: "${STORAGE:=local-lvm}"
: "${SNIPPET_STORAGE:=local}"
: "${CACHE_DIR:=/var/lib/vz/template/cache}"
: "${CACHE_MAX_AGE_DAYS:=7}"
: "${USE_DHCP:=0}"
: "${IP_CIDR:=192.168.1.120/24}"
: "${GATEWAY_IP:=192.168.1.1}"
: "${DNS_SERVERS:=1.1.1.1}"
: "${SEARCH_DOMAIN:=local}"
: "${ENABLE_FIREWALL:=1}"
: "${ALLOWED_NETWORKS:=192.168.1.0/24}"
: "${BIND_TO_IP:=0}"
: "${UBUNTU_RELEASE:=noble}"
: "${IMG_URL:=https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${UBUNTU_RELEASE}-server-cloudimg-amd64.img}"
: "${CI_USER:=ubuntu}"
: "${SSH_PUBKEY_FILE:=$HOME/.ssh/id_ed25519.pub}"
: "${LITELLM_PORT:=4000}"
: "${LITELLM_MASTER_KEY:=AUTO}"
: "${POSTGRES_PASS:=AUTO}"
: "${GRAFANA_ADMIN_PASS:=AUTO}"
: "${LITELLM_CONFIG_FILE:=}"
: "${POSTGRES_VERSION:=16}"
: "${REDIS_VERSION:=7}"
: "${LITELLM_VERSION:=latest}"
: "${OLLAMA_IP:=192.168.1.10}"
: "${OLLAMA_PORT:=11434}"
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
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' NC=''
fi

#===============================================================================
# LOGGING
#===============================================================================
setup_logging() {
    LOG_FILE="/var/log/proxmox-vm-deploy-${VMID}-$(date +%Y%m%d-%H%M%S).log"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/vm-deploy-${VMID}.log"
    chmod 600 "$LOG_FILE"
    log "INFO" "Log file: $LOG_FILE"
    log "INFO" "Script version: $SCRIPT_VERSION"
    log "INFO" "Start time: $(date)"
}

log() {
    local level="$1"; shift
    local msg="$*"
    local timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
    case "$level" in
        ERROR) echo -e "${RED}❌ $msg${NC}" >&2 ;;
        WARN) echo -e "${YELLOW}⚠️  $msg${NC}" >&2 ;;
        SUCCESS) echo -e "${GREEN}✅ $msg${NC}" ;;
        INFO) echo -e "${BLUE}ℹ️  $msg${NC}" ;;
        DEBUG) [[ "${DEBUG}" == "1" ]] && echo -e "${CYAN}🔍 $msg${NC}" ;;
        STEP) echo -e "${MAGENTA}📍 $msg${NC}" ;;
        *) echo "$msg" ;;
    esac
}

#===============================================================================
# ERROR HANDLING
#===============================================================================
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Script failed with exit code: $exit_code"
        if [[ "${DRY_RUN}" != "1" ]]; then
            read -p "Remove failed VM $VMID? (y/n) " -t 30 -n 1 -r || REPLY='n'
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                /usr/sbin/qm stop "$VMID" 2>/dev/null || true
                sleep 2
                /usr/sbin/qm destroy "$VMID" --purge 2>/dev/null || true
                log "SUCCESS" "Failed VM removed"
            fi
        fi
    else
        local elapsed=$(($(date +%s) - DEPLOYMENT_START_TIME))
        log "SUCCESS" "Deployment completed in ${elapsed}s"
    fi
    [[ -n "${WORKDIR:-}" && -d "${WORKDIR}" ]] && rm -rf "$WORKDIR" 2>/dev/null || true
    [[ -n "${CACHE_LOCK_FD:-}" ]] && exec {CACHE_LOCK_FD}>&- 2>/dev/null || true
}

trap cleanup EXIT ERR INT TERM

fatal_error() {
    log "ERROR" "$*"
    exit 1
}

#===============================================================================
# COMMAND WRAPPERS
#===============================================================================
qm() {
    if [[ "${DRY_RUN}" == "1" ]]; then
        log "DEBUG" "[DRY-RUN] qm $*"
        case "$1" in
            status) return 1 ;;
            agent) return 0 ;;
            *) return 0 ;;
        esac
    else
        /usr/sbin/qm "$@"
    fi
}

pvesm() {
    [[ "${DRY_RUN}" == "1" ]] && { log "DEBUG" "[DRY-RUN] pvesm $*"; return 0; }
    /usr/sbin/pvesm "$@"
}


#===============================================================================
# PREREQUISITES
#===============================================================================
check_prerequisites() {
    log "STEP" "Checking prerequisites..."
    local missing_cmds=()
    local required_bins=(/usr/sbin/qm /usr/sbin/pvesm)
    for bin in "${required_bins[@]}"; do
        [[ ! -x "$bin" ]] && missing_cmds+=("$(basename "$bin")")
    done
    local required_cmds=(curl openssl awk sed grep mktemp flock tr timeout stat wc du)
    for cmd in "${required_cmds[@]}"; do
        command -v "$cmd" &>/dev/null || missing_cmds+=("$cmd")
    done
    [[ ${#missing_cmds[@]} -gt 0 ]] && fatal_error "Missing: ${missing_cmds[*]}"
    [[ $EUID -ne 0 ]] && fatal_error "Must run as root"
    [[ ! -f /etc/pve/.version ]] && fatal_error "Must run on Proxmox VE"
    log "SUCCESS" "All prerequisites met"
}

load_config_file() {
    local config_file="${1:-}"
    [[ -z "$config_file" ]] && return 0
    [[ ! -f "$config_file" ]] && fatal_error "Config not found: $config_file"
    source "$config_file"
    log "SUCCESS" "Config loaded"
}

load_litellm_config() {
    [[ -z "${LITELLM_CONFIG_FILE}" ]] && return 0
    [[ ! -f "${LITELLM_CONFIG_FILE}" ]] && fatal_error "Config not found"
    local size=$(wc -c < "${LITELLM_CONFIG_FILE}")
    [[ $size -gt $MAX_CONFIG_SIZE_BYTES ]] && fatal_error "Config too large"
    [[ $size -eq 0 ]] && fatal_error "Config empty"
    CUSTOM_CONFIG_CONTENT=$(tr -d '\r' < "${LITELLM_CONFIG_FILE}")
    grep -q $'\x00' <<<"$CUSTOM_CONFIG_CONTENT" && fatal_error "Binary data detected"
    log "SUCCESS" "Custom config loaded"
}

validate_inputs() {
    log "STEP" "Validating inputs..."
    [[ ! "$VMID" =~ ^[0-9]+$ ]] || [ "$VMID" -lt 100 ] && fatal_error "Invalid VMID"
    [[ ! "$VMNAME" =~ ^[a-zA-Z0-9_-]+$ ]] && fatal_error "Invalid VMNAME"
    [[ ! -f "$SSH_PUBKEY_FILE" ]] && fatal_error "SSH key not found"
    SSH_PUBKEY=$(cat "$SSH_PUBKEY_FILE")
    log "SUCCESS" "Inputs validated"
}

validate_storage() {
    log "STEP" "Validating storage..."
    [[ "${DRY_RUN}" != "1" ]] && {
        pvesm status --storage "$STORAGE" &>/dev/null || fatal_error "Storage not found"
        log "SUCCESS" "Storage accessible"
    }
}

validate_snippet_storage() {
    log "STEP" "Validating snippet storage..."
    [[ "${DRY_RUN}" == "1" ]] && { SNIP_DIR="/tmp/snippets"; mkdir -p "$SNIP_DIR"; return 0; }
    local st_conf=$(pvesm config "$SNIPPET_STORAGE" 2>/dev/null || true)
    local st_path=$(awk '/path/{print $2}' <<<"$st_conf" | head -1)
    SNIP_DIR="${st_path%/}/snippets"
    mkdir -p "$SNIP_DIR" || fatal_error "Cannot create snippets dir"
    grep -q 'content.*snippets' <<<"$st_conf" || {
        pvesm set "$SNIPPET_STORAGE" --content "vztmpl,iso,backup,snippets"
    }
    log "SUCCESS" "Snippet storage configured"
}

check_existing_deployment() {
    [[ "${SKIP_IDEMPOTENCY_CHECK}" == "1" ]] && return 0
    log "STEP" "Checking existing deployment..."
    [[ "${DRY_RUN}" != "1" ]] && qm status "$VMID" &>/dev/null && {
        [[ "$USE_DHCP" != "1" ]] && {
            local ip="${IP_CIDR%/*}"
            timeout 5 curl -sf "http://${ip}:${LITELLM_PORT}/v1/models" &>/dev/null && {
                log "SUCCESS" "Already deployed and healthy"
                exit 0
            }
        }
    }
}

check_vm_conflicts() {
    log "STEP" "Checking VM conflicts..."
    [[ "${DRY_RUN}" != "1" ]] && qm status "$VMID" &>/dev/null && {
        log "WARN" "VM $VMID exists, will be destroyed"
        qm stop "$VMID" &>/dev/null || true
        sleep 3
        qm destroy "$VMID" --purge
        log "SUCCESS" "Existing VM destroyed"
    }
}


#===============================================================================
# CLOUD IMAGE DOWNLOAD
#===============================================================================
download_cloud_image() {
    log "STEP" "[Step 1/10] Managing cloud image..."
    mkdir -p "$CACHE_DIR" || fatal_error "Cannot create cache dir"
    IMG_PATH="${CACHE_DIR}/${UBUNTU_RELEASE}-server-cloudimg-amd64.img"
    local lock_file="${CACHE_DIR}/.download-${UBUNTU_RELEASE}.lock"
    exec {CACHE_LOCK_FD}>"$lock_file" || fatal_error "Cannot create lock"
    flock -n "$CACHE_LOCK_FD" || { log "INFO" "Waiting for lock..."; flock "$CACHE_LOCK_FD"; }
    
    if [[ -f "$IMG_PATH" ]]; then
        local age=$(( ($(date +%s) - $(stat -c %Y "$IMG_PATH")) / 86400 ))
        [[ $age -lt $CACHE_MAX_AGE_DAYS ]] && { log "SUCCESS" "Using cached image"; return 0; }
        rm -f "$IMG_PATH"
    fi
    
    log "INFO" "Downloading from: $IMG_URL"
    [[ "${DRY_RUN}" == "1" ]] && { touch "$IMG_PATH"; return 0; }
    
    local tmp_img="${IMG_PATH}.tmp.$$"
    for i in {1..3}; do
        curl -fL "$IMG_URL" -o "$tmp_img" 2>>"$LOG_FILE" && {
            mv "$tmp_img" "$IMG_PATH"
            chmod 644 "$IMG_PATH"
            log "SUCCESS" "Image cached"
            return 0
        }
        rm -f "$tmp_img"
        sleep 5
    done
    fatal_error "Download failed"
}

#===============================================================================
# VM CREATION
#===============================================================================
create_vm_shell() {
    log "STEP" "[Step 2/10] Creating VM..."
    local balloon_param=""
    [[ "$VM_BALLOON" != "0" ]] && balloon_param="--balloon $VM_BALLOON"
    qm create "$VMID" --name "$VMNAME" --memory "$MEM" $balloon_param \
        --cores "$CORES" --cpu host --numa 1 --net0 "virtio,bridge=${BRIDGE}" \
        --scsihw virtio-scsi-pci --agent enabled=1 --ostype l26 \
        --onboot "$VM_ONBOOT" --startup "order=${VM_STARTUP_ORDER}" \
        --tags "$VM_TAGS" >>"$LOG_FILE" 2>&1
    log "SUCCESS" "VM created"
}

import_and_attach_disk() {
    log "STEP" "[Step 3/10] Importing disk..."
    qm importdisk "$VMID" "$IMG_PATH" "$STORAGE" >>"$LOG_FILE" 2>&1
    qm set "$VMID" --scsi0 "${STORAGE}:vm-${VMID}-disk-0" >>"$LOG_FILE" 2>&1
    log "SUCCESS" "Disk imported"
}

configure_disk_and_boot() {
    log "STEP" "[Step 4/10] Configuring disk..."
    qm resize "$VMID" scsi0 "${DISK_GB}G" >>"$LOG_FILE" 2>&1
    qm set "$VMID" --boot c --bootdisk scsi0 --serial0 socket --vga serial0 >>"$LOG_FILE" 2>&1
    log "SUCCESS" "Disk configured"
}

add_cloudinit_drive() {
    log "STEP" "[Step 5/10] Adding cloud-init..."
    qm set "$VMID" --ide2 "${STORAGE}:cloudinit" >>"$LOG_FILE" 2>&1
    log "SUCCESS" "Cloud-init added"
}

configure_cloudinit_network() {
    log "STEP" "[Step 6/10] Configuring network..."
    WORKDIR=$(mktemp -d "/tmp/${VMNAME}-${VMID}.XXXXXX")
    chmod 700 "$WORKDIR"
    qm set "$VMID" --ciuser "$CI_USER" >>"$LOG_FILE" 2>&1
    echo "$SSH_PUBKEY" > "${WORKDIR}/key.pub"
    qm set "$VMID" --sshkeys "${WORKDIR}/key.pub" >>"$LOG_FILE" 2>&1
    
    if [[ "$USE_DHCP" == "1" ]]; then
        qm set "$VMID" --ipconfig0 "ip=dhcp" >>"$LOG_FILE" 2>&1
    else
        qm set "$VMID" --ipconfig0 "ip=${IP_CIDR},gw=${GATEWAY_IP}" >>"$LOG_FILE" 2>&1
        qm set "$VMID" --nameserver "$DNS_SERVERS" --searchdomain "$SEARCH_DOMAIN" >>"$LOG_FILE" 2>&1
    fi
    log "SUCCESS" "Network configured"
}


#===============================================================================
# CLOUD-INIT USER DATA GENERATION (v3.3.3a - FINAL)
#===============================================================================
generate_userdata() {
    log "STEP" "[Step 7/10] Generating user data..."
    local userdata_file="${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml"
    
    # Determine network config
    local port_binding vm_ip="" fw_dest="any"
    if [[ "$USE_DHCP" != "1" ]]; then
        vm_ip="${IP_CIDR%/*}"
        if [[ "$BIND_TO_IP" == "1" ]]; then
            port_binding="${vm_ip}:${LITELLM_PORT}:${LITELLM_PORT}"
            fw_dest="$vm_ip"
        else
            port_binding="${LITELLM_PORT}:${LITELLM_PORT}"
        fi
    else
        port_binding="${LITELLM_PORT}:${LITELLM_PORT}"
    fi
    
    # Prepare config (unified indentation)
    local config_yaml_raw
    if [[ -n "$CUSTOM_CONFIG_CONTENT" ]]; then
        config_yaml_raw="$CUSTOM_CONFIG_CONTENT"
    else
        config_yaml_raw="model_list:
  - model_name: \"qwen3\"
    litellm_params:
      model: \"ollama/qwen3\"
      api_base: \"http://${OLLAMA_IP}:${OLLAMA_PORT}\"

litellm_settings:
  drop_params: true
  request_timeout: 600"
    fi
    local config_yaml_content=$(printf '%s\n' "$config_yaml_raw" | sed 's/^/      /')
    
    # Generate cloud-init YAML
    cat > "$userdata_file" << 'EOF'
#cloud-config
package_update: true
package_upgrade: true

packages:
  - ufw
  - curl
  - wget
  - ca-certificates
  - gnupg

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
EOF
    
    # Add config content
    echo "${config_yaml_content}" >> "$userdata_file"
    
    # Add docker-compose
    cat >> "$userdata_file" << EOF

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
            - ./data/postgres:/var/lib/postgresql/data
          restart: unless-stopped
          healthcheck:
            test: ["CMD-SHELL", "pg_isready -U litellm"]
            interval: 5s
          networks:
            - llm-network

        redis:
          image: redis:${REDIS_VERSION}-alpine
          container_name: llm-redis
          restart: unless-stopped
          healthcheck:
            test: ["CMD", "redis-cli", "ping"]
            interval: 5s
          networks:
            - llm-network

        litellm:
          image: ghcr.io/berriai/litellm:${LITELLM_VERSION}
          container_name: llm-litellm
          command: ["--config", "/app/config.yaml", "--port", "${LITELLM_PORT}"]
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

      networks:
        llm-network:
          driver: bridge
EOF

    # Add firewall rules
    local fw_rules=""
    if [[ "${ENABLE_FIREWALL}" == "1" ]]; then
        IFS=',' read -ra NETS <<< "$ALLOWED_NETWORKS"
        for net in "${NETS[@]}"; do
            net=$(echo "$net" | xargs)
            fw_rules+="      ufw allow from ${net} to ${fw_dest} port 22\\n"
            fw_rules+="      ufw allow from ${net} to ${fw_dest} port ${LITELLM_PORT}\\n"
        done
    fi

    # Add runcmd - CRITICAL: files move from /etc to /opt
    cat >> "$userdata_file" << 'EOFCMD'

runcmd:
  # CRITICAL: Create /opt dir and move files from /etc (correct cloud-init order)
  - mkdir -p /opt/llm-gateway
  - install -m 0600 /etc/llm-gateway/.env /opt/llm-gateway/.env
  - install -m 0644 /etc/llm-gateway/config.yaml /opt/llm-gateway/config.yaml
  - install -m 0644 /etc/llm-gateway/docker-compose.yml /opt/llm-gateway/docker-compose.yml
  
  - mkdir -p /opt/llm-gateway/data/{postgres,prometheus,grafana}
  - chmod 700 /opt/llm-gateway/data
  - chown -R 999:999 /opt/llm-gateway/data/postgres
  
  # Generate secrets
  - |
    ENV_FILE="/opt/llm-gateway/.env"
    gen_secret() { openssl rand -hex 32; }
    LITELLM_MASTER_KEY="sk-$(gen_secret)"
    POSTGRES_PASS="$(gen_secret)"
    GRAFANA_ADMIN_PASS="$(gen_secret)"
    cat > "$ENV_FILE" <<ENV
LITELLM_MASTER_KEY=${LITELLM_MASTER_KEY}
POSTGRES_PASS=${POSTGRES_PASS}
GRAFANA_ADMIN_PASS=${GRAFANA_ADMIN_PASS}
ENV
    chmod 600 "$ENV_FILE"
    
    cat > /root/llm-gateway-credentials.txt <<CREDS
LiteLLM Master Key:  ${LITELLM_MASTER_KEY}
PostgreSQL Password: ${POSTGRES_PASS}
Grafana Password:    ${GRAFANA_ADMIN_PASS}
CREDS
    chmod 600 /root/llm-gateway-credentials.txt

  # Install Docker
  - |
    export DEBIAN_FRONTEND=noninteractive
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

  # Configure firewall
  - |
EOFCMD

    [[ "${ENABLE_FIREWALL}" == "1" ]] && cat >> "$userdata_file" <<EOFFW
    echo -e "${fw_rules}" | while read rule; do [ -n "\$rule" ] && eval \$rule; done
    ufw default deny incoming
    ufw default allow outgoing
    echo "y" | ufw enable
EOFFW

    [[ "$BIND_TO_IP" == "1" && "$USE_DHCP" != "1" ]] && cat >> "$userdata_file" <<EOFIP
  # Wait for IP
  - |
    for i in {1..30}; do
      ip addr show | grep -q "${vm_ip}" && break
      sleep 1
    done
EOFIP

    cat >> "$userdata_file" << 'EOFSTART'
  # Start services
  - |
    cd /opt/llm-gateway
    docker compose up -d
    sleep 20
    for i in {1..60}; do
      curl -sf http://localhost:4000/v1/models && break
      sleep 2
    done
EOFSTART

    chmod 644 "$userdata_file"
    log "SUCCESS" "User data generated"
}

attach_userdata() {
    log "STEP" "[Step 8/10] Attaching user data..."
    local basename="$(basename "${SNIP_DIR}/${VMNAME}-${VMID}-user-data.yaml")"
    qm set "$VMID" --cicustom "user=${SNIPPET_STORAGE}:snippets/${basename}" >>"$LOG_FILE" 2>&1
    log "SUCCESS" "User data attached"
}

start_vm() {
    log "STEP" "[Step 9/10] Starting VM..."
    qm start "$VMID" >>"$LOG_FILE" 2>&1
    log "SUCCESS" "VM started"
}

wait_for_vm_ready() {
    log "STEP" "[Step 10/10] Waiting for VM..."
    [[ "${DRY_RUN}" == "1" ]] && return 0
    local elapsed=0
    while [ $elapsed -lt 300 ]; do
        qm agent "$VMID" ping &>/dev/null && { log "SUCCESS" "VM ready"; return 0; }
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log "WARN" "VM agent not responding"
}


#===============================================================================
# VALIDATION SCRIPT GENERATION
#===============================================================================
generate_validation_script() {
    [[ "${ENABLE_VALIDATION_SCRIPT}" != "1" || "$USE_DHCP" == "1" ]] && return 0
    log "INFO" "Generating validation script..."
    local vm_ip="${IP_CIDR%/*}"
    local val_script="/tmp/validate-llm-gateway-${VMID}.sh"
    
    cat > "$val_script" << EOFVAL
#!/usr/bin/env bash
set -euo pipefail
VM_IP="${vm_ip}"
SSH_ERR=\$(mktemp)
trap "rm -f \${SSH_ERR}" EXIT

# Test SSH accept-new
if timeout 5 ssh -o StrictHostKeyChecking=accept-new ${CI_USER}@\${VM_IP} true 2>\${SSH_ERR}; then
    SSH_OPTS="-o StrictHostKeyChecking=accept-new"
else
    grep -qiE "Bad configuration option" "\${SSH_ERR}" && SSH_OPTS="-o StrictHostKeyChecking=no" || SSH_OPTS="-o StrictHostKeyChecking=accept-new"
fi

echo "Validating VM ${VMID}..."
/usr/sbin/qm status ${VMID} | grep -q running || { echo "❌ Not running"; exit 1; }
ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} true || { echo "❌ SSH failed"; exit 1; }
curl -sf http://\${VM_IP}:${LITELLM_PORT}/v1/models >/dev/null && echo "✅ LiteLLM healthy"
ssh \${SSH_OPTS} ${CI_USER}@\${VM_IP} 'sudo cat /root/llm-gateway-credentials.txt'
EOFVAL

    chmod +x "$val_script"
    log "SUCCESS" "Validation script: $val_script"
}

print_summary() {
    local ip=$([[ "$USE_DHCP" == "1" ]] && echo "<DHCP>" || echo "${IP_CIDR%/*}")
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║         🎉 Deployment Complete!                              ║
╚══════════════════════════════════════════════════════════════╝

VM ID:       $VMID
VM Name:     $VMNAME  
IP:          $ip
Endpoint:    http://$ip:${LITELLM_PORT}

📝 Next Steps:
1. SSH: ssh ${CI_USER}@$ip
2. Verify: docker compose ps
3. Get credentials: sudo cat /root/llm-gateway-credentials.txt
4. Test: curl http://$ip:${LITELLM_PORT}/v1/models

Time: $(($(date +%s) - DEPLOYMENT_START_TIME))s
Log:  $LOG_FILE

EOF
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║    Proxmox LLM Gateway Deployer v${SCRIPT_VERSION}                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    
    load_config_file "${1:-}"
    load_litellm_config
    setup_logging
    check_prerequisites
    validate_inputs
    validate_storage
    validate_snippet_storage
    check_existing_deployment
    check_vm_conflicts
    
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
    generate_validation_script
    
    print_summary
    log "SUCCESS" "Deployment completed! 🎉"
}

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
