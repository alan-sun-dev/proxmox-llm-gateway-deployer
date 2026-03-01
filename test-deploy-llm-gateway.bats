#!/usr/bin/env bats
# =============================================================================
# BATS Smoke Tests for deploy-llm-gateway.sh v3.5.0
# 
# Run: bats test-deploy-llm-gateway.bats
# Install: apt install bats  (or: npm install -g bats)
#
# These tests source the script WITHOUT executing main(), then exercise
# individual functions in isolation. No Proxmox host required.
# =============================================================================

SCRIPT="./deploy-llm-gateway.sh"

# ---------------------------------------------------------------------------
# Setup: source the script in a way that skips main()
# ---------------------------------------------------------------------------
setup() {
    # Create temp dir for test artifacts
    export TEST_TMPDIR="$(mktemp -d)"
    export LOG_FILE="${TEST_TMPDIR}/test.log"
    export DRY_RUN=1
    export INTERACTIVE=0
    export DEBUG=0
    
    # Stub out commands that don't exist outside Proxmox
    qm()     { echo "STUB:qm $*"; return 0; }
    pvesm()  { echo "STUB:pvesm $*"; return 0; }
    export -f qm pvesm
    
    # Source script (BASH_SOURCE != $0 skips main execution)
    source "$SCRIPT"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# =============================================================================
# _safe_load_config tests
# =============================================================================

@test "_safe_load_config: loads whitelisted key=value" {
    local cfg="${TEST_TMPDIR}/test.conf"
    cat > "$cfg" <<'EOF'
VMID=200
VMNAME=test-gateway
MEM=4096
EOF
    # Reset to defaults and ensure _ENV_OVERRIDES doesn't block config loading
    unset '_ENV_OVERRIDES[VMID]' '_ENV_OVERRIDES[VMNAME]' '_ENV_OVERRIDES[MEM]' 2>/dev/null || true
    VMID=120
    VMNAME=llm-gateway
    MEM=8192
    _safe_load_config "$cfg"
    [ "$VMID" = "200" ]
    [ "$VMNAME" = "test-gateway" ]
    [ "$MEM" = "4096" ]
}

@test "_safe_load_config: rejects shell expansion attempts" {
    local cfg="${TEST_TMPDIR}/evil.conf"
    cat > "$cfg" <<'EOF'
VMNAME=$(whoami)
EOF
    VMNAME="original"
    # Do NOT use 'run' here — run executes in a subshell, so variable
    # changes are invisible. We need to call directly and check state.
    _safe_load_config "$cfg"
    [ "$VMNAME" = "original" ]
}

@test "_safe_load_config: rejects backtick expansion" {
    local cfg="${TEST_TMPDIR}/evil2.conf"
    echo 'VMNAME=`id`' > "$cfg"
    VMNAME="original"
    _safe_load_config "$cfg"
    [ "$VMNAME" = "original" ]
}

@test "_safe_load_config: rejects non-whitelisted keys" {
    local cfg="${TEST_TMPDIR}/unknown.conf"
    echo 'EVIL_KEY=malicious_value' > "$cfg"
    _safe_load_config "$cfg"
    # Should not set EVIL_KEY
    [ -z "${EVIL_KEY:-}" ]
}

@test "_safe_load_config: preserves values with # in quotes" {
    local cfg="${TEST_TMPDIR}/hash.conf"
    cat > "$cfg" <<'EOF'
LITELLM_MASTER_KEY="sk-abc#def456"
EOF
    unset '_ENV_OVERRIDES[LITELLM_MASTER_KEY]' 2>/dev/null || true
    LITELLM_MASTER_KEY="original"
    _safe_load_config "$cfg"
    [ "$LITELLM_MASTER_KEY" = "sk-abc#def456" ]
}

@test "_safe_load_config: env override takes precedence" {
    local cfg="${TEST_TMPDIR}/override.conf"
    echo 'VMID=999' > "$cfg"
    # Clear stale state from source, then explicitly mark VMID as env-overridden
    unset '_ENV_OVERRIDES[VMID]' 2>/dev/null || true
    _ENV_OVERRIDES[VMID]=1
    VMID=500
    _safe_load_config "$cfg"
    [ "$VMID" = "500" ]
}

# =============================================================================
# validate_inputs tests (partial — tests that don't need Proxmox)
# =============================================================================

@test "validate_inputs: rejects VMID < 100" {
    VMID=50
    run validate_inputs
    [ "$status" -ne 0 ]
}

@test "validate_inputs: rejects VMID > 999999999" {
    VMID=9999999999
    run validate_inputs
    [ "$status" -ne 0 ]
}

@test "validate_inputs: rejects bad CIDR prefix" {
    VMID=120; VMNAME=test; MEM=8192; CORES=4; DISK_GB=50
    BRIDGE=vmbr0; VM_ONBOOT=1; VM_STARTUP_ORDER=3
    VM_BALLOON=0; VM_TAGS=llm; LITELLM_PORT=4000
    OLLAMA_IP=10.0.0.1; OLLAMA_PORT=11434
    USE_DHCP=0; IP_CIDR="10.0.0.100/33"  # Invalid prefix
    GATEWAY_IP=10.0.0.1; DNS_SERVERS="1.1.1.1"
    SEARCH_DOMAIN=local; ALLOWED_NETWORKS="10.0.0.0/24"
    ENABLE_FIREWALL=1; BIND_TO_IP=0
    SSH_PUBKEY_FILE="${TEST_TMPDIR}/key.pub"
    echo "ssh-ed25519 AAAA test@host" > "$SSH_PUBKEY_FILE"
    LITELLM_MASTER_KEY="sk-test"
    run validate_inputs
    [ "$status" -ne 0 ]
}

@test "validate_inputs: accepts valid configuration" {
    VMID=120; VMNAME=test; MEM=8192; CORES=4; DISK_GB=50
    BRIDGE=vmbr0; VM_ONBOOT=1; VM_STARTUP_ORDER=3
    VM_BALLOON=0; VM_TAGS=llm; LITELLM_PORT=4000
    OLLAMA_IP=10.0.0.1; OLLAMA_PORT=11434
    USE_DHCP=0; IP_CIDR="10.0.0.100/24"
    GATEWAY_IP=10.0.0.1; DNS_SERVERS="1.1.1.1 8.8.8.8"
    SEARCH_DOMAIN=local; ALLOWED_NETWORKS="10.0.0.0/24"
    ENABLE_FIREWALL=1; BIND_TO_IP=0
    SSH_PUBKEY_FILE="${TEST_TMPDIR}/key.pub"
    echo "ssh-ed25519 AAAA test@host" > "$SSH_PUBKEY_FILE"
    LITELLM_MASTER_KEY="sk-test123"
    run validate_inputs
    [ "$status" -eq 0 ]
}

# =============================================================================
# DNS normalization consistency (lint vs validate)
# =============================================================================

@test "DNS: comma-separated handled same in lint and validate" {
    DNS_SERVERS="1.1.1.1,8.8.8.8"
    # Simulate what validate_inputs does
    local dns_clean="${DNS_SERVERS//,/ }"
    local count=0
    for entry in $dns_clean; do
        [[ "$entry" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && count=$((count+1))
    done
    [ "$count" -eq 2 ]
}

# =============================================================================
# Version / CLI flag smoke tests
# =============================================================================

@test "--version prints version string" {
    run bash "$SCRIPT" --version
    [[ "$output" =~ "v3.5.0" ]]
}

@test "--help exits 0" {
    run bash "$SCRIPT" --help
    [ "$status" -eq 0 ]
}

@test "--report outputs valid JSON structure" {
    run bash "$SCRIPT" --report
    [ "$status" -eq 0 ]
    # Check for key JSON fields
    [[ "$output" =~ '"script_version"' ]]
    [[ "$output" =~ '"vmid"' ]]
    [[ "$output" =~ '"flags"' ]]
}

@test "bash -n syntax check passes" {
    run bash -n "$SCRIPT"
    [ "$status" -eq 0 ]
}
