# Changelog

## [3.3.3a] - 2025-02-17 - Final Production Release

### Critical Fixes
- Fixed cloud-init execution order (write_files to /etc, then move to /opt in runcmd)
- Ensures directory creation happens before file writes

### Added
- Validation script timeout for SSH accept-new detection
- IP availability wait when BIND_TO_IP is enabled

## [3.3.3] - 2025-02-17

### Fixed
- Validation script SSH accept-new detection
- DHCP mode vm_ip handling

### Added
- Wait for IP availability before starting Docker
- Robust error handling in validation script

## [3.3.2] - 2025-02-17

### Critical Fixes
- Removed LiteLLM container healthcheck
- Unified config indentation pipeline
- Binary detection for config validation

## [3.3.0] - 2025-02-17

### Added
- VM resource optimizations
- External LiteLLM config support
- BIND_TO_IP security option
- Validation script generation

## [3.0.0] - 2025-02-16

### Initial Release
- Automated Proxmox VM deployment
- Docker stack deployment
- Cloud-init configuration
- Monitoring stack
