# Configuration Reference

## Environment Variables

All settings can be configured via environment variables or config file.

### VM Settings

- `VMID`: VM ID number (default: 120)
- `VMNAME`: VM name (default: llm-gateway)
- `MEM`: Memory in MB (default: 8192)
- `CORES`: CPU cores (default: 4)
- `DISK_GB`: Disk size (default: 60)

### Network Settings

- `USE_DHCP`: Use DHCP (0 or 1)
- `IP_CIDR`: Static IP with CIDR
- `GATEWAY_IP`: Gateway IP
- `ALLOWED_NETWORKS`: Allowed networks for firewall

### Features

- `ENABLE_MONITORING`: Enable Prometheus/Grafana (0 or 1)
- `ENABLE_FIREWALL`: Enable UFW firewall (0 or 1)
- `BIND_TO_IP`: Bind to specific IP only (0 or 1)

For complete reference, see config/llm-gateway.conf.example
