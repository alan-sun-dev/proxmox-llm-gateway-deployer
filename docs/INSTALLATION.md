# Installation Guide

## Quick Start

\`\`\`bash
curl -O https://raw.githubusercontent.com/alan-sun-dev/proxmox-llm-gateway-deployer/main/deploy-llm-gateway.sh
chmod +x deploy-llm-gateway.sh
sudo ./deploy-llm-gateway.sh
\`\`\`

## System Requirements

- Proxmox VE 7.0+
- 8GB+ RAM
- 60GB+ storage
- Root access

## Configuration

1. Copy example configuration:
\`\`\`bash
cp config/llm-gateway.conf.example config/llm-gateway.conf
\`\`\`

2. Edit settings:
\`\`\`bash
nano config/llm-gateway.conf
\`\`\`

3. Run deployment:
\`\`\`bash
sudo ./deploy-llm-gateway.sh config/llm-gateway.conf
\`\`\`

For complete documentation, visit:
https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer
