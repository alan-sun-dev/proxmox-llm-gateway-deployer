# Troubleshooting Guide

## Common Issues

### VM not starting

Check VM status:
\`\`\`bash
qm status <VMID>
\`\`\`

### Services not ready

SSH to VM and check:
\`\`\`bash
ssh ubuntu@<VM_IP>
docker compose logs -f
\`\`\`

### Network issues

Verify configuration:
\`\`\`bash
qm config <VMID> | grep net
\`\`\`

For more help, visit:
https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer/issues
