# Proxmox LLM Gateway Deployer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-3.3.3a-blue.svg)](CHANGELOG.md)
[![Proxmox](https://img.shields.io/badge/Proxmox-VE%207%2B-orange.svg)](https://www.proxmox.com/)

Enterprise-grade automation script for deploying LiteLLM API gateway on Proxmox VE with full monitoring stack.

## ✨ Features

- 🚀 **One-Command Deployment**: Fully automated VM provisioning and service configuration
- 🔒 **Production Security**: UFW firewall, network isolation, auto-generated secrets
- 📊 **Built-in Monitoring**: Optional Prometheus + Grafana stack
- 🐳 **Docker-based**: PostgreSQL, Redis, LiteLLM in containerized environment
- ☁️ **Cloud-init Powered**: Declarative infrastructure with Ubuntu cloud images
- 🔄 **Idempotent**: Safe to re-run, detects existing deployments
- 📝 **Enterprise Ready**: Comprehensive logging, validation scripts, error handling

## 🎯 Quick Start

### Prerequisites

- Proxmox VE 7.0+ host
- Root access to Proxmox host
- 8GB+ RAM available for VM
- 60GB+ storage space

### Basic Deployment

\`\`\`bash
curl -O https://raw.githubusercontent.com/alan-sun-dev/proxmox-llm-gateway-deployer/main/deploy-llm-gateway.sh
chmod +x deploy-llm-gateway.sh
sudo ./deploy-llm-gateway.sh
\`\`\`

## 📋 Configuration

See [config/llm-gateway.conf.example](config/llm-gateway.conf.example) for all options.

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

For complete documentation and full script, visit:
https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer
