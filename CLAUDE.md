# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 語言與互動偏好

- 使用**繁體中文**回應
- 執行任何會改變系統狀態的操作前，先向使用者確認
- 這是家用 home lab 環境，非生產環境

## 主機概要

- **主機名稱**: pve1
- **系統**: Proxmox VE 9.1 (Debian-based)，核心 6.17.x-pve
- **用途**: Home lab — 管理 VM 與 LXC 容器
- **網路**: LAN `192.168.200.30/24` (vmbr0)，Tailscale `100.109.65.57`
- **使用者**: shou.shih@

## 儲存配置

| 名稱 | 類型 | 用途 |
|------|------|------|
| local | 目錄 (`/var/lib/vz`) | ISO、模板、備份、snippets |
| local-lvm | LVM-thin (VG: pve) | VM 磁碟、容器 rootdir |
| ssdpool | ZFS pool | VM 磁碟、容器 rootdir |

## 常用 Proxmox 指令

```bash
# VM 管理
qm list                          # 列出所有 VM
qm start/stop/shutdown <VMID>    # 啟動/強制停止/優雅關機 VM
qm config <VMID>                 # 查看 VM 配置

# LXC 容器管理
pct list                         # 列出所有容器
pct start/stop/shutdown <CTID>   # 啟動/停止/關機容器
pct config <CTID>                # 查看容器配置

# 儲存
pvesm status                     # 儲存狀態
zpool status ssdpool             # ZFS pool 狀態
lvs                              # LVM 邏輯卷列表

# 網路
tailscale status                 # Tailscale 網路狀態

# 系統
pveversion -v                    # 完整版本資訊
systemctl status pvedaemon       # PVE daemon 狀態
journalctl -u pvedaemon -f       # 即時日誌
```

## 部署腳本

`/root/deploy-llm-gateway.sh` — LiteLLM Gateway VM 自動部署腳本 (v3.5.0)

```bash
./deploy-llm-gateway.sh --help          # 查看用法
./deploy-llm-gateway.sh --print-config  # 輸出當前配置
./deploy-llm-gateway.sh --report        # JSON 格式配置報告
./deploy-llm-gateway.sh --lint          # 語法檢查
./deploy-llm-gateway.sh --self-test     # 自我測試
INTERACTIVE=0 ./deploy-llm-gateway.sh   # 非互動模式部署
```

測試：
```bash
bats /root/test-deploy-llm-gateway.bats   # 執行 BATS 單元測試（不需要 Proxmox 環境）
```

### 腳本架構注意事項

- 部署流程為 10 個步驟，由 `main()` 依序呼叫各函式（create_vm_shell → import_and_attach_disk → configure_disk_and_boot → add_cloudinit_drive → configure_cloudinit_network → generate_userdata → ...）
- cloud-init user data 以 heredoc 一次寫入（`cat > $userdata_file <<EOF`），其中的變數（如 `$SSH_PUBKEY`）會在寫入時展開，修改時注意不要寫死值
- `qm importdisk` 的進度和結果都輸出到 **stderr**，擷取輸出時需要 `2>&1` 而非只靠 stdout
- LiteLLM Docker 映像的 `latest` tag 只有 arm64，amd64 主機必須用 `main-stable` tag
- Prometheus 容器以 UID 65534 (nobody) 執行，Grafana 以 UID 472 執行，掛載的 data 目錄需要對應的 chown
- `set -euo pipefail` 全域生效，管線中的 `grep` 無匹配會導致腳本退出，需加 `|| true` 保護

### 重新部署流程

```bash
qm stop 120 && qm destroy 120 --purge   # 刪除舊 VM
ssh-keygen -R 192.168.200.120            # 清除舊的 host key
INTERACTIVE=0 ./deploy-llm-gateway.sh    # 重新部署
```

## 目前運行的 VM

- **VMID 120**: llm-gateway
  - IP: `192.168.200.120`，SSH: `ssh ubuntu@192.168.200.120`
  - 服務：LiteLLM (:4000)、PostgreSQL、Redis、Prometheus (:9090)、Grafana (:3000)
  - 儲存：ssdpool (ZFS)，60GB 磁碟
  - 開機自啟：順序 3，延遲 30s
