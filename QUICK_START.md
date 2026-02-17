# 快速開始指南

## 📦 下載完整腳本

由於主腳本文件較大（約 30KB），完整版本請從 GitHub 下載：

### 方法 1: 直接下載主腳本

```bash
# 下載最新版本的完整腳本
curl -O https://raw.githubusercontent.com/alan-sun-dev/proxmox-llm-gateway-deployer/main/deploy-llm-gateway.sh

# 賦予執行權限
chmod +x deploy-llm-gateway.sh

# 運行部署
sudo ./deploy-llm-gateway.sh
```

### 方法 2: Clone 整個項目

```bash
git clone https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer.git
cd proxmox-llm-gateway-deployer
chmod +x deploy-llm-gateway.sh
sudo ./deploy-llm-gateway.sh
```

## 📋 本壓縮包包含

- ✅ 項目結構模板
- ✅ 配置文件範例
- ✅ 完整文檔
- ✅ 使用範例
- ⚠️  主腳本（需從 GitHub 下載）

## 🚀 快速部署步驟

1. **下載完整腳本**（見上方方法）

2. **準備配置**（可選）
```bash
cp config/llm-gateway.conf.example config/llm-gateway.conf
nano config/llm-gateway.conf  # 編輯您的設置
```

3. **運行部署**
```bash
sudo ./deploy-llm-gateway.sh
# 或使用配置文件
sudo ./deploy-llm-gateway.sh config/llm-gateway.conf
```

4. **驗證部署**
```bash
# 運行自動生成的驗證腳本
/tmp/validate-llm-gateway-<VMID>.sh
```

## 📞 需要幫助？

- GitHub Issues: https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer/issues
- 完整文檔: docs/INSTALLATION.md

## ⭐ 項目地址

https://github.com/alan-sun-dev/proxmox-llm-gateway-deployer
