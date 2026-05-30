# VPN Gate Proxy

一个自动获取 [VPN Gate](https://www.vpngate.net/) 公共 VPN 节点、检测 IP 类型、自动连接并生成 SOCKS5 代理的 Docker 容器项目。提供 Web 面板进行可视化管理和实时监控。

## ✨ 功能

- 🌐 **自动获取节点列表**：从 VPN Gate API 拉取最新节点，支持地区过滤
- 🔍 **IP 检测**：连接成功后通过 ip-api 检测出口 IP 属性（国家、ISP、是否代理/机房）
- 🔗 **自动连接与切换**：自动选择可用节点并建立 OpenVPN 连接，连接中断时自动切换至预检节点
- 🧦 **SOCKS5 代理**：连接成功后启动 SOCKS5 代理，**仅代理经过代理的流量，不影响容器或宿主机网络**
- 🖥️ **Web 管理面板**：
  - 实时日志查看
  - 连接状态、IP 信息、SOCKS5 地址展示（支持一键复制）
  - 节点列表（按地区筛选、统计信息）
  - 手动连接/断开/重连
  - 设置面板：修改面板密码、API 地址、VPN 凭证、默认连接地区、节点/检测上限、自动更新间隔
- 📦 **Docker 部署**：开箱即用，支持 `NET_ADMIN` 权限建立隧道

## 📁 项目结构

```
vpngate-proxy/
├── .github/workflows/
│ └── docker-build.yml            # GitHub Actions 自动构建并推送镜像
├── app/
│ ├── app.py                      # Flask Web 服务 & API & WebSocket
│ ├── config.py                   # 配置读写，首次运行自动生成 secret_key
│ ├── vpn_manager.py              # VPN 管理核心：节点获取、连接、健康检测、策略路由、SOCKS5
│ ├── socks_server.py             # 极简 SOCKS5 服务器，出口绑定 VPN IP
│ └── templates/
│ ├── index.html                  # Web 控制面板（单页应用）
│ └── login.html                  # 登录页
├── Dockerfile
├── requirements.txt
└── README.md
```

## 🚀 快速开始

### 前提条件

- 一台 Linux 主机（或任何支持 Docker 的设备）
- 需要暴露的端口未被占用（默认 `5000` 用于面板，`1080` 用于 SOCKS5）

### 使用预构建镜像（推荐）

```
docker run -d \
  --name vpn-proxy \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 8080:8080 \
  -p 1080:1080 \
  ghcr.io/xiaowen-king/vpngate-proxy:latest
```
