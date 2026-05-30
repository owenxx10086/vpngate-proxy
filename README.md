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

- 一台 Linux 主机（或任何支持 Docker 的设备并安装了docker）
- 需要暴露的端口未被占用（默认 `8080` 用于面板，`1080` 用于 SOCKS5）

### 使用预构建镜像（推荐）

```
docker run -d --name vpn-proxy \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  -p 8080:8080 -p 1080:1080 \
  -v ./data:/data \
  ghcr.io/xiaowen-king/vpngate-proxy:latest
```
### 从源码构建

```
git clone https://github.com/xiaowen-king/vpngate-proxy.git
cd vpngate-proxy
docker build -t vpngate-proxy .
docker run -d --name vpn-proxy \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 8080:8080 \
  -p 1080:1080 \
  -v ./data:/data \
  vpngate-proxy
```

### 使用docker-compose.yaml文件

```
services:
  vpn-proxy:
    image: ghcr.io/xiaowen-king/vpngate-proxy:latest
    container_name: vpn-proxy
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "8080:8080"
      - "1080:1080"
    volumes:
      - ./data:/data
    restart: unless-stopped
```

## ⚙️ 配置说明

首次启动后，访问 http://你的主机IP:8080，使用默认密码 admin 登录。

|配置项|说明|默认值|
|------|---|-------|
|面板密码|Web登录密码|admin|
|API 地址|获取VPNGate节点列表的URL|（空，需填写）|
|SOCKS端口|SOCKS5代理监听端口|1080|
|VPN用户名 / 密码|OpenVPN认证信息（VPN Gate 默认为 vpn）|（空，需填写）|
|默认连接地区|自动连接和后台检测时使用的地区代码（如 JP）|all（所有地区）|
|节点数据上限|每次从 API 拉取节点时返回的最大数量|200|
|检测数量上限|后台预检时最多检测的节点数量|20|
|自动更新节点间隔|浏览器和后端自动刷新节点缓存的时间间隔（分钟），0 表示关闭|0|

## 📖 使用说明

### 填写配置

登录后在设置页填入 API 地址（如 https://http-api.kongbai5202019-09b.workers.dev 或自建中转）、VPN 用户名/密码（默认都为 vpn），保存。

### 选择地区（可选）

在设置中修改默认连接地区，或在节点列表页手动筛选地区。

### 连接 VPN：

仪表盘点击 “连接” 按钮，或在节点列表点击某行节点旁的 “连接” 按钮

### 使用 SOCKS5 代理：
仪表盘会显示 SOCKS5 地址（如 socks5://172.17.0.2:1080），可直接复制使用。

浏览器插件（SwitchyOmega）或应用程序配置此地址即可通过 VPN 节点访问互联网。

只有主动连接此代理的流量会走 VPN，主机和其他容器不受影响。

### 手动切换节点

在节点列表点击 “连接”，会弹出连接进度弹窗并显示实时日志。若连接失败，会自动重试下一节点或使用默认地区自动连接。
