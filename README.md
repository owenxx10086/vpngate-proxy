# VPN Gate Proxy

一个自动获取 [VPN Gate](https://www.vpngate.net/) 公共 VPN 节点、检测 IP 类型、自动连接并生成 SOCKS5 代理的 Docker 容器项目。提供 Web 面板进行可视化管理和实时监控。

## 目前进度

目前为测试阶段，已经可以正常使用，但是不知道是否稳定

## 目前实现功能

### 功能概述

通过api获取gate节点列表，自动连接节点并生成SK代理，当连接节点未通过健康检测达到一定次数后自动切换节点

### 仪表盘

一、显示连接信息（连接状态、节点名称、IP地址、归属地、SK代理连接、节点连接时长、节点延迟、节点下载速度、断开连接按钮、连接按钮、重新连接按钮、延迟检测按钮、测试按钮）

二、IP检测结果（ISP、是否为代理、国家、地区、城市、是否机房/托管、IP地址，是否移动网络）

三、实时日志，实时显示连接日志，健康检测日志，获取节点日志等

### 节点列表

显示从aip获取的节点列表，可以在节点列表中手动切换节点，可以通过地区筛选节点，可以手动刷新节点

### 设置

一、可以自定义获取节点API链接

二、可以SK代理端口

三、可以自定义面板端口

四、可以指定切换节点区域

五、可以自定义获取节点数量，通过API获取的只有一百个左右

六、可以自定义预备节点检测数量

七、可以自定义更新节点列表时间

八、可以自定义检点检测阈值，例如连续失败多少次切换节点

九、可以自定义当前连接节点阈值检测间隔时间

十、可以之定义检测网址，支持多个网址，当所有自定义网址使用SK代理访问都不可达达到一定数量判断节点不可用自动切换节点

十一、自定义日志保存天数

十二、可以自定义节点列表自动跟新间隔

十三、可自定义测试链接

十四、新增优先连接同网段IP节点开关，可以选择优先连接同网段节点，减少IP切换跨大地区问题

十五、新增连接记录，可以在连接记录里面设置优先连接节点，最多可以设置三个，可以在连接记录里面直接点击“连接”按钮对设置了优先连接的节点进行连接

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

## 界面展示

![1](https://github.com/xiaowen-king/vpngate-proxy/blob/main/images/1.png)

![2](https://github.com/xiaowen-king/vpngate-proxy/blob/main/images/2.png)

![3](https://github.com/xiaowen-king/vpngate-proxy/blob/main/images/3.png)

![4](https://github.com/xiaowen-king/vpngate-proxy/blob/main/images/4.png)

![5](https://github.com/xiaowen-king/vpngate-proxy/blob/main/images/5.png)

## 常见问题

### 一、使用vpngate的aip链接（https://www.vpngate.net/api/iphone/）获取不到节点信息怎么办？

如果使用vpngate的api链接获取不到节点信息是被屏蔽了，可以利用CF（cloudflare）免费的Workers 和 Pages来做中转

中转代码如下：

```
export default {
  async fetch(request, env, ctx) {
    const TARGET_URL = "http://www.vpngate.net/api/iphone";
    
    const headers = {
      "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    };

    try {
      const response = await fetch(TARGET_URL, { headers, timeout: 8000 });
      
      if (!response.ok) {
        return new Response(`CF 边缘节点抓取失败，状态码: ${response.status}`, { status: 502 });
      }

      const rawText = await response.text();

      // 2. 刚性校验：防止抓到混淆的 SOAP 加密串或空白页
      if (!rawText.includes("#HostName") || !rawText.includes("OpenVPN_ConfigData_Base64")) {
        return new Response("抓取成功但数据已被混淆劫持，非合规 CSV 格式", { status: 502 });
      }

      // 3. 将洗白后的标准文本流，套上防嗅探请求头，干净地吐给你的 Linux 服务器
      return new Response(rawText, {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "no-cache, no-store, must-revalidate"
        }
      });

    } catch (error) {
      return new Response(`CF 算力中转发生崩溃: ${error.message}`, { status: 500 });
    }
  }
};
```

### 二、当前连接的节点不在节点列表里面

这种情况正常，因为gate的节点非常多，但是gate的API只能每次获取一百个节点左右，只要当前节点通过健康检测就可以正常使用

## 联系方式

邮箱：239972420@qq.com
