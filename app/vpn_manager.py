import base64
import csv
import io
import json
import os
import re
import subprocess
import threading
import time
import logging
from datetime import datetime

import requests
from bs4 import BeautifulSoup

import config
from socks_server import Socks5Server

logger = logging.getLogger("vpn_manager")

class VpnManager:
    def __init__(self):
        self.config = config.load_config()
        self.nodes = []
        self.current_node = None
        self.vpn_process = None
        self.socks_server = None
        self.status = {
            "connected": False,
            "node_info": {},
            "ip_info": None,       # ping0.cc 检测结果
            "socks": ""
        }
        self._stop_event = threading.Event()
        self._health_thread = None
        self._bg_check_thread = None
        self._log_callback = None  # 用于向 Web 推送日志

    def set_log_callback(self, cb):
        self._log_callback = cb

    def log(self, message):
        logger.info(message)
        if self._log_callback:
            self._log_callback(message)

    def set_config(self, cfg):
        self.config = cfg
        config.save_config(cfg)

    def fetch_nodes(self):
        """获取 VPN Gate 节点列表"""
        self.log("正在获取节点列表...")
        try:
            resp = requests.get(self.config["api_url"], timeout=30)
            resp.encoding = "utf-8"
            text = resp.text
            lines = text.splitlines()

            # 查找表头行（以 #HostName 开头）
            header_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("#HostName"):
                    header_index = i
                    break

            if header_index is None:
                self.log("未找到节点表头，可能 API 格式变化")
                return

            # 从表头行开始，后续都是 CSV 数据
            csv_lines = [lines[header_index]]  # 表头
            for line in lines[header_index+1:]:
                # 跳过空白行
                if line.strip() == "":
                    continue
                csv_lines.append(line)

            csv_text = "\n".join(csv_lines)
            reader = csv.DictReader(io.StringIO(csv_text))
            nodes = []
            for row in reader:
                if not row.get("#HostName"):
                    continue
                nodes.append({
                    "hostname": row.get("#HostName", ""),
                    "ip": row.get("IP", ""),
                    "score": row.get("Score", ""),
                    "ping": row.get("Ping", ""),
                    "speed": row.get("Speed", ""),
                    "country_long": row.get("CountryLong", ""),
                    "country_short": row.get("CountryShort", ""),
                    "num_sessions": row.get("NumVpnSessions", ""),
                    "uptime": row.get("Uptime", ""),
                    "total_users": row.get("TotalUsers", ""),
                    "total_traffic": row.get("TotalTraffic", ""),
                    "log_type": row.get("LogType", ""),
                    "operator": row.get("Operator", ""),
                    "message": row.get("Message", ""),
                    "openvpn_config_base64": row.get("OpenVPN_ConfigData_Base64", "")
                })
            self.nodes = nodes
            self.log(f"获取到 {len(nodes)} 个节点")
        except Exception as e:
            self.log(f"获取节点列表失败: {str(e)}")

    def filter_nodes(self, region="all"):
        if region == "all":
            return self.nodes
        return [n for n in self.nodes if n["country_short"].upper() == region.upper()]

    def detect_ip(self, ip):
        """使用 ping0.cc 检测 IP 信息"""
        try:
            url = f"https://ping0.cc/ip/{ip}"
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code != 200:
                return None
            soup = BeautifulSoup(resp.text, "html.parser")
            data = {}
            # 解析常见字段
            items = soup.select("div.card-body .row .col")
            for item in items:
                text = item.get_text(strip=True)
                if ":" in text:
                    key, val = text.split(":", 1)
                    data[key.strip()] = val.strip()
            # 补充特定字段
            risk_el = soup.find(string=re.compile("风控", re.IGNORECASE))
            if risk_el:
                data["风险值"] = risk_el.find_next().get_text(strip=True)
            native_el = soup.find(string=re.compile("原生", re.IGNORECASE))
            if native_el:
                data["原生IP"] = native_el.find_next().get_text(strip=True)
            usage_el = soup.find(string=re.compile("使用场景", re.IGNORECASE))
            if usage_el:
                data["使用场景"] = usage_el.find_next().get_text(strip=True)
            ai_el = soup.find(string=re.compile("大模型", re.IGNORECASE))
            if ai_el:
                data["大模型检测"] = ai_el.find_next().get_text(strip=True)
            return data if data else None
        except Exception as e:
            self.log(f"IP检测失败: {str(e)}")
            return None

    def test_node(self, node):
        """测试节点是否可用（占位，实际可做连通性检查）"""
        # TODO: 实现真正的连通性测试，例如 TCP 连接或 ICMP ping
        return True

    def connect_node(self, node):
        """连接到指定节点，启动 SOCKS5 代理"""
        self.disconnect()
        self.current_node = node
        self.log(f"正在连接到节点: {node['hostname']} ({node['ip']})")
        # 解码 OpenVPN 配置
        try:
            config_b64 = node["openvpn_config_base64"]
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except:
            self.log("解码 OpenVPN 配置失败")
            return False

        # 写入 auth 文件
        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config['vpn_user']}\n{self.config['vpn_pass']}\n")

        # 修改 ovpn 配置：添加 auth-user-pass 和路由策略
        if "auth-user-pass" not in ovpn_content:
            ovpn_content += f"\nauth-user-pass {auth_path}\n"
        ovpn_content += "\nroute-nopull\n"  # 不拉取默认路由

        # 兼容 OpenVPN 2.6+：添加服务器可能使用的旧加密算法
        ovpn_content += "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n"

        ovpn_path = "/tmp/vpn_config.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn_content)

        # 启动 openvpn
        try:
            self.vpn_process = subprocess.Popen(
                ["openvpn", "--config", ovpn_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log(f"启动 OpenVPN 失败: {str(e)}")
            return False

        # 等待连接成功并获取 tun0 IP
        tun_ip = None
        deadline = time.time() + 30
        while time.time() < deadline:
            line = self.vpn_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            self.log(f"[OpenVPN] {line.strip()}")
            if "Peer Connection Initiated" in line:
                pass
            if "ifconfig" in line and "netmask" in line:
                parts = line.split()
                if len(parts) >= 2:
                    tun_ip = parts[1]
                    break
        if not tun_ip:
            try:
                result = subprocess.run(["ip", "addr", "show", "dev", "tun0"], capture_output=True, text=True)
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", result.stdout)
                if match:
                    tun_ip = match.group(1)
            except:
                pass
        if not tun_ip:
            self.log("获取 VPN IP 失败，无法启动 SOCKS5 代理")
            self.disconnect()
            return False

        self.log(f"VPN 连接成功，本机 VPN IP: {tun_ip}")
        # 启动 SOCKS5 代理
        socks_bind = "0.0.0.0"
        socks_port = self.config["socks_port"]
        self.socks_server = Socks5Server(socks_bind, socks_port, tun_ip)
        self.socks_server.start()

        self.status["connected"] = True
        self.status["node_info"] = node
        self.status["socks"] = f"socks5://{self._get_host_ip()}:{socks_port}"
        self.status["ip_info"] = self.detect_ip(node["ip"])
        self.log(f"SOCKS5 代理已启动: {self.status['socks']}")
        return True

    def disconnect(self):
        if self.vpn_process:
            self.log("断开当前连接...")
            self.vpn_process.terminate()
            try:
                self.vpn_process.wait(timeout=5)
            except:
                self.vpn_process.kill()
            self.vpn_process = None
        if self.socks_server:
            self.socks_server.stop()
            self.socks_server = None
        self.status["connected"] = False
        self.status["node_info"] = {}
        self.status["socks"] = ""

    def _get_host_ip(self):
        """获取容器对外 IP（供外部访问 socks）"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def health_check_loop(self):
        """持续检测当前连接，不可用时自动切换"""
        while not self._stop_event.is_set():
            time.sleep(10)
            if not self.status["connected"]:
                continue
            try:
                output = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", "-I", "tun0", "8.8.8.8"],
                    capture_output=True, text=True
                )
                if "1 received" not in output.stdout:
                    self.log("当前连接不可用，准备切换...")
                    self._switch_to_next_available()
            except:
                self.log("健康检测异常")
        self.disconnect()

    def background_check_nodes(self):
        """定时检测其他节点，保持可用节点列表"""
        while not self._stop_event.is_set():
            time.sleep(60)
            if self._stop_event.is_set():
                break
            nodes = self.filter_nodes(self.config["region"])
            self.log("开始后台节点检测...")
            available = []
            for node in nodes[:20]:
                if self._stop_event.is_set():
                    break
                if self.status["connected"] and node["ip"] == self.status["node_info"].get("ip"):
                    continue
                if self.test_node(node):
                    available.append(node)
            self._available_nodes = available
            self.log(f"当前可用节点: {len(available)} 个")

    def _switch_to_next_available(self):
        """切换到最近的可用节点"""
        if hasattr(self, "_available_nodes") and self._available_nodes:
            next_node = self._available_nodes.pop(0)
            self.log(f"切换到节点: {next_node['hostname']}")
            self.connect_node(next_node)
        else:
            self.log("没有可用节点，尝试从列表重新获取")
            self.fetch_nodes()
            nodes = self.filter_nodes(self.config["region"])
            for node in nodes:
                if self._stop_event.is_set():
                    break
                if node["ip"] == self.status["node_info"].get("ip"):
                    continue
                if self.test_node(node):
                    self.connect_node(node)
                    return
            self.log("所有节点均不可用，等待下次检测")

    def start(self):
        self._stop_event.clear()
        self.fetch_nodes()
        nodes = self.filter_nodes(self.config["region"])
        for node in nodes:
            if self.test_node(node):
                self.connect_node(node)
                break
        self._health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
        self._health_thread.start()
        self._bg_check_thread = threading.Thread(target=self.background_check_nodes, daemon=True)
        self._bg_check_thread.start()

    def stop(self):
        self._stop_event.set()
        self.disconnect()
