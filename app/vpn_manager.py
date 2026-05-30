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
            "ip_info": None,
            "socks": ""
        }
        self._stop_event = threading.Event()
        self._health_thread = None
        self._bg_check_thread = None
        self._log_callback = None
        self.tun_dev = None        # 当前 VPN 接口名

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
        self.log("正在获取节点列表...")
        try:
            resp = requests.get(self.config["api_url"], timeout=30)
            resp.encoding = "utf-8"
            text = resp.text
            lines = text.splitlines()

            header_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("#HostName"):
                    header_index = i
                    break

            if header_index is None:
                self.log("未找到节点表头，可能 API 格式变化")
                return

            csv_lines = [lines[header_index]]
            for line in lines[header_index+1:]:
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
        try:
            url = f"https://ping0.cc/ip/{ip}"
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code != 200:
                return None
            soup = BeautifulSoup(resp.text, "html.parser")
            data = {}
            items = soup.select("div.card-body .row .col")
            for item in items:
                text = item.get_text(strip=True)
                if ":" in text:
                    key, val = text.split(":", 1)
                    data[key.strip()] = val.strip()
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
        return True

    def _get_tun_info(self):
        """获取最新的 tun 接口 IP 和名称，返回 (ip, dev) 或 (None, None)"""
        try:
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            # 匹配所有 tun 接口行及紧随的 inet 地址，取最后一个
            matches = re.findall(r"(tun\d+):\s.*?\n\s+inet (\d+\.\d+\.\d+\.\d+)", result.stdout, re.DOTALL)
            if matches:
                dev, ip = matches[-1]
                return ip, dev
        except Exception:
            pass
        return None, None

    def connect_node(self, node):
        """连接到指定节点，返回 True 表示成功"""
        self.disconnect()
        self.current_node = node
        self.log(f"正在连接到节点: {node['hostname']} ({node['ip']})")

        # 解码 OpenVPN 配置
        try:
            config_b64 = node["openvpn_config_base64"]
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except Exception:
            self.log("解码 OpenVPN 配置失败")
            return False

        # 写入认证文件
        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config['vpn_user']}\n{self.config['vpn_pass']}\n")

        # 修改配置
        if "auth-user-pass" not in ovpn_content:
            ovpn_content += f"\nauth-user-pass {auth_path}\n"
        ovpn_content += "\nroute-nopull\n"
        ovpn_content += "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n"

        ovpn_path = "/tmp/vpn_config.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn_content)

        # 启动 OpenVPN
        try:
            self.vpn_process = subprocess.Popen(
                ["openvpn", "--config", ovpn_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log(f"启动 OpenVPN 失败: {str(e)}")
            return False

        # 监控输出
        tun_ip = None
        tun_dev = None
        connected_flag = False
        start_time = time.time()
        timeout = 25

        while time.time() - start_time < timeout:
            if self.vpn_process.poll() is not None:
                self.log("OpenVPN 进程已退出，连接失败")
                self.vpn_process = None
                return False

            line = self.vpn_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            self.log(f"[OpenVPN] {line.strip()}")

            if "Peer Connection Initiated" in line:
                self.log("TLS 握手成功，等待配置...")

            if "Initialization Sequence Completed" in line:
                connected_flag = True
                self.log("OpenVPN 初始化完成")
                break

            # 直接从 net_addr_ptp_v4_add 提取 IP（可能没有接口名）
            if "net_addr_ptp_v4_add" in line:
                match = re.search(r"net_addr_ptp_v4_add: (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    tun_ip = match.group(1)
                    self.log(f"从 OpenVPN 日志获取到 VPN IP: {tun_ip}")
                    # 此时接口可能还没完全 up，继续循环直到完成

        # 如果已有 IP 或连接成功，但还没拿到 IP，尝试从系统获取
        if connected_flag or tun_ip:
            self.log("正在从系统获取 VPN 接口信息...")
            ip, dev = self._get_tun_info()
            if ip:
                tun_ip = ip
                tun_dev = dev
            else:
                self.log("无法从系统获取 VPN IP")
                self.disconnect()
                return False
        else:
            self.log("获取 VPN IP 失败，无法启动 SOCKS5 代理")
            self.disconnect()
            return False

        self.tun_dev = tun_dev
        self.log(f"VPN 连接成功，本机 VPN IP: {tun_ip}, 接口: {tun_dev}")

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
            try:
                self.vpn_process.terminate()
                self.vpn_process.wait(timeout=3)
            except Exception:
                try:
                    self.vpn_process.kill()
                except Exception:
                    pass
            self.vpn_process = None
        if self.socks_server:
            self.socks_server.stop()
            self.socks_server = None
        self.tun_dev = None
        self.status["connected"] = False
        self.status["node_info"] = {}
        self.status["socks"] = ""

    def _get_host_ip(self):
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def health_check_loop(self):
        while not self._stop_event.is_set():
            time.sleep(10)
            if not self.status["connected"] or not self.tun_dev:
                continue
            try:
                # 使用动态接口名
                output = subprocess.run(
                    ["ping", "-c", "1", "-W", "3", "-I", self.tun_dev, "8.8.8.8"],
                    capture_output=True, text=True, timeout=5
                )
                if "1 received" not in output.stdout:
                    self.log("当前连接不可用，准备切换...")
                    self._switch_to_next_available()
            except Exception as e:
                self.log(f"健康检测异常: {str(e)}")

    def background_check_nodes(self):
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

        connected = False
        for node in nodes:
            if self._stop_event.is_set():
                break
            if self.connect_node(node):
                connected = True
                break
            self.log(f"节点 {node['hostname']} 连接失败，尝试下一个...")
            time.sleep(1)

        if not connected:
            self.log("所有节点均连接失败，请检查网络或更换地区")
        else:
            self.log("VPN 连接成功建立")

        self._health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
        self._health_thread.start()
        self._bg_check_thread = threading.Thread(target=self.background_check_nodes, daemon=True)
        self._bg_check_thread.start()

    def stop(self):
        self._stop_event.set()
        self.disconnect()
