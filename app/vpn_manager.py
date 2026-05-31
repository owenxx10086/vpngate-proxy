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
        self._auto_update_thread = None
        self._auto_update_trigger = threading.Event()
        self._log_callback = None
        self.tun_dev = None
        self.tun_ip = None
        self.health_fail_count = 0
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self._available_nodes = []
        self.policy_routing_set = False
        self._failed_ips = set()   # 记录本轮切换中尝试失败的 IP

    def set_log_callback(self, cb):
        self._log_callback = cb

    def log(self, message):
        logger.info(message)
        if self._log_callback:
            self._log_callback(message)

    def set_config(self, cfg):
        self.config = cfg
        config.save_config(cfg)
        self.max_health_fails = self.config.get("health_fail_threshold", 3)
        self._auto_update_trigger.set()

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
        nodes = list(self.nodes)
        if region == "all":
            return nodes
        return [n for n in nodes if (n.get("country_short") or "").upper() == region.upper()]

    def detect_ip(self, ip):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,proxy,hosting,mobile,query"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            if data.get("status") != "success":
                self.log(f"ip-api 查询失败: {data.get('message')}")
                return None
            return {
                "查询IP": data.get("query", ip),
                "国家": data.get("country", ""),
                "地区": data.get("regionName", ""),
                "城市": data.get("city", ""),
                "ISP": data.get("isp", ""),
                "代理/VPN": "是" if data.get("proxy") else "否",
                "机房/托管": "是" if data.get("hosting") else "否",
                "移动网络": "是" if data.get("mobile") else "否",
            }
        except Exception as e:
            self.log(f"IP检测失败: {str(e)}")
            return None

    def test_node(self, node):
        return True

    def _get_tun_info(self):
        try:
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
            matches = re.findall(r"(tun\d+):\s.*?\n\s+inet (\d+\.\d+\.\d+\.\d+)", result.stdout, re.DOTALL)
            if matches:
                dev, ip = matches[-1]
                return ip, dev
        except Exception:
            pass
        return None, None

    def _setup_policy_routing(self, ip, dev):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", "100"], check=False)
            subprocess.run(["ip", "rule", "add", "from", ip, "table", "100"], check=False)
            self.log(f"策略路由已配置: from {ip} lookup table 100 (default dev {dev})")
            self.policy_routing_set = True
        except Exception as e:
            self.log(f"配置策略路由失败: {e}")

    def _teardown_policy_routing(self, ip, dev):
        if not self.policy_routing_set:
            return
        try:
            subprocess.run(["ip", "rule", "del", "from", ip, "table", "100"], check=False)
            subprocess.run(["ip", "route", "del", "default", "dev", dev, "table", "100"], check=False)
            self.log("策略路由已清理")
        except Exception as e:
            self.log(f"清理策略路由失败: {e}")

    def connect_node(self, node):
        self.disconnect()
        self.current_node = node
        self.log(f"正在连接到节点: {node['hostname']} ({node['ip']})")

        try:
            config_b64 = node["openvpn_config_base64"]
            ovpn_content = base64.b64decode(config_b64).decode("utf-8")
        except Exception:
            self.log("解码 OpenVPN 配置失败")
            return False

        auth_path = "/tmp/vpn_auth.txt"
        with open(auth_path, "w") as f:
            f.write(f"{self.config['vpn_user']}\n{self.config['vpn_pass']}\n")

        if "auth-user-pass" not in ovpn_content:
            ovpn_content += f"\nauth-user-pass {auth_path}\n"

        ovpn_content += "\nroute-nopull\n"
        ovpn_content += "\ndata-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC:CHACHA20-POLY1305\n"

        ovpn_path = "/tmp/vpn_config.ovpn"
        with open(ovpn_path, "w") as f:
            f.write(ovpn_content)

        try:
            self.vpn_process = subprocess.Popen(
                ["openvpn", "--config", ovpn_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
        except Exception as e:
            self.log(f"启动 OpenVPN 失败: {str(e)}")
            return False

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

            if "net_addr_ptp_v4_add" in line:
                match = re.search(r"net_addr_ptp_v4_add: (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    tun_ip = match.group(1)
                    self.log(f"从 OpenVPN 日志获取到 VPN IP: {tun_ip}")

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
        self.tun_ip = tun_ip
        self.health_fail_count = 0

        self._setup_policy_routing(tun_ip, tun_dev)

        self.log(f"VPN 连接成功，本机 VPN IP: {tun_ip}, 接口: {tun_dev}")

        socks_bind = "0.0.0.0"
        socks_port = self.config["socks_port"]
        self.socks_server = Socks5Server(socks_bind, socks_port, tun_ip)
        self.socks_server.start()

        self.status["connected"] = True
        self.status["node_info"] = node
        self.status["socks"] = f"socks5://{self._get_host_ip()}:{socks_port}"
        self.status["ip_info"] = self.detect_ip(node["ip"])
        self.log(f"SOCKS5 代理已启动: {self.status['socks']}")

        # 连接成功，清空失败记录
        self._failed_ips.clear()
        return True

    def disconnect(self):
        if self.tun_ip and self.tun_dev:
            self._teardown_policy_routing(self.tun_ip, self.tun_dev)

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
        self.tun_ip = None
        self.status["connected"] = False
        self.status["node_info"] = {}
        self.status["socks"] = ""
        self.policy_routing_set = False

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

    # ---------- 修改了 _is_tunnel_alive 和 health_check_loop ----------
    def _is_tunnel_alive(self):
        """使用 SOCKS5 代理访问 httpbin.org，只要请求成功就认为隧道可用"""
        # 首先检查进程是否存活
        if not self.vpn_process or self.vpn_process.poll() is not None:
            return False
        # 然后检查接口是否存在
        if not self.tun_dev or not self.tun_ip:
            return False
        try:
            ip_check = subprocess.run(
                ["ip", "addr", "show", "dev", self.tun_dev],
                capture_output=True, text=True, timeout=5
            )
            if ip_check.returncode != 0 or self.tun_ip not in ip_check.stdout:
                return False
        except Exception:
            return False

        # 通过 SOCKS5 代理请求测试站点，只验证连通性，不再比对 IP
        try:
            socks_port = self.config.get("socks_port", 1080)
            result = subprocess.run(
                ["curl", "-s", "--socks5", f"127.0.0.1:{socks_port}", "--max-time", "8",
                 "http://httpbin.org/ip"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if "origin" in data:
                    # 成功获取到出口 IP，说明代理工作正常
                    return True
            self.log(f"curl 检测失败: {result.stderr.strip()}")
            return False
        except Exception as e:
            self.log(f"SOCKS5 代理检测异常: {e}")
            return False

    def health_check_loop(self):
        while not self._stop_event.is_set():
            time.sleep(10)
            if not self.status["connected"]:
                self.health_fail_count = 0
                continue

            if self._is_tunnel_alive():
                self.health_fail_count = 0
                # 成功时不记录日志，减少刷屏
            else:
                self.health_fail_count += 1
                self.log(f"健康检测失败 (连续 {self.health_fail_count} 次)")

            if self.health_fail_count >= self.max_health_fails:
                self.log(f"连续 {self.health_fail_count} 次健康检测失败，准备切换节点")
                self._switch_to_next_available()
                self.health_fail_count = 0
    # ---------------------------------------------------------------

    def background_check_nodes(self):
        while not self._stop_event.is_set():
            time.sleep(60)
            if self._stop_event.is_set():
                break
            nodes = self.filter_nodes(self.config["region"])
            self.log("开始后台节点检测...")
            available = []
            check_limit = self.config.get("check_limit", 20)
            for node in nodes[:check_limit]:
                if self._stop_event.is_set():
                    break
                if self.status["connected"] and node["ip"] == self.status["node_info"].get("ip"):
                    continue
                if self.test_node(node):
                    available.append(node)
            self._available_nodes = available
            self.log(f"当前可用节点: {len(available)} 个")

    def _auto_update_loop(self):
        while not self._stop_event.is_set():
            interval_min = self.config.get("auto_update_interval", 0)
            if interval_min <= 0:
                self._auto_update_trigger.wait(3600)
                self._auto_update_trigger.clear()
                continue
            interval_sec = interval_min * 60
            self._auto_update_trigger.wait(interval_sec)
            self._auto_update_trigger.clear()
            if self._stop_event.is_set():
                break
            current_interval = self.config.get("auto_update_interval", 0)
            if current_interval <= 0:
                continue
            self.fetch_nodes()

    def _switch_to_next_available(self):
        if self._available_nodes:
            next_node = self._available_nodes.pop(0)
            self.log(f"切换到节点: {next_node['hostname']}")
            self.connect_node(next_node)
        else:
            self.log("没有预先检测的可用节点，尝试从当前列表中选择...")
            nodes = self.filter_nodes(self.config["region"])
            for node in nodes:
                if self._stop_event.is_set():
                    break
                # 跳过已尝试失败的节点
                if node["ip"] in self._failed_ips:
                    continue
                if self.status["connected"] and node["ip"] == self.status["node_info"].get("ip"):
                    continue
                # 记录当前尝试的 IP
                self._failed_ips.add(node["ip"])
                self.log(f"尝试节点: {node['hostname']} ({node['ip']})")
                if self.test_node(node):
                    success = self.connect_node(node)
                    if success:
                        return
            self.log("所有节点均不可用，等待下次检测")

    def start(self):
        self._stop_event.clear()
        self._auto_update_trigger.clear()
        self._failed_ips.clear()
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
        self._auto_update_thread = threading.Thread(target=self._auto_update_loop, daemon=True)
        self._auto_update_thread.start()

    def stop(self):
        self._stop_event.set()
        self._auto_update_trigger.set()
        self.disconnect()
