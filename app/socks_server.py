import asyncio
import socket
import struct
import threading
import logging

logger = logging.getLogger("socks_server")

class Socks5Server:
    """极简 SOCKS5 代理，出口流量绑定到指定接口 IP"""
    def __init__(self, bind_host, bind_port, outbound_ip):
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.outbound_ip = outbound_ip  # VPN 接口 IP，用于 bind 出站连接
        self.server_socket = None
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            return
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.bind_host, self.bind_port))
        self.server_socket.listen(5)
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        logger.info(f"SOCKS5 server listening on {self.bind_host}:{self.bind_port}, outbound via {self.outbound_ip}")

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("SOCKS5 server stopped")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True).start()
            except OSError:
                if self.running:
                    logger.exception("Accept error")
                break

    def _handle_client(self, client_sock):
        try:
            # 握手协商（仅支持无认证）
            data = client_sock.recv(256)
            if not data or data[0] != 0x05:
                client_sock.close()
                return
            n_methods = data[1]
            methods = data[2:2+n_methods]
            if 0x00 in methods:
                client_sock.sendall(b"\x05\x00")  # 选择无认证
            else:
                client_sock.sendall(b"\x05\xff")
                client_sock.close()
                return

            # 接收请求
            data = client_sock.recv(4)
            if not data or data[0] != 0x05:
                client_sock.close()
                return
            cmd = data[1]
            if cmd != 0x01:  # 只支持 CONNECT
                client_sock.sendall(b"\x05\x07\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
                client_sock.close()
                return
            addr_type = data[3]
            if addr_type == 0x01:  # IPv4
                addr_data = client_sock.recv(4)
                target_addr = socket.inet_ntoa(addr_data)
            elif addr_type == 0x03:  # 域名
                name_len = ord(client_sock.recv(1))
                target_addr = client_sock.recv(name_len).decode()
            else:
                client_sock.sendall(b"\x05\x08\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00")
                client_sock.close()
                return
            port_data = client_sock.recv(2)
            target_port = struct.unpack(">H", port_data)[0]

            # 建立到目标的连接，并绑定出站 IP
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.bind((self.outbound_ip, 0))   # 绑定 VPN 接口 IP
            remote.connect((target_addr, target_port))
            logger.debug(f"Proxying to {target_addr}:{target_port} via {self.outbound_ip}")

            # 回应成功
            bind_addr = remote.getsockname()
            resp = b"\x05\x00\x00\x01" + socket.inet_aton(bind_addr[0]) + struct.pack(">H", bind_addr[1])
            client_sock.sendall(resp)

            # 双向转发
            self._relay(client_sock, remote)
        except Exception:
            logger.exception("SOCKS5 handling error")
        finally:
            try:
                client_sock.close()
            except:
                pass

    def _relay(self, a, b):
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass
        t1 = threading.Thread(target=forward, args=(a, b), daemon=True)
        t2 = threading.Thread(target=forward, args=(b, a), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
