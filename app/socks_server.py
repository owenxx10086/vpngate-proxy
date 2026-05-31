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
        self.outbound_ip = outbound_ip
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
            # 握手
            data = self._recv_all(client_sock, 256)
            if not data or data[0] != 0x05:
                client_sock.close()
                return
            n_methods = data[1]
            methods = data[2:2+n_methods]
            if 0x00 in methods:
                client_sock.sendall(b"\x05\x00")
            else:
                client_sock.sendall(b"\x05\xff")
                client_sock.close()
                return

            # 接收请求
            data = self._recv_all(client_sock, 4)
            if not data or data[0] != 0x05:
                client_sock.close()
                return
            cmd = data[1]
            if cmd != 0x01:  # 只支持 CONNECT
                self._send_reply(client_sock, 0x07)
                client_sock.close()
                return

            addr_type = data[3]
            if addr_type == 0x01:  # IPv4
                addr_data = self._recv_all(client_sock, 4)
                target_addr = socket.inet_ntoa(addr_data)
            elif addr_type == 0x03:  # 域名
                name_len = self._recv_all(client_sock, 1)[0]
                addr_data = self._recv_all(client_sock, name_len)
                target_addr = addr_data.decode()
            else:
                self._send_reply(client_sock, 0x08)
                client_sock.close()
                return
            port_data = self._recv_all(client_sock, 2)
            target_port = struct.unpack(">H", port_data)[0]

            # 建立到目标的连接，并绑定出站 IP
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            remote.bind((self.outbound_ip, 0))
            remote.connect((target_addr, target_port))
            logger.debug(f"Proxying to {target_addr}:{target_port} via {self.outbound_ip}")

            # 回应成功
            bind_addr = remote.getsockname()
            reply = struct.pack("!BBBBIH", 0x05, 0x00, 0x00, 0x01,
                                struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0],
                                bind_addr[1])
            client_sock.sendall(reply)

            # 双向转发（使用更稳定的 select 方式）
            self._relay(client_sock, remote)
        except Exception as e:
            logger.error(f"SOCKS5 handling error: {e}")
        finally:
            try:
                client_sock.close()
            except:
                pass

    def _send_reply(self, sock, rep):
        """发送错误响应"""
        sock.sendall(struct.pack("!BBBBIH", 0x05, rep, 0x00, 0x01, 0, 0))

    def _recv_all(self, sock, length):
        """接收指定长度的数据"""
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _relay(self, a, b):
        """双向转发数据，任一方向关闭则结束"""
        import select
        sockets = [a, b]
        while True:
            try:
                readable, _, exceptional = select.select(sockets, [], sockets, 10)
            except (select.error, ValueError):
                break
            if exceptional:
                break
            for sock in readable:
                data = sock.recv(4096)
                if not data:
                    # 一方关闭，结束转发
                    return
                other = b if sock is a else a
                try:
                    other.sendall(data)
                except:
                    return
