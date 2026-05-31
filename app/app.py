import eventlet
eventlet.monkey_patch()

import os
import time
import threading
import logging
import secrets
from logging.handlers import TimedRotatingFileHandler

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit

from config import load_config, save_config
from vpn_manager import VpnManager

# ---------- 日志持久化配置 ----------
LOG_DIR = "/data/logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "vpn-proxy.log")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

# 每天午夜轮转一次，保留 3 个文件（3 天）
file_handler = TimedRotatingFileHandler(
    LOG_FILE,
    when="midnight",
    interval=1,
    backupCount=3,
    encoding="utf-8"
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(file_handler)

# 控制台输出（便于 docker logs 查看）
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(console_handler)
# ---------------------------------------

app = Flask(__name__)
app.config['SESSION_COOKIE_NAME'] = 'vpngate_proxy_session'

cfg = load_config()
app.secret_key = cfg.get("secret_key") or secrets.token_hex(24)

socketio = SocketIO(app, async_mode="eventlet")

manager = VpnManager()

def push_log(msg):
    socketio.emit("log", {"message": msg})

manager.set_log_callback(push_log)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "未登录"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == load_config()["web_password"]:
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/api/status")
@login_required
def status():
    return jsonify(manager.status)

@app.route("/api/nodes")
@login_required
def nodes():
    region = request.args.get("region", "all")
    try:
        nodes = manager.filter_nodes(region)
        limit = int(manager.config.get("node_limit", 200))
        return jsonify(nodes[:limit])
    except Exception as e:
        manager.log(f"API /api/nodes 异常: {str(e)}")
        return jsonify({"error": f"服务器内部错误: {str(e)}"}), 500

@app.route("/api/connect", methods=["POST"])
@login_required
def connect():
    data = request.json
    ip = data.get("ip")
    for node in manager.nodes:
        if node["ip"] == ip:
            success = manager.connect_node(node)
            return jsonify({"success": success})
    return jsonify({"success": False, "error": "节点未找到"})

@app.route("/api/disconnect", methods=["POST"])
@login_required
def disconnect():
    manager.disconnect()
    return jsonify({"success": True})

@app.route("/api/config", methods=["GET", "POST"])
@login_required
def handle_config():
    if request.method == "GET":
        return jsonify(load_config())
    else:
        new_cfg = request.json
        manager.set_config(new_cfg)
        restart_needed = False
        current = load_config()
        if new_cfg.get("socks_port") != current.get("socks_port") or \
           new_cfg.get("web_port") != current.get("web_port"):
            restart_needed = True
        return jsonify({"success": True, "restart_needed": restart_needed})

@app.route("/api/restart", methods=["POST"])
@login_required
def restart():
    try:
        manager.stop()
        time.sleep(1)
        new_cfg = load_config()
        manager.set_config(new_cfg)
        threading.Thread(target=manager.start, daemon=True).start()
        return jsonify({"success": True, "message": "正在重启..."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/auto_connect", methods=["POST"])
@login_required
def auto_connect():
    try:
        region = manager.config.get("region", "all")
        nodes = manager.filter_nodes(region)
        if not nodes:
            return jsonify({"success": False, "error": "当前地区没有可用节点"})
        success = manager.connect_node(nodes[0])
        if success:
            return jsonify({"success": True, "node": nodes[0]["hostname"]})
        else:
            return jsonify({"success": False, "error": "连接失败"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/system")
@login_required
def system_info():
    import subprocess
    info = {}
    try:
        ver = subprocess.check_output(["openvpn", "--version"], stderr=subprocess.STDOUT, text=True)
        info["openvpn"] = ver.splitlines()[0].strip()
    except Exception:
        info["openvpn"] = "未知"
    try:
        ver = subprocess.check_output(["python", "--version"], stderr=subprocess.STDOUT, text=True)
        info["python"] = ver.strip()
    except Exception:
        info["python"] = "未知"
    try:
        ver = subprocess.check_output(["ip", "-V"], stderr=subprocess.STDOUT, text=True)
        info["iproute2"] = ver.strip()
    except Exception:
        info["iproute2"] = "未知"
    try:
        ver = subprocess.check_output(["curl", "--version"], stderr=subprocess.STDOUT, text=True)
        info["curl"] = ver.splitlines()[0].strip()
    except Exception:
        info["curl"] = "未知"
    return jsonify(info)

# ---------- 新增：历史日志接口 ----------
@app.route("/api/logs")
@login_required
def get_logs():
    """返回最近的日志内容（最多 1000 行）"""
    try:
        if not os.path.exists(LOG_FILE):
            return jsonify([])
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        # 取最后 1000 行，避免数据量过大
        recent_lines = lines[-1000:]
        return jsonify([line.strip() for line in recent_lines])
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# -----------------------------------------

@socketio.on("connect")
def handle_connect():
    emit("log", {"message": "WebSocket 已连接"})

def run_app():
    port = int(load_config().get("web_port", 8080))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    threading.Thread(target=manager.start, daemon=True).start()
    run_app()
