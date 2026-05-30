import eventlet
eventlet.monkey_patch()

import os
import signal
import logging
import threading

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit

from config import load_config, save_config
from vpn_manager import VpnManager

app = Flask(__name__)
app.secret_key = os.urandom(24)
socketio = SocketIO(app, async_mode="eventlet")

# 加载配置
cfg = load_config()
manager = VpnManager()

# 日志回调推送到 Web
def push_log(msg):
    socketio.emit("log", {"message": msg})

manager.set_log_callback(push_log)

# 简单认证装饰器
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
@app.route("/api/nodes")
@login_required
def nodes():
    region = request.args.get("region", "all")
    try:
        nodes = manager.filter_nodes(region)
        return jsonify(nodes[:200])
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
        if new_cfg.get("socks_port") != cfg.get("socks_port") or \
           new_cfg.get("web_port") != cfg.get("web_port"):
            restart_needed = True
        return jsonify({"success": True, "restart_needed": restart_needed})

@socketio.on("connect")
def handle_connect():
    emit("log", {"message": "WebSocket 已连接"})

def run_app():
    port = int(load_config().get("web_port", 8080))
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    import threading
    threading.Thread(target=manager.start, daemon=True).start()
    run_app()
