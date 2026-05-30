import json
import os

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "web_password": "admin",
    "api_url": "https://http-api.kongbai5202019-09b.workers.dev",
    "socks_port": 1080,
    "web_port": 8080,
    "vpn_user": "vpn",
    "vpn_pass": "vpn",
    "region": "all",
    "node_limit": 200,
    "check_limit": 20
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
