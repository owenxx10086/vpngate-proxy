import json
import os
import secrets

CONFIG_PATH = "/data/config.json"

DEFAULT_CONFIG = {
    "web_password": "admin",
    "api_url": "",
    "socks_port": 1080,
    "web_port": 8080,
    "vpn_user": "",
    "vpn_pass": "",
    "region": "all",
    "node_limit": 200,
    "check_limit": 20,
    "secret_key": "",
    "auto_update_interval": 0,
    "health_fail_threshold": 3,
    "health_check_interval": 10,
    "log_retention_days": 3,
    "health_check_urls": "",
    "latency_check_target": ""
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = DEFAULT_CONFIG.copy()
        cfg["secret_key"] = secrets.token_hex(24)
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    if not cfg.get("secret_key"):
        cfg["secret_key"] = secrets.token_hex(24)
        save_config(cfg)
    return cfg

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
