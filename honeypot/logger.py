import json
import os
import threading 
from datetime import datetime
from honeypot import config

_log_lock = threading.Lock()

def log_event(ip, port, message):
    os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {ip}:{port} | {message}\n"
    with _log_lock:
        with open(config.LOG_FILE, "a") as f:
            f.write(line)

def log_credentials(ip, port, username, password):
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "ip": ip,
        "port": port,
        "username": username,
        "password": password,
    }
    os.makedirs(os.path.dirname(config.CREDS_FILE), exist_ok=True)
    with _log_lock:
        with open(config.CREDS_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")