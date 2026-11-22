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