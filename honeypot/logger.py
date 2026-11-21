import os
from datetime import datetime
from honeypot import config

def log_event(ip, port, message):
    os.makedirs(os.path.dirname(config.LOG_FILE), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} | {ip}:{port} | {message}\n"
    with open(config.LOG_FILE, "a") as f:
        f.write(line)