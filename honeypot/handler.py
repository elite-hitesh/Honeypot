from honeypot import config
from honeypot.logger import log_event

def handle_client(conn, addr):
    ip, port = addr
    log_event(ip, port, "connected")
    try:
        conn.sendall(config.BANNER)
    except OSError as e:
        log_event(ip, port, f"error sending banner: {e}")
    finally:
        conn.close()
        log_event(ip, port, "disconnected")
