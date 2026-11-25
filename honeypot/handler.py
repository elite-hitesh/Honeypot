import socket
from honeypot import config
from honeypot.logger import log_event, log_credentials


def read_line(conn):
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            return None
        data += chunk
        if len(data) > config.MAX_INPUT:
            break
    line = data.split(b"\n", 1)[0]
    text = line.decode("utf-8", errors="replace").strip()
    return text[: config.MAX_INPUT]


def handle_client(conn, addr):
    ip, port = addr
    log_event(ip, port, "connected")
    conn.settimeout(config.TIMEOUT)
    try:
        conn.sendall(config.BANNER)
        for attempt in range(1, config.MAX_ATTEMPTS + 1):
            conn.sendall(config.LOGIN_PROMPT)
            username = read_line(conn)
            if username is None:
                break

            conn.sendall(config.PASSWORD_PROMPT)
            password = read_line(conn)
            if password is None:
                break

            log_credentials(ip, port, username, password)
            log_event(ip, port, f"login attempt {attempt}: user={username!r}")
            conn.sendall(config.DENIED_MESSAGE)
        else:
            conn.sendall(config.LOCKOUT_MESSAGE)
    except socket.timeout:
        log_event(ip, port, "timed out")
    except OSError as e:
        log_event(ip, port, f"connection error: {e}")
    finally:
        conn.close()
        log_event(ip, port, "disconnected")