from honeypot import config
from honeypot.logger import log_event

def read_line(conn):
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(1024)
        if not chunk:
            return None
        data += chunk
        if len(data) > connfig.MAX_INPUT:
            break
        line = data.split(b"\n", 1)[0]
        text = line.decode("utf-8", errors="replace").strip()
        return text[: config.MAX_INPUT]
