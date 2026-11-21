import socket
from honeypot import config
from honeypot.handler import handle_client


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.HOST, config.PORT))
    server.listen(5)
    print(f"[*] Listening on {config.HOST}:{config.PORT}")

    try:
        while True:
            conn, addr = server.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            handle_client(conn, addr)
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        server.close()