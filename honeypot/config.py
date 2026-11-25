HOST = "127.0.0.1"
PORT = 2222

BANNER = b"Ubuntu 22.04.3 LTS\r\n"
LOGIN_PROMPT = b"login: "
PASSWORD_PROMPT = b"Password: "
DENIED_MESSAGE = b"Login incorrect\r\n"
LOCKOUT_MESSAGE = b"Too many failed attempts\r\n"

MAX_ATTEMPTS = 3
TIMEOUT = 30
MAX_INPUT = 256

LOG_FILE = "logs/honeypot.log"
CREDS_FILE = "logs/credentials.jsonl"

COMMON_USERNAMES = {
    "root", "admin", "administrator", "user", "test",
    "guest", "ubuntu", "oracle", "postgres", "pi",
}
BURST_ATTEMPTS = 5
BURST_WINDOW = 60
SCORE_MEDIUM = 10
SCORE_HIGH = 25