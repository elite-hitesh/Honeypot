import json
from collections import defaultdict
from datetime import datetime
from honeypot import config


def load_attempts(path=None):
    path = path or config.CREDS_FILE
    attempts = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    record["when"] = datetime.fromisoformat(record["time"])
                    record["ip"]
                    record["username"]
                except (ValueError, KeyError, TypeError):
                    continue
                attempts.append(record)
    except FileNotFoundError:
        pass
    return attempts


def group_by_ip(attempts):
    grouped = defaultdict(list)
    for attempt in attempts:
        grouped[attempt["ip"]].append(attempt)
    return grouped