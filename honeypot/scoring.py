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

def has_burst(times):
    times = sorted(times)
    n = config.BURST_ATTEMPTS
    for i in range(len(times) - n + 1):
        gap = (times[i + n - 1] - times[i]).total_seconds()
        if gap <= config.BURST_WINDOW:
            return True
    return False


def score_ip(attempts):
    score = 0
    reasons = []

    count = len(attempts)
    score += min(count, 20)
    reasons.append(f"{count} attempts")

    common = sum(
        1 for a in attempts if a["username"].lower() in config.COMMON_USERNAMES
    )
    if common:
        score += common * 2
        reasons.append(f"{common} common usernames")

    distinct = len({a["username"] for a in attempts})
    if distinct >= 5:
        score += 5
        reasons.append(f"{distinct} different usernames")

    if has_burst([a["when"] for a in attempts]):
        score += 10
        reasons.append("burst")

    return score, reasons


def level(score):
    
    if score >= config.SCORE_HIGH:
        return "high"
    
    if score >= config.SCORE_MEDIUM:
        return "medium"
    
    return "low"