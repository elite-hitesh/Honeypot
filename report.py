from collections import Counter
from honeypot import scoring


def main():
    attempts = scoring.load_attempts()
    if not attempts:
        print("No login attempts recorded yet.")
        return

    rows = []
    for ip, items in scoring.group_by_ip(attempts).items():
        score, reasons = scoring.score_ip(items)
        rows.append((score, ip, reasons))
    rows.sort(reverse=True)

    print(f"{'IP':<18}{'SCORE':>6}  {'LEVEL':<7} WHY")
    for score, ip, reasons in rows:
        print(f"{ip:<18}{score:>6}  {scoring.level(score):<7} {', '.join(reasons)}")

    print("\nTop usernames:")
    for name, n in Counter(a["username"] for a in attempts).most_common(5):
        print(f"  {n:>4}  {name[:40]!r}")

    print("\nTop passwords:")
    for pw, n in Counter(a.get("password", "") for a in attempts).most_common(5):
        print(f"  {n:>4}  {pw[:40]!r}")


if __name__ == "__main__":
    main()