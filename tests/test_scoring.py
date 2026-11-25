import unittest
from datetime import datetime, timedelta
from honeypot import scoring


def attempt(username, seconds, ip="9.9.9.9"):
    start = datetime(2026, 1, 1, 0, 0, 0)
    return {
        "ip": ip,
        "username": username,
        "password": "x",
        "when": start + timedelta(seconds=seconds),
    }


class TestBurst(unittest.TestCase):
    def test_fast_attempts_are_a_burst(self):
        times = [attempt("a", s)["when"] for s in range(5)]
        self.assertTrue(scoring.has_burst(times))

    def test_slow_attempts_are_not_a_burst(self):
        times = [attempt("a", s * 100)["when"] for s in range(5)]
        self.assertFalse(scoring.has_burst(times))

    def test_too_few_attempts_are_not_a_burst(self):
        times = [attempt("a", s)["when"] for s in range(3)]
        self.assertFalse(scoring.has_burst(times))


class TestScore(unittest.TestCase):
    def test_common_usernames_score_higher(self):
        common = [attempt("root", s * 100) for s in range(3)]
        rare = [attempt("zzzz", s * 100) for s in range(3)]
        self.assertGreater(scoring.score_ip(common)[0], scoring.score_ip(rare)[0])

    def test_burst_scores_higher_than_slow(self):
        fast = [attempt("zzzz", s) for s in range(6)]
        slow = [attempt("zzzz", s * 100) for s in range(6)]
        self.assertGreater(scoring.score_ip(fast)[0], scoring.score_ip(slow)[0])

    def test_levels(self):
        self.assertEqual(scoring.level(0), "low")
        self.assertEqual(scoring.level(10), "medium")
        self.assertEqual(scoring.level(25), "high")


if __name__ == "__main__":
    unittest.main()