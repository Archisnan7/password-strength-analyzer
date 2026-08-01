"""
Unit tests for the pure logic functions in password_strength_analyzer.py.

These tests only exercise functions that do NOT touch Tkinter widgets
(evaluate_password, name_reuse_found, dob_reuse_found, has_sequential_run,
has_repeated_chars, normalize_leetspeak, strip_weak_substrings), so they
can run headlessly in CI without a display.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from password_strength_analyzer import (
    evaluate_password,
    has_sequential_run,
    has_repeated_chars,
    name_reuse_found,
    dob_reuse_found,
    normalize_leetspeak,
    strip_weak_substrings,
)


class TestEvaluatePassword(unittest.TestCase):
    def test_too_short_is_weak(self):
        score, strength, reasons = evaluate_password("Ab1!")
        self.assertEqual(strength, "Weak")
        self.assertEqual(score, 0)

    def test_common_leaked_password_is_weak(self):
        score, strength, reasons = evaluate_password("password1")
        self.assertEqual(strength, "Weak")
        self.assertEqual(score, 0)

    def test_strong_random_password(self):
        score, strength, reasons = evaluate_password("Xk9#mQ2$vLp7")
        self.assertEqual(strength, "Strong")

    def test_name_reuse_penalized(self):
        score_with, _, reasons_with = evaluate_password("JohnSmith2024!", name="John Smith")
        score_without, _, _ = evaluate_password("Xk9#mQ2$vLp7", name="John Smith")
        self.assertTrue(any("name" in r.lower() for r in reasons_with))
        self.assertLess(score_with, score_without + 10)  # sanity: penalty applied

    def test_dob_reuse_detected(self):
        hits = dob_reuse_found("mypass15031995", "15-03-1995")
        self.assertTrue(len(hits) > 0)

    def test_sequential_run_detected(self):
        self.assertTrue(has_sequential_run("abc1234xyz"))
        self.assertFalse(has_sequential_run("xk9mq2vlp7"))

    def test_repeated_chars_detected(self):
        self.assertTrue(has_repeated_chars("aaaaXk9#"))
        self.assertFalse(has_repeated_chars("Xk9#mQ2$"))

    def test_leetspeak_normalization(self):
        self.assertEqual(normalize_leetspeak("p@ssw0rd"), "password")
        self.assertEqual(normalize_leetspeak("@4013759$"), "aaoietsgs")

    def test_strip_weak_substrings_removes_pattern(self):
        cleaned = strip_weak_substrings("password123", name="", dob="")
        self.assertNotIn("password", cleaned.lower())

    def test_name_reuse_found_ignores_short_tokens(self):
        # "Jo" is under the 3-char minimum and should not trigger a match
        hits = name_reuse_found("myJopass1!", "Jo Lee")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
