import unittest

from unicode_guard.scanner import build_clean_text, scan_text


class ScannerTests(unittest.TestCase):
    def test_bidi_override_is_critical(self):
        report = scan_text('print("safe") # \u202e } malicious {')
        self.assertTrue(any(item.rule_id == "BIDI_CONTROL" and item.severity == "CRITICAL" for item in report.findings))
        self.assertFalse(report.passed)

    def test_identifier_collision(self):
        report = scan_text("i = 1\nі = 2\nprint(i)\n")
        self.assertTrue(any(item.rule_id == "IDENTIFIER_COLLISION" for item in report.findings))

    def test_mixed_script_identifier(self):
        report = scan_text("isАdmin = False\n")
        self.assertTrue(any(item.rule_id == "IDENTIFIER_MIXED_SCRIPT" for item in report.findings))

    def test_clean_text_removes_invisible(self):
        self.assertEqual(build_clean_text("ab\u200bcd"), "abcd")


if __name__ == "__main__":
    unittest.main()
