from __future__ import annotations

import unittest

from skillguard.models import Finding, Severity
from skillguard.scoring import score_findings


def finding(severity: Severity, file: str = "SKILL.md", rule_id: str = "PI001") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        category="test",
        severity=severity,
        file=file,
        message="test",
        remediation="fix it",
    )


class ScoringTests(unittest.TestCase):
    def test_clean_result_is_safe(self) -> None:
        score = score_findings([])
        self.assertEqual(score.value, 0)
        self.assertEqual(score.recommendation, "SAFE")
        self.assertTrue(score.safe_to_install)

    def test_critical_floor(self) -> None:
        score = score_findings([finding(Severity.CRITICAL)])
        self.assertEqual(score.value, 81)
        self.assertEqual(score.severity, Severity.CRITICAL)
        self.assertEqual(score.recommendation, "DO NOT INSTALL")
        self.assertFalse(score.safe_to_install)

    def test_high_floor(self) -> None:
        score = score_findings([finding(Severity.HIGH)])
        self.assertEqual(score.value, 51)
        self.assertEqual(score.recommendation, "DO NOT INSTALL")

    def test_medium_caution(self) -> None:
        score = score_findings([finding(Severity.MEDIUM)])
        self.assertEqual(score.value, 21)
        self.assertEqual(score.recommendation, "CAUTION")

    def test_low_is_safe(self) -> None:
        score = score_findings([finding(Severity.LOW)])
        self.assertEqual(score.value, 5)
        self.assertEqual(score.recommendation, "SAFE")

    def test_partial_coverage_is_never_safe(self) -> None:
        score = score_findings([], coverage="partial")
        self.assertEqual(score.recommendation, "CAUTION")
        self.assertFalse(score.safe_to_install)

    def test_executable_multiplier(self) -> None:
        score = score_findings(
            [finding(Severity.LOW, file="run.py")],
            executable_files={"run.py"},
        )
        self.assertEqual(score.value, 7)

    def test_top_actions_are_deduplicated(self) -> None:
        score = score_findings(
            [
                finding(Severity.HIGH, rule_id="A"),
                finding(Severity.HIGH, rule_id="B"),
            ]
        )
        self.assertEqual(score.top_actions, ["fix it"])


if __name__ == "__main__":
    unittest.main()
