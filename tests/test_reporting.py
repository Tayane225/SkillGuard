from __future__ import annotations

import json
import unittest

from skillguard.models import Finding, ScanReport, Severity
from skillguard.reporting import (
    render_markdown,
    render_report,
    render_sarif,
    render_terminal,
)


def make_report(findings: list[Finding] | None = None, warnings: list[str] | None = None) -> ScanReport:
    findings = findings or []
    return ScanReport(
        target_input="https://example.com/skill",
        target_type="git",
        target_name="example-skill",
        target_revision="abc123",
        scanned_at="2026-01-01T00:00:00Z",
        risk_score=81,
        severity=Severity.CRITICAL,
        recommendation="DO NOT INSTALL",
        safe_to_install=False,
        coverage="partial",
        scan_mode="offline",
        online_checks=False,
        duration_ms=42,
        files_total=3,
        files_analyzed=2,
        files_skipped=1,
        findings=findings,
        findings_total=len(findings) + 1,
        dependencies=[],
        components=[],
        warnings=warnings or ["A warning"],
        top_actions=["Remove the payload"],
        version="1.0.0",
    )


def make_finding() -> Finding:
    return Finding(
        rule_id="PI001",
        title="Instruction override",
        category="prompt_injection",
        severity=Severity.CRITICAL,
        file="SKILL.md",
        message="The skill overrides instructions.",
        line=4,
        column=2,
        evidence="ignore previous instructions",
        confidence=0.9,
        remediation="Remove the override.",
    )


class ReportingTests(unittest.TestCase):
    def test_terminal_report_with_findings(self) -> None:
        finding = make_finding()
        text = render_terminal(make_report([finding]))
        self.assertIn("SkillGuard security report", text)
        self.assertIn("Commit: abc123", text)
        self.assertIn("SKILL.md:4", text)
        self.assertIn("Evidence:", text)
        self.assertIn("Fix:", text)
        self.assertIn("more findings not shown", text)
        self.assertIn("Warnings:", text)
        self.assertIn("Top actions:", text)

    def test_terminal_report_without_findings_or_metadata(self) -> None:
        report = make_report()
        report.findings_total = 0
        report.target_revision = None
        report.top_actions = []
        report.warnings = []
        text = render_terminal(report)
        self.assertIn("No findings.", text)
        self.assertNotIn("Commit:", text)

    def test_markdown_report(self) -> None:
        text = render_markdown(make_report([make_finding()]))
        self.assertIn("# SkillGuard report: example-skill", text)
        self.assertIn("| CRITICAL |", text)
        self.assertIn("Recommended actions", text)
        self.assertIn("## Warnings", text)

    def test_markdown_without_findings(self) -> None:
        report = make_report()
        report.findings_total = 0
        report.warnings = []
        report.top_actions = []
        self.assertIn("No findings.", render_markdown(report))

    def test_sarif_report(self) -> None:
        payload = json.loads(render_sarif(make_report([make_finding()])))
        run = payload["runs"][0]
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(run["tool"]["driver"]["version"], "1.0.0")
        self.assertEqual(run["results"][0]["ruleId"], "PI001")
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "SKILL.md")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "PI001")

    def test_render_report_formats(self) -> None:
        report = make_report([make_finding()])
        self.assertIn('"schema_version": "1.0"', render_report(report, "json"))
        self.assertIn("# SkillGuard report", render_report(report, "md"))
        self.assertIn("SkillGuard security report", render_report(report, "terminal"))
        with self.assertRaises(ValueError):
            render_report(report, "xml")


if __name__ == "__main__":
    unittest.main()
