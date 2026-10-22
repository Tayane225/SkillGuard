from __future__ import annotations

import json
from typing import Any

from .models import ScanReport, Severity

SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _finding_location(finding: Any) -> str:
    if finding.line:
        return f"{finding.file}:{finding.line}"
    return finding.file


def render_terminal(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("SkillGuard security report")
    lines.append("=" * 26)
    lines.append(f"Target: {report.target_name} ({report.target_type})")
    lines.append(f"Input:  {report.target_input}")
    if report.target_revision:
        lines.append(f"Commit: {report.target_revision}")
    lines.append(
        f"Score:  {report.risk_score}/100 {report.severity.value} - {report.recommendation}"
    )
    lines.append(
        f"Files:  {report.files_analyzed} analyzed, {report.files_skipped} skipped, "
        f"{report.files_total} total"
    )
    lines.append(f"Coverage: {report.coverage}")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
    else:
        lines.append(f"Findings ({report.findings_total}):")
        for finding in report.findings:
            lines.append(
                f"[{finding.severity.value}] {finding.rule_id} {finding.title} "
                f"({_finding_location(finding)})"
            )
            if finding.evidence:
                lines.append(f"  Evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"  Fix: {finding.remediation}")
        if report.findings_total > len(report.findings):
            lines.append(
                f"  ... {report.findings_total - len(report.findings)} more findings not shown"
            )
    if report.top_actions:
        lines.append("")
        lines.append("Top actions:")
        for action in report.top_actions:
            lines.append(f"- {action}")
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in report.warnings:
            lines.append(f"- {warning}")
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append(f"# SkillGuard report: {report.target_name}")
    lines.append("")
    lines.append(f"**Decision:** `{report.recommendation}`")
    lines.append("")
    lines.append(f"- Risk score: **{report.risk_score}/100** ({report.severity.value})")
    lines.append(f"- Safe to install: **{'yes' if report.safe_to_install else 'no'}**")
    lines.append(f"- Coverage: `{report.coverage}`")
    lines.append(f"- Files analyzed: {report.files_analyzed} of {report.files_total}")
    if report.target_revision:
        lines.append(f"- Commit: `{report.target_revision}`")
    lines.append("")
    if report.findings:
        lines.append("| Severity | Rule | Location | Finding |")
        lines.append("| --- | --- | --- | --- |")
        for finding in report.findings:
            location = _finding_location(finding).replace("|", "\\|")
            title = finding.title.replace("|", "\\|")
            lines.append(
                f"| {finding.severity.value} | `{finding.rule_id}` | `{location}` | {title} |"
            )
    else:
        lines.append("No findings.")
    if report.top_actions:
        lines.append("")
        lines.append("## Recommended actions")
        for action in report.top_actions:
            lines.append(f"- {action}")
    if report.warnings:
        lines.append("")
        lines.append("## Warnings")
        for warning in report.warnings:
            lines.append(f"- {warning}")
    return "\n".join(lines)


def render_sarif(report: ScanReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    for finding in report.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation or finding.message},
                "properties": {"category": finding.category, "severity": finding.severity.value},
            },
        )
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": level_map[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file.replace("\\", "/")},
                        "region": {
                            "startLine": finding.line or 1,
                            "startColumn": finding.column or 1,
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "evidence": finding.evidence,
            },
        }
        results.append(result)
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": report.version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_report(report: ScanReport, output_format: str = "terminal") -> str:
    normalized = output_format.lower()
    if normalized == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if normalized in {"md", "markdown"}:
        return render_markdown(report)
    if normalized == "sarif":
        return render_sarif(report)
    if normalized == "terminal":
        return render_terminal(report)
    raise ValueError(f"Unsupported output format: {output_format}")
