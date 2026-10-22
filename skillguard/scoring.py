from __future__ import annotations

from dataclasses import dataclass

from .models import SEVERITY_ORDER, Finding, Severity

WEIGHTS = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

FLOORS = {
    Severity.CRITICAL: 81,
    Severity.HIGH: 51,
    Severity.MEDIUM: 21,
}

RECOMMENDATION_DO_NOT_INSTALL = "DO NOT INSTALL"
RECOMMENDATION_CAUTION = "CAUTION"
RECOMMENDATION_SAFE = "SAFE"


@dataclass
class Score:
    value: int
    severity: Severity
    recommendation: str
    safe_to_install: bool
    top_actions: list[str]


def _severity_for_score(value: int) -> Severity:
    if value >= 81:
        return Severity.CRITICAL
    if value >= 51:
        return Severity.HIGH
    if value >= 21:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return Severity.INFO


def _recommendation(findings: list[Finding], severity: Severity, coverage: str) -> str:
    if any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in findings):
        return RECOMMENDATION_DO_NOT_INSTALL
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return RECOMMENDATION_DO_NOT_INSTALL
    if any(finding.severity == Severity.MEDIUM for finding in findings):
        return RECOMMENDATION_CAUTION
    if coverage != "full":
        return RECOMMENDATION_CAUTION
    return RECOMMENDATION_SAFE


def _top_actions(findings: list[Finding]) -> list[str]:
    actions: list[str] = []
    seen: set[str] = set()
    for finding in sorted(findings, key=lambda item: item.sort_key()):
        action = finding.remediation or finding.message
        if not action or action in seen:
            continue
        seen.add(action)
        actions.append(action)
        if len(actions) >= 5:
            break
    return actions


def score_findings(
    findings: list[Finding],
    coverage: str = "full",
    executable_files: set[str] | None = None,
) -> Score:
    executable_files = executable_files or set()
    total = 0.0
    maximum = Severity.INFO
    for finding in findings:
        weight = WEIGHTS[finding.severity]
        if finding.file in executable_files:
            weight *= 1.3
        total += weight
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[maximum]:
            maximum = finding.severity

    floor = FLOORS.get(maximum, 0)
    value = min(100, max(0, int(max(total, floor) + 0.5)))
    severity = _severity_for_score(value)
    if SEVERITY_ORDER[maximum] > SEVERITY_ORDER[severity]:
        severity = maximum
    recommendation = _recommendation(findings, severity, coverage)
    safe = recommendation == RECOMMENDATION_SAFE and coverage == "full"
    return Score(
        value=value,
        severity=severity,
        recommendation=recommendation,
        safe_to_install=safe,
        top_actions=_top_actions(findings),
    )
