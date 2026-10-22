from __future__ import annotations

from ..models import Finding, Severity
from ..rules.definitions import get_rule
from ..utils import evidence


def create_finding(
    rule_id: str,
    file: str,
    message: str | None = None,
    line: int | None = None,
    column: int | None = None,
    evidence_text: str = "",
    confidence: float | None = None,
) -> Finding:
    meta = get_rule(rule_id)
    return Finding(
        rule_id=meta.id,
        title=meta.title,
        category=meta.category,
        severity=Severity(meta.severity),
        file=file,
        line=line,
        column=column,
        message=message or meta.description,
        evidence=evidence(evidence_text) if evidence_text else "",
        confidence=confidence if confidence is not None else 0.8,
        remediation=meta.remediation,
    )


def line_text(text: str, start: int, end: int | None = None, limit: int = 400) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    if end is None:
        line_end = text.find("\n", start)
    else:
        line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    value = text[line_start:line_end]
    return value[:limit]
