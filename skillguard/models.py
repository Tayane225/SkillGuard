from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class ScanError(Exception):
    pass


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: Severity
    file: str
    message: str
    line: int | None = None
    column: int | None = None
    evidence: str = ""
    confidence: float = 0.8
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "remediation": self.remediation,
        }

    def sort_key(self) -> tuple[int, str, int, str]:
        return (
            -SEVERITY_ORDER[self.severity],
            self.file,
            self.line or 0,
            self.rule_id,
        )


@dataclass
class Component:
    path: str
    kind: str
    bytes: int
    lines: int
    executable: bool
    analyzed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "bytes": self.bytes,
            "lines": self.lines,
            "executable": self.executable,
            "analyzed": self.analyzed,
        }


@dataclass
class Dependency:
    ecosystem: str
    name: str
    spec: str
    file: str
    line: int | None = None
    pinned: bool = False
    url: bool = False
    install_script: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "spec": self.spec,
            "file": self.file,
            "line": self.line,
            "pinned": self.pinned,
            "url": self.url,
            "install_script": self.install_script,
            "notes": self.notes,
        }


@dataclass
class ScanOptions:
    online: bool = False
    timeout: int = 120
    max_files: int = 2000
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 104_857_600
    max_members: int = 5000
    max_findings: int = 500
    allow_private_targets: bool = False
    max_download_bytes: int = 26_214_400


@dataclass
class ScanReport:
    target_input: str
    target_type: str
    target_name: str
    target_revision: str | None
    scanned_at: str
    risk_score: int
    severity: Severity
    recommendation: str
    safe_to_install: bool
    coverage: str
    scan_mode: str
    online_checks: bool
    duration_ms: int
    files_total: int
    files_analyzed: int
    files_skipped: int
    findings: list[Finding]
    findings_total: int
    dependencies: list[Dependency]
    components: list[Component]
    warnings: list[str]
    top_actions: list[str]
    version: str

    def to_dict(self) -> dict[str, Any]:
        by_severity = {s.value: 0 for s in Severity}
        by_category: dict[str, int] = {}
        for finding in self.findings:
            by_severity[finding.severity.value] += 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1
        return {
            "schema_version": "1.0",
            "tool": {"name": "SkillGuard", "version": self.version},
            "target": {
                "input": self.target_input,
                "type": self.target_type,
                "name": self.target_name,
                "revision": self.target_revision,
            },
            "scanned_at": self.scanned_at,
            "scan": {
                "mode": self.scan_mode,
                "online_checks": self.online_checks,
                "llm_used": False,
                "duration_ms": self.duration_ms,
                "coverage": self.coverage,
                "files_total": self.files_total,
                "files_analyzed": self.files_analyzed,
                "files_skipped": self.files_skipped,
            },
            "score": {
                "value": self.risk_score,
                "severity": self.severity.value,
                "recommendation": self.recommendation,
                "safe_to_install": self.safe_to_install,
            },
            "summary": {
                "total": self.findings_total,
                "returned": len(self.findings),
                "truncated": self.findings_total > len(self.findings),
                "by_severity": by_severity,
                "by_category": dict(sorted(by_category.items())),
            },
            "findings": [f.to_dict() for f in self.findings],
            "dependencies": [d.to_dict() for d in self.dependencies],
            "components": [c.to_dict() for c in self.components],
            "warnings": self.warnings,
            "top_actions": self.top_actions,
        }
