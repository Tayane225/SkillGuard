from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding
from ..utils import SECRET_PATTERNS, line_number
from .common import create_finding

PLACEHOLDER_RE = re.compile(
    r"(?i)(?:your|example|placeholder|change[_-]?me|dummy|sample|redacted|none|null|"
    r"false|true|xxxx|\*\*\*|\.\.\.|<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+)"
)

ENV_NAME_SUFFIXES = (".example", ".sample", ".template", ".dist")
ENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _looks_placeholder(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    if not stripped:
        return True
    return bool(PLACEHOLDER_RE.search(stripped))


def scan_secrets(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if label == "assigned-secret" and _looks_placeholder(value):
                continue
            line = line_number(text, match.start())
            rule_id = "SEC002" if label == "private-key" else "SEC001"
            key = (rule_id, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                create_finding(
                    rule_id,
                    path,
                    message=f"Possible {label.replace('-', ' ')} is embedded in the skill.",
                    line=line,
                    column=match.start() - text.rfind("\n", 0, match.start()),
                    evidence_text=value,
                    confidence=0.9,
                )
            )
            if len(findings) >= 12:
                return findings
    return findings


def is_committed_env_file(path: str) -> bool:
    name = Path(path).name.lower()
    if name in {".env", ".env.local", ".env.production", ".env.development", ".env.staging"}:
        return True
    return bool(name.startswith(".env.") and not name.endswith(ENV_NAME_SUFFIXES))


def scan_committed_env(path: str, text: str) -> list[Finding]:
    if not is_committed_env_file(path):
        return []
    real_values = 0
    first_line: int | None = None
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ENV_LINE_RE.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        if _looks_placeholder(value):
            continue
        real_values += 1
        if first_line is None:
            first_line = index
    if not real_values:
        return []
    return [
        create_finding(
            "SEC003",
            path,
            message=f"Environment file contains {real_values} non-placeholder value(s).",
            line=first_line,
            evidence_text="Environment values are present but intentionally not reproduced.",
            confidence=0.86,
        )
    ]
