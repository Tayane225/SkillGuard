from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path

from . import __version__
from .analyzers import (
    analyze_code_text,
    analyze_content,
    analyze_manifest,
    analyze_python,
    lookup_osv,
    scan_secrets,
)
from .analyzers.common import create_finding
from .analyzers.secrets import scan_committed_env
from .ingest import prepare_target
from .models import Component, Dependency, Finding, ScanOptions, ScanReport
from .scoring import score_findings
from .utils import (
    AGENT_CONFIG_PATHS,
    ARCHIVE_SUFFIXES,
    CODE_SUFFIXES,
    PYTHON_SUFFIXES,
    SKIP_DIRS,
    decode_text,
    file_kind,
    is_executable_path,
    is_probably_text,
    rel_posix,
    utc_now_iso,
)

BINARY_EXECUTABLE_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".scr", ".jar", ".msi",
}
DOCUMENT_ASSET_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".mp3", ".mp4",
    ".wav", ".webm", ".mov",
}
MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
    "package.json", "pyproject.toml", "go.mod",
}
ENV_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
}


def _is_binary_executable(path: Path, suffix: str, data: bytes | None) -> bool:
    if suffix in BINARY_EXECUTABLE_SUFFIXES:
        return True
    if not data:
        return False
    return data.startswith((b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"))


def _is_instruction(rel: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if name in {"skill.md", "agents.md", "claude.md"}:
        return True
    if normalized.startswith(".claude/") or "/.claude/" in normalized:
        return True
    return normalized.startswith(".cursor/rules/") or "/.cursor/rules/" in normalized


def _is_manifest(rel: str) -> bool:
    name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in MANIFEST_NAMES or name.startswith("requirements")


def _skill_name(text: str) -> str | None:
    head = text[:5000]
    match = re.search(r"(?m)^name\s*:\s*[\"']?([^\"'\n]{1,120})[\"']?\s*$", head)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _walk_files(root: Path, max_files: int) -> tuple[list[tuple[Path, str]], list[Finding], bool]:
    files: list[tuple[Path, str]] = []
    findings: list[Finding] = []
    truncated = False
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        kept: list[str] = []
        for dirname in dirnames:
            full = base / dirname
            rel = rel_posix(full, root)
            if full.is_symlink():
                findings.append(
                    create_finding(
                        "FS001",
                        rel,
                        message="Symbolic link directory is present in the skill bundle.",
                        evidence_text=rel,
                        confidence=0.9,
                    )
                )
                try:
                    resolved = full.resolve()
                    if root.resolve() not in resolved.parents and resolved != root.resolve():
                        findings.append(
                            create_finding(
                                "FS002",
                                rel,
                                message="Symbolic link points outside the skill root.",
                                evidence_text=str(resolved),
                                confidence=0.95,
                            )
                        )
                except OSError:
                    pass
                continue
            if dirname in SKIP_DIRS:
                continue
            kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            if len(files) >= max_files:
                truncated = True
                break
            full = base / filename
            rel = rel_posix(full, root)
            files.append((full, rel))
        if truncated:
            break
    return files, findings, truncated


def _dedupe(findings: list[Finding]) -> list[Finding]:
    best: dict[tuple[str, str, int | None], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        current = best.get(key)
        if current is None or finding.confidence > current.confidence:
            best[key] = finding
    return sorted(best.values(), key=lambda item: item.sort_key())


def scan(target: str, options: ScanOptions | None = None) -> ScanReport:
    options = options or ScanOptions()
    started = time.monotonic()
    with prepare_target(target, options) as prepared:
        root = prepared.root
        findings: list[Finding] = []
        warnings: list[str] = list(prepared.warnings)
        coverage_issues: list[str] = []
        components: list[Component] = []
        dependencies: list[Dependency] = []
        executable_files: set[str] = set()
        parse_warnings: list[str] = []
        files, symlink_findings, truncated = _walk_files(root, options.max_files)
        findings.extend(symlink_findings)
        if truncated:
            warnings.append(f"File count exceeded the {options.max_files} file limit.")
            coverage_issues.append("file limit reached")

        skill_present = any(rel.replace("\\", "/").rsplit("/", 1)[-1].lower() == "skill.md" for _, rel in files)
        skill_text: str | None = None
        analyzed = 0
        skipped = 0
        total_bytes = 0

        for full, rel in files:
            suffix = full.suffix.lower()
            name = full.name.lower()
            if full.is_symlink():
                findings.append(
                    create_finding(
                        "FS001",
                        rel,
                        message="Symbolic link is present in the skill bundle.",
                        evidence_text=rel,
                        confidence=0.9,
                    )
                )
                try:
                    resolved = full.resolve()
                    if root.resolve() not in resolved.parents and resolved != root.resolve():
                        findings.append(
                            create_finding(
                                "FS002",
                                rel,
                                message="Symbolic link points outside the skill root.",
                                evidence_text=str(resolved),
                                confidence=0.95,
                            )
                        )
                except OSError:
                    pass
                skipped += 1
                components.append(Component(rel, file_kind(rel), 0, 0, False, False))
                continue
            try:
                file_stat = full.stat()
            except OSError as exc:
                warnings.append(f"Could not inspect {rel}: {exc}")
                coverage_issues.append(f"unreadable file {rel}")
                skipped += 1
                continue

            size = file_stat.st_size
            setuid = bool(file_stat.st_mode & (stat.S_ISUID | stat.S_ISGID))
            if setuid:
                findings.append(
                    create_finding(
                        "FS008",
                        rel,
                        message="File has setuid or setgid permissions.",
                        evidence_text=rel,
                        confidence=0.95,
                    )
                )

            if suffix == ".pyc" or suffix == ".pyo":
                findings.append(
                    create_finding(
                        "FS004",
                        rel,
                        message="Compiled Python bytecode is shipped in the skill.",
                        evidence_text=rel,
                        confidence=0.9,
                    )
                )
            if suffix in ARCHIVE_SUFFIXES:
                findings.append(
                    create_finding(
                        "FS005",
                        rel,
                        message="A nested archive is shipped inside the skill.",
                        evidence_text=rel,
                        confidence=0.8,
                    )
                )
            if rel.replace("\\", "/").lower() in AGENT_CONFIG_PATHS or name in {
                ".mcp.json", "opencode.json",
            }:
                findings.append(
                    create_finding(
                        "FS006",
                        rel,
                        message="An agent configuration or instruction file is shipped in the bundle.",
                        evidence_text=rel,
                        confidence=0.78,
                    )
                )

            if size > options.max_file_bytes:
                warnings.append(
                    f"Skipped {rel}: {size} bytes exceeds the per-file limit of {options.max_file_bytes}."
                )
                coverage_issues.append(f"oversized file {rel}")
                skipped += 1
                components.append(Component(rel, file_kind(rel), size, 0, False, False))
                continue

            if total_bytes + size > options.max_total_bytes:
                warnings.append(
                    f"Skipped {rel}: total scan size would exceed {options.max_total_bytes} bytes."
                )
                coverage_issues.append("total size limit reached")
                skipped += 1
                components.append(Component(rel, file_kind(rel), size, 0, False, False))
                continue
            total_bytes += size

            try:
                data = full.read_bytes()
            except OSError as exc:
                warnings.append(f"Could not read {rel}: {exc}")
                coverage_issues.append(f"unreadable file {rel}")
                skipped += 1
                components.append(Component(rel, file_kind(rel), size, 0, False, False))
                continue

            binary_exec = _is_binary_executable(full, suffix, data)
            if binary_exec:
                findings.append(
                    create_finding(
                        "FS003",
                        rel,
                        message="An executable binary is shipped in the skill.",
                        evidence_text=rel,
                        confidence=0.9,
                    )
                )
                executable_files.add(rel)
                components.append(Component(rel, file_kind(rel), size, 0, True, False))
                skipped += 1
                continue

            if not is_probably_text(data):
                if suffix not in DOCUMENT_ASSET_SUFFIXES:
                    warnings.append(f"Skipped non-text file {rel}.")
                    coverage_issues.append(f"non-text file {rel}")
                components.append(Component(rel, file_kind(rel), size, 0, False, False))
                skipped += 1
                continue

            text = decode_text(data)
            lines = text.count("\n") + 1
            executable = is_executable_path(rel, text)
            if executable:
                executable_files.add(rel)
            if name.startswith(".") and executable and not name.startswith(".env"):
                findings.append(
                    create_finding(
                        "FS007",
                        rel,
                        message="A hidden executable script is present.",
                        evidence_text=rel,
                        confidence=0.78,
                    )
                )

            analyzed += 1
            components.append(Component(rel, file_kind(rel), size, lines, executable, True))
            findings.extend(scan_secrets(rel, text))
            if name in ENV_NAMES or name.startswith(".env."):
                findings.extend(scan_committed_env(rel, text))

            if _is_instruction(rel):
                findings.extend(analyze_content(rel, text))
                if name == "skill.md" and skill_text is None:
                    skill_text = text

            kind = file_kind(rel)
            if suffix in PYTHON_SUFFIXES:
                findings.extend(analyze_python(text, rel, executable=executable, warnings=parse_warnings))
            elif kind in {"javascript", "shell"} or suffix in CODE_SUFFIXES:
                findings.extend(analyze_code_text(rel, text))

            if _is_manifest(rel):
                manifest_findings, manifest_deps = analyze_manifest(rel, text, warnings=parse_warnings)
                findings.extend(manifest_findings)
                dependencies.extend(manifest_deps)

        if parse_warnings:
            warnings.extend(parse_warnings)
            coverage_issues.extend(parse_warnings)

        if options.online and dependencies:
            online_findings, online_warnings = lookup_osv(
                dependencies, timeout=min(options.timeout, 20)
            )
            findings.extend(online_findings)
            warnings.extend(online_warnings)
            if online_warnings:
                coverage_issues.extend(online_warnings)

        if not skill_present:
            warnings.append("No SKILL.md was found in the target; this may not be an agent skill bundle.")
            coverage_issues.append("missing SKILL.md")

        deduped = _dedupe(findings)
        score = score_findings(deduped, coverage="full" if not coverage_issues else "partial", executable_files=executable_files)
        findings_total = len(deduped)
        displayed = deduped[: options.max_findings]
        target_name = _skill_name(skill_text or "") or prepared.name or "skill"
        duration_ms = int((time.monotonic() - started) * 1000)

        return ScanReport(
            target_input=prepared.input,
            target_type=prepared.type,
            target_name=target_name,
            target_revision=prepared.revision,
            scanned_at=utc_now_iso(),
            risk_score=score.value,
            severity=score.severity,
            recommendation=score.recommendation,
            safe_to_install=score.safe_to_install,
            coverage="full" if not coverage_issues else "partial",
            scan_mode="online" if options.online else "offline",
            online_checks=options.online,
            duration_ms=duration_ms,
            files_total=len(files),
            files_analyzed=analyzed,
            files_skipped=skipped,
            findings=displayed,
            findings_total=findings_total,
            dependencies=dependencies,
            components=components,
            warnings=warnings,
            top_actions=score.top_actions,
            version=__version__,
        )
