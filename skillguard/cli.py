from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import SEVERITY_ORDER, ScanError, ScanOptions, Severity
from .reporting import render_report
from .rules.definitions import RULES
from .scanner import scan


def _gate_failed(report, fail_on: str) -> bool:
    if fail_on.lower() == "none":
        return False
    threshold = Severity(fail_on.upper())
    return any(
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold]
        for finding in report.findings
    )


def _scan_command(args: argparse.Namespace) -> int:
    options = ScanOptions(
        online=args.online,
        timeout=args.timeout,
        max_files=args.max_files,
        allow_private_targets=args.allow_private_targets,
    )
    try:
        report = scan(args.target, options)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 2

    rendered = render_report(report, args.format)
    if args.output:
        output = Path(args.output)
        try:
            output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 2
        print(str(output), file=sys.stderr)
    else:
        print(rendered)

    return 1 if _gate_failed(report, args.fail_on) else 0


def _rules_command(args: argparse.Namespace) -> int:
    rules = list(RULES.values())
    if args.category:
        category = args.category.lower()
        rules = [rule for rule in rules if rule.category.lower() == category]
    if args.format == "json":
        payload = [
            {
                "id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "engine": rule.engine,
                "description": rule.description,
                "remediation": rule.remediation,
            }
            for rule in rules
        ]
        print(json.dumps(payload, indent=2))
        return 0
    for rule in rules:
        print(f"{rule.id:8} {rule.severity:8} {rule.category:20} {rule.title}")
    return 0


def _mcp_command(args: argparse.Namespace) -> int:
    from .mcp_server import run_stdio

    return run_stdio()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skillguard",
        description="Security auditor for AI agent skills and instruction bundles.",
    )
    parser.add_argument("--version", action="version", version=f"skillguard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a skill before installation.")
    scan_parser.add_argument("target", help="Local path, HTTPS URL, ZIP, or Git repository.")
    scan_parser.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "sarif"),
        default="terminal",
        help="Report format (default: terminal).",
    )
    scan_parser.add_argument("-o", "--output", help="Write the report to a file.")
    scan_parser.add_argument("--online", action="store_true", help="Enable OSV vulnerability lookup.")
    scan_parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "none"),
        default="high",
        help="Exit 1 when a finding at or above this severity exists (default: high).",
    )
    scan_parser.add_argument("--timeout", type=int, default=120, help="Network timeout in seconds.")
    scan_parser.add_argument("--max-files", type=int, default=2000, help="Maximum files to inspect.")
    scan_parser.add_argument(
        "--allow-private-targets",
        action="store_true",
        help="Allow private, loopback, or link-local network targets.",
    )
    scan_parser.set_defaults(func=_scan_command)

    rules_parser = subparsers.add_parser("rules", help="List detection rules.")
    rules_parser.add_argument("--format", choices=("text", "json"), default="text")
    rules_parser.add_argument("--category", help="Filter by rule category.")
    rules_parser.set_defaults(func=_rules_command)

    mcp_parser = subparsers.add_parser("mcp", help="Run the MCP server over stdio.")
    mcp_parser.set_defaults(func=_mcp_command)

    version_parser = subparsers.add_parser("version", help="Print the version.")
    version_parser.set_defaults(func=lambda args: (print(__version__) or 0))

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
    return int(args.func(args))
