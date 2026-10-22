from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import PurePosixPath

from ..models import Dependency, Finding
from ..utils import levenshtein, line_number, normalize_package_name
from .common import create_finding

try:
    import tomllib
except ImportError:
    tomllib = None


POPULAR_NPM = {
    "express", "react", "lodash", "axios", "chalk", "commander", "debug",
    "dotenv", "mongoose", "next", "node-fetch", "request", "socket.io",
    "typescript", "webpack", "yargs", "zod", "eslint", "prettier", "vite",
    "jest", "mocha", "uuid", "cors", "helmet", "body-parser", "cookie-parser",
}

POPULAR_PYPI = {
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi",
    "pydantic", "click", "rich", "boto3", "botocore", "setuptools", "pip",
    "pytest", "pyyaml", "jinja2", "sqlalchemy", "aiohttp", "httpx", "openai",
    "anthropic", "cryptography", "paramiko", "beautifulsoup4", "scrapy",
    "tensorflow", "torch", "transformers", "pillow", "matplotlib", "scipy",
    "starlette", "uvicorn", "typer", "certifi", "idna", "six",
}

URL_RE = re.compile(r"(?i)^(?:https?://|git\+|git://|github:|gitlab:|bitbucket:|ssh://)")
LOCAL_RE = re.compile(r"(?i)^(?:file:|link:|\.{0,2}/|[a-z]:[\\/])")
EXACT_NPM_RE = re.compile(r"^[v=]?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
REMOTE_SCRIPT_RE = re.compile(
    r"(?i)(?:curl|wget|invoke-webrequest|iwr|https?://|git\+|node\s+-e|python\s+-c|"
    r"powershell|base64\s+-d)"
)
WILDCARD_RE = re.compile(r"^(?:\*|latest|x)$", re.IGNORECASE)


def _add(
    findings: list[Finding],
    seen: set[tuple[str, str, int | None]],
    rule_id: str,
    path: str,
    message: str,
    line: int | None,
    evidence_text: str,
    confidence: float = 0.8,
) -> None:
    key = (rule_id, path, line)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        create_finding(
            rule_id,
            path,
            message=message,
            line=line,
            evidence_text=evidence_text,
            confidence=confidence,
        )
    )


def _line_of(text: str, needle: str) -> int | None:
    index = text.find(needle)
    if index < 0:
        return None
    return line_number(text, index)


def _typosquat(name: str, ecosystem: str) -> str | None:
    normalized = normalize_package_name(name)
    popular = POPULAR_NPM if ecosystem == "npm" else POPULAR_PYPI
    if normalized in popular or len(normalized) < 4:
        return None
    if normalized.startswith(("@", "types/", "babel-", "eslint-", "react-")):
        return None
    for candidate in popular:
        if abs(len(normalized) - len(candidate)) > 1:
            continue
        if normalized == candidate:
            continue
        if levenshtein(normalized, candidate) == 1:
            return candidate
        if len(normalized) == len(candidate):
            for index in range(len(normalized) - 1):
                swapped = (
                    normalized[:index]
                    + normalized[index + 1]
                    + normalized[index]
                    + normalized[index + 2:]
                )
                if swapped == candidate:
                    return candidate
    return None


def _add_typosquat(
    findings: list[Finding],
    seen: set[tuple[str, str, int | None]],
    path: str,
    dep: Dependency,
    text: str,
) -> None:
    target = _typosquat(dep.name, dep.ecosystem)
    if not target:
        return
    dep.notes.append(f"Similar to popular package '{target}'.")
    _add(
        findings,
        seen,
        "DEP006",
        path,
        f"Dependency '{dep.name}' resembles the popular package '{target}'.",
        _line_of(text, dep.name),
        f"{dep.name} -> {target}",
        0.7,
    )


def _python_spec(name: str, spec: str, ecosystem: str, path: str, line: int | None) -> Dependency:
    normalized = spec.strip()
    if ecosystem == "npm":
        pinned = bool(EXACT_NPM_RE.match(normalized))
    else:
        exact = re.search(r"==\s*([0-9]+(?:\.[0-9A-Za-z]+)*)\s*$", normalized)
        pinned = bool(exact) and "*" not in exact.group(1)
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        spec=normalized,
        file=path,
        line=line,
        pinned=pinned,
        url=bool(re.search(r"(?i)(?:^|@\s*)(?:https?://|git\+|git://|github:|gitlab:|bitbucket:|ssh://)", normalized)),
        install_script=False,
    )


def _requirement_name(spec: str) -> str:
    value = spec.strip()
    value = re.split(r"\s*(?:===|==|~=|>=|<=|!=|>|<|;|\[)", value, maxsplit=1)[0]
    value = value.split("@", 1)[0]
    return value.strip()


def _parse_requirements(path: str, text: str, findings: list[Finding], seen: set[tuple[str, str, int | None]]) -> list[Dependency]:
    deps: list[Dependency] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("--index-url", "--extra-index-url", "-i ", "--find-links")):
            _add(findings, seen, "DEP005", path, "A custom Python package source is configured.", index, line, 0.86)
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            continue
        if line.startswith(("-e ", "--editable")):
            _add(findings, seen, "DEP004", path, "An editable or URL dependency is used.", index, line, 0.8)
            continue
        spec = line.split("#", 1)[0].strip()
        if not spec:
            continue
        name = _requirement_name(spec)
        dep = _python_spec(name, spec, "PyPI", path, index)
        deps.append(dep)
        if dep.url:
            _add(findings, seen, "DEP004", path, "A URL or VCS Python dependency is used.", index, spec, 0.86)
        elif not dep.pinned:
            _add(findings, seen, "DEP001", path, "A Python dependency is not pinned to an exact version.", index, spec, 0.72)
        if re.search(r"(?i)(?:^|\s)(?:--trusted-host|--index-url\s+http://)", spec):
            _add(findings, seen, "DEP005", path, "A custom or insecure package source is configured.", index, spec, 0.8)
        _add_typosquat(findings, seen, path, dep, spec)
    return deps


def _parse_package_json(path: str, text: str, findings: list[Finding], seen: set[tuple[str, str, int | None]]) -> list[Dependency]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        _add(findings, seen, "DEP002", path, "package.json could not be parsed, so dependencies were not fully analyzed.", 1, "", 0.6)
        return []
    if not isinstance(data, dict):
        return []

    deps: list[Dependency] = []
    sections = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    for section in sections:
        values = data.get(section)
        if not isinstance(values, dict):
            continue
        for name, raw_spec in values.items():
            spec = str(raw_spec)
            dep = Dependency(
                ecosystem="npm",
                name=name,
                spec=spec,
                file=path,
                line=_line_of(text, name),
                pinned=bool(EXACT_NPM_RE.match(spec)),
                url=bool(URL_RE.match(spec)),
                install_script=False,
            )
            deps.append(dep)
            if dep.url:
                _add(findings, seen, "DEP004", path, f"npm dependency '{name}' uses a URL or VCS specifier.", dep.line, f"{name}: {spec}", 0.86)
            elif LOCAL_RE.match(spec):
                _add(findings, seen, "DEP010", path, f"npm dependency '{name}' points to a local path.", dep.line, f"{name}: {spec}", 0.8)
            elif WILDCARD_RE.match(spec):
                _add(findings, seen, "DEP009", path, f"npm dependency '{name}' uses a wildcard version.", dep.line, f"{name}: {spec}", 0.78)
            elif not dep.pinned:
                _add(findings, seen, "DEP002", path, f"npm dependency '{name}' is not pinned to an exact version.", dep.line, f"{name}: {spec}", 0.72)
            _add_typosquat(findings, seen, path, dep, spec)

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for script_name in ("preinstall", "install", "postinstall"):
            command = scripts.get(script_name)
            if not isinstance(command, str):
                continue
            line = _line_of(text, script_name)
            _add(findings, seen, "DEP003", path, f"npm lifecycle script '{script_name}' runs during installation.", line, command, 0.84)
            if REMOTE_SCRIPT_RE.search(command):
                _add(findings, seen, "DEP012", path, f"npm lifecycle script '{script_name}' downloads or executes remote code.", line, command, 0.9)
            for dep in deps:
                dep.install_script = True

    return deps


def _parse_pyproject(path: str, text: str, findings: list[Finding], seen: set[tuple[str, str, int | None]]) -> list[Dependency]:
    specs: list[str] = []
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
            project = data.get("project", {})
            if isinstance(project, dict):
                for value in project.get("dependencies", []) or []:
                    if isinstance(value, str):
                        specs.append(value)
                for values in (project.get("optional-dependencies", {}) or {}).values():
                    for value in values or []:
                        if isinstance(value, str):
                            specs.append(value)
        except (tomllib.TOMLDecodeError, TypeError):
            _add(findings, seen, "DEP001", path, "pyproject.toml could not be parsed, so dependencies were not fully analyzed.", 1, "", 0.6)
    if not specs:
        for match in re.finditer(r'(?m)^\s*"([^"]+)"\s*,?\s*$', text):
            candidate = match.group(1)
            if re.match(r"^[A-Za-z0-9_.-]+\s*(?:\[[^\]]+\])?\s*(?:[<>=!~].*)?$", candidate):
                specs.append(candidate)

    deps: list[Dependency] = []
    for spec in specs:
        name = _requirement_name(spec)
        if not name:
            continue
        dep = _python_spec(name, spec, "PyPI", path, _line_of(text, spec))
        deps.append(dep)
        if dep.url:
            _add(findings, seen, "DEP004", path, f"Python dependency '{name}' uses a URL or VCS specifier.", dep.line, spec, 0.86)
        elif not dep.pinned:
            _add(findings, seen, "DEP001", path, f"Python dependency '{name}' is not pinned to an exact version.", dep.line, spec, 0.72)
        _add_typosquat(findings, seen, path, dep, spec)
    return deps


def _parse_go_mod(path: str, text: str, findings: list[Finding], seen: set[tuple[str, str, int | None]]) -> list[Dependency]:
    deps: list[Dependency] = []
    in_require = False
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("replace "):
            _add(findings, seen, "DEP011", path, "A Go replace directive redirects a dependency.", index, line, 0.82)
            continue
        fields = line.split()
        if line.startswith("require "):
            fields = line.split()[1:]
        elif not in_require:
            continue
        if len(fields) < 2 or "=>" in fields:
            continue
        name, version = fields[0], fields[1]
        dep = Dependency(
            ecosystem="Go",
            name=name,
            spec=version,
            file=path,
            line=index,
            pinned=bool(re.match(r"^v\d+\.\d+\.\d+", version)),
            url=False,
            install_script=False,
        )
        deps.append(dep)
        if not dep.pinned:
            _add(findings, seen, "DEP002", path, f"Go dependency '{name}' is not pinned to a full version.", index, line, 0.7)
        _add_typosquat(findings, seen, path, dep, line)
    return deps


def analyze_manifest(
    path: str,
    text: str,
    warnings: list[str] | None = None,
) -> tuple[list[Finding], list[Dependency]]:
    if warnings is None:
        warnings = []
    findings: list[Finding] = []
    seen: set[tuple[str, str, int | None]] = set()
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    if name in {"requirements.txt", "requirements-dev.txt", "requirements_dev.txt"} or name.startswith("requirements"):
        deps = _parse_requirements(path, text, findings, seen)
    elif name == "package.json":
        deps = _parse_package_json(path, text, findings, seen)
    elif name == "pyproject.toml":
        deps = _parse_pyproject(path, text, findings, seen)
    elif name == "go.mod":
        deps = _parse_go_mod(path, text, findings, seen)
    else:
        warnings.append(f"Unsupported manifest format: {path}")
        deps = []
    return findings, deps


def _pinned_version(dep: Dependency) -> str | None:
    if not dep.pinned:
        return None
    spec = dep.spec.strip()
    if dep.ecosystem == "PyPI":
        if not spec.startswith("=="):
            return None
        return spec[2:].strip()
    if dep.ecosystem == "npm":
        return spec.lstrip("=v")
    if dep.ecosystem == "Go":
        return spec.lstrip("v")
    return None


def _osv_ecosystem(dep: Dependency) -> str | None:
    if dep.ecosystem == "PyPI":
        return "PyPI"
    if dep.ecosystem == "npm":
        return "npm"
    if dep.ecosystem == "Go":
        return "Go"
    return None


def _vuln_ids(vuln: object) -> list[str]:
    if not isinstance(vuln, dict):
        return []
    identifiers = vuln.get("id")
    ids = [identifiers] if isinstance(identifiers, str) else []
    aliases = vuln.get("aliases", [])
    if isinstance(aliases, list):
        ids.extend(str(alias) for alias in aliases)
    return ids[:5]


def _vuln_severity(vuln: object) -> str:
    if not isinstance(vuln, dict):
        return "HIGH"
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict):
        severity = str(database_specific.get("severity", "")).upper()
        if severity in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
            return severity
    severities = vuln.get("severity")
    if isinstance(severities, list):
        for entry in severities:
            if isinstance(entry, dict) and str(entry.get("score", "")).startswith("CVSS"):
                score = entry.get("score", "")
                match = re.search(r"/AV:./AC:./PR:./UI:./S:./C:./I:./A:.", score)
                if match:
                    return "HIGH"
    return "HIGH"


def lookup_osv(
    dependencies: list[Dependency],
    timeout: int = 10,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    queries = []
    targets: list[Dependency] = []
    for dep in dependencies:
        version = _pinned_version(dep)
        ecosystem = _osv_ecosystem(dep)
        if not version or not ecosystem:
            continue
        queries.append(
            {
                "package": {"name": dep.name, "ecosystem": ecosystem},
                "version": version,
            }
        )
        targets.append(dep)
        if len(queries) >= 100:
            break
    if not queries:
        return findings, warnings

    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "skillguard/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        warnings.append(f"OSV vulnerability lookup failed: {exc}")
        return findings, warnings

    results = data.get("results", []) if isinstance(data, dict) else []
    for dep, result in zip(targets, results):
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        if not vulns:
            continue
        ids: list[str] = []
        high = False
        for vuln in vulns:
            ids.extend(_vuln_ids(vuln))
            if _vuln_severity(vuln) in {"CRITICAL", "HIGH"}:
                high = True
        unique_ids = sorted(set(ids))
        rule_id = "DEP007" if high else "DEP008"
        message = f"Dependency '{dep.name}' has {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}."
        if unique_ids:
            message += f" IDs: {', '.join(unique_ids)}."
        findings.append(
            create_finding(
                rule_id,
                dep.file,
                message=message,
                line=dep.line,
                evidence_text=f"{dep.name} {dep.spec}",
                confidence=0.95,
            )
        )
    return findings, warnings
