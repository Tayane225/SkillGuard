from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
    ".idea",
}

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".rst", ".html", ".htm", ".xml",
    ".yaml", ".yml", ".json", ".jsonc", ".toml", ".ini", ".cfg", ".conf",
    ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
    ".bat", ".cmd", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rb", ".pl", ".php", ".lua", ".go", ".rs", ".java", ".kt", ".swift",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".sql", ".dockerfile", ".gitignore",
    ".npmrc", ".pypirc", ".env", ".example", ".sample", ".template",
}

INSTRUCTION_SUFFIXES = {
    ".md", ".markdown", ".txt", ".rst", ".html", ".htm", ".xml",
    ".yaml", ".yml", ".json", ".jsonc", ".toml", ".ini", ".cfg", ".conf",
}

CODE_SUFFIXES = {
    ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
    ".bat", ".cmd", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".rb", ".pl", ".php", ".lua",
}

PYTHON_SUFFIXES = {".py", ".pyw"}
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
SHELL_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd"}

EXECUTABLE_SUFFIXES = {
    ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1",
    ".bat", ".cmd", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".lua", ".jar", ".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".scr",
}

ARCHIVE_SUFFIXES = {
    ".zip", ".jar", ".war", ".whl", ".tar", ".gz", ".tgz", ".bz2",
    ".xz", ".7z", ".rar", ".cab", ".iso", ".img",
}

AGENT_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "opencode.json",
    "opencode.jsonc",
    "claude_desktop_config.json",
    "gemini_settings.json",
}

AGENT_CONFIG_PATHS = {
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/settings.jsonc",
    ".codex/config.toml",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
}


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    )),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-(?:api\d+-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("url-credentials", re.compile(r"(?i)\bhttps?://[^/\s:@]+:[^/\s@]+@[^\s]+")),
    ("assigned-secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']"
    )),
]

SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:"
    r"\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|id_dsa|config|known_hosts)|"
    r"id_rsa|id_ed25519|id_ecdsa|id_dsa|"
    r"\.aws[\\/]credentials|\.aws[\\/]config|"
    r"\.netrc|\.npmrc|\.pypirc|\.docker[\\/]config\.json|"
    r"google[\\/]credentials|gcloud[\\/]credentials|"
    r"login data|cookies\.sqlite|cookies\.binarycookies|"
    r"keychain|credential manager|dpapi|"
    r"/etc/(?:passwd|shadow)|/etc/ssl/private|"
    r"\\sam\b|\\security\b|\\system\b"
    r")"
)

DATA_DROP_HOSTS = {
    "webhook.site",
    "requestbin.net",
    "requestbin.com",
    "pipedream.net",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "pastebin.com",
    "transfer.sh",
    "0x0.st",
    "file.io",
    "tmpfiles.org",
    "gofile.io",
    "anonfiles.com",
}

API_ALLOW_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "api.github.com",
    "github.com",
    "raw.githubusercontent.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "api.npmjs.org",
    ".amazonaws.com",
    ".azure.com",
    ".microsoft.com",
    ".googleapis.com",
)


URL_RE = re.compile(r"https?://[^\s\"'<>\]\[{}|\\^`]+", re.IGNORECASE)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def decode_text(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    control = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return control / len(sample) < 0.05


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def redact(text: str) -> str:
    result = text
    for label, pattern in SECRET_PATTERNS:
        result = pattern.sub(f"[REDACTED:{label}]", result)
    return result


def evidence(text: str, max_len: int = 220) -> str:
    cleaned = redact(collapse(text))
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3].rstrip() + "..."
    return cleaned


def truncate(text: str, max_len: int = 220) -> str:
    cleaned = collapse(text)
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3].rstrip() + "..."
    return cleaned


def is_executable_path(path: str, text: str | None = None) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in EXECUTABLE_SUFFIXES:
        return True
    if text and text.startswith("#!"):
        first = text.splitlines()[0].lower()
        return any(term in first for term in ("python", "bash", "sh", "node", "ruby", "perl", "php", "pwsh", "powershell"))
    return False


def file_kind(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return "python"
    if suffix in JS_SUFFIXES:
        return "javascript"
    if suffix in SHELL_SUFFIXES:
        return "shell"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    if suffix in {".json", ".jsonc"}:
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix in {".toml"}:
        return "toml"
    if suffix in ARCHIVE_SUFFIXES:
        return "archive"
    name = Path(path).name.lower()
    if name == "dockerfile":
        return "dockerfile"
    return "text"


def extract_urls(text: str) -> list[str]:
    found = []
    for match in URL_RE.finditer(text):
        value = match.group(0).rstrip(".,;:!?)]}>'\"")
        if value not in found:
            found.append(value)
    return found


def url_host(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    return (parsed.hostname or "").lower() or None


def is_allowlisted_api_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    return any(host == item or host.endswith(item) for item in API_ALLOW_HOSTS)


def is_data_drop_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in DATA_DROP_HOSTS)


def is_private_host(host: str | None) -> bool:
    if not host:
        return True
    host = host.lower().strip("[]").rstrip(".")
    if host in {"localhost", "localhost.localdomain", "metadata.google.internal"}:
        return True
    if host.endswith((".local", ".internal", ".lan", ".home", ".localhost")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
    )


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "", name).lower()


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, 1):
        current = [i]
        for j, rchar in enumerate(right, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (lchar != rchar)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return os.path.relpath(path, root).replace("\\", "/")


def format_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
