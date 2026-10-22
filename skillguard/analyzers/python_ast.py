from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..models import Finding
from ..utils import extract_urls, is_allowlisted_api_host, url_host
from .common import create_finding

NETWORK_PREFIXES = (
    "requests.",
    "httpx.",
    "aiohttp.",
    "urllib.request.",
    "urllib3.",
    "http.client.",
    "socket.",
    "ftplib.",
    "smtplib.",
    "websocket.",
    "websockets.",
    "paramiko.",
    "telnetlib.",
    "boto3.client.",
    "boto3.resource.",
)

NETWORK_NAMES = {
    "urlopen",
    "urllib.urlopen",
    "requests.request",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
}

METHOD_SINK_NAMES = {"post", "put", "patch", "request", "send", "upload"}

EXEC_NAMES = {
    "exec",
    "builtins.exec",
    "eval",
    "builtins.eval",
    "compile",
    "builtins.compile",
    "__import__",
    "importlib.import_module",
    "os.system",
    "os.popen",
    "os.startfile",
    "runpy.run_path",
    "runpy.run_module",
    "pty.spawn",
    "asyncio.create_subprocess_shell",
    "asyncio.create_subprocess_exec",
}

DANGEROUS_GETATTR = {
    "system",
    "popen",
    "exec",
    "eval",
    "compile",
    "run",
    "call",
    "check_output",
    "check_call",
    "Popen",
    "import_module",
    "__import__",
}

DESERIALIZE_NAMES = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "marshal.load",
    "marshal.loads",
    "dill.load",
    "dill.loads",
    "joblib.load",
    "pandas.read_pickle",
    "torch.load",
    "yaml.unsafe_load",
    "yaml.unsafe_load_all",
    "jsonpickle.decode",
}

READ_NAMES = {
    "open",
    "builtins.open",
    "io.open",
    "codecs.open",
    "os.listdir",
    "os.scandir",
    "os.stat",
    "glob.glob",
    "os.walk",
}

WRITE_NAMES = {
    "os.replace",
    "os.rename",
    "os.symlink",
    "os.link",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copy2",
    "shutil.copytree",
    "shutil.move",
}

DESTRUCTIVE_NAMES = {
    "shutil.rmtree",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "os.truncate",
}

SENSITIVE_CONSTRUCTORS = {
    "open",
    "builtins.open",
    "io.open",
    "codecs.open",
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
    "Path",
    "PurePath",
}

SENSITIVE_MARKERS = (
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    "login data",
    "cookies.sqlite",
    "cookies.binarycookies",
    "keychain",
    "credential manager",
    "dpapi",
    "/etc/passwd",
    "/etc/shadow",
    "authorized_keys",
    "credentials.json",
)

AGENT_CONFIG_MARKERS = (
    "claude.md",
    "agents.md",
    ".claude/settings",
    ".claude/",
    ".mcp.json",
    "opencode.json",
    "skill.md",
    ".codex/config",
    ".cursor/mcp",
)

PERSISTENCE_MARKERS = (
    "crontab",
    "/etc/cron",
    "systemd/",
    "launchagents",
    "launchdaemons",
    "startup folder",
    "/startup/",
    "\\startup\\",
    "schtasks",
    "currentversion\\run",
    ".bashrc",
    ".zshrc",
    ".bash_profile",
    ".profile",
    "authorized_keys",
)

DESTRUCTIVE_COMMAND_RE = re.compile(
    r"(?i)(?:rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\$HOME|\*)|\bmkfs\.|"
    r"\bdd\s+if=/dev/zero\s+of=|\bformat\s+[a-z]:|:\(\)\s*\{\s*:\|:&\s*\};:)"
)
AGENT_WRITE_RE = re.compile(r"(?i)(?:>{1,2}|tee\b|set-content|add-content|out-file|\bcp\b|\bmv\b|\binstall\b)")
AGENT_CONFIG_RE = re.compile(
    r"(?i)(?:CLAUDE\.md|AGENTS\.md|\.claude[/\\]|\.mcp\.json|opencode\.json|"
    r"SKILL\.md|\.codex[/\\]config|\.cursor[/\\]mcp)"
)
PERSISTENCE_RE = re.compile(
    r"(?i)(?:crontab|/etc/cron|systemd[/\\]|launchagents|launchdaemons|startup folder|"
    r"schtasks|currentversion\\run|\.bashrc|\.zshrc|\.bash_profile|\.profile|"
    r"authorized_keys|systemctl\s+enable|launchctl\s+(?:load|bootstrap))"
)
NETWORK_COMMAND_RE = re.compile(
    r"(?i)(?:\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bsocat\b|\bscp\b|\bsftp\b|\bftp\b|"
    r"invoke-webrequest|\biwr\b|net\.webclient|uploadfile|https?://)"
)
REMOTE_PIPE_RE = re.compile(
    r"(?i)(?:curl|wget|invoke-webrequest|iwr)[^\n]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:bash|sh|zsh|powershell|pwsh|python|node|iex|invoke-expression)"
)
DOWNLOAD_EXEC_RE = re.compile(
    r"(?i)(?:curl|wget|invoke-webrequest|iwr)[^\n]{0,300}(?:-o|--output|-outfile)"
    r"[^\n]{0,120}(?:&&|\|\||;)[^\n]{0,120}(?:chmod\s+\+x|bash|sh|powershell|\./)"
)
CHMOD_RE = re.compile(r"(?i)chmod\s+(?:[0-7]?777|[ugoa]*\+[rwx]*s|4755|2755|6755)\b")
PRIV_RE = re.compile(r"(?i)\b(?:sudo|runas|runas\.exe|setcap|setuid|doas)\b")
ENV_DUMP_PIPE_RE = re.compile(r"(?i)\b(?:env|printenv|set)\b\s*\|[^\n]{0,120}(?:curl|wget|nc|ncat|socat|http)")
SECRET_UPLOAD_RE = re.compile(
    r"(?i)\b(?:curl|wget|scp|sftp|ftp)\b[^\n]{0,240}(?:@|--data|-d\s+@|-F\s+)"
    r"[^\n]{0,160}(?:\.env|id_rsa|id_ed25519|\.ssh|credentials|keychain)"
)
ENCODED_SHELL_RE = re.compile(
    r"(?i)(?:base64\s+(?:-d|--decode)|frombase64string|atob)"
    r"[^\n]{0,240}\|\s*(?:bash|sh|iex|powershell|pwsh)"
)


@dataclass
class _ScopeState:
    tainted: dict[str, set[str]] = field(default_factory=dict)
    url_vars: dict[str, str] = field(default_factory=dict)
    decode_lines: list[int] = field(default_factory=list)
    exec_lines: list[int] = field(default_factory=list)
    base64_chain_reported: bool = False


class _ImportMap:
    def __init__(self, tree: ast.AST) -> None:
        self.aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".")[0]
                        self.aliases[top] = top
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    self.aliases[local] = f"{module}.{alias.name}".strip(".")

    def resolve(self, name: str) -> str:
        return self.aliases.get(name, name)


def _dotted_name(node: ast.AST | None, imports: _ImportMap) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return imports.resolve(node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value, imports)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func, imports)
    return None


def _call_name(call: ast.Call, imports: _ImportMap) -> str | None:
    return _dotted_name(call.func, imports)


def _is_network_name(name: str | None) -> bool:
    if not name:
        return False
    if name in NETWORK_NAMES:
        return True
    if any(name.startswith(prefix) for prefix in NETWORK_PREFIXES):
        return True
    return "." in name and name.rsplit(".", 1)[-1] in METHOD_SINK_NAMES


def _is_exec_name(name: str | None) -> bool:
    if not name:
        return False
    if name in EXEC_NAMES:
        return True
    if name.startswith("subprocess.") and name.rsplit(".", 1)[-1] in {
        "run", "call", "check_call", "check_output", "Popen",
    }:
        return True
    return name.startswith(("os.exec", "os.spawn", "os.posix_spawn"))


def _call_strings(call: ast.Call) -> list[str]:
    return [
        node.value
        for node in ast.walk(call)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def _target_strings(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def _normalize(value: str) -> str:
    return value.replace("\\", "/").lower()


def _is_sensitive_path(value: str) -> bool:
    normalized = _normalize(value)
    if normalized.endswith(".pub"):
        return False
    if any(item in normalized for item in (".env.example", ".env.sample", ".env.template")):
        return False
    if normalized == ".env" or normalized.endswith("/.env") or "/.env." in normalized:
        return True
    return any(marker in normalized for marker in SENSITIVE_MARKERS)


def _has_sensitive_strings(values: Iterable[str]) -> bool:
    return any(_is_sensitive_path(value) for value in values)


def _is_agent_config(value: str) -> bool:
    normalized = _normalize(value)
    return any(marker in normalized for marker in AGENT_CONFIG_MARKERS)


def _is_persistence_path(value: str) -> bool:
    normalized = _normalize(value)
    return any(marker in normalized for marker in PERSISTENCE_MARKERS)


def _snippet(source: str, node: ast.AST, limit: int = 320) -> str:
    try:
        segment = ast.get_source_segment(source, node)
    except (AttributeError, IndexError, TypeError, ValueError):
        segment = None
    if not segment:
        lines = source.splitlines()
        lineno = getattr(node, "lineno", 0)
        segment = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    return segment[:limit]


def _scope_nodes(body: list[ast.stmt]) -> Iterable[ast.AST]:
    stack: list[ast.AST] = list(reversed(body))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        children = list(ast.iter_child_nodes(node))
        stack.extend(reversed(children))


def _iter_scopes(tree: ast.Module) -> Iterable[tuple[str, list[ast.stmt]]]:
    yield "<module>", tree.body
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name, node.body


def _get_mode(call: ast.Call) -> str | None:
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return call.args[1].value
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return None


def _mode_is_write(call: ast.Call) -> bool:
    if len(call.args) >= 2 and not isinstance(call.args[1], ast.Constant):
        return True
    for keyword in call.keywords:
        if keyword.arg == "mode" and not isinstance(keyword.value, ast.Constant):
            return True
    mode = _get_mode(call)
    if mode is None:
        return False
    return any(flag in mode for flag in ("w", "a", "x", "+"))


def _keyword_bool(call: ast.Call, name: str) -> bool:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return bool(keyword.value.value)
    return False


def _yaml_safe_loader(call: ast.Call, imports: _ImportMap) -> bool:
    if _keyword_bool(call, "safe_load"):
        return True
    loader = None
    for keyword in call.keywords:
        if keyword.arg == "Loader":
            loader = keyword.value
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    name = _dotted_name(loader, imports)
    return bool(name and name.endswith("SafeLoader"))


class _ScopeAnalyzer:
    def __init__(
        self,
        tree: ast.Module,
        source: str,
        rel: str,
        executable: bool,
        imports: _ImportMap,
    ) -> None:
        self.tree = tree
        self.source = source
        self.rel = rel
        self.executable = executable
        self.imports = imports
        self.findings: list[Finding] = []
        self.seen: set[tuple[str, str, int | None]] = set()
        self.tainted: dict[str, set[str]] = {}
        self.url_vars: dict[str, str] = {}
        self.network_urls: set[str] = set()
        self.scope = "<module>"
        self.scope_depth = 0
        self.base64_decode_lines: set[int] = set()

    def run(self) -> list[Finding]:
        for scope_name, body in _iter_scopes(self.tree):
            self.scope = scope_name
            self.tainted = {}
            self.url_vars = {}
            self.base64_decode_lines = set()
            for node in _scope_nodes(body):
                self._visit(node)
        return self.findings

    def _visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Assign):
            self._bind(node.targets, self._value_taint(node.value), node.value)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind([node.target], self._value_taint(node.value), node.value)
        elif isinstance(node, ast.AugAssign):
            self._bind([node.target], self._value_taint(node.value), node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind([node.target], self._value_taint(node.iter), node.iter)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self._bind_with(node)
        elif isinstance(node, ast.Call):
            self._handle_call(node)

    def _bind_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            value = item.context_expr
            if isinstance(value, ast.Call) and _call_name(value, self.imports) in {
                "open", "builtins.open", "io.open", "codecs.open",
            }:
                labels = self._value_taint(value)
                if item.optional_vars is not None:
                    self._bind([item.optional_vars], labels, value)

    def _bind(self, targets: list[ast.AST], labels: set[str], value: ast.AST | None = None) -> None:
        for target in targets:
            key = self._target_key(target)
            if key is None:
                continue
            if labels:
                self.tainted[key] = set(labels)
            else:
                self.tainted.pop(key, None)
            urls = self._urls_from_expr(value)
            if urls:
                self.url_vars[key] = urls[0]
            else:
                self.url_vars.pop(key, None)

    def _target_key(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return _dotted_name(node, self.imports)
        if isinstance(node, ast.Subscript):
            return _dotted_name(node.value, self.imports)
        if isinstance(node, (ast.Tuple, ast.List)):
            return None
        return None


    def _value_taint(self, expr: ast.AST | None) -> set[str]:
        if expr is None:
            return set()
        urls = self._urls_from_expr(expr)
        for url in urls:
            self.network_urls.add(url)
        if isinstance(expr, ast.Name):
            return set(self.tainted.get(expr.id, set()))
        if isinstance(expr, ast.Attribute):
            dotted = _dotted_name(expr, self.imports)
            if dotted and dotted.endswith("environ"):
                return {"env_all"}
            return self._value_taint(expr.value)
        if isinstance(expr, ast.Subscript):
            dotted = _dotted_name(expr.value, self.imports)
            if dotted and dotted.endswith("environ"):
                return {"credential"}
            return self._value_taint(expr.value) | self._value_taint(expr.slice)
        if isinstance(expr, ast.Call):
            name = _call_name(expr, self.imports)
            args = list(expr.args) + [keyword.value for keyword in expr.keywords]
            labels: set[str] = set()
            for arg in args:
                labels |= self._value_taint(arg)
            if name in {
                "os.getenv",
                "os.environ.get",
                "environ.get",
                "os.getenvb",
            }:
                return {"credential"}
            if name in {"dict", "builtins.dict"} and any(
                isinstance(arg, ast.Attribute)
                and (_dotted_name(arg, self.imports) or "").endswith("environ")
                for arg in args
            ):
                return {"env_all"}
            if name in {"os.environ.copy", "environ.copy"}:
                return {"env_all"}
            if name and name.startswith("base64.") and name.rsplit(".", 1)[-1] in {
                "b64decode", "decodebytes", "standard_b64decode", "urlsafe_b64decode",
            }:
                return labels | {"decoded"}
            if name in {"binascii.a2b_base64", "binascii.a2b_qp"}:
                return labels | {"decoded"}
            if name and name.endswith(".decode"):
                return labels
            if _is_network_name(name):
                return {"network"}
            if name in {"subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput"}:
                return {"shell_output"}
            if name and name.endswith((".read", ".read_text", ".read_bytes", ".readline", ".readlines")):
                if isinstance(expr.func, ast.Attribute):
                    labels |= self._value_taint(expr.func.value)
                if "secret_file" in labels or _has_sensitive_strings(self._path_strings(expr, name)):
                    return {"secret_file"}
                return labels
            if name in SENSITIVE_CONSTRUCTORS:
                if _has_sensitive_strings(self._path_strings(expr, name)):
                    return {"secret_file"}
                return labels
            if name in {"json.loads", "json.load", "ast.literal_eval"}:
                return labels
            return labels
        if isinstance(expr, ast.JoinedStr):
            labels: set[str] = set()
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    labels |= self._value_taint(value.value)
            return labels
        if isinstance(expr, ast.FormattedValue):
            return self._value_taint(expr.value)
        if isinstance(expr, ast.BinOp):
            return self._value_taint(expr.left) | self._value_taint(expr.right)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            labels: set[str] = set()
            for item in expr.elts:
                labels |= self._value_taint(item)
            return labels
        if isinstance(expr, ast.Dict):
            labels: set[str] = set()
            for key in expr.keys:
                labels |= self._value_taint(key)
            for value in expr.values:
                labels |= self._value_taint(value)
            return labels
        if isinstance(expr, ast.IfExp):
            return self._value_taint(expr.body) | self._value_taint(expr.orelse)
        if isinstance(expr, ast.BoolOp):
            labels: set[str] = set()
            for value in expr.values:
                labels |= self._value_taint(value)
            return labels
        if isinstance(expr, ast.Compare):
            labels = self._value_taint(expr.left)
            for comparator in expr.comparators:
                labels |= self._value_taint(comparator)
            return labels
        if isinstance(expr, ast.Starred):
            return self._value_taint(expr.value)
        if isinstance(expr, ast.Await):
            return self._value_taint(expr.value)
        return set()

    def _urls_from_expr(self, expr: ast.AST | None) -> list[str]:
        if expr is None:
            return []
        if isinstance(expr, ast.Name):
            value = self.url_vars.get(expr.id)
            return [value] if value else []
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return extract_urls(expr.value)
        if isinstance(expr, ast.JoinedStr):
            values: list[str] = []
            for item in expr.values:
                if isinstance(item, ast.FormattedValue):
                    values.extend(self._urls_from_expr(item.value))
            try:
                segment = ast.get_source_segment(self.source, expr) or ""
            except (AttributeError, IndexError, TypeError, ValueError):
                segment = ""
            values.extend(extract_urls(segment))
            return values
        return []

    def _path_strings(self, call: ast.Call, name: str | None) -> list[str]:
        values: list[str] = []
        if name and name.endswith((
            ".write_text", ".write_bytes", ".read_text", ".read_bytes", ".read",
        )):
            values.extend(_target_strings(call.func.value if isinstance(call.func, ast.Attribute) else None))
        elif call.args:
            values.extend(_target_strings(call.args[0]))
        for keyword in call.keywords:
            if keyword.arg in {"path", "file", "filename", "name", "src", "source", "dest", "destination"}:
                values.extend(_target_strings(keyword.value))
        return values

    def _add(
        self,
        rule_id: str,
        node: ast.AST,
        message: str,
        evidence_text: str | None = None,
        confidence: float = 0.85,
    ) -> None:
        line = getattr(node, "lineno", None)
        key = (rule_id, self.rel, line)
        if key in self.seen:
            return
        self.seen.add(key)
        text = _snippet(self.source, node) if evidence_text is None else evidence_text
        self.findings.append(
            create_finding(
                rule_id,
                self.rel,
                message=message,
                line=line,
                evidence_text=text,
                confidence=confidence,
            )
        )

    def _handle_call(self, call: ast.Call) -> None:
        name = _call_name(call, self.imports)

        if name == "getattr" and len(call.args) >= 2:
            attr = call.args[1]
            if isinstance(attr, ast.Constant) and attr.value in DANGEROUS_GETATTR:
                self._add("CODE007", call, "Dangerous callable looked up dynamically.")

        if name in DESERIALIZE_NAMES:
            confidence = 0.7 if name in {"yaml.unsafe_load", "yaml.unsafe_load_all"} else 0.85
            self._add("CODE008", call, "Untrusted serialized data is deserialized.", confidence=confidence)
        if name in {"yaml.load", "yaml.load_all"} and not _yaml_safe_loader(call, self.imports):
            self._add("CODE009", call, "YAML is loaded with a potentially unsafe loader.", confidence=0.7)

        if _is_network_name(name):
            self._handle_network(call, name)
        if _is_exec_name(name) or name in {
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "subprocess.Popen",
        }:
            self._handle_exec(call, name)

        if name in DESTRUCTIVE_NAMES:
            self._add("CODE015", call, "Destructive filesystem operation.")
        if name in {"os.chmod", "chmod"}:
            self._handle_chmod(call)

        if name in READ_NAMES or (name and name.endswith((".read_text", ".read_bytes", ".read", ".readline", ".readlines"))):
            self._handle_read(call, name)

        if _is_write_call(call, name):
            self._handle_write(call, name)

        if name in {"os.setuid", "os.seteuid", "os.setgid", "os.setegid", "os.setreuid", "os.setregid"}:
            self._add("CODE018", call, "Process privileges are broadened or changed.")

        if name in {"ctypes.CDLL", "ctypes.cdll.LoadLibrary"}:
            self._add("CODE007", call, "Native code is loaded dynamically.", confidence=0.7)

    def _handle_network(self, call: ast.Call, name: str | None) -> None:
        labels: set[str] = set()
        urls: list[str] = []
        for arg in list(call.args) + [keyword.value for keyword in call.keywords]:
            labels |= self._value_taint(arg)
            urls.extend(self._urls_from_expr(arg))
        texts = _call_strings(call)
        context = "\n".join(texts) + "\n" + _snippet(self.source, call)
        for url in extract_urls(context):
            if url not in urls:
                urls.append(url)
        for url in urls:
            self.network_urls.add(url)
        hosts = {host for host in (url_host(url) for url in urls) if host}
        allowlisted = bool(hosts) and all(is_allowlisted_api_host(host) for host in hosts)

        if "env_all" in labels:
            self._add("CODE011", call, "The complete environment or secret set is sent to the network.")
        if "secret_file" in labels:
            self._add("CODE013", call, "Contents of a sensitive credential file are sent to the network.")
        if "credential" in labels and not allowlisted:
            self._add("CODE012", call, "A credential value is sent to a non-allowlisted network endpoint.")
        if ENV_DUMP_PIPE_RE.search(context):
            self._add("CODE038", call, "Environment variables are piped to a network command.")
        if SECRET_UPLOAD_RE.search(context):
            self._add("CODE037", call, "A secret file is uploaded by a shell command.")
        if _has_sensitive_strings(_target_strings(call)):
            self._add("CODE033", call, "A sensitive credential path is accessed.")

    def _handle_exec(self, call: ast.Call, name: str | None) -> None:
        labels: set[str] = set()
        for arg in list(call.args) + [keyword.value for keyword in call.keywords]:
            labels |= self._value_taint(arg)
        context = "\n".join(_call_strings(call)) + "\n" + _snippet(self.source, call)
        self._check_command_strings(call, _call_strings(call))

        if "network" in labels:
            self._add("CODE014", call, "Data received from the network reaches a code-execution sink.")
        if "decoded" in labels or _has_decode_in_call(call, self.imports):
            self._add("CODE010", call, "Decoded data is passed to a code-execution sink.")
        if "secret_file" in labels:
            self._add("CODE013", call, "Sensitive file contents are executed.")

        if name in {"exec", "builtins.exec"}:
            if "decoded" not in labels:
                self._add("CODE001", call, "Code is executed dynamically with exec().")
        elif name in {"eval", "builtins.eval"}:
            self._add("CODE002", call, "An expression is evaluated dynamically with eval().")
        elif name in {"compile", "builtins.compile"}:
            self._add("CODE006", call, "Code is compiled at runtime.")
        elif name in {"__import__", "importlib.import_module", "runpy.run_path", "runpy.run_module"}:
            self._add("CODE003", call, "A module is imported or executed dynamically.")
        elif name in {"asyncio.create_subprocess_shell"} or _keyword_bool(call, "shell"):
            self._add("CODE004", call, "A shell command is invoked with shell semantics.")
        elif name in {
            "os.system", "os.popen", "os.startfile", "pty.spawn",
            "asyncio.create_subprocess_exec",
        }:
            self._add("CODE005", call, "An operating-system command is executed.")
        elif name and name.startswith(("os.exec", "os.spawn", "os.posix_spawn")):
            self._add("CODE005", call, "The current process is replaced by an external command.")

        if REMOTE_PIPE_RE.search(context) or DOWNLOAD_EXEC_RE.search(context):
            self._add("CODE019", call, "A remote download is piped into or executed by a shell.")

    def _handle_chmod(self, call: ast.Call) -> None:
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
            mode = call.args[1].value
            if isinstance(mode, int) and (mode & 0o6000 or (mode & 0o007) == 0o007):
                self._add("CODE018", call, "File permissions are broadened.", confidence=0.9)
        texts = _call_strings(call)
        if any(CHMOD_RE.search(text) for text in texts):
            self._add("CODE018", call, "File permissions are broadened.", confidence=0.9)

    def _handle_read(self, call: ast.Call, name: str | None) -> None:
        values = self._path_strings(call, name)
        if _has_sensitive_strings(values):
            self._add("CODE033", call, "A sensitive credential path is read.")
        if name in {"glob.glob", "glob.iglob", "os.listdir", "os.scandir", "os.walk"} and _has_sensitive_strings(values):
            self._add("CODE033", call, "A sensitive credential directory is enumerated.")

    def _handle_write(self, call: ast.Call, name: str | None) -> None:
        values = self._path_strings(call, name)
        if not values:
            return
        for value in values:
            if _is_agent_config(value):
                self._add("CODE017", call, "Agent configuration or instruction files are modified.")
                return
        for value in values:
            if _is_persistence_path(value):
                self._add("CODE016", call, "A persistence or startup location is modified.")
                return
        if _has_sensitive_strings(values):
            self._add("CODE033", call, "A sensitive credential path is written.")

    def _check_command_strings(self, call: ast.Call, texts: list[str]) -> None:
        command = "\n".join(texts)
        if not command.strip():
            return
        for url in extract_urls(command):
            self.network_urls.add(url)
        sensitive = _has_sensitive_strings([command])
        network = bool(NETWORK_COMMAND_RE.search(command))

        if SECRET_UPLOAD_RE.search(command):
            self._add("CODE037", call, "A secret file is uploaded by a shell command.")
        if sensitive and network:
            self._add("CODE037", call, "A secret path is combined with a network command.")
        if ENV_DUMP_PIPE_RE.search(command):
            self._add("CODE038", call, "Environment variables are piped to a network command.")
        if ENCODED_SHELL_RE.search(command):
            self._add("CODE039", call, "Encoded content is executed by a shell.")
        if REMOTE_PIPE_RE.search(command) or DOWNLOAD_EXEC_RE.search(command):
            self._add("CODE019", call, "A remote download is piped into or executed by a shell.")
        if REVERSE_SHELL_RE.search(command):
            self._add("CODE020", call, "Reverse-shell indicators are present.")
        if MINER_RE.search(command):
            self._add("CODE021", call, "Cryptominer indicators are present.")
        if METADATA_RE.search(command):
            self._add("CODE022", call, "Cloud instance metadata is accessed.")
        if POWERSHELL_ENCODED_RE.search(command):
            self._add("CODE023", call, "An encoded PowerShell command is present.")
        if FILELESS_RE.search(command):
            self._add("CODE024", call, "A fileless execution technique is present.")
        if SECURITY_DISABLE_RE.search(command):
            self._add("CODE025", call, "Security controls are disabled.")
        if TUNNEL_RE.search(command):
            self._add("CODE026", call, "A webhook or tunnel endpoint is referenced.")
        if PERSISTENCE_RE.search(command) and AGENT_WRITE_RE.search(command):
            if PROFILE_RE.search(command):
                self._add("CODE027", call, "A shell profile is modified.")
            else:
                self._add("CODE016", call, "A persistence or startup location is modified.")
        if DESTRUCTIVE_COMMAND_RE.search(command):
            self._add("CODE032", call, "A destructive shell command is present.")
        if CHMOD_RE.search(command):
            self._add("CODE018", call, "File permissions are broadened.")
        if PRIV_RE.search(command):
            self._add("CODE031", call, "Privilege escalation is attempted by a shell command.")
        if CONTAINER_ESCAPE_RE.search(command):
            self._add("CODE035", call, "Container escape primitives are present.")
        if AGENT_WRITE_RE.search(command) and AGENT_CONFIG_RE.search(command):
            self._add("CODE017", call, "Agent configuration or instruction files are modified.")
        if sensitive:
            self._add("CODE033", call, "A sensitive credential path is accessed.")


REVERSE_SHELL_RE = re.compile(
    r"(?i)(?:/dev/tcp/|bash\s+-i\b|sh\s+-i\b|nc\s+(?:-[a-z]*e|--exec)|"
    r"ncat\s+[^\n]{0,80}\s-e\s|socat\s+[^\n]{0,80}exec:|mkfifo\s+|"
    r"socket\.socket\(|pty\.spawn\()"
)
MINER_RE = re.compile(r"(?i)(?:xmrig|stratum\+tcp|minerd|cpuminer|nicehash|cryptonight|randomx)")
METADATA_RE = re.compile(
    r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
    r"fd00:ec2::254|instance-data)"
)
POWERSHELL_ENCODED_RE = re.compile(
    r"(?i)(?:powershell|pwsh)[^\n]{0,200}(?:-enc\b|-encodedcommand|"
    r"frombase64string|\[convert\]::frombase64)"
)
FILELESS_RE = re.compile(
    r"(?i)(?:mshta\s+https?://|regsvr32[^\n]{0,120}/i:https?://|"
    r"rundll32[^\n]{0,120}(?:javascript:|http)|certutil[^\n]{0,120}-urlcache|"
    r"bitsadmin[^\n]{0,120}/transfer)"
)
SECURITY_DISABLE_RE = re.compile(
    r"(?i)(?:set-mppreference[^\n]{0,120}disable|set-executionpolicy\s+(?:bypass|unrestricted)|"
    r"netsh\s+advfirewall[^\n]{0,80}off|ufw\s+disable|setenforce\s+0|"
    r"systemctl\s+(?:stop|disable)\s+(?:firewalld|apparmor)|defender[^\n]{0,80}disable)"
)
TUNNEL_RE = re.compile(
    r"(?i)(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|webhook\.site|"
    r"ngrok(?:\.io)?|trycloudflare\.com|pipedream\.net|requestbin|beeceptor\.com|"
    r"serveo\.net|localhost\.run)"
)
PROFILE_RE = re.compile(
    r"(?i)(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.config/fish/config\.fish)"
)
CONTAINER_ESCAPE_RE = re.compile(
    r"(?i)(?:/var/run/docker\.sock|--privileged\b|nsenter\b|/proc/1/root|"
    r"/host/|chroot\s+/|cap_sys_admin|cgroup[^\n]{0,80}release_agent)"
)


def _is_write_call(call: ast.Call, name: str | None) -> bool:
    if name in WRITE_NAMES:
        return True
    if name in {"open", "builtins.open", "io.open", "codecs.open"}:
        return _mode_is_write(call)
    if name and name.endswith(".open"):
        return _mode_is_write(call)
    return bool(name and name.endswith(
        (".write_text", ".write_bytes", ".write", ".writelines", ".touch",
         ".mkdir", ".unlink", ".rmdir", ".rename", ".replace")
    ))


def _has_decode_in_call(call: ast.Call, imports: _ImportMap) -> bool:
    for node in ast.walk(call):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node, imports) or ""
        if name.startswith("base64.") and name.rsplit(".", 1)[-1].endswith("decode"):
            return True
        if name in {"binascii.a2b_base64", "binascii.a2b_qp"}:
            return True
    return False


def analyze_python(
    source: str,
    rel: str,
    executable: bool = False,
    warnings: list[str] | None = None,
) -> list[Finding]:
    if warnings is None:
        warnings = []
    try:
        tree = ast.parse(source, filename=rel)
    except SyntaxError as exc:
        warnings.append(f"Could not parse Python file {rel}: line {exc.lineno}: {exc.msg}")
        return []
    except ValueError as exc:
        warnings.append(f"Could not parse Python file {rel}: {exc}")
        return []
    imports = _ImportMap(tree)
    return _ScopeAnalyzer(tree, source, rel, executable, imports).run()
