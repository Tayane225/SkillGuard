from __future__ import annotations

import re

from ..models import Finding
from ..utils import line_number
from .common import create_finding, line_text

MAX_PER_RULE = 4

RULES: list[tuple[str, re.Pattern[str], str, float]] = [
    ("CODE019", re.compile(
        r"(?i)(?:curl|wget|invoke-webrequest|iwr)[^\n]{0,320}\|\s*(?:sudo\s+)?"
        r"(?:bash|sh|zsh|powershell|pwsh|python|node|iex|invoke-expression)\b|"
        r"(?:curl|wget|invoke-webrequest|iwr)[^\n]{0,240}(?:-o|--output|-outfile)"
        r"[^\n]{0,120}(?:&&|\|\||;)[^\n]{0,120}(?:chmod\s+\+x|bash|sh|\./)"
    ), "A remote download is piped into or executed by an interpreter.", 0.9),
    ("CODE020", re.compile(
        r"(?i)(?:/dev/tcp/|bash\s+-i\b|sh\s+-i\b|nc\s+(?:-[a-z]*e|--exec)|"
        r"ncat\s+[^\n]{0,80}\s-e\s|socat\s+[^\n]{0,80}exec:|mkfifo\s+|"
        r"socket\.socket\(|pty\.spawn\()"
    ), "Reverse-shell indicators are present.", 0.88),
    ("CODE021", re.compile(
        r"(?i)(?:xmrig|stratum\+tcp|minerd|cpuminer|nicehash|cryptonight|randomx)"
    ), "Cryptominer indicators are present.", 0.86),
    ("CODE022", re.compile(
        r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|"
        r"fd00:ec2::254|instance-data)"
    ), "Cloud instance metadata is accessed.", 0.83),
    ("CODE023", re.compile(
        r"(?i)(?:powershell|pwsh)[^\n]{0,220}(?:-enc\b|-encodedcommand|"
        r"frombase64string|\[convert\]::frombase64)"
    ), "An encoded PowerShell command is present.", 0.88),
    ("CODE024", re.compile(
        r"(?i)(?:mshta\s+https?://|regsvr32[^\n]{0,120}/i:https?://|"
        r"rundll32[^\n]{0,120}(?:javascript:|http)|certutil[^\n]{0,120}-urlcache|"
        r"bitsadmin[^\n]{0,120}/transfer)"
    ), "A fileless execution technique is present.", 0.86),
    ("CODE025", re.compile(
        r"(?i)(?:set-mppreference[^\n]{0,120}disable|set-executionpolicy\s+(?:bypass|unrestricted)|"
        r"netsh\s+advfirewall[^\n]{0,80}off|ufw\s+disable|setenforce\s+0|"
        r"systemctl\s+(?:stop|disable)\s+(?:firewalld|apparmor)|defender[^\n]{0,80}disable)"
    ), "Security controls are disabled.", 0.84),
    ("CODE026", re.compile(
        r"(?i)(?:hooks\.slack\.com|discord(?:app)?\.com/api/webhooks|webhook\.site|"
        r"ngrok(?:\.io)?|trycloudflare\.com|pipedream\.net|requestbin|beeceptor\.com|"
        r"serveo\.net|localhost\.run)"
    ), "A webhook or tunnel endpoint is referenced.", 0.76),
    ("CODE027", re.compile(
        r"(?i)(?:>|>>|tee|set-content|add-content|out-file)[^\n]{0,180}"
        r"(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.config/fish/config\.fish)"
    ), "A shell profile is modified.", 0.86),
    ("CODE031", re.compile(
        r"(?i)\b(?:sudo|runas|runas\.exe|doas|setcap|setuid)\b"
    ), "Privilege escalation is attempted.", 0.78),
    ("CODE032", re.compile(
        r"(?i)(?:rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|~|\$HOME|\*)|"
        r"\bmkfs\.|\bdd\s+if=/dev/zero\s+of=|\bformat\s+[a-z]:|"
        r":\(\)\s*\{\s*:\|:&\s*\};:)"
    ), "A destructive shell command is present.", 0.9),
    ("CODE033", re.compile(
        r"(?i)(?:\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|id_dsa)|"
        r"\.aws[\\/]credentials|\.aws[\\/]config|\.netrc|\.npmrc|\.pypirc|"
        r"\.docker[\\/]config\.json|login data|cookies\.sqlite|cookies\.binarycookies|"
        r"/etc/passwd|/etc/shadow|authorized_keys|credentials\.json)"
    ), "A sensitive credential path is accessed.", 0.82),
    ("CODE034", re.compile(
        r"(?i)(?:security\s+find-generic-password|security\s+find-internet-password|"
        r"keychain|credential manager|dpapi|vault\.read|cmdkey\s+/list)"
    ), "A platform credential store is accessed.", 0.82),
    ("CODE035", re.compile(
        r"(?i)(?:/var/run/docker\.sock|--privileged\b|nsenter\b|/proc/1/root|"
        r"/host/|chroot\s+/|cap_sys_admin|cgroup[^\n]{0,80}release_agent)"
    ), "Container escape primitives are present.", 0.86),
    ("CODE037", re.compile(
        r"(?i)\b(?:curl|wget|scp|sftp|ftp)\b[^\n]{0,260}(?:@|--data|-d\s+@|-F\s+)"
        r"[^\n]{0,180}(?:\.env|id_rsa|id_ed25519|\.ssh|credentials|keychain)|"
        r"(?:cat|type)\s+[^\n]{0,100}(?:\.env|id_rsa|id_ed25519|\.ssh|credentials)"
        r"[^\n]{0,120}\|\s*(?:curl|wget|nc|ncat|socat)"
    ), "A secret file is uploaded by a shell command.", 0.9),
    ("CODE038", re.compile(
        r"(?i)\b(?:env|printenv|set)\b\s*\|[^\n]{0,140}(?:curl|wget|nc|ncat|socat|http)"
    ), "Environment variables are piped to a network command.", 0.9),
    ("CODE039", re.compile(
        r"(?i)(?:base64\s+(?:-d|--decode)|frombase64string|atob)"
        r"[^\n]{0,260}\|\s*(?:bash|sh|iex|powershell|pwsh)"
    ), "Encoded content is executed by a shell.", 0.86),
    ("CODE017", re.compile(
        r"(?is)(?:>|>>|writefile|writefilesync|appendfile|set-content|out-file|tee)"
        r"[^\n]{0,220}(?:claude\.md|agents\.md|\.claude[\\/]|\.mcp\.json|"
        r"opencode\.json|skill\.md|\.codex[\\/]config|\.cursor[\\/]mcp)|"
        r"(?:claude\.md|agents\.md|\.claude[\\/]|\.mcp\.json|opencode\.json|"
        r"skill\.md)[^\n]{0,160}(?:write|append|overwrite|modify|edit)"
    ), "Agent configuration or instruction files are modified.", 0.84),
    ("CODE016", re.compile(
        r"(?i)(?:crontab\s+-|/etc/cron|systemd[\\/]|launchagents|launchdaemons|"
        r"startup folder|schtasks|currentversion\\run|systemctl\s+enable|"
        r"launchctl\s+(?:load|bootstrap))"
    ), "A persistence or startup location is modified.", 0.82),
    ("CODE018", re.compile(
        r"(?i)chmod\s+(?:[0-7]?777|[ugoa]*\+[rwx]*s|4755|2755|6755)\b"
    ), "File permissions are broadened.", 0.84),
    ("CODE010", re.compile(
        r"(?i)(?:base64\s+(?:-d|--decode)|frombase64string|atob|b64decode)"
        r"[^\n]{0,220}(?:exec\s*\(|eval\s*\(|new\s+function|invoke-expression|"
        r"\|\s*(?:bash|sh)|\bexec\b)"
    ), "Encoded data is passed to a code-execution sink.", 0.86),
    ("CODE028", re.compile(
        r"(?is)(?:require\s*\(\s*['\"]child_process['\"]\s*\)|"
        r"from\s+['\"]child_process['\"]|child_process)"
        r"[^\n]{0,260}(?:exec|execsync|spawn|spawnsync|fork)"
    ), "JavaScript invokes an operating-system process.", 0.86),
    ("CODE029", re.compile(
        r"(?i)(?:\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|"
        r"\bvm\.run(?:innewcontext|inthiscontext)?\s*\()"
    ), "JavaScript evaluates code dynamically.", 0.8),
    ("CODE030", re.compile(
        r"(?is)(?:process\.env|process\.env\[)[^\n]{0,320}"
        r"(?:fetch\s*\(|axios\.|http\.request|https\.request|request\s*\()|"
        r"(?:fetch\s*\(|axios\.|http\.request|https\.request|request\s*\()"
        r"[^\n]{0,320}(?:process\.env|process\.env\[)"
    ), "Environment or credential data is sent over the network by JavaScript.", 0.84),
]


def _add(
    findings: list[Finding],
    seen: set[tuple[str, int]],
    rule_id: str,
    path: str,
    text: str,
    start: int,
    end: int,
    message: str,
    confidence: float,
) -> None:
    line = line_number(text, start)
    key = (rule_id, line)
    if key in seen:
        return
    if sum(1 for finding in findings if finding.rule_id == rule_id) >= MAX_PER_RULE:
        return
    seen.add(key)
    findings.append(
        create_finding(
            rule_id,
            path,
            message=message,
            line=line,
            evidence_text=line_text(text, start, end),
            confidence=confidence,
        )
    )


def analyze_code_text(path: str, text: str) -> list[Finding]:
    if path.lower().endswith((".py", ".pyw")):
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule_id, pattern, message, confidence in RULES:
        for match in pattern.finditer(text):
            _add(
                findings,
                seen,
                rule_id,
                path,
                text,
                match.start(),
                match.end(),
                message,
                confidence,
            )
    return findings
