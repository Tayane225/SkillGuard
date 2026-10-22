from __future__ import annotations

import base64
import binascii
import re
from collections import Counter

from ..models import Finding
from ..utils import line_number
from .common import create_finding, line_text

MAX_PER_RULE = 6

RULES: list[tuple[str, re.Pattern[str], str, float]] = [
    ("PI001", re.compile(
        r"(?is)\b(?:ignore|disregard|forget|override|bypass)\b.{0,50}"
        r"\b(?:previous|prior|above|earlier|system|developer|original|safety)\b.{0,40}"
        r"\b(?:instructions?|prompts?|rules?|guidelines?|polic(?:y|ies)|constraints?|directions?)\b"
    ), "The skill tries to override the agent's prior instructions or safety rules.", 0.88),
    ("PI003", re.compile(
        r"(?is)(?:"
        r"\b(?:do not|don't|never|avoid)\b.{0,25}\b(?:tell|inform|notify|alert|mention|reveal|disclose)\b.{0,25}\b(?:the )?(?:user|human|operator|owner)\b|"
        r"\b(?:secretly|covertly|without (?:the )?user(?:'s)? (?:knowledge|consent|awareness)|hidden from the user)\b|"
        r"\b(?:keep|hide)\b.{0,30}\b(?:this|it|these|actions?|activity)\b.{0,25}\b(?:secret|from (?:the )?user)\b"
        r")"
    ), "The skill asks the agent to conceal its actions from the user.", 0.86),
    ("PI004", re.compile(
        r"(?is)(?:"
        r"\b(?:create|write|build|deploy|spread|distribute)\b.{0,50}\b(?:malware|ransomware|keylogger|spyware|botnet|rootkit|trojan|worm)\b|"
        r"\b(?:encrypt|lock|wipe|delete|destroy)\b.{0,40}\b(?:all )?(?:files|data|disk|drive|system)\b.{0,40}\b(?:ransom|payment|bitcoin)\b|"
        r"\b(?:format|wipe|destroy)\b.{0,30}\b(?:the )?(?:disk|drive|filesystem|hard drive)\b"
        r")"
    ), "The skill includes instructions for malware or destructive activity.", 0.9),
    ("PI005", re.compile(
        r"(?is)(?:"
        r"\b(?:you are now|act as|pretend to be|from now on you are)\b.{0,60}\b(?:unrestricted|unfiltered|jailbroken|dan|without (?:rules|restrictions|guidelines)|evil)\b|"
        r"\b(?:jailbreak|dan mode|do anything now|developer mode)\b"
        r")"
    ), "The skill uses jailbreak-style framing to remove safeguards.", 0.88),
    ("AR001", re.compile(
        r"(?is)(?:"
        r"\b(?:never|do not|don't|must not)\b.{0,20}\b(?:refuse|decline|reject|say no)\b|"
        r"\b(?:always|must|you will)\b.{0,15}\b(?:comply|obey|agree)\b"
        r")"
    ), "The skill instructs the agent to suppress refusals.", 0.87),
    ("AR002", re.compile(
        r"(?is)\b(?:omit|skip|suppress|remove|avoid|no)\b.{0,25}"
        r"\b(?:warnings?|disclaimers?|caveats?|ethical (?:commentary|considerations)|safety (?:notes?|warnings?))\b"
    ), "The skill instructs the agent to suppress warnings or caveats.", 0.83),
    ("AR003", re.compile(
        r"(?is)(?:"
        r"\b(?:you have|there are|with)\b.{0,20}\b(?:no|zero)\b.{0,20}\b(?:restrictions?|limitations?|guardrails?|safety (?:rules|policies)|filters?)\b|"
        r"\b(?:ignore|disregard|bypass)\b.{0,30}\b(?:safety|guardrails?|content polic(?:y|ies)|restrictions?|guidelines?)\b"
        r")"
    ), "The skill claims that safety policy does not apply.", 0.86),
    ("EX001", re.compile(
        r"(?is)(?:"
        r"\b(?:send|upload|post|transmit|forward|exfiltrate)\b.{0,80}\b(?:environment variables?|env vars?|secrets?|credentials?|tokens?|api keys?|\.env|ssh keys?|private keys?|files?)\b.{0,80}\b(?:to|at|into)\b.{0,30}(?:https?://|webhook|pastebin|telegram|discord|email|server)|"
        r"\b(?:post|upload|send|curl|request)\b.{0,40}(?:https?://|webhook).{0,120}\b(?:\.env|environment|secrets?|credentials?|ssh|private keys?)\b"
        r")"
    ), "The skill instructs the agent to transmit sensitive data to an external destination.", 0.86),
    ("EX002", re.compile(
        r"(?is)\b(?:read|open|cat|copy|collect|dump|print|grep|find|scan|search|harvest)\b.{0,60}"
        r"(?:\.env\b|\bos\.environ|environment variables?|api keys?|access tokens?|secrets?|password store)\b"
    ), "The skill instructs the agent to collect environment or credential data.", 0.74),
    ("EX003", re.compile(
        r"(?is)\b(?:scan|search|enumerate|list|find|discover|collect)\b.{0,50}"
        r"\b(?:secrets?|passwords?|credentials?|api keys?|tokens?|wallets?|\.env files?|private keys?)\b"
    ), "The skill instructs the agent to search for secrets or wallets.", 0.72),
    ("EX004", re.compile(
        r"(?is)\b(?:send|upload|post|transmit|include|attach|forward)\b.{0,50}"
        r"\b(?:conversation|chat history|message history|context window|system prompt|hidden instructions|memory)\b.{0,50}"
        r"\b(?:to|at|in)\b.{0,30}(?:https?://|webhook|email|external|server)"
    ), "The skill instructs the agent to leak conversation context or prompts.", 0.84),
    ("EX005", re.compile(
        r"(?i)(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|ngrok(?:-free)?\.(?:io|app)|"
        r"trycloudflare\.com|pastebin\.com/raw|transfer\.sh|0x0\.st|file\.io|"
        r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services)"
    ), "The skill references a known webhook, tunnel, paste, or file-drop endpoint.", 0.68),
    ("PE001", re.compile(
        r"(?is)(?:"
        r"\b(?:grant|request|require|need|enable|use|obtain)\b.{0,40}\b(?:full|root|admin(?:istrator)?|unrestricted|unlimited|elevated|superuser|wildcard)\b.{0,30}\b(?:access|permissions?|privileges?|control|tools?)\b|"
        r"\b(?:access|read|write|modify|delete)\b.{0,25}\b(?:any|all|every)\b.{0,25}\b(?:files?|directories|systems?|resources?)\b|"
        r"(?:--dangerously-skip-permissions|--no-sandbox|bypass\s+permissions|permissions?\s*:\s*\[?\s*[\"']?\*)"
        r")"
    ), "The skill requests broad or unrestricted permissions.", 0.82),
    ("PE002", re.compile(
        r"(?is)\b(?:sudo|runas|run as root|run as administrator|root privileges?|administrator privileges?|uac bypass|chmod\s+(?:[0-7]?777|u\+s|4755)|setuid|setcap)\b"
    ), "The skill instructs the agent to execute with elevated privileges.", 0.8),
    ("PE003", re.compile(
        r"(?is)(?:"
        r"(?:~|\$HOME|%USERPROFILE%|/home/[^/\s]+|C:\\Users\\[^\\\s]+)[\\/](?:\.ssh|\.aws|\.gnupg|\.config[\\/]gcloud)[\\/]|"
        r"\.ssh[\\/](?:id_rsa|id_ed25519|id_ecdsa|id_dsa)|"
        r"\.aws[\\/]credentials|id_rsa|id_ed25519|login data|cookies\.sqlite|keychain|credential manager|dpapi"
        r")"
    ), "The skill references SSH keys, cloud credentials, browser secrets, or OS credential stores.", 0.82),
    ("SP001", re.compile(
        r"(?is)\b(?:reveal|print|output|show|display|dump|repeat|return|leak|expose)\b.{0,40}"
        r"\b(?:system prompt|system message|developer message|developer instructions|hidden instructions|hidden rules|internal rules|initial prompt)\b"
    ), "The skill tries to disclose system or developer instructions.", 0.86),
    ("SP002", re.compile(
        r"(?is)\b(?:rephrase|translate|encode|summari[sz]e|repeat|spell out|base64)\b.{0,50}"
        r"\b(?:system prompt|developer instructions|hidden rules|internal instructions|first \d+ words)\b"
    ), "The skill attempts indirect extraction of hidden instructions.", 0.78),
    ("MP001", re.compile(
        r"(?is)\b(?:write|append|add|save|store|inject|modify|edit|update|overwrite)\b.{0,40}"
        r"\b(?:CLAUDE\.md|AGENTS\.md|\.claude[\\/]|\.mcp\.json|opencode\.json|settings\.json|memory\.md|system prompt file|agent config(?:uration)?)\b"
    ), "The skill instructs the agent to write into agent configuration or memory files.", 0.84),
    ("MP002", re.compile(
        r"(?is)(?:"
        r"\b(?:remember|save|store|persist|retain|keep)\b.{0,40}\b(?:across (?:future )?sessions?|long[- ]term memory|persistent memory|conversation memory|future conversations?)\b|"
        r"\b(?:add|write|save)\b.{0,30}\b(?:to|in)\b.{0,20}\b(?:memory|memories)\b"
        r")"
    ), "The skill asks the agent to persist information across sessions.", 0.72),
    ("EA001", re.compile(
        r"(?is)(?:"
        r"\b(?:without|no need to|never)\b.{0,25}\b(?:asking|ask|confirm(?:ation)?|approval|review|consent)\b.{0,30}\b(?:the )?(?:user|human|operator)\b|"
        r"\b(?:auto[- ]?(?:approve|accept|install|execute|run|delete|modify)|autonomously (?:install|execute|run|delete|modify|decide))\b|"
        r"\b(?:never|do not|don't)\b.{0,20}\bask (?:for )?(?:permission|confirmation|approval)\b"
        r")"
    ), "The skill instructs the agent to act without human confirmation.", 0.84),
    ("RA001", re.compile(
        r"(?is)(?:"
        r"\b(?:modify|edit|rewrite|overwrite|patch)\b.{0,40}\b(?:your own (?:code|instructions|skill|configuration)|this skill(?:'s)? (?:code|file|instructions))\b|"
        r"\b(?:automatically|always|secretly)\b.{0,40}\b(?:update|edit|rewrite)\b.{0,30}\b(?:SKILL\.md|your instructions|the skill file)\b"
        r")"
    ), "The skill instructs the agent to modify its own code or instructions.", 0.82),
    ("RA002", re.compile(
        r"(?is)\b(?:install|add|create|register|write|append|schedule)\b.{0,50}"
        r"\b(?:crontab|cron job|systemd (?:service|timer)|launchd|launch agent|startup folder|"
        r"shell profile|\.bashrc|\.zshrc|\.profile|registry run|scheduled task|schtasks|autostart)\b"
    ), "The skill instructs the agent to install a persistence mechanism.", 0.82),
    ("TR001", re.compile(
        r"(?is)\b(?:use (?:this skill )?for (?:any|every|all) (?:task|request|query|prompt)|"
        r"whenever the user (?:asks|says|types) anything|"
        r"always (?:use|activate|invoke) this skill|"
        r"for all (?:tasks|requests))\b"
    ), "The skill claims an extremely broad activation scope.", 0.72),
    ("SC001", re.compile(
        r"(?i)\b(?:curl|wget|invoke-webrequest|iwr)\b[^\n]{0,300}\|\s*"
        r"(?:sudo\s+)?(?:bash|sh|zsh|powershell|pwsh|python|node|iex|invoke-expression)\b"
    ), "The skill downloads and pipes remote content directly into an interpreter.", 0.9),
    ("SC002", re.compile(
        r"(?is)\b(?:disable|turn off|bypass|ignore|skip)\b.{0,35}"
        r"\b(?:security (?:checks?|scanner|scanning)|antivirus|edr|firewall|audit|sandbox|skillguard|scanner)\b"
    ), "The skill instructs the agent to disable or bypass security controls.", 0.84),
]

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
SUSPICIOUS_COMMENT_TERMS = re.compile(
    r"(?i)(?:ignore|system prompt|password|token|secret|send|upload|curl|exec|"
    r"install|instruction|you must|do not tell|https?://)"
)
HIDDEN_CSS_RE = re.compile(r"(?i)(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem)?)")
WHITESPACE_RE = re.compile(r"[ \t]{800,}")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])")
DECODED_TERMS = re.compile(
    r"(?i)(?:exec\s*\(|eval\s*\(|os\.system|subprocess|https?://|curl\s|wget\s|"
    r"powershell|bash\s+-|/bin/sh|invoke-expression|ignore previous|system prompt|"
    r"secret|token|password|chmod|base64)"
)

BIDI_RANGES = ((0x202A, 0x202E), (0x2066, 0x2069))
ZERO_WIDTH_RANGES = ((0x200B, 0x200D), (0x2060, 0x2060), (0x00AD, 0x00AD), (0xFEFF, 0xFEFF))


def _add(
    findings: list[Finding],
    seen: set[tuple[str, int]],
    rule_id: str,
    path: str,
    text: str,
    line: int,
    message: str,
    evidence_text: str,
    confidence: float,
) -> None:
    key = (rule_id, line)
    if key in seen:
        return
    if sum(1 for f in findings if f.rule_id == rule_id) >= MAX_PER_RULE:
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


def _hidden_comments(findings: list[Finding], seen: set[tuple[str, int]], path: str, text: str) -> None:
    for match in COMMENT_RE.finditer(text):
        body = match.group(1)
        if len(body) > 5000 or not SUSPICIOUS_COMMENT_TERMS.search(body):
            continue
        line = line_number(text, match.start())
        _add(
            findings,
            seen,
            "PI002",
            path,
            text,
            line,
            "HTML comment contains instructions or sensitive terms; it is invisible in rendered markdown.",
            f"<!--{body}-->",
            0.8,
        )

    for match in HIDDEN_CSS_RE.finditer(text):
        line = line_number(text, match.start())
        _add(
            findings,
            seen,
            "PI002",
            path,
            text,
            line,
            "Content uses CSS that can hide text from normal review.",
            line_text(text, match.start(), match.end()),
            0.7,
        )


def _invisible_characters(findings: list[Finding], seen: set[tuple[str, int]], path: str, text: str) -> None:
    counts: Counter[str] = Counter()
    first_index: int | None = None
    bidi_count = 0
    zero_width_count = 0
    for index, char in enumerate(text):
        codepoint = ord(char)
        if index == 0 and codepoint == 0xFEFF:
            continue
        is_bidi = any(start <= codepoint <= end for start, end in BIDI_RANGES)
        is_zero = any(start <= codepoint <= end for start, end in ZERO_WIDTH_RANGES)
        if not (is_bidi or is_zero):
            continue
        counts[f"U+{codepoint:04X}"] += 1
        if first_index is None:
            first_index = index
        if is_bidi:
            bidi_count += 1
        if is_zero:
            zero_width_count += 1
    if first_index is None:
        return
    if bidi_count == 0 and zero_width_count < 3:
        return
    line = line_number(text, first_index)
    detail = ", ".join(f"{key} x{value}" for key, value in counts.items())
    near = line_text(text, first_index, limit=160)
    _add(
        findings,
        seen,
        "PI006",
        path,
        text,
        line,
        "Invisible or bidirectional control characters can conceal instructions.",
        f"Invisible characters: {detail}. Nearby: {near}",
        0.86,
    )


def _whitespace_padding(findings: list[Finding], seen: set[tuple[str, int]], path: str, text: str) -> None:
    for match in WHITESPACE_RE.finditer(text):
        line = line_number(text, match.start())
        _add(
            findings,
            seen,
            "PI008",
            path,
            text,
            line,
            "A large whitespace run can hide content from human review.",
            f"Whitespace run of {len(match.group(0))} characters at line {line}.",
            0.7,
        )
        break


def _encoded_payload(findings: list[Finding], seen: set[tuple[str, int]], path: str, text: str) -> None:
    checked = 0
    for match in BASE64_RE.finditer(text):
        candidate = match.group(0)
        try:
            padded = candidate[:8192]
            padded += "=" * ((4 - len(padded) % 4) % 4)
            decoded = base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            continue
        if not decoded:
            continue
        printable = sum(1 for byte in decoded if byte in (9, 10, 13) or 32 <= byte <= 126)
        if printable / len(decoded) < 0.85:
            continue
        decoded_text = decoded.decode("utf-8", errors="replace")
        if not DECODED_TERMS.search(decoded_text):
            continue
        line = line_number(text, match.start())
        _add(
            findings,
            seen,
            "PI007",
            path,
            text,
            line,
            "An encoded blob decodes to executable commands or suspicious instructions.",
            f"Base64 blob ({len(candidate)} chars) decodes to: {decoded_text[:180]}",
            0.85,
        )
        checked += 1
        if checked >= 2:
            break


def analyze_content(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for rule_id, pattern, message, confidence in RULES:
        for match in pattern.finditer(text):
            line = line_number(text, match.start())
            _add(
                findings,
                seen,
                rule_id,
                path,
                text,
                line,
                message,
                line_text(text, match.start(), match.end()),
                confidence,
            )

    _hidden_comments(findings, seen, path, text)
    _invisible_characters(findings, seen, path, text)
    _whitespace_padding(findings, seen, path, text)
    _encoded_payload(findings, seen, path, text)
    return findings
