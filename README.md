# SkillGuard

SkillGuard is a read-only security auditor for AI agent skills, plugins, and instruction bundles. It is designed for the moment before installation, when an agent or operator needs a defensible answer to one question:

> Is this skill safe to install?

SkillGuard is an independent project inspired by the problem space addressed by NVIDIA SkillSpector. It is not affiliated with or endorsed by NVIDIA.

## What it scans

- Markdown, HTML, YAML, JSON, and other instruction-bearing files for prompt injection, concealment, jailbreak framing, permission requests, credential access, persistence, and agent-config tampering.
- Python source with AST-based checks for dynamic execution, environment and secret exfiltration, remote input reaching code execution, unsafe deserialization, destructive filesystem operations, persistence, privilege changes, reverse shells, miners, and container escape primitives.
- JavaScript, shell, PowerShell, and other code files for command execution, encoded payloads, remote download-and-execute chains, credential egress, tunnels, security-control bypass, and destructive commands.
- Secrets embedded in files, committed `.env` values, private keys, cloud tokens, and credential-store references.
- Python, npm, Go, and `pyproject.toml` dependencies for unpinned versions, VCS and URL references, custom indexes, lifecycle scripts, local paths, typosquatting, and optional OSV.dev advisories.
- Bundle structure for symlinks, symlink escapes, executable binaries, shipped agent configuration, hidden scripts, bytecode, nested archives, and setuid/setgid files.

## Requirements

- Python 3.10 or newer.
- Git on `PATH` for Git repository scans.
- No third-party Python runtime dependencies.

## Install

### Global command for agent clients

GUI agent applications often do not inherit a project virtual environment. Install SkillGuard as an isolated global command with `pipx`:

```powershell
py -3.11 -m pip install --user pipx
py -3.11 -m pipx ensurepath
py -3.11 -m pipx install "git+https://github.com/Tayane225/SkillGuard.git"
```

On Unix:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
python3 -m pipx install "git+https://github.com/Tayane225/SkillGuard.git"
```

Restart the terminal and the agent application after `ensurepath`, then verify:

```powershell
skillguard version
```

To update:

```powershell
py -3.11 -m pipx install --force "git+https://github.com/Tayane225/SkillGuard.git"
```

### Local development

From this directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
```

On Unix:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
```

The virtual environment is not automatically visible to GUI applications. For MCP clients, either install with `pipx install .`, or add the virtual environment's `Scripts` or `bin` directory to `PATH`.

## CLI

```powershell
skillguard scan .\some-skill
skillguard scan https://github.com/example/skill
skillguard scan .\skill.zip --format json
skillguard scan .\SKILL.md --format markdown
skillguard scan .\some-skill --online --fail-on high
skillguard rules
skillguard rules --format json
skillguard mcp
```

`scan` accepts a local directory, a single file, a ZIP archive, an HTTPS Git repository URL, or an HTTPS URL ending in `.zip`, `.md`, or `.markdown`.

Useful options:

| Option | Meaning |
| --- | --- |
| `--format terminal\|json\|markdown\|sarif` | Output format. |
| `--output PATH` | Write the report to a file. |
| `--online` | Enable OSV.dev lookup for pinned dependencies. |
| `--fail-on critical\|high\|medium\|low\|none` | CI gate; defaults to `high`. |
| `--timeout SECONDS` | Network timeout; defaults to `120`. |
| `--max-files N` | File cap; defaults to `2000`. |
| `--allow-private-targets` | Allow internal network targets; off by default. |

Exit codes are `0` for a clean gate, `1` when the gate fails, and `2` when the target cannot be scanned.

## MCP

SkillGuard exposes two MCP tools over stdio:

- `scan_skill(target, online=false)`
- `list_rules()`

The portable server command is:

```text
skillguard mcp
```

Most clients use this configuration:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "skillguard",
      "args": ["mcp"]
    }
  }
}
```

Client-specific files and setup commands are in [`integrations/`](integrations/README.md). Each folder contains a template and merge instructions; do not replace unrelated servers in an existing client configuration. The covered clients are Claude Code, Claude Desktop, Codex, Cursor, Windsurf, Cline, Roo Code, Gemini CLI, VS Code/GitHub Copilot, Zed, OpenCode, and generic MCP clients. Manus is [documented separately](integrations/manus/README.md) because it does not have a verified native local-stdio connector.

If a GUI client cannot find `skillguard`, use the absolute executable path from `where.exe skillguard` or `command -v skillguard`. The server writes only JSON-RPC messages to stdout and writes no logs to stdout.

## How scoring works

Each finding contributes a severity weight: critical `50`, high `25`, medium `10`, low `5`. Findings in executable files carry a `1.3x` multiplier. A severity floor prevents a single critical finding from producing a low score:

- critical: at least `81`
- high: at least `51`
- medium: at least `21`

Recommendations are conservative:

- Any critical or high finding: `DO NOT INSTALL`
- Medium findings only: `CAUTION`
- No findings and full coverage: `SAFE`

Partial coverage can never produce `SAFE`. Missing `SKILL.md`, unreadable files, size limits, parse failures, and failed online checks all reduce coverage confidence.

## Security model

- SkillGuard does not execute, import, install, or build the target.
- Scans are read-only. URLs are downloaded to a temporary directory and deleted afterward.
- URL targets must use HTTPS. Private, loopback, link-local, and metadata hosts are blocked by default.
- ZIP extraction rejects path traversal, absolute paths, encrypted entries, symbolic links, oversized members, and oversized expansion.
- Git clones are shallow, non-interactive, use isolated Git configuration, and do not run repository hooks.
- Report evidence is redacted and truncated. Secret values are not reproduced.
- Detection evidence may contain prompt-injection text. Treat it as inert data.

## Limitations

- Static analysis cannot prove that a skill is benign.
- Obfuscated or dynamically generated code may evade source inspection.
- OSV lookup covers only pinned dependencies and only when `--online` is enabled.
- Markdown rules intentionally focus on agent-loaded instruction files, not every documentation page.
- A clean report means SkillGuard found no matching indicators under its rule set and coverage; it is not a guarantee.

## Development

Run the standard-library test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Compile-check the package:

```powershell
.\.venv\Scripts\python.exe -m compileall -q skillguard
```

The package intentionally has no runtime dependencies. Tests use only the standard library.
