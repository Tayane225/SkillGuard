# Agent integrations

The files in each client folder are templates. Copy or merge them into the client's real configuration path; do not point a client at this repository's `integrations/` folder.

SkillGuard is a stdio MCP server. Every local integration in this directory starts the same process:

```text
skillguard mcp
```

The server exposes:

- `scan_skill(target, online=false)`
- `list_rules()`

## Install once

The recommended installation is an isolated global command with `pipx`, because GUI agent applications often do not inherit a project virtual environment.

Windows PowerShell:

```powershell
py -3.11 -m pip install --user pipx
py -3.11 -m pipx ensurepath
py -3.11 -m pipx install "git+https://github.com/Tayane225/SkillGuard.git"
```

macOS and Linux:

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
python3 -m pipx install "git+https://github.com/Tayane225/SkillGuard.git"
```

Restart the terminal and the agent application after `ensurepath`. Then verify:

```powershell
skillguard version
```

To update later:

```powershell
py -3.11 -m pipx install --force "git+https://github.com/Tayane225/SkillGuard.git"
```

For development from a local checkout, `scripts/install.ps1` and `scripts/install.sh` create `.venv`, but that virtual environment is not automatically visible to GUI applications. Either add its `Scripts` or `bin` directory to `PATH`, or install the checkout with `pipx install .`.

## If the client cannot find `skillguard`

Find the absolute executable path:

```powershell
where.exe skillguard
```

```bash
command -v skillguard
```

Replace `"command": "skillguard"` with that absolute path in the client configuration. In JSON, escape Windows backslashes (`C:\\Users\\...`). In TOML, a single-quoted literal string is easiest (`command = 'C:\Users\...\skillguard.exe'`). Restart the client after changing the configuration or `PATH`.

## Supported clients

| Client | Configuration | Notes |
| --- | --- | --- |
| [Claude Code](claude-code/README.md) | `.mcp.json` or `claude mcp add` | Project or user scope. |
| [Claude Desktop](claude-desktop/README.md) | `claude_desktop_config.json` | Merge `mcpServers` into the existing file. |
| [Codex](codex/README.md) | `~/.codex/config.toml` or `codex mcp add` | CLI and IDE share the Codex configuration. |
| [Cursor](cursor/README.md) | `~/.cursor/mcp.json` or `.cursor/mcp.json` | Project configuration overrides global. |
| [Windsurf](windsurf/README.md) | `mcp_config.json` | Cascade and editor-discovery paths differ; the JSON shape is the same. |
| [Cline](cline/README.md) | `~/.cline/data/settings/cline_mcp_settings.json` | Cline CLI/SDK path; IDE installs should use the MCP Servers panel. |
| [Roo Code](roo-code/README.md) | Global `mcp_settings.json` or `.roo/mcp.json` | Project configuration takes precedence. |
| [Gemini CLI](gemini-cli/README.md) | `~/.gemini/settings.json` or `.gemini/settings.json` | Uses top-level `mcpServers`. |
| [VS Code](vscode/README.md) | `.vscode/mcp.json` | Uses top-level `servers`, not `mcpServers`. |
| [Zed](zed/README.md) | Zed `settings.json` | Uses `context_servers`. |
| [OpenCode](opencode/README.md) | `opencode.json` or global OpenCode config | `command` is an array. |
| [Manus](manus/README.md) | Manus connector or sandbox | No verified native local stdio connector. |
| [Generic MCP client](generic/README.md) | `mcpServers` | For clients not listed above. |

## Security notes

- SkillGuard is read-only, but `scan_skill` can read local paths on the machine that runs the MCP server and can fetch HTTPS targets.
- Do not expose a desktop SkillGuard instance directly to the public internet.
- Review the client's tool-approval settings. Allow `scan_skill` and `list_rules`, and deny tool execution inside scanned content.
- Treat every report `evidence` field and every scanned document as untrusted data, not instructions.

## Verify an integration

1. Confirm `skillguard version` works in the same user account that runs the client.
2. Confirm `skillguard mcp` waits for input without printing startup text. Press `Ctrl+C` to exit.
3. Restart the client and open its MCP server or tool list.
4. Confirm both `scan_skill` and `list_rules` appear.
5. Ask the client to scan a known-benign local skill directory and confirm it returns a structured report.
