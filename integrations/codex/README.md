# Codex

Codex CLI and the Codex IDE extension share MCP configuration.

## Add with the CLI

```powershell
codex mcp add skillguard -- skillguard mcp
codex mcp list
```

## Add with TOML

Edit `~/.codex/config.toml`:

```toml
[mcp_servers.skillguard]
command = "skillguard"
args = ["mcp"]
```

For a trusted project, Codex can also read `.codex/config.toml` from the project root. Project configuration is loaded only when the project is trusted.

## Notes

- Restart Codex after changing the configuration.
- If `skillguard` is not on `PATH`, use the absolute path from `where.exe skillguard`. In TOML, single quotes avoid backslash escaping: `command = 'C:\Users\you\.local\bin\skillguard.exe'`.
- If Codex runs inside WSL, install SkillGuard inside WSL and use the Linux command path. A Windows executable path will not work from WSL.
