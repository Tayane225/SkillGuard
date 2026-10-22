# Claude Code

Claude Code supports project-scoped and user-scoped MCP servers.

## Add with the CLI

From the project where you want SkillGuard available:

```powershell
claude mcp add --scope project skillguard -- skillguard mcp
claude mcp list
claude mcp get skillguard
```

Use `--scope user` instead of `--scope project` to make SkillGuard available in all projects.

## Add with a project file

Copy `mcp.json` to the project root as `.mcp.json` and merge it with any existing servers:

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

Claude Code asks you to approve project-scoped MCP servers. Review the configuration before approving it.

## Notes

- If `skillguard` is not on the application's `PATH`, replace the command with the absolute path from `where.exe skillguard`.
- Do not commit machine-specific absolute paths to `.mcp.json`.
- Restart Claude Code or reload the project after changing the configuration.
