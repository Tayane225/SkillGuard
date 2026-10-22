# VS Code / GitHub Copilot

VS Code workspace MCP configuration uses a top-level `servers` object, not `mcpServers`.

## Configure

1. Create `.vscode/mcp.json` in the workspace.
2. Merge the `servers` entry from `mcp.json` into the file.
3. Open the MCP view or run **MCP: List Servers**, start `skillguard`, and approve the trust prompt.

```json
{
  "servers": {
    "skillguard": {
      "type": "stdio",
      "command": "skillguard",
      "args": ["mcp"]
    }
  }
}
```

For user-level configuration, run **MCP: Open User Configuration** from the Command Palette and add the same entry.

## Portable `.mcp.json`

GitHub Copilot coding agent can read a portable `.mcp.json` file that uses the `mcpServers` shape. See [the generic integration](../generic/README.md). Do not use top-level `servers` in a portable `.mcp.json`.

## Notes

- Restart VS Code or reload the window after changing the workspace file.
- If `skillguard` is not on `PATH`, use the absolute path from `where.exe skillguard`.
- Review the trust prompt before starting the server.
