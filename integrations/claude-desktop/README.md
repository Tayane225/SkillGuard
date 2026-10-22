# Claude Desktop

## Configure

1. Open Claude Desktop.
2. Open **Settings > Developer > Edit Config**.
3. Merge the `mcpServers` entry from `claude_desktop_config.json` into the existing configuration. Do not replace other servers.
4. Fully quit Claude Desktop, including the tray or menu-bar process, and reopen it.

Configuration locations:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

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

## Verify

Open a conversation and check the tools or connectors menu for `scan_skill` and `list_rules`.

## Notes

- Claude Desktop may not inherit your shell `PATH`. If the server fails to start, run `where.exe skillguard` and use the absolute executable path in JSON.
- The server is read-only, but it can read local paths on this computer. Keep it local and review each tool call.
