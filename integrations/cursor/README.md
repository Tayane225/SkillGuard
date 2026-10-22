# Cursor

## Configure

Use one of these locations:

- Global: `~/.cursor/mcp.json`
- Project: `.cursor/mcp.json` in the project root

Merge the `mcpServers` entry from `mcp.json` into the existing file:

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

Project configuration overrides global configuration for the same server name.

## Verify

Restart Cursor, open the MCP settings or tools panel, and confirm that `skillguard` is enabled. Cursor may ask you to approve individual tool calls.

## Notes

- If Cursor cannot find `skillguard`, run `where.exe skillguard` and use the absolute path in JSON.
- Keep the server local. `scan_skill` can read local paths in the account that launched Cursor.
