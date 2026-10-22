# Roo Code

## Configure

Use one of these configurations:

- Global: open **MCP Servers > Edit Global MCP** and merge the entry into `mcp_settings.json`.
- Project: create `.roo/mcp.json` in the project root.

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "skillguard",
      "args": ["mcp"],
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

Project-level configuration takes precedence over global configuration for the same server name.

## Verify

Reload the MCP panel or restart the extension host. Confirm that `skillguard` is enabled and exposes `scan_skill` and `list_rules`.

## Notes

- An empty `alwaysAllow` list means Roo Code should ask before each tool call. Keep that default unless you have reviewed the server.
- If `skillguard` is not on `PATH`, use the absolute path from `where.exe skillguard`.
