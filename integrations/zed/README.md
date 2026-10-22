# Zed

Zed calls MCP servers `context_servers`.

## Configure

Open Zed settings with the `zed: open settings` command, then merge the entry:

```json
{
  "context_servers": {
    "skillguard": {
      "source": "custom",
      "command": "skillguard",
      "args": ["mcp"]
    }
  }
}
```

Restart Zed or reload the settings. Open the agent panel's context server settings and confirm that `skillguard` is running.

## Notes

- If Zed cannot find `skillguard`, use the absolute path from `where.exe skillguard`.
- Keep the server local. `scan_skill` can read local paths in the account that launched Zed.
