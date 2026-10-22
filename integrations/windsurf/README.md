# Windsurf

Windsurf has two relevant MCP configuration locations. Use the file opened by your build's **Open MCP config file** action.

- Cascade's Cortex-managed configuration: `%APPDATA%\devin\mcp_config.json` on Windows or `~/.config/devin/mcp_config.json` on macOS/Linux.
- Editor MCP discovery: `%USERPROFILE%\.codeium\windsurf\mcp_config.json` on Windows or `~/.codeium/windsurf/mcp_config.json` on macOS/Linux for the stable build.

If you want Cascade to discover a server from the editor-specific file, enable the `windsurf` source for `chat.mcp.discovery.enabled` in Windsurf settings.

The JSON body is the same for the local server:

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

Merge the entry with any existing `mcpServers` and restart Windsurf.

## Notes

- Do not create duplicate `skillguard` entries in multiple files unless your build explicitly reads them.
- If the application cannot find `skillguard`, replace the command with the absolute path from `where.exe skillguard`.
- The server runs on the local machine and can read local paths. Do not expose it through a public tunnel.
