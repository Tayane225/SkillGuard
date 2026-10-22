# Cline

## Configure

Open the Cline MCP Servers panel and choose **Configure MCP Servers**. On IDE installations, use the file that button opens.

The Cline CLI and SDK use the shared settings file:

```text
~/.cline/data/settings/cline_mcp_settings.json
```

On Windows this is normally:

```text
C:\Users\<you>\.cline\data\settings\cline_mcp_settings.json
```

Merge the entry into `mcpServers`:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "skillguard",
      "args": ["mcp"],
      "disabled": false
    }
  }
}
```

If you set `CLINE_MCP_SETTINGS_PATH`, edit the file at that path instead.

## Verify

Reload the Cline MCP panel or restart the extension host. Confirm that `skillguard` is enabled and exposes `scan_skill` and `list_rules`.

## Notes

- Cline may ask for approval for each tool call. Keep approval enabled for `scan_skill`.
- If the command cannot be found, use the absolute path from `where.exe skillguard`.
