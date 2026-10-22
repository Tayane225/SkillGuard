# Gemini CLI

## Configure

Edit the user settings:

```text
~/.gemini/settings.json
```

On Windows this is normally `C:\Users\<you>\.gemini\settings.json`.

For a project-scoped server, use `.gemini/settings.json` in the project root instead.

Merge the entry into `mcpServers`:

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

Restart Gemini CLI and run `/mcp` in an interactive session to inspect the server and its tools.

## Notes

- Gemini CLI reads MCP configuration from settings files, not from this directory directly.
- If the application cannot find `skillguard`, use the absolute path from `where.exe skillguard`.
- Keep the server local; `scan_skill` can read local paths in the account that launched Gemini CLI.
