# OpenCode

## Configure

Use one of these locations:

- Project: `opencode.json` or `opencode.jsonc` in the project root
- Global: `~/.config/opencode/opencode.json` on macOS/Linux, or `%USERPROFILE%\.config\opencode\opencode.json` on Windows

Copy the `mcp` object from `opencode.config.example.json` into `opencode.json` and merge it with any existing `mcp` entries:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "skillguard": {
      "type": "local",
      "command": ["skillguard", "mcp"],
      "enabled": true
    }
  }
}
```

OpenCode's local `command` is an array: the executable first, then arguments. The example file is not active until you copy it to one of OpenCode's configuration locations.

## Verify

Restart OpenCode and open its MCP status or tool list. Confirm that `scan_skill` and `list_rules` are available.

## Notes

- If OpenCode cannot find `skillguard`, use the absolute path as the first array element.
- Keep the server local; `scan_skill` can read local paths in the account that launched OpenCode.
