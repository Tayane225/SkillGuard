# Generic MCP client

Many MCP clients use the same `mcpServers` configuration shape:

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

If your client requires an explicit transport, add:

```json
{
  "mcpServers": {
    "skillguard": {
      "type": "stdio",
      "command": "skillguard",
      "args": ["mcp"]
    }
  }
}
```

If your client uses a different top-level key, keep the inner server object and see that client's documentation for the wrapper.

## Notes

- `command` must resolve in the client's environment. GUI clients may not inherit your shell `PATH`.
- Relative paths are resolved from the client's working directory, which is often not your project. Use absolute paths for targets when necessary.
- Restart the client after adding the server.
- Do not expose this local stdio server through an unauthenticated network bridge.
