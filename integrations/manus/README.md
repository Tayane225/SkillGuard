# Manus

Manus supports custom MCP connectors, but there is no verified native local-stdio integration that connects a Manus cloud connector to a Windows or macOS desktop process.

Official references:

- <https://manus.im/docs/integrations/custom-mcp>
- <https://www.manus.im/features/connectors>

In Manus, open **Settings > Integrations > Custom MCP Servers** and choose a server URL, a command, or **Import by JSON**. A command connector may run in Manus's environment rather than on your computer; verify where your build executes commands. Do not assume that a local path such as `C:\SkillGuard\.venv\Scripts\skillguard.exe` is reachable from a Manus cloud session.

## Option 1: Manus sandbox with Python

Use this only if your Manus workspace provides a persistent shell or sandbox and its MCP command connector runs inside that sandbox.

1. From this directory, install SkillGuard inside the sandbox:

   ```bash
   bash install.sh
   ```

   Or run the commands directly:

   ```bash
   python3 -m pip install --user "git+https://github.com/Tayane225/SkillGuard.git"
   python3 -m skillguard --version
   ```

2. In Manus, open **Settings > Integrations > Custom MCP Servers > Add Server**, choose **Command**, and enter:

   ```text
   python3 -m skillguard mcp
   ```

   You can also import `mcp.sandbox.example.json`. It is an example, not a promise that every Manus build imports this file.

3. Confirm that `scan_skill` and `list_rules` appear before relying on the connector.

If your Manus build runs command connectors on your own computer, use the absolute `skillguard` executable path with the argument `mcp` instead of `python3 -m skillguard mcp`.

## Option 2: Remote HTTPS bridge

SkillGuard currently ships a stdio server, not an HTTP server. To use a Manus URL connector, run `skillguard mcp` on a host you control behind a maintained stdio-to-HTTP MCP bridge, then configure the HTTPS URL in Manus.

This is an advanced deployment and is not provided as a turnkey script. At minimum:

- Require TLS and authentication on the bridge.
- Restrict which filesystem paths the server process can read.
- Do not expose a desktop filesystem or a developer machine to the public internet.
- Treat every Manus caller as untrusted.

## Option 3: CLI workflow

If your Manus workspace provides a computer or shell tool, run the scanner directly instead of using MCP:

```bash
python3 -m skillguard scan <path-or-url> --format json --fail-on high
```

## Known limitation

No `integrations/manus` configuration should be described as a fully local, native Manus MCP installation. The supported paths are the sandbox, a secured remote bridge, or direct CLI use.
