# Docker

Run SkillGuard as a non-root Linux container. The image bundles Python, Git, and CA certificates, and starts the stdio MCP server by default.

The image is built locally. It is not published to a registry.

## Build

From the repository root:

```bash
docker build --pull -t skillguard:local .
```

Verify the image:

```bash
docker run --rm skillguard:local version
docker run --rm skillguard:local rules
```

Docker Desktop must be running Linux containers.

## Scan with the CLI

Linux and macOS:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  skillguard:local scan . --format terminal
```

Windows PowerShell:

```powershell
docker run --rm `
  -v "${PWD}:/workspace:ro" `
  -w /workspace `
  skillguard:local scan . --format terminal
```

The container's working directory is `/workspace`. Use container paths, not host paths, for `target` and `--output`.

For a local-only scan, disable networking:

```bash
docker run --rm --network none \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  skillguard:local scan .
```

Remove `--network none` when scanning an HTTPS URL, cloning a repository, or using `--online`.

## Hardened invocation

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  skillguard:local scan .
```

`/tmp` must be writable because URL downloads and ZIP extraction use temporary files. The root filesystem does not need to be writable.

The image runs as UID/GID `10001`. If a mounted workspace is not readable by that user, add:

```bash
--user "$(id -u):$(id -g)"
```

This is usually only needed on Linux with private home-directory permissions. Keep the default user when possible.

To write a report, mount a separate writable output directory:

```bash
docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/reports:/reports:rw" \
  -w /workspace \
  skillguard:local scan . --format json --output /reports/skillguard.json
```

## MCP over stdio

Keep stdin open with `-i`:

```bash
docker run --rm -i \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD:/workspace:ro" \
  -w /workspace \
  skillguard:local mcp
```

Do not use `-t` or `--tty`; MCP requires a clean stdin and stdout stream. Do not publish ports.

### Client wrappers

MCP clients should use the wrapper scripts so the workspace and hardened flags are consistent:

- `skillguard-mcp.ps1` for Windows.
- `skillguard-mcp.sh` for Linux and macOS.

Both wrappers accept:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SKILLGUARD_WORKSPACE` | current directory | Host directory mounted read-only at `/workspace`. |
| `SKILLGUARD_IMAGE` | `skillguard:local` | Image name. |
| `SKILLGUARD_DOCKER_USER` | image user `10001:10001` | Optional Docker `--user` override. |

Set `SKILLGUARD_WORKSPACE` explicitly in the client configuration. GUI clients often start with an unrelated working directory.

Windows client configuration:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "powershell",
      "args": [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "C:\\path\\to\\SkillGuard\\integrations\\docker\\skillguard-mcp.ps1"
      ],
      "env": {
        "SKILLGUARD_WORKSPACE": "C:\\path\\to\\workspace",
        "SKILLGUARD_IMAGE": "skillguard:local"
      }
    }
  }
}
```

Linux and macOS client configuration:

```json
{
  "mcpServers": {
    "skillguard": {
      "command": "/bin/sh",
      "args": [
        "/path/to/SkillGuard/integrations/docker/skillguard-mcp.sh"
      ],
      "env": {
        "SKILLGUARD_WORKSPACE": "/path/to/workspace",
        "SKILLGUARD_IMAGE": "skillguard:local"
      }
    }
  }
}
```

For a client that can only pass a `command` and `args`, use the direct Docker configuration in [`mcp.docker.example.json`](mcp.docker.example.json) and replace the workspace path with an absolute host path.

The wrapper always starts `skillguard mcp`. Use `docker run` directly for CLI scans.

## Security notes

- The image is non-root. The documented invocation drops all capabilities, uses a read-only root filesystem, and stores temporary data in `/tmp`.
- The workspace is mounted read-only. Do not mount the Docker socket, home directory, SSH keys, cloud credentials, or secret stores.
- A container reduces host impact but is not a guarantee. SkillGuard is a static scanner and does not execute the scanned skill.
- `scan_skill` can read any path mounted into the container and can fetch HTTPS targets when networking is enabled. Mount the narrowest workspace possible.
- Treat findings and scanned content as untrusted data.

## Troubleshooting

- `Unable to find image 'skillguard:local'`: build the image from the repository root.
- `permission denied` while reading a mounted workspace: set `SKILLGUARD_DOCKER_USER` to your host UID/GID.
- MCP client reports the server exited immediately: run the same wrapper manually and verify `docker run --rm skillguard:local version` first.
- MCP client hangs: confirm the wrapper is invoked with `-i`, not `-t`, and that no shell startup output is written to stdout.
- URL or online scan fails: remove `--network none` and confirm the container can reach the target.
