from __future__ import annotations

import json
import unittest
from pathlib import Path

try:
    import tomllib
except ImportError:
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
INTEGRATIONS = ROOT / "integrations"

CLIENTS = [
    "claude-code",
    "claude-desktop",
    "codex",
    "cursor",
    "windsurf",
    "cline",
    "roo-code",
    "gemini-cli",
    "vscode",
    "zed",
    "opencode",
    "manus",
    "docker",
    "generic",
]

MCP_SERVERS_CLIENTS = [
    "claude-code",
    "claude-desktop",
    "cursor",
    "windsurf",
    "cline",
    "roo-code",
    "gemini-cli",
    "generic",
]


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class IntegrationTests(unittest.TestCase):
    def test_every_client_has_readme_and_config(self) -> None:
        for client in CLIENTS:
            with self.subTest(client=client):
                directory = INTEGRATIONS / client
                self.assertTrue(directory.is_dir())
                self.assertTrue((directory / "README.md").is_file())
                self.assertTrue(any(directory.glob("*.json")) or any(directory.glob("*.toml")))

    def test_all_integration_json_parses(self) -> None:
        for path in INTEGRATIONS.rglob("*.json"):
            with self.subTest(path=path):
                self.assertIsInstance(load_json(path), dict)

    def test_portable_mcp_servers_configs(self) -> None:
        for client in MCP_SERVERS_CLIENTS:
            with self.subTest(client=client):
                directory = INTEGRATIONS / client
                path = next(directory.glob("*.json"))
                payload = load_json(path)
                server = payload["mcpServers"]["skillguard"]
                self.assertEqual(server["command"], "skillguard")
                self.assertEqual(server["args"], ["mcp"])

    def test_codex_toml_config(self) -> None:
        text = (INTEGRATIONS / "codex" / "config.toml").read_text(encoding="utf-8")
        if tomllib is None:
            self.assertIn("[mcp_servers.skillguard]", text)
            self.assertIn('command = "skillguard"', text)
            self.assertIn('args = ["mcp"]', text)
            return
        server = tomllib.loads(text)["mcp_servers"]["skillguard"]
        self.assertEqual(server["command"], "skillguard")
        self.assertEqual(server["args"], ["mcp"])

    def test_vscode_uses_servers_key(self) -> None:
        server = load_json(INTEGRATIONS / "vscode" / "mcp.json")["servers"]["skillguard"]
        self.assertEqual(server["type"], "stdio")
        self.assertEqual(server["command"], "skillguard")
        self.assertEqual(server["args"], ["mcp"])

    def test_zed_uses_context_servers(self) -> None:
        server = load_json(INTEGRATIONS / "zed" / "settings.json")["context_servers"]["skillguard"]
        self.assertEqual(server["source"], "custom")
        self.assertEqual(server["command"], "skillguard")
        self.assertEqual(server["args"], ["mcp"])

    def test_opencode_uses_local_command_array(self) -> None:
        server = load_json(INTEGRATIONS / "opencode" / "opencode.config.example.json")["mcp"][
            "skillguard"
        ]
        self.assertEqual(server["type"], "local")
        self.assertEqual(server["command"], ["skillguard", "mcp"])
        self.assertTrue(server["enabled"])

    def test_docker_config_keeps_stdio_open_and_is_hardened(self) -> None:
        config = load_json(INTEGRATIONS / "docker" / "mcp.docker.example.json")
        server = config["mcpServers"]["skillguard"]
        self.assertEqual(server["command"], "docker")
        args = server["args"]
        for flag in (
            "--rm",
            "-i",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "mcp",
        ):
            self.assertIn(flag, args)
        self.assertIn("skillguard:local", args)
        self.assertTrue(any(arg.endswith(":/workspace:ro") for arg in args))

    def test_docker_wrappers_keep_stdio_open_and_are_hardened(self) -> None:
        wrappers = {
            "skillguard-mcp.sh": ('exec docker "$@"', "SKILLGUARD_WORKSPACE"),
            "skillguard-mcp.ps1": ("& docker @dockerArgs", "SKILLGUARD_WORKSPACE"),
        }
        for name, (execution, workspace_env) in wrappers.items():
            with self.subTest(wrapper=name):
                text = (INTEGRATIONS / "docker" / name).read_text(encoding="utf-8")
                self.assertIn(execution, text)
                self.assertIn(workspace_env, text)
                for flag in (
                    "--rm",
                    "-i",
                    "--read-only",
                    "--tmpfs",
                    "/tmp",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "mcp",
                ):
                    self.assertIn(flag, text)

    def test_dockerfile_uses_a_non_root_runtime(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12-slim-bookworm", text)
        self.assertIn("ca-certificates", text)
        self.assertIn("git", text)
        self.assertIn("USER skillguard", text)
        self.assertIn('ENTRYPOINT ["skillguard"]', text)
        self.assertIn('CMD ["mcp"]', text)
        self.assertIn("COPY --from=builder /opt/venv /opt/venv", text)

    def test_dockerignore_excludes_development_state(self) -> None:
        entries = set(
            (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        )
        for entry in (".git", ".venv", "tests", "integrations", "__pycache__"):
            self.assertIn(entry, entries)

    def test_manus_is_documented_without_false_local_claim(self) -> None:
        config = load_json(INTEGRATIONS / "manus" / "mcp.sandbox.example.json")
        server = config["mcpServers"]["skillguard"]
        self.assertEqual(server["command"], "python3")
        self.assertEqual(server["args"], ["-m", "skillguard", "mcp"])
        readme = (INTEGRATIONS / "manus" / "README.md").read_text(encoding="utf-8")
        self.assertIn("no verified native local-stdio integration", readme)
        self.assertIn("https://manus.im/docs/integrations/custom-mcp", readme)
        installer = (INTEGRATIONS / "manus" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("github.com/Tayane225/SkillGuard.git", installer)

    def test_integration_index_covers_all_clients(self) -> None:
        text = (INTEGRATIONS / "README.md").read_text(encoding="utf-8").lower()
        labels = {"vscode": "vs code"}
        for client in CLIENTS:
            with self.subTest(client=client):
                self.assertIn(labels.get(client, client.replace("-", " ")), text)

    def test_integration_configs_have_no_machine_paths(self) -> None:
        for path in INTEGRATIONS.rglob("*"):
            if path.suffix not in {".json", ".toml"}:
                continue
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("C:\\SkillGuard", text)
                self.assertNotIn("/SkillGuard", text)


if __name__ == "__main__":
    unittest.main()
