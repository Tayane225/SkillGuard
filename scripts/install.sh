#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .

echo "SkillGuard installed in .venv."
echo "Run: .venv/bin/skillguard scan <target>"
echo "For MCP clients, install globally with: python3 -m pipx install ."
echo "Or add $root/.venv/bin to PATH and restart the client."
