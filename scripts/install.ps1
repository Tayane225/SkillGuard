$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

if (-not (Test-Path -LiteralPath ".venv")) {
    py -3.11 -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .

Write-Output "SkillGuard installed in .venv."
Write-Output "Run: .\.venv\Scripts\skillguard.exe scan <target>"
Write-Output "For MCP clients, install globally with: py -3.11 -m pipx install ."
Write-Output "Or add $root\.venv\Scripts to PATH and restart the client."
