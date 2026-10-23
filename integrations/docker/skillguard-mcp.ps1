param(
    [string]$Workspace = $(if ($env:SKILLGUARD_WORKSPACE) { $env:SKILLGUARD_WORKSPACE } else { (Get-Location).Path }),
    [string]$Image = $(if ($env:SKILLGUARD_IMAGE) { $env:SKILLGUARD_IMAGE } else { "skillguard:local" })
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine("error: docker is not installed or not on PATH")
    exit 127
}

if (-not [System.IO.Path]::IsPathRooted($Workspace)) {
    $Workspace = (Resolve-Path -LiteralPath $Workspace).Path
}

$dockerArgs = @(
    "run",
    "--rm",
    "-i",
    "--read-only",
    "--tmpfs",
    "/tmp",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges"
)

if ($env:SKILLGUARD_DOCKER_USER) {
    $dockerArgs += @("--user", $env:SKILLGUARD_DOCKER_USER)
}

$dockerArgs += @(
    "-v",
    "${Workspace}:/workspace:ro",
    "-w",
    "/workspace",
    $Image,
    "mcp"
)

& docker @dockerArgs
exit $LASTEXITCODE
