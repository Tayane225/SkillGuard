#!/usr/bin/env sh
set -eu

image="${SKILLGUARD_IMAGE:-skillguard:local}"
workspace="${SKILLGUARD_WORKSPACE:-$(pwd)}"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is not installed or not on PATH" >&2
    exit 127
fi

case "$workspace" in
    /*) ;;
    *) workspace="$(cd "$workspace" && pwd)" ;;
esac

set -- run --rm -i --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges

if [ -n "${SKILLGUARD_DOCKER_USER:-}" ]; then
    set -- "$@" --user "$SKILLGUARD_DOCKER_USER"
fi

set -- "$@" -v "$workspace:/workspace:ro" -w /workspace "$image" mcp
exec docker "$@"
