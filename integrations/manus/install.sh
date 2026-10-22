#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install --user "git+https://github.com/Tayane225/SkillGuard.git"
python3 -m skillguard --version
