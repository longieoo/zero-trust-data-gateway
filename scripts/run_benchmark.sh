#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python scripts/seed_data.py
python -m benchmark.runner "$@"
