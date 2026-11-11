#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
python -m pytest -q --junitxml=tests/results.xml
