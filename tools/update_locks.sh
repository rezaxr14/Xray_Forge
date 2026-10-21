#!/usr/bin/env bash
# Regenerate the hash-pinned Python lock files (needs network + uv).
#
#   tools/update_locks.sh
#
# Writes requirements.lock (runtime) and requirements-ci.lock (runtime + CI/build
# tools).  --universal makes one file valid for Linux and Windows and every
# supported Python; --generate-hashes lets `pip install --require-hashes` verify
# each download.  Review the diff, commit, then switch the workflows to:
#   pip install --require-hashes -r requirements-ci.lock
set -euo pipefail
cd "$(dirname "$0")/.."
uv pip compile requirements.txt --universal --generate-hashes --python-version 3.10 \
  --no-header -o requirements.lock
uv pip compile requirements-ci.in --universal --generate-hashes --python-version 3.10 \
  --no-header -o requirements-ci.lock
echo "wrote requirements.lock and requirements-ci.lock"
