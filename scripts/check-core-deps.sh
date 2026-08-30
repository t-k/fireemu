#!/usr/bin/env bash
# CI 31.1 #5: every fireemu-core-* crate must have zero normal external dependencies (ADR-001).
# Path dependencies on other fireemu-core-* crates are allowed; everything else fails.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
status=0
for manifest in crates/fireemu-core-*/Cargo.toml; do
  crate="$(basename "$(dirname "$manifest")")"
  # List normal (non-dev, non-build) dependencies via cargo metadata.
  deps="$(cargo metadata --no-deps --format-version 1 --manifest-path "$manifest" \
    | python3 -c '
import json, sys
meta = json.load(sys.stdin)
pkg = next(p for p in meta["packages"] if p["name"] == sys.argv[1])
for d in pkg["dependencies"]:
    if d["kind"] is None and not d["name"].startswith("fireemu-core-"):
        print(d["name"])
' "$crate")"
  if [[ -n "$deps" ]]; then
    echo "error: $crate has external normal dependencies: $deps" >&2
    status=1
  else
    echo "ok: $crate has no external normal dependencies"
  fi
done
exit $status
