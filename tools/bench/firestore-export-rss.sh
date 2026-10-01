#!/usr/bin/env bash
# Linux measurement for the heavy-verification linux-measure job: the resident memory of a
# release daemon around a Firestore export, at 100,000 and 300,000 documents of 1 KiB.
# Writes JSON lines to $HEAVY_OUT/firestore-export-rss.jsonl.
set -euo pipefail
out=${HEAVY_OUT:?HEAVY_OUT names the directory the job keeps}
cargo build --release --locked -p fireemu --bin fireemu
binary=$PWD/target/release/fireemu
for documents in 100000 300000; do
  # An export refuses a destination below a directory other users can write (such as /tmp).
  work=$(mktemp -d -p "${RUNNER_TEMP:-$PWD/target}")
  python3 tools/bench/firestore_export_rss.py "$binary" "$work" "$documents" 1024 |
    tee -a "$out/firestore-export-rss.jsonl"
  rm -rf "$work"
done
