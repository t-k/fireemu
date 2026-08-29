#!/usr/bin/env bash
# Runs TLC on every model in this directory (or the models given as arguments).
#
# Requires Java 21 and the pinned TLA+ Tools jar. Set TLA2TOOLS_JAR to point at
# tla2tools.jar (v1.8.0, sha256 eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a,
# https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
jar="${TLA2TOOLS_JAR:-$here/../../.tools/tla2tools-1.8.0.jar}"
if [[ ! -f "$jar" ]]; then
  echo "error: tla2tools.jar not found at $jar (set TLA2TOOLS_JAR)" >&2
  exit 2
fi

models=("$@")
if [[ ${#models[@]} -eq 0 ]]; then
  models=()
  for f in "$here"/*.tla; do
    models+=("$(basename "$f" .tla)")
  done
fi

status=0
for m in "${models[@]}"; do
  echo "== TLC $m"
  workdir="$(mktemp -d)"
  cp "$here/$m.tla" "$here/$m.cfg" "$workdir/"
  if ! (cd "$workdir" && java -XX:+UseParallelGC -Dtlc2.TLC.stopAfter=600 -cp "$jar" tlc2.TLC \
        -workers auto -deadlock -config "$m.cfg" "$m.tla" | tail -n 25); then
    status=1
  fi
  rm -rf "$workdir"
done
exit $status
