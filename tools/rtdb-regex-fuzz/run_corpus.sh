#!/usr/bin/env bash
# Probes a fixed corpus on a fresh official emulator per chunk and on fireemu, then compares.
#
#   JAR=<jar> FIREEMU=<host:port> tools/rtdb-regex-fuzz/run_corpus.sh <corpus.json> <out dir> [chunk]
#
# The official emulator holds every namespace in memory, so it starts again for each chunk
# (2,000 expressions by default). Exits 1 when a row allows on fireemu what it denies.
set -euo pipefail
corpus=$1 out=$2 chunk=${3:-2000}
here=$(cd "$(dirname "$0")" && pwd)
jar_port=${JAR_PORT:-19600}
: "${JAR:?JAR names the official database emulator jar}" "${FIREEMU:?FIREEMU is host:port}"
mkdir -p "$out"
name=$(basename "$corpus" .json)
count=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$corpus")
part=0
for ((from = 0; from < count; from += chunk)); do
  part=$((part + 1))
  python3 -c "import json,sys; rows=json.load(open(sys.argv[1])); json.dump(rows[int(sys.argv[2]):int(sys.argv[2])+int(sys.argv[3])], open(sys.argv[4],'w'), ensure_ascii=False)" \
    "$corpus" "$from" "$chunk" "$out/$name.$part.json"
  while curl -s -o /dev/null "http://127.0.0.1:$jar_port/.json?ns=x"; do sleep 1; done
  java -Xmx2g -Duser.language=en -jar "$JAR" --port "$jar_port" --host 127.0.0.1 > "$out/jar-$name.$part.log" 2>&1 &
  jar_pid=$!
  # A probe that stops must not leave the emulator holding the port for the next run.
  trap 'kill "$jar_pid" 2>/dev/null || true; wait "$jar_pid" 2>/dev/null || true' EXIT
  until curl -s -o /dev/null "http://127.0.0.1:$jar_port/.json?ns=x"; do sleep 1; done
  node "$here/probe.mjs" "127.0.0.1:$jar_port" "$out/$name.$part.json" "$out/jar-$name.$part.json" "${PROBE_WORKERS:-4}" &
  probe=$!
  node "$here/probe.mjs" "$FIREEMU" "$out/$name.$part.json" "$out/emu-$name.$part.json" "${PROBE_WORKERS:-4}"
  wait "$probe"
  kill "$jar_pid"
  wait "$jar_pid" 2>/dev/null || true
done
python3 - "$out" "$name" "$part" <<'PY'
import json, sys
out, name, parts = sys.argv[1], sys.argv[2], int(sys.argv[3])
for side in ("jar", "emu"):
    rows = []
    for p in range(1, parts + 1):
        rows += json.load(open(f"{out}/{side}-{name}.{p}.json", encoding="utf-8"))
    json.dump(rows, open(f"{out}/{side}-{name}.json", "w", encoding="utf-8"), ensure_ascii=False)
PY
python3 "$here/compare.py" "$out/jar-$name.json" "$out/emu-$name.json" "$out/report-$name.txt" "$out/interesting-$name.json"
! grep -q '^BLOCKING' "$out/report-$name.txt"
