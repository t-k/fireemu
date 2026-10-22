#!/usr/bin/env bash
# One differential round: a fresh official emulator, a generated corpus, both servers probed in
# every cell (see probe.mjs), the answers compared. Exits 1 when a cell allows on fireemu what the
# official emulator denies.
#
#   JAR=<firebase-database-emulator-v4.11.2.jar> FIREEMU=<host:port of a running fireemu> \
#     tools/rtdb-regex-fuzz/round.sh <seed> <count> <out dir> [edges]
#
# fireemu must serve the Realtime Database under the emulator profile (unsigned tokens are users),
# for example `fireemu up --only database --database-port 19601` with {"profile": "emulator"}.
set -euo pipefail
seed=$1 count=$2 out=$3 edges=${4:-}
here=$(cd "$(dirname "$0")" && pwd)
jar_port=${JAR_PORT:-19600}
: "${JAR:?JAR names the official database emulator jar}" "${FIREEMU:?FIREEMU is host:port}"
mkdir -p "$out"
# The previous round's emulator may still be stopping: wait until the port is free.
while curl -s -o /dev/null "http://127.0.0.1:$jar_port/.json?ns=x"; do sleep 1; done
java -Xmx2g -Duser.language=en -jar "$JAR" --port "$jar_port" --host 127.0.0.1 > "$out/jar-$seed.log" 2>&1 &
jar_pid=$!
trap 'kill "$jar_pid" 2>/dev/null || true; wait "$jar_pid" 2>/dev/null || true' EXIT
until curl -s -o /dev/null "http://127.0.0.1:$jar_port/.json?ns=x"; do sleep 1; done
python3 "$here/gen.py" "$seed" "$count" "$out/corpus-$seed.json" $edges > /dev/null
python3 "$here/check_coverage.py" "$out/corpus-$seed.coverage.json" "${MIN_COVERAGE:-5}" $edges
# The second, third and fourth independent generators (the r8, r9 and r10 reviews wrote them
# without reference to gen.py) add as many expressions each, each with its negation.
python3 "$here/gen2.py" "$seed" "$count" "$out/gen2-$seed.json" > /dev/null
python3 "$here/gen9.py" "$seed" "$count" "$out/gen9-$seed.json" > /dev/null
python3 "$here/gen10.py" "$seed" "$count" "$out/gen10-$seed.json" > /dev/null
python3 - "$out/corpus-$seed.json" "$out/gen2-$seed.json" "$out/gen9-$seed.json" "$out/gen10-$seed.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1], encoding="utf-8"))
for extra in sys.argv[2:]:
    for expr in json.load(open(extra, encoding="utf-8")):
        rows += [expr, f"!({expr})"]
json.dump(rows, open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=0)
PY
node "$here/probe.mjs" "127.0.0.1:$jar_port" "$out/corpus-$seed.json" "$out/jar-$seed.json" "${PROBE_WORKERS:-4}" &
probe=$!
node "$here/probe.mjs" "$FIREEMU" "$out/corpus-$seed.json" "$out/emu-$seed.json" "${PROBE_WORKERS:-4}"
wait "$probe"
python3 "$here/compare.py" "$out/jar-$seed.json" "$out/emu-$seed.json" "$out/report-$seed.txt" "$out/interesting-$seed.json"
# The write kinds: gen11 entries (its controls first) over every write operation.
python3 "$here/gen11.py" "$seed" "${WRITE_COUNT:-500}" "$out/writes-$seed.json" "$out/writes-$seed.coverage.json" > /dev/null
node "$here/write_probe.mjs" "127.0.0.1:$jar_port" "$out/writes-$seed.json" "$out/jar-writes-$seed.json" "${PROBE_WORKERS:-4}" > /dev/null &
probe=$!
node "$here/write_probe.mjs" "$FIREEMU" "$out/writes-$seed.json" "$out/emu-writes-$seed.json" "${PROBE_WORKERS:-4}" > /dev/null
wait "$probe"
python3 "$here/write_compare.py" "$out/jar-writes-$seed.json" "$out/emu-writes-$seed.json" "$out/report-writes-$seed.txt" "$out/interesting-writes-$seed.json"
! grep -q '^BLOCKING' "$out/report-$seed.txt" "$out/report-writes-$seed.txt"
