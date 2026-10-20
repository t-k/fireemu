#!/usr/bin/env bash
# One differential round: a fresh official emulator, a generated corpus, both servers probed,
# the answers compared. Exits 1 when a row allows on fireemu what the official emulator denies.
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
java -Xmx2g -Duser.language=en -jar "$JAR" --port "$jar_port" --host 127.0.0.1 > "$out/jar-$seed.log" 2>&1 &
jar_pid=$!
trap 'kill "$jar_pid" 2>/dev/null || true' EXIT
until curl -s -o /dev/null "http://127.0.0.1:$jar_port/.json?ns=x"; do sleep 1; done
python3 "$here/gen.py" "$seed" "$count" "$out/corpus-$seed.json" $edges > /dev/null
node "$here/probe.mjs" "127.0.0.1:$jar_port" "$out/corpus-$seed.json" "$out/jar-$seed.json" &
probe=$!
node "$here/probe.mjs" "$FIREEMU" "$out/corpus-$seed.json" "$out/emu-$seed.json"
wait "$probe"
python3 "$here/compare.py" "$out/jar-$seed.json" "$out/emu-$seed.json" "$out/report-$seed.txt" "$out/interesting-$seed.json"
! grep -q '^BLOCKING' "$out/report-$seed.txt"
