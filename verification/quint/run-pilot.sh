#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cd "$repository_root"

passes=${PILOT_PASSES:-1}
case "$passes" in
  ''|*[!0-9]*|0)
    echo "error: PILOT_PASSES must be a positive integer" >&2
    exit 2
    ;;
esac

: "${QUINT_REAL_BIN:?QUINT_REAL_BIN must be an absolute pinned Quint executable}"
case "$QUINT_REAL_BIN" in
  /*) ;;
  *) echo "error: QUINT_REAL_BIN must be absolute" >&2; exit 2 ;;
esac
if [ ! -x "$QUINT_REAL_BIN" ]; then
  echo "error: QUINT_REAL_BIN is not executable" >&2
  exit 2
fi

owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-quint-pilot.XXXXXX")
cleanup() {
  rm -rf -- "$owned_temp"
}
trap cleanup EXIT HUP INT TERM

run_gate() {
  gate=$1
  shift
  echo "gate: $gate"
  "$@"
}

pass=1
while [ "$pass" -le "$passes" ]; do
  echo "EventDelivery Quint pilot pass $pass/$passes"
  mutation_evidence="$owned_temp/EventDelivery-pass-$pass.json"

  run_gate tla-model verification/tla/run-tlc.sh EventDelivery
  run_gate tla-replay cargo run -p tla-verification -- check-eventdelivery
  run_gate quint-model cargo run -p fireemu-verification-quint -- verify-model
  run_gate quint-scenarios cargo test -p fireemu-verification-quint --test event_delivery_connect deterministic_scenarios_cover_all_actions -- --ignored --exact
  run_gate quint-generated cargo test -p fireemu-verification-quint --test event_delivery_connect generated_traces_match_rust -- --ignored --exact
  run_gate quint-projection-negative cargo test -p fireemu-verification-quint --test event_delivery_connect each_projection_field_detects_drift -- --ignored --exact
  run_gate quint-mutations cargo run -p fireemu-verification-quint -- mutate-event-delivery --evidence "$mutation_evidence"
  run_gate quint-evidence cargo run -p fireemu-verification-quint -- verify-evidence
  run_gate traceability cargo run -p traceability-check

  pass=$((pass + 1))
done
