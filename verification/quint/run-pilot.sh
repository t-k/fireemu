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

group_launcher="$script_dir/bin/process-group"
if [ ! -x "$group_launcher" ]; then
  echo "error: process-group launcher is not executable" >&2
  exit 2
fi

owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-quint-pilot.XXXXXX")
active_pid=
active_pgid=
cleanup() {
  rm -rf -- "$owned_temp"
}

stop_active_gate() {
  if [ -z "$active_pid" ] || [ -z "$active_pgid" ]; then
    return
  fi

  pid=$active_pid
  pgid=$active_pgid
  kill -TERM -- "-$pgid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  (
    sleep 2
    kill -KILL -- "-$pgid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
  ) &
  escalation_pid=$!

  set +e
  wait "$pid" 2>/dev/null
  set -e
  if kill -0 -- "-$pgid" 2>/dev/null; then
    set +e
    wait "$escalation_pid" 2>/dev/null
    set -e
  else
    kill -TERM "$escalation_pid" 2>/dev/null || true
    set +e
    wait "$escalation_pid" 2>/dev/null
    set -e
  fi
  active_pid=
  active_pgid=
}

handle_signal() {
  status=$1
  trap - EXIT HUP INT TERM
  stop_active_gate
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

run_gate() {
  gate=$1
  shift
  echo "gate: $gate"
  "$group_launcher" "$@" &
  active_pid=$!
  active_pgid=$active_pid
  set +e
  wait "$active_pid"
  status=$?
  set -e
  active_pid=
  active_pgid=
  return "$status"
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
