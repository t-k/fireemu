#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cd "$repository_root"

passes=${VERIFICATION_PASSES:-1}
case "$passes" in
  ''|*[!0-9]*|0)
    echo "error: VERIFICATION_PASSES must be a positive integer" >&2
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

owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-quint-authority.XXXXXX")
active_pid=
launching=0
pending_signal=
cleanup() {
  rm -rf -- "$owned_temp"
}

stop_active_gate() {
  signal_name=$1
  if [ -z "$active_pid" ]; then
    return
  fi

  pid=$active_pid
  kill "-$signal_name" "$pid" 2>/dev/null || true
  set +e
  wait "$pid" 2>/dev/null
  set -e
  active_pid=
}

handle_signal() {
  signal_name=$1
  status=$2
  if [ "$launching" -eq 1 ]; then
    pending_signal="$signal_name:$status"
    return
  fi
  trap - EXIT HUP INT TERM
  stop_active_gate "$signal_name"
  cleanup
  exit "$status"
}

trap cleanup EXIT
trap 'handle_signal HUP 129' HUP
trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM

run_gate() {
  gate=$1
  shift
  echo "gate: $gate"
  launching=1
  "$group_launcher" "$@" &
  active_pid=$!
  launching=0
  if [ -n "$pending_signal" ]; then
    signal_name=${pending_signal%%:*}
    signal_status=${pending_signal#*:}
    pending_signal=
    handle_signal "$signal_name" "$signal_status"
  fi
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
  echo "Quint authority pass $pass/$passes"
  for entry in \
    AtomicCommitOutbox:atomic_commit_outbox_connect \
    AtomicExportPublication:atomic_export_publication_connect \
    AuthTotp:auth_totp_connect \
    AwaitIdle:await_idle_connect \
    EventDelivery:event_delivery_connect \
    RegexAuthorization:regex_authorization_connect \
    RulesetActivation:ruleset_activation_connect \
    SessionEpoch:session_epoch_connect \
    StorageGeneration:storage_generation_connect
  do
    model=${entry%%:*}
    test_target=${entry#*:}
    mutation_evidence="$owned_temp/$model-pass-$pass.json"
    run_gate "$model-model" cargo run -p fireemu-verification-quint -- verify-model --model "$model"
    run_gate "$model-connect" cargo test -p fireemu-verification-quint --test "$test_target" -- --ignored --test-threads=1
    run_gate "$model-mutations" cargo run -p fireemu-verification-quint -- mutate-model --model "$model" --evidence "$mutation_evidence"
    run_gate "$model-evidence" cargo run -p fireemu-verification-quint -- verify-evidence --model "$model" --evidence "$mutation_evidence"
  done
  run_gate traceability cargo run -p traceability-check

  pass=$((pass + 1))
done
