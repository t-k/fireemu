#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
cd "$repository_root"

authority_lock="$script_dir/bin/authority-lock"
authority_target="$script_dir/evidence"
lock_fd=${FIREEMU_QUINT_AUTHORITY_LOCK_FD:-}
if [ -z "$lock_fd" ]; then
  if [ ! -x "$authority_lock" ]; then
    echo "error: authority lock launcher is not executable" >&2
    exit 2
  fi
  exec "$authority_lock" --target "$authority_target" "$0" "$@"
fi
"$authority_lock" --validate "$authority_target" "$lock_fd"
refresh=0
case "$#" in
  0) ;;
  1)
    if [ "$1" != "--refresh" ]; then
      echo "error: unknown argument: $1" >&2
      exit 2
    fi
    refresh=1
    ;;
  *)
    echo "error: usage: verification/quint/run-verification.sh [--refresh]" >&2
    exit 2
    ;;
esac

APALACHE_VERSION=0.56.1
APALACHE_JAR_SHA256=4753c0ebb2cbb266e2c6ac19ab5ca3827d726cc80fd1fc5d7c1eeb64736cd60b
quint_home=${QUINT_HOME:-${HOME:?HOME or QUINT_HOME is required}/.quint}
QUINT_HOME=$quint_home
export QUINT_HOME
"$script_dir/bin/install-apalache" --verify-only
apalache_jar="$quint_home/apalache-dist-$APALACHE_VERSION/apalache/lib/apalache.jar"
if [ ! -f "$apalache_jar" ]; then
  echo "error: pinned Apalache JAR is missing: $apalache_jar" >&2
  exit 2
fi
printf '%s  %s\n' "$APALACHE_JAR_SHA256" "$apalache_jar" | shasum -a 256 -c -

server_endpoint=${FIREEMU_QUINT_APALACHE_ENDPOINT:-}
server_owner_pid=${FIREEMU_QUINT_APALACHE_OWNER_PID:-}
if [ -z "$server_endpoint" ] && [ -z "$server_owner_pid" ]; then
  authority_server="$script_dir/bin/authority-server"
  if [ ! -x "$authority_server" ]; then
    echo "error: authority server launcher is not executable" >&2
    exit 2
  fi
  exec "$authority_server" "$0" "$@"
fi
if [ -z "$server_endpoint" ] || [ -z "$server_owner_pid" ]; then
  echo "error: incomplete runner-owned Apalache metadata" >&2
  exit 2
fi
unset FIREEMU_QUINT_AUTHORITY_LOCK_FD

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

checker_output="$script_dir/_apalache-out"
if [ -e "$checker_output" ] || [ -L "$checker_output" ]; then
  echo "error: refusing to replace pre-existing checker output: $checker_output" >&2
  exit 2
fi

cleanup_checker_output() {
  if [ ! -e "$checker_output" ] && [ ! -L "$checker_output" ]; then
    return
  fi
  if [ -L "$checker_output" ] || [ ! -d "$checker_output" ]; then
    echo "error: checker output is not an owned directory: $checker_output" >&2
    return 1
  fi
  rm -rf -- "$checker_output"
}

owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-quint-authority.XXXXXX")
staged_evidence="$owned_temp/evidence"
mkdir "$staged_evidence"
authority_path="$script_dir/evidence/cargo-authority.json"
active_pid=
launching=0
pending_signal=
cleanup() {
  cleanup_checker_output || true
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
  cleanup_checker_output || return 1
  return "$status"
}

if [ "$refresh" -eq 1 ]; then
  run_gate cargo-authority cargo run -p fireemu-verification-quint -- cargo-authority --write "$staged_evidence/cargo-authority.json"
else
  run_gate cargo-authority cargo run -p fireemu-verification-quint -- cargo-authority --check "$authority_path"
  cp -- "$authority_path" "$staged_evidence/cargo-authority.json"
fi

pass=1
while [ "$pass" -le "$passes" ]; do
  echo "Quint authority pass $pass/$passes"
  for entry in \
    AtomicCommitOutbox:atomic_commit_outbox_connect \
    AtomicExportPublication:atomic_export_publication_connect \
    AuthTotp:auth_totp_connect \
    AwaitIdle:await_idle_connect \
    CompatibilitySelection:compatibility_selection_connect \
    EventDelivery:event_delivery_connect \
    FirestoreListenRefresh:firestore_listen_refresh_connect \
    RegexAuthorization:regex_authorization_connect \
    RegexEvaluationCache:regex_evaluation_cache_connect \
    RegexLinearRepeat:regex_linear_repeat_connect \
    RulesetActivation:ruleset_activation_connect \
    SessionEpoch:session_epoch_connect \
    StorageGeneration:storage_generation_connect \
    TransactionConditionalLock:transaction_conditional_lock_connect
  do
    model=${entry%%:*}
    test_target=${entry#*:}
    mutation_evidence="$staged_evidence/$model.json"
    run_gate "$model-model" cargo run -p fireemu-verification-quint -- verify-model --model "$model" --server-endpoint "$server_endpoint" --server-owner-pid "$server_owner_pid"
    run_gate "$model-connect" cargo test -p fireemu-verification-quint --test "$test_target" -- --ignored --test-threads=1
    run_gate "$model-mutations" cargo run -p fireemu-verification-quint -- mutate-model --model "$model" --server-endpoint "$server_endpoint" --server-owner-pid "$server_owner_pid" --evidence "$mutation_evidence" --cargo-authority "$staged_evidence/cargo-authority.json"
    run_gate "$model-evidence" cargo run -p fireemu-verification-quint -- verify-evidence --model "$model" --evidence "$mutation_evidence" --cargo-authority "$staged_evidence/cargo-authority.json"
  done
  run_gate traceability cargo run -p traceability-check -- --quint-evidence-dir "$staged_evidence"

  pass=$((pass + 1))
done

if [ "$refresh" -eq 1 ]; then
  run_gate publish-evidence cargo run -p fireemu-verification-quint -- publish-evidence --source "$staged_evidence" --target "$script_dir/evidence"
  echo "Quint evidence refreshed atomically"
fi
