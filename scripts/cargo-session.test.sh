#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
wrapper="$repo_root/scripts/cargo-session"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

assert_fails() {
  if "$@" >/dev/null 2>&1; then
    fail "command unexpectedly succeeded: $*"
  fi
}

alpha=$($wrapper --session alpha --mode normal --print-target-dir)
beta=$($wrapper --session beta --mode normal --print-target-dir)
loom=$($wrapper --session alpha --mode loom --print-target-dir)

[[ "$alpha" == "$repo_root/target/agent/alpha/normal" ]] || fail "unexpected alpha target: $alpha"
[[ "$beta" == "$repo_root/target/agent/beta/normal" ]] || fail "unexpected beta target: $beta"
[[ "$loom" == "$repo_root/target/agent/alpha/loom" ]] || fail "unexpected loom target: $loom"
[[ "$alpha" != "$beta" ]] || fail "sessions share a target directory"
[[ "$alpha" != "$loom" ]] || fail "normal and loom modes share a target directory"

assert_fails "$wrapper" --session ../escape --print-target-dir
assert_fails "$wrapper" --session 'has space' --print-target-dir
assert_fails "$wrapper" --session alpha --mode invalid --print-target-dir
assert_fails env CARGO_TARGET_DIR=/tmp/external "$wrapper" --session alpha --print-target-dir

normal_env=$($wrapper --session alpha --mode normal -- sh -c 'printf "%s|%s" "$CARGO_TARGET_DIR" "${RUSTFLAGS-}"')
[[ "$normal_env" == "$alpha|" ]] || fail "normal environment was not isolated: $normal_env"

loom_env=$(RUSTFLAGS='-D warnings' "$wrapper" --session alpha --mode loom -- sh -c 'printf "%s|%s" "$CARGO_TARGET_DIR" "$RUSTFLAGS"')
[[ "$loom_env" == "$loom|-D warnings --cfg loom" ]] || fail "loom environment was not isolated: $loom_env"

set +e
"$wrapper" --session alpha -- sh -c 'exit 37'
status=$?
set -e
[[ $status -eq 37 ]] || fail "child exit status was not preserved: $status"

printf 'cargo-session contract passed\n'
