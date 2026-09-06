#!/usr/bin/env bash
# Self-test of scripts/local-regression-gate: a passing crate passes, a failing crate fails,
# an empty selection and a missing cargo-nextest are failures with their own status, and the
# report always names the commit, the profile, the arguments and the counts.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
gate="$repo_root/scripts/local-regression-gate"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

field() {
  # `field <report> <json key>`: the raw JSON value of a top-level scalar key.
  sed -nE "s/^  \"$2\": (.*[^,]),?\$/\1/p" "$1"
}

owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-local-gate-test.XXXXXX")
trap 'rm -rf -- "$owned_temp"' EXIT

make_crate() {
  # `make_crate <name> <lib.rs body>`
  local dir="$owned_temp/$1"
  mkdir -p "$dir/src"
  cat >"$dir/Cargo.toml" <<EOF
[package]
name = "$1"
version = "0.0.0"
edition = "2021"
[workspace]
EOF
  printf '%s\n' "$2" >"$dir/src/lib.rs"
  printf '%s' "$dir"
}

passing=$(make_crate gate-passing '#[test]
fn it_passes() {}
#[test]
#[ignore]
fn it_is_skipped() {}')
failing=$(make_crate gate-failing '#[test]
fn it_fails() { panic!("intended"); }')
empty=$(make_crate gate-empty 'pub fn nothing() {}')

reports="$owned_temp/reports"

# A passing crate: exit 0, status passed, one run, one skipped.
"$gate" --session local-gate-selftest --report "$reports/passing.json" --profile default -- \
  --manifest-path "$passing/Cargo.toml" --offline >/dev/null 2>&1 \
  || fail "the passing crate did not pass"
[[ "$(field "$reports/passing.json" status)" == '"passed"' ]] || fail "passing status: $(field "$reports/passing.json" status)"
[[ "$(field "$reports/passing.json" kind)" == '"runtime-tests"' ]] || fail "the report must describe runtime tests"
[[ "$(field "$reports/passing.json" counts)" == '{"run": 1, "passed": 1, "failed": 0, "skipped": 1}' ]] \
  || fail "passing counts: $(field "$reports/passing.json" counts)"
[[ "$(field "$reports/passing.json" profile)" == '"default"' ]] || fail "profile was not recorded"
[[ "$(field "$reports/passing.json" commit)" == "\"$(git rev-parse HEAD)\"" ]] || fail "commit was not recorded"
grep -q -- '"--manifest-path"' "$reports/passing.json" || fail "arguments were not recorded"
grep -Eq -- '"dirty": (true|false),' "$reports/passing.json" || fail "dirty flag was not recorded"
grep -q -- '"nextest": "cargo-nextest' "$reports/passing.json" || fail "nextest version was not recorded"
grep -q -- 'readonly' "$reports/passing.json" && fail "a runtime report must not describe itself as a read-only check"

# A failing crate: non-zero, status failed, the failure counted.
set +e
"$gate" --session local-gate-selftest --report "$reports/failing.json" --profile default -- \
  --manifest-path "$failing/Cargo.toml" --offline >/dev/null 2>&1
status=$?
set -e
((status != 0)) || fail "the failing crate passed"
[[ "$(field "$reports/failing.json" status)" == '"failed"' ]] || fail "failing status: $(field "$reports/failing.json" status)"
[[ "$(field "$reports/failing.json" counts)" == '{"run": 1, "passed": 0, "failed": 1, "skipped": 0}' ]] \
  || fail "failing counts: $(field "$reports/failing.json" counts)"

# No test selected: non-zero, status no-tests, never a pass.
set +e
"$gate" --session local-gate-selftest --report "$reports/empty.json" --profile default -- \
  --manifest-path "$empty/Cargo.toml" --offline >/dev/null 2>&1
status=$?
set -e
((status != 0)) || fail "an empty selection passed"
[[ "$(field "$reports/empty.json" status)" == '"no-tests"' ]] || fail "empty status: $(field "$reports/empty.json" status)"

# A filter that matches nothing in a crate with tests is also no-tests.
set +e
"$gate" --session local-gate-selftest --report "$reports/filtered.json" --profile default -- \
  --manifest-path "$passing/Cargo.toml" --offline -E 'test(no_such_test)' >/dev/null 2>&1
status=$?
set -e
((status != 0)) || fail "a filter matching nothing passed"
[[ "$(field "$reports/filtered.json" status)" == '"no-tests"' ]] || fail "filtered status: $(field "$reports/filtered.json" status)"

# cargo-nextest missing: a shim `cargo` that knows no `nextest` subcommand.
shim="$owned_temp/shim"
mkdir -p "$shim"
real_cargo=$(command -v cargo)
cat >"$shim/cargo" <<EOF
#!/usr/bin/env bash
if [[ "\${1-}" == nextest ]]; then
  printf 'error: no such command: nextest\n' >&2
  exit 101
fi
exec "$real_cargo" "\$@"
EOF
chmod +x "$shim/cargo"
set +e
PATH="$shim:$PATH" "$gate" --session local-gate-selftest --report "$reports/missing.json" --profile default -- \
  --manifest-path "$passing/Cargo.toml" --offline >/dev/null 2>&1
status=$?
set -e
((status != 0)) || fail "a missing cargo-nextest passed"
[[ "$(field "$reports/missing.json" status)" == '"missing-dependency"' ]] || fail "missing status: $(field "$reports/missing.json" status)"
[[ "$(field "$reports/missing.json" counts)" == '{"run": 0, "passed": 0, "failed": 0, "skipped": 0}' ]] \
  || fail "missing counts: $(field "$reports/missing.json" counts)"

# Invalid invocations.
if "$gate" --session local-gate-selftest -- -p nothing >/dev/null 2>&1; then fail "a gate without --report ran"; fi
if "$gate" --report "$reports/x.json" -- -p nothing >/dev/null 2>&1; then fail "a gate without --session ran"; fi
if "$gate" --session s --report "$reports/x.json" --profile '../pr' -- -p nothing >/dev/null 2>&1; then fail "an invalid profile name ran"; fi

printf 'local-regression-gate contract passed\n'
