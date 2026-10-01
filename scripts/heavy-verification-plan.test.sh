#!/usr/bin/env bash
# Runs the input validation of the `plan` job of heavy-verification.yml (the script text is taken
# from the workflow itself) on accepted and refused inputs, and checks the outputs it writes.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ruby -ryaml -e '
  workflow = YAML.safe_load(File.read(ARGV[0]), aliases: true)
  step = workflow.fetch("jobs").fetch("plan").fetch("steps").find { |s| s["id"] == "validate" }
  puts step.fetch("run")
' "$root/.github/workflows/heavy-verification.yml" > "$work/validate.sh"

failures=0
pass() { echo "ok   $1"; }
flunk() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# validate JOB REF PACKAGE BASE SHARDS SCRIPT TAG
validate() {
  : > "$work/output"
  INPUT_JOB=$1 INPUT_REF=$2 INPUT_PACKAGE=$3 INPUT_BASE=$4 INPUT_SHARDS=$5 INPUT_SCRIPT=$6 INPUT_TAG=${7-} \
    GITHUB_OUTPUT="$work/output" bash "$work/validate.sh" > "$work/log" 2>&1
}
accepts() {
  if validate "$@"; then pass "accepts: $*"; else flunk "accepts: $* ($(cat "$work/log"))"; fi
}
refuses() {
  if validate "$@"; then flunk "refuses: ${*//$'\n'/ }"; elif [[ -s $work/output ]]; then flunk "refuses without output: $*"; else pass "refuses: $*"; fi
}

accepts mutants work/my-branch "" main 8 "" ""
accepts mutants 0123456789abcdef0123456789abcdef01234567 fireemu-core-auth main 16 "" heavy-1.2_x
accepts nextest feature/a.b-c "" release/1.0 1 "" ""
accepts linux-measure main "" main 8 tools/bench/run.sh ""

validate mutants work/x fireemu-core-auth origin/main 05 "" tag
if grep -qx "ref=work/x" "$work/output" && grep -qx "base=origin/main" "$work/output" &&
  grep -qx "package=fireemu-core-auth" "$work/output" && grep -qx "total=5" "$work/output" &&
  grep -qx "matrix=\[0,1,2,3,4\]" "$work/output"; then
  pass "the outputs carry the validated values"
else
  flunk "the outputs carry the validated values ($(cat "$work/output"))"
fi

refuses publish main "" main 8 "" ""
refuses mutants "" "" main 8 "" ""
refuses mutants -rf "" main 8 "" ""
refuses mutants a..b "" main 8 "" ""
refuses mutants a//b "" main 8 "" ""
refuses mutants a/ "" main 8 "" ""
refuses mutants 'a b' "" main 8 "" ""
refuses mutants 'a;id' "" main 8 "" ""
refuses mutants "$(printf 'a\nb')" "" main 8 "" ""
# shellcheck disable=SC2016
refuses mutants 'x$(id)' "" main 8 "" ""
refuses mutants main "" -x 8 "" ""
refuses mutants main "" main 0 "" ""
refuses mutants main "" main 17 "" ""
refuses mutants main "" main 8x "" ""
refuses mutants main "" main "" "" ""
refuses mutants main "a;b" main 8 "" ""
refuses mutants main '../x' main 8 "" ""
refuses mutants main "" main 8 scripts/x.sh ""
refuses linux-measure main "" main 8 "" ""
refuses linux-measure main "" main 8 /etc/passwd ""
refuses linux-measure main "" main 8 scripts/../x.sh ""
refuses linux-measure main "" main 8 other/x.sh ""
refuses nextest main "" main 8 "" 'a b'
exit "$failures"
