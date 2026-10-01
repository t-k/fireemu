#!/usr/bin/env bash
# Runs the input validation of the `plan` job of heavy-verification.yml (the script text is taken
# from the workflow itself) on accepted and refused inputs, against a local repository standing in
# for the project's, and checks the outputs it writes. Runs under C.UTF-8 and en_US.UTF-8 alike.
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

ruby -ryaml -e '
  workflow = YAML.safe_load(File.read(ARGV[0]), aliases: true)
  step = workflow.fetch("jobs").fetch("plan").fetch("steps").find { |s| s["id"] == "validate" }
  puts step.fetch("run")
' "$root/.github/workflows/heavy-verification.yml" > "$work/validate.sh"

# The scratch repositories of this test read no user or system git configuration at all.
git_in() { GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git -C "$1" -c user.name=t -c user.email=t@example.invalid "${@:2}"; }

# The project's repository: branches, a commit only a "fork" has, and a pull-request head.
git init -q --bare "$work/origin.git"
git init -q "$work/src"
git_in "$work/src" checkout -q -b main
git_in "$work/src" commit -q --allow-empty -m one
git_in "$work/src" commit -q --allow-empty -m two
for branch in work/my-branch release/1.0 feature/a.b-c ci/heavy; do git_in "$work/src" branch "$branch"; done
git_in "$work/src" checkout -q -b only-here
git_in "$work/src" commit -q --allow-empty -m "only on a pull request head"
pr_sha=$(git_in "$work/src" rev-parse HEAD)
git_in "$work/src" checkout -q main
git_in "$work/src" push -q "$work/origin.git" main work/my-branch release/1.0 feature/a.b-c ci/heavy
git_in "$work/src" push -q "$work/origin.git" "$pr_sha:refs/pull/1/head"
main_sha=$(git_in "$work/src" rev-parse main)
mine_sha=$(git_in "$work/src" rev-parse work/my-branch)
git init -q "$work/fork"
git_in "$work/fork" commit -q --allow-empty -m "a commit of a fork"
fork_sha=$(git_in "$work/fork" rev-parse HEAD)

failures=0
pass() { echo "ok   $1"; }
flunk() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# validate JOB REF PACKAGE BASE SHARDS SCRIPT TAG
validate() {
  : > "$work/output"
  GITHUB_REF=${GITHUB_REF_UNDER_TEST-refs/heads/ci/heavy} DEFAULT_BRANCH=main REPO_URL="file://$work/origin.git" \
    RUNNER_TEMP="$work/tmp" INPUT_JOB=$1 INPUT_REF=$2 INPUT_PACKAGE=$3 INPUT_BASE=$4 INPUT_SHARDS=$5 INPUT_SCRIPT=$6 \
    INPUT_TAG=${7-} GITHUB_OUTPUT="$work/output" bash "$work/validate.sh" > "$work/log" 2>&1
  local status=$?
  rm -rf "$work/tmp"
  mkdir -p "$work/tmp"
  return "$status"
}
accepts() {
  if validate "$@"; then pass "accepts: $*"; else flunk "accepts: $* ($(cat "$work/log"))"; fi
}
refuses() {
  if validate "$@"; then flunk "refuses: ${*//$'\n'/ }"; elif [[ -s $work/output ]]; then flunk "refuses without output: $*"; else pass "refuses: ${*//$'\n'/ }"; fi
}

for locale in C.UTF-8 en_US.UTF-8; do
  export LC_ALL=$locale
  echo "-- $locale"

  accepts mutants work/my-branch "" main 8 "" ""
  accepts mutants "$mine_sha" fireemu-core-auth main 16 "" heavy-1.2_x
  accepts nextest feature/a.b-c "" release/1.0 1 "" ""
  accepts nextest main "" main 8 "" ""
  accepts linux-measure work/my-branch "" main 8 tools/bench/run.sh ""

  validate mutants work/my-branch fireemu-core-auth "$main_sha" 05 "" tag
  if grep -qx "ref=$mine_sha" "$work/output" && grep -qx "base=$main_sha" "$work/output" &&
    grep -qx "package=fireemu-core-auth" "$work/output" && grep -qx "total=5" "$work/output" &&
    grep -qx "matrix=\[0,1,2,3,4\]" "$work/output"; then
    pass "the outputs carry the resolved commits and the validated values"
  else
    flunk "the outputs carry the resolved commits and the validated values ($(cat "$work/output"))"
  fi

  # The run must not belong to the default branch, a tag or anything but a branch.
  for scope in refs/heads/main refs/tags/v1.0.0 refs/pull/1/merge HEAD ""; do
    GITHUB_REF_UNDER_TEST=$scope refuses mutants work/my-branch "" main 8 "" ""
  done
  GITHUB_REF_UNDER_TEST=refs/heads/work/my-branch accepts mutants work/my-branch "" main 8 "" ""

  # What names a ref outside refs/heads, or a commit this repository does not hold.
  refuses mutants refs/pull/1/head "" main 8 "" ""
  refuses mutants refs/heads/main "" main 8 "" ""
  refuses mutants refs/remotes/origin/x "" main 8 "" ""
  refuses mutants HEAD "" main 8 "" ""
  refuses mutants FETCH_HEAD "" main 8 "" ""
  refuses mutants "$pr_sha" "" main 8 "" ""
  refuses mutants "$fork_sha" "" main 8 "" ""
  refuses mutants no-such-branch "" main 8 "" ""
  refuses mutants deadbeef "" main 8 "" ""
  refuses mutants work/my-branch "" refs/pull/1/head 8 "" ""
  refuses mutants work/my-branch "" "$fork_sha" 8 "" ""

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
  refuses mutants "$(printf 'a\xc3\xa9')" "" main 8 "" ""
  refuses mutants "$(printf 'a\xe2\x80\xaeb')" "" main 8 "" ""
  refuses mutants work/my-branch "" -x 8 "" ""
  refuses mutants work/my-branch "" main 0 "" ""
  refuses mutants work/my-branch "" main 17 "" ""
  refuses mutants work/my-branch "" main 8x "" ""
  refuses mutants work/my-branch "" main "" "" ""
  refuses mutants work/my-branch "a;b" main 8 "" ""
  refuses mutants work/my-branch '../x' main 8 "" ""
  refuses mutants work/my-branch "" main 8 scripts/x.sh ""
  refuses linux-measure work/my-branch "" main 8 "" ""
  refuses linux-measure work/my-branch "" main 8 /etc/passwd ""
  refuses linux-measure work/my-branch "" main 8 scripts/../x.sh ""
  refuses linux-measure work/my-branch "" main 8 other/x.sh ""
  refuses nextest work/my-branch "" main 8 "" 'a b'
done
exit "$failures"
