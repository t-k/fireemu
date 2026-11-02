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
one_sha=$(git_in "$work/src" rev-parse HEAD)
# The second commit holds Rust (the nightly mutates a diff that has some) and the weekly rotation.
mkdir -p "$work/src/crates/a/src" "$work/src/tools/ci"
echo 'fn main() {}' > "$work/src/crates/a/src/lib.rs"
cat > "$work/src/tools/ci/mutation-weekly.txt" << 'LIST'
# a comment line
fireemu-core-auth  # the whole package
fireemu-adapter-http crates/fireemu-adapter-http/src/identity_toolkit.rs
fireemu-adapter-http !crates/fireemu-adapter-http/src/identity_toolkit.rs !crates/x/*.rs
LIST
git_in "$work/src" add -A
git_in "$work/src" commit -q -m two
for branch in work/my-branch release/1.0 feature/a.b-c ci/heavy; do git_in "$work/src" branch "$branch"; done
git_in "$work/src" checkout -q -b only-here
git_in "$work/src" commit -q --allow-empty -m "only on a pull request head"
pr_sha=$(git_in "$work/src" rev-parse HEAD)
git_in "$work/src" checkout -q main
# Branches whose rotation file holds one hostile line (the weekly takes the file from the commit under test).
hostile() { # BRANCH LINE
  git_in "$work/src" checkout -q -b "$1" main
  printf '%s\n' "$2" > "$work/src/tools/ci/mutation-weekly.txt"
  git_in "$work/src" commit -q -am "hostile rotation"
  git_in "$work/src" checkout -q main
}
hostile hostile-dotdot 'fireemu-core-auth crates/../secrets.rs'
hostile hostile-slashes 'fireemu-core-auth crates//x.rs'
hostile hostile-semicolon 'fireemu-core-auth crates/x.rs;id'
# shellcheck disable=SC2016
hostile hostile-subshell 'fireemu-core-auth $(id)'
# shellcheck disable=SC2016
hostile hostile-backtick 'fireemu-core-auth `id`'
hostile hostile-exclude-dotdot 'fireemu-core-auth !../x.rs'
hostile hostile-package-semicolon 'fireemu-core-auth;id crates/x.rs'
# shellcheck disable=SC2016
hostile hostile-package-subshell '$(id)'
hostile hostile-package-flag '--help'
hostile hostile-empty '# only a comment'
hostile hostile-clean 'fireemu-core-auth crates/fireemu-core-auth/src/*.rs !crates/fireemu-core-auth/src/lib.rs'
git_in "$work/src" push -q "$work/origin.git" main work/my-branch release/1.0 feature/a.b-c ci/heavy hostile-dotdot hostile-slashes hostile-semicolon hostile-subshell hostile-backtick hostile-exclude-dotdot hostile-package-semicolon hostile-package-subshell hostile-package-flag hostile-empty hostile-clean
git_in "$work/src" push -q "$work/origin.git" "$pr_sha:refs/pull/1/head"
main_sha=$(git_in "$work/src" rev-parse main)
mine_sha=$(git_in "$work/src" rev-parse work/my-branch)
git init -q "$work/fork"
git_in "$work/fork" commit -q --allow-empty -m "a commit of a fork"
fork_sha=$(git_in "$work/fork" rev-parse HEAD)

# A `curl` that answers the list of workflow runs the nightly asks GitHub for: the runs named by
# CURL_RUNS (SHA, conclusion, title) lines, or a failure when CURL_FAILS is set.
mkdir -p "$work/bin"
cat > "$work/bin/curl" << 'CURL'
#!/usr/bin/env bash
[[ -z ${CURL_FAILS-} ]] || exit 22
printf '{"workflow_runs": ['
sep=""
while read -r sha conclusion title; do
  [[ -n $sha ]] || continue
  printf '%s{"head_sha": "%s", "conclusion": "%s", "display_title": "%s"}' "$sep" "$sha" "$conclusion" "$title"
  sep=","
done <<< "${CURL_RUNS-}"
printf ']}'
CURL
chmod +x "$work/bin/curl"

failures=0
pass() { echo "ok   $1"; }
flunk() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# validate JOB REF PACKAGE BASE SHARDS SCRIPT TAG
validate() {
  : > "$work/output"
  PATH="$work/bin:$PATH" EVENT_NAME=${EVENT_NAME_UNDER_TEST-workflow_dispatch} EVENT_SCHEDULE=${EVENT_SCHEDULE_UNDER_TEST-} GITHUB_SHA=${GITHUB_SHA_UNDER_TEST-$main_sha} \
    REPOSITORY=t-k/fireemu \
    GITHUB_REF=${GITHUB_REF_UNDER_TEST-refs/heads/ci/heavy} DEFAULT_BRANCH=${DEFAULT_BRANCH_UNDER_TEST-main} REPO_URL="file://$work/origin.git" \
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
# A refusal must come from a check of the script (an ::error:: line, containing $EXPECT when given),
# not from an incidental failure further down.
refuses() {
  local expect=${EXPECT-::error::}
  if validate "$@"; then
    flunk "refuses: ${*//$'\n'/ }"
  elif [[ -s $work/output ]]; then
    flunk "refuses without output: $*"
  elif ! grep -qF -- "$expect" "$work/log"; then
    flunk "refuses for another reason: ${*//$'\n'/ } (wanted '$expect', got: $(head -c 300 "$work/log"))"
  else
    pass "refuses: ${*//$'\n'/ }"
  fi
}
syntax_refuses() { EXPECT="must be a branch name or a full commit SHA" refuses "$@"; }
unresolved_refuses() { EXPECT="is not a branch of this repository, nor a commit of one" refuses "$@"; }

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

  validate mutants work/my-branch "" release/1.0 3 "" ""
  if grep -qx "base=$(git_in "$work/src" rev-parse release/1.0)" "$work/output" && grep -qx "ref=$mine_sha" "$work/output"; then
    pass "a base named by a branch is resolved to its commit"
  else
    flunk "a base named by a branch is resolved to its commit ($(cat "$work/output"))"
  fi

  # The run must not belong to the default branch, a tag or anything but a branch.
  for scope in refs/heads/main refs/tags/v1.0.0 refs/pull/1/merge HEAD ""; do
    GITHUB_REF_UNDER_TEST=$scope refuses mutants work/my-branch "" main 8 "" ""
  done
  # An unreadable default branch must not turn the guard off.
  for scope in refs/heads/main refs/heads/work/my-branch; do
    DEFAULT_BRANCH_UNDER_TEST="" GITHUB_REF_UNDER_TEST=$scope EXPECT="cannot read the repository's default branch" refuses mutants work/my-branch "" main 8 "" ""
  done
  GITHUB_REF_UNDER_TEST=refs/heads/work/my-branch accepts mutants work/my-branch "" main 8 "" ""

  # What names a ref outside refs/heads, or a commit this repository does not hold.
  syntax_refuses mutants refs/pull/1/head "" main 8 "" ""
  syntax_refuses mutants refs/heads/main "" main 8 "" ""
  syntax_refuses mutants refs/remotes/origin/x "" main 8 "" ""
  syntax_refuses mutants HEAD "" main 8 "" ""
  syntax_refuses mutants FETCH_HEAD "" main 8 "" ""
  unresolved_refuses mutants "$pr_sha" "" main 8 "" ""
  unresolved_refuses mutants "$fork_sha" "" main 8 "" ""
  unresolved_refuses mutants no-such-branch "" main 8 "" ""
  unresolved_refuses mutants deadbeef "" main 8 "" ""
  EXPECT="base must be a branch name or a full commit SHA" refuses mutants work/my-branch "" refs/pull/1/head 8 "" ""
  EXPECT="base is not a branch of this repository" refuses mutants work/my-branch "" "$fork_sha" 8 "" ""
  # A full SHA only: an abbreviation is not a branch either.
  unresolved_refuses mutants "${main_sha:0:12}" "" main 8 "" ""
  syntax_refuses mutants ORIG_HEAD "" main 8 "" ""
  syntax_refuses mutants refs/heads/work/my-branch "" main 8 "" ""

  refuses publish main "" main 8 "" ""
  refuses mutants "" "" main 8 "" ""
  syntax_refuses mutants -rf "" main 8 "" ""
  syntax_refuses mutants a..b "" main 8 "" ""
  syntax_refuses mutants a//b "" main 8 "" ""
  syntax_refuses mutants a/ "" main 8 "" ""
  syntax_refuses mutants 'a b' "" main 8 "" ""
  syntax_refuses mutants 'a;id' "" main 8 "" ""
  syntax_refuses mutants "$(printf 'a\nb')" "" main 8 "" ""
  # shellcheck disable=SC2016
  syntax_refuses mutants 'x$(id)' "" main 8 "" ""
  syntax_refuses mutants "$(printf 'a\xc3\xa9')" "" main 8 "" ""
  syntax_refuses mutants "$(printf 'a\xe2\x80\xaeb')" "" main 8 "" ""
  EXPECT="base must be a branch name or a full commit SHA" refuses mutants work/my-branch "" -x 8 "" ""
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
  EXPECT="package must be a workspace package name" refuses mutants work/my-branch --help main 8 "" ""
  EXPECT="package must be a workspace package name" refuses mutants work/my-branch -p main 8 "" ""
  EXPECT="package must be a workspace package name" refuses mutants work/my-branch 'a;b' main 8 "" ""

  # The scheduled runs: the head of the default branch, no inputs, and the schedule says which run.
  # The nightly takes the diff since the last completed nightly; the weekly one package of the list.
  scheduled() { # SCHEDULE
    EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST=$1 GITHUB_REF_UNDER_TEST=refs/heads/main "${@:2}"
  }
  has() { grep -qxF -- "$1" "$work/output"; }
  nightly_title="heavy-verification scheduled nightly"
  # Rust changed since the last nightly (the commit before the one that added it): mutate that diff.
  CURL_RUNS="$one_sha success $nightly_title" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has job=mutants && has mode=nightly && has skip=false && has fail_on_missed=true && has "ref=$main_sha" && has "base=$one_sha" &&
    has total=8 && has package= && has files=; then
    pass "the nightly mutates the Rust diff since the last completed nightly and fails on a miss"
  else
    flunk "the nightly mutates the Rust diff since the last completed nightly ($(cat "$work/output"))"
  fi
  # No Rust since the last nightly: nothing to do.
  CURL_RUNS="$main_sha success $nightly_title" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=true && has "base=$main_sha"; then pass "the nightly skips a diff without Rust"; else flunk "the nightly skips a diff without Rust ($(cat "$work/output"))"; fi
  # A nightly that failed moves the base as well (the diff must not grow until it times out); one that was
  # cancelled, skipped or is not finished does not, and the newest completed one wins.
  CURL_RUNS="$main_sha failure $nightly_title" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=true && has "base=$main_sha"; then pass "a failed nightly moves the base"; else flunk "a failed nightly moves the base ($(cat "$work/output"))"; fi
  for conclusion in cancelled skipped timed_out null ""; do
    CURL_RUNS="$main_sha ${conclusion:-null} $nightly_title" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
    if has skip=false && ! has "base=$main_sha"; then pass "a nightly that ended ${conclusion:-null} does not move the base"; else flunk "a nightly that ended ${conclusion:-null} does not move the base ($(cat "$work/output"))"; fi
  done
  CURL_RUNS="$(printf '%s cancelled %s\n%s failure %s\n%s success %s' "$main_sha" "$nightly_title" "$one_sha" "$nightly_title" "$main_sha" "$nightly_title")" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=false && has "base=$one_sha"; then pass "the newest nightly that completed is the base, skipping a cancelled one"; else flunk "the newest nightly that completed is the base ($(cat "$work/output"))"; fi
  # Another workflow run, a run that is not a nightly and a commit this branch does not contain are not the base.
  CURL_RUNS="$main_sha success heavy-verification scheduled weekly" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=false && ! has "base=$main_sha"; then pass "a weekly run is not the last nightly"; else flunk "a weekly run is not the last nightly ($(cat "$work/output"))"; fi
  CURL_RUNS="$fork_sha success $nightly_title" scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=false && ! has "base=$fork_sha"; then pass "a nightly commit outside the history is not the base"; else flunk "a nightly commit outside the history is not the base ($(cat "$work/output"))"; fi
  # No answer from GitHub: 24 hours back, which here reaches before the first commit.
  CURL_FAILS=1 scheduled "23 3 * * *" validate "" "" "" "" "" "" ""
  if has skip=false && has "ref=$main_sha" && ! has "base=$main_sha"; then pass "without an answer the nightly falls back to 24 hours"; else flunk "without an answer the nightly falls back to 24 hours ($(cat "$work/output"))"; fi
  # The weekly: the line of the ISO week, whole, and only reporting.
  week=$((10#$(date -u +%V)))
  mapfile -t listed < <(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$work/src/tools/ci/mutation-weekly.txt")
  read -r -a chosen <<< "${listed[$((week % ${#listed[@]}))]}"
  scheduled "41 4 * * 6" validate "" "" "" "" "" "" ""
  if has job=mutants && has mode=weekly && has skip=false && has fail_on_missed=false && has total=16 && has "package=${chosen[0]}" &&
    has "files=${chosen[*]:1}" && has base=; then
    pass "the weekly takes the line of the ISO week and only reports"
  else
    flunk "the weekly takes the line of the ISO week ($(cat "$work/output"))"
  fi
  # A dispatch of the weekly names the line by package, from a branch; the first line of a package wins.
  validate weekly work/my-branch fireemu-adapter-http main 4 "" ""
  if has "package=fireemu-adapter-http" && has "files=crates/fireemu-adapter-http/src/identity_toolkit.rs" && has total=4; then
    pass "a dispatched weekly takes the named package's line"
  else
    flunk "a dispatched weekly takes the named package's line ($(cat "$work/output"))"
  fi
  EXPECT="is not in tools/ci/mutation-weekly.txt" refuses weekly work/my-branch no-such-package main 4 "" ""
  # A hostile rotation line (the file comes from the commit under test) is refused before anything uses it.
  for branch in hostile-dotdot hostile-slashes hostile-semicolon hostile-subshell hostile-backtick hostile-exclude-dotdot; do
    EXPECT="the rotation names a bad file" refuses weekly "$branch" "" main 4 "" ""
  done
  for branch in hostile-package-semicolon hostile-package-subshell hostile-package-flag; do
    EXPECT="the rotation names a bad package" refuses weekly "$branch" "" main 4 "" ""
  done
  EXPECT="lists no package" refuses weekly hostile-empty "" main 4 "" ""
  validate weekly hostile-clean "" main 4 "" ""
  if has "package=fireemu-core-auth" && has "files=crates/fireemu-core-auth/src/*.rs !crates/fireemu-core-auth/src/lib.rs"; then
    pass "a clean rotation line with a glob and an exclusion is accepted"
  else
    flunk "a clean rotation line with a glob and an exclusion is accepted ($(cat "$work/output"))"
  fi
  # A dispatched nightly can be tried on a branch, and keeps the ban on the default branch.
  accepts nightly work/my-branch "" main 4 "" ""
  GITHUB_REF_UNDER_TEST=refs/heads/main refuses nightly work/my-branch "" main 4 "" ""
  # A schedule only belongs to the default branch and to the two known crons; nothing else may start it.
  EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST="23 3 * * *" GITHUB_REF_UNDER_TEST=refs/heads/work/my-branch EXPECT="belongs to the default branch" refuses "" "" "" "" "" "" ""
  EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST="23 3 * * *" GITHUB_REF_UNDER_TEST=refs/tags/v1.0.0 EXPECT="belongs to the default branch" refuses "" "" "" "" "" "" ""
  EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST="1 2 * * *" GITHUB_REF_UNDER_TEST=refs/heads/main EXPECT="unknown schedule" refuses "" "" "" "" "" "" ""
  EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST="" GITHUB_REF_UNDER_TEST=refs/heads/main EXPECT="unknown schedule" refuses "" "" "" "" "" "" ""
  EVENT_NAME_UNDER_TEST=schedule EVENT_SCHEDULE_UNDER_TEST="23 3 * * *" GITHUB_REF_UNDER_TEST=refs/heads/main GITHUB_SHA_UNDER_TEST=nothex EXPECT="needs the commit" refuses "" "" "" "" "" "" ""
  EVENT_NAME_UNDER_TEST=pull_request EXPECT="unexpected event" refuses mutants work/my-branch "" main 8 "" ""
done
exit "$failures"
