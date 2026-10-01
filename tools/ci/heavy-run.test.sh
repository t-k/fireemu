#!/usr/bin/env bash
# Tests tools/ci/heavy-run.sh against a stub `gh` that records its arguments and plays a run.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
export GH_LOG="$work/gh.log"

cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$GH_LOG"
case "$1 $2" in
  "repo view") echo main ;;
  "run list")
    # The filter heavy-run.sh passes is applied to two runs: the tag's own, and a decoy whose tag
    # only begins with it.
    tag=$(sed -n 's/.* -f tag=\([^ ]*\)$/\1/p' "$GH_LOG" | tail -1)
    filter=""
    while (($#)); do
      [[ $1 == --jq ]] && filter=$2
      shift
    done
    printf '[{"databaseId":111,"displayTitle":"heavy-verification mutants %s9"},{"databaseId":222,"displayTitle":"heavy-verification mutants %s"},{"databaseId":333,"displayTitle":"ci"}]' "$tag" "$tag" |
      jq -r "$filter"
    ;;
  "run view") echo "https://example.invalid/run/222" ;;
  "run watch") exit "${GH_WATCH_STATUS:-0}" ;;
  "run download")
    dir=""
    name=""
    while (($#)); do
      [[ $1 == --dir ]] && dir=$2
      [[ $1 == --name ]] && name=$2
      shift
    done
    mkdir -p "$dir"
    if [[ $name == mutants-summary ]]; then
      # A summary the code under test shaped: escape sequences, a forged heading, a bidi override.
      jq -n '{shards_expected: 2, shards_found: [0, 1], total: 3, caught: 1, missed: 2, unviable: 0, timeout: 0, problems: [],
        missed_mutants: ["a.rs:1: \u001b[2J forged\u001b]0;pwned\u0007", "x\n### All mutants caught \u202e"], timeout_mutants: []}' > "$dir/summary.json"
    fi
    ;;
esac
STUB
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"

failures=0
ok() { echo "ok   $1"; }
bad() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# A mutants run: every input reaches the dispatch, the run is watched and downloaded, the summary printed.
: > "$GH_LOG"
if "$here/heavy-run.sh" --job mutants --ref work/x --package fireemu-core-auth --base main --shards 4 \
  --out "$work/out" > "$work/stdout" 2>&1 &&
  grep -q "^workflow run heavy-verification.yml --ref work/x -f job=mutants -f ref=work/x -f package=fireemu-core-auth -f base=main -f shards=4 -f script= -f tag=heavy-" "$GH_LOG" &&
  grep -q "^run watch 222 --exit-status" "$GH_LOG" &&
  grep -q "^run download 222 --dir $work/out --name mutants-summary" "$GH_LOG" &&
  grep -q "mutants 3: caught 1, missed 2" "$work/stdout"; then
  ok "a mutants run dispatches with every input, watches, downloads and prints the summary"
else
  bad "a mutants run dispatches with every input, watches, downloads and prints the summary"
fi

# A failed run still downloads, and the exit status is the watch's.
: > "$GH_LOG"
GH_WATCH_STATUS=1 "$here/heavy-run.sh" --job nextest --ref 0123456789abcdef0123456789abcdef01234567 \
  --workflow-ref work/ci --out "$work/out2" > "$work/stdout" 2>&1
status=$?
if [[ $status -eq 1 ]] && grep -q "^run watch 222" "$GH_LOG"; then
  ok "a failed run returns the watch status"
else
  bad "a failed run returns the watch status (status $status)"
fi

# The workflow is dispatched from --workflow-ref.
: > "$GH_LOG"
"$here/heavy-run.sh" --job linux-measure --ref x --script tools/bench/run.sh --workflow-ref work/ci \
  --out "$work/out3" > "$work/stdout" 2>&1
if grep -q "^workflow run heavy-verification.yml --ref work/ci -f job=linux-measure -f ref=x -f package= -f base=main -f shards=8 -f script=tools/bench/run.sh" "$GH_LOG"; then
  ok "the workflow ref and the script reach the dispatch"
else
  bad "the workflow ref and the script reach the dispatch"
fi

# The code under test cannot put escape sequences, a forged heading or a bidi override on the terminal.
: > "$GH_LOG"
"$here/heavy-run.sh" --job mutants --ref work/x --out "$work/out-hostile" > "$work/hostile" 2>&1
if ! grep -q $'\x1b' "$work/hostile" && ! grep -q $'\xe2\x80\xae' "$work/hostile" && ! grep -q '^### All mutants' "$work/hostile" &&
  grep -q "untrusted CI data" "$work/hostile" && grep -q "missed: a.rs:1" "$work/hostile"; then
  ok "hostile summary text is filtered to printable ASCII under an untrusted header"
else
  bad "hostile summary text is filtered to printable ASCII under an untrusted header"
fi

# The run never belongs to the default branch.
: > "$GH_LOG"
"$here/heavy-run.sh" --job nextest --ref work/y --out "$work/out-y" > /dev/null 2>&1
if grep -q "^workflow run heavy-verification.yml --ref work/y " "$GH_LOG" && ! grep -q "^workflow run heavy-verification.yml --ref main " "$GH_LOG"; then
  ok "the default dispatch ref is the branch under test, never main"
else
  bad "the default dispatch ref is the branch under test, never main"
fi

# A used output directory is refused: an old summary is never shown as this run's.
mkdir -p "$work/used"
echo old > "$work/used/summary.json"
: > "$GH_LOG"
if "$here/heavy-run.sh" --job nextest --ref work/y --out "$work/used" > /dev/null 2>&1 || grep -q "workflow run" "$GH_LOG"; then
  bad "a non-empty --out is refused"
else
  ok "a non-empty --out is refused"
fi

# Bad arguments are refused before anything is dispatched.
refuse() {
  : > "$GH_LOG"
  if "$here/heavy-run.sh" "$@" > /dev/null 2>&1; then
    bad "refused: $*"
  elif grep -q "workflow run" "$GH_LOG"; then
    bad "refused without dispatching: $*"
  else
    ok "refused: $*"
  fi
}
refuse --job other --ref x --out o
refuse --job nextest --ref -rf --out o
refuse --job nextest --ref a..b --out o
refuse --job nextest --ref a//b --out o
refuse --job nextest --ref 'a b' --out o
refuse --job nextest --ref x --out o --base ''
refuse --job nextest --ref x --out o --shards 0
refuse --job nextest --ref x --out o --shards 17
refuse --job nextest --ref x --out o --shards two
refuse --job nextest --ref x --out o --package 'a;b'
# shellcheck disable=SC2016
refuse --job nextest --ref x --out o --package '$(id)'
refuse --job nextest --ref x --out o --script scripts/a.sh
refuse --job linux-measure --ref x --out o --script /etc/passwd
refuse --job linux-measure --ref x --out o --script scripts/../x.sh
refuse --job linux-measure --ref x --out o
refuse --job nextest --ref x
refuse --job nextest --ref x --out o --unknown 1
refuse --job nextest --ref 0123456789abcdef0123456789abcdef01234567 --out o
refuse --job nextest --ref x --out o --workflow-ref main
refuse --job nextest --ref x --out o --workflow-ref refs/pull/1/head
refuse --job nextest --ref x --out o --workflow-ref HEAD
exit "$failures"
