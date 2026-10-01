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
  "run list") echo 222 ;;
  "run view") echo "https://example.invalid/run/222" ;;
  "run watch") exit "${GH_WATCH_STATUS:-0}" ;;
  "run download")
    dir=""
    while (($#)); do
      [[ $1 == --dir ]] && dir=$2
      shift
    done
    mkdir -p "$dir/mutants-summary"
    echo "## Mutation testing (stub)" > "$dir/mutants-summary/summary.md"
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
  grep -q "^workflow run heavy-verification.yml --ref main -f job=mutants -f ref=work/x -f package=fireemu-core-auth -f base=main -f shards=4 -f script= -f tag=heavy-" "$GH_LOG" &&
  grep -q "^run watch 222 --exit-status" "$GH_LOG" &&
  grep -q "^run download 222" "$GH_LOG" &&
  grep -q "Mutation testing (stub)" "$work/stdout"; then
  ok "a mutants run dispatches with every input, watches, downloads and prints the summary"
else
  bad "a mutants run dispatches with every input, watches, downloads and prints the summary"
fi

# A failed run still downloads, and the exit status is the watch's.
: > "$GH_LOG"
GH_WATCH_STATUS=1 "$here/heavy-run.sh" --job nextest --ref 0123456789abcdef0123456789abcdef01234567 \
  --out "$work/out2" > "$work/stdout" 2>&1
status=$?
if [[ $status -eq 1 ]] && grep -q "^run download 222" "$GH_LOG"; then
  ok "a failed run is downloaded and its status is returned"
else
  bad "a failed run is downloaded and its status is returned (status $status)"
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

# The run is found by the tag in its title: the filter picks only the run that ends with the tag.
tag="heavy-1-2"
picked=$(printf '[{"databaseId":111,"displayTitle":"heavy-verification mutants heavy-1-22"},{"databaseId":222,"displayTitle":"heavy-verification mutants heavy-1-2"}]' |
  jq -r "map(select(.displayTitle | endswith(\" $tag\"))) | .[0].databaseId // empty")
if [[ $picked == 222 ]]; then ok "the run is found by the tag, not by a longer one"; else bad "the run is found by the tag, not by a longer one ($picked)"; fi

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
exit "$failures"
