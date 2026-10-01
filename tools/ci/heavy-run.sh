#!/usr/bin/env bash
# Dispatches the heavy-verification workflow, waits for it, downloads its artifacts into a
# directory and prints the summary.
#
#   tools/ci/heavy-run.sh --job mutants --ref work/my-branch --out /tmp/heavy \
#       [--package fireemu-core-auth] [--base main] [--shards 8]
#   tools/ci/heavy-run.sh --job nextest --ref <sha> --out /tmp/heavy
#   tools/ci/heavy-run.sh --job linux-measure --ref <ref> --script tools/bench/run.sh --out /tmp/heavy
#
# The ref must be pushed to the repository: the workflow checks it out on GitHub. Needs the GitHub
# CLI (`gh`), logged in with a token that may run workflows. The workflow file itself is taken from
# --workflow-ref (default: main), because `workflow_dispatch` only exists once the file is on it.
set -euo pipefail

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-2}"
}

fail() {
  echo "heavy-run: $1" >&2
  exit 2
}

job="" ref="" out="" package="" base="main" shards="8" script="" workflow_ref="main"
while (($#)); do
  case "$1" in
    --job) job=${2:?--job needs a value}; shift 2 ;;
    --ref) ref=${2:?--ref needs a value}; shift 2 ;;
    --out) out=${2:?--out needs a value}; shift 2 ;;
    --package) package=${2:?--package needs a value}; shift 2 ;;
    --base) base=${2:?--base needs a value}; shift 2 ;;
    --shards) shards=${2:?--shards needs a value}; shift 2 ;;
    --script) script=${2:?--script needs a value}; shift 2 ;;
    --workflow-ref) workflow_ref=${2:?--workflow-ref needs a value}; shift 2 ;;
    -h | --help) usage 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

ref_ok() {
  local value=$1
  [[ $value =~ ^[0-9a-f]{40}$ ]] && return 0
  [[ $value =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$ ]] || return 1
  [[ $value != *..* && $value != *//* && $value != */ && $value != *.lock ]]
}

# The same rules the workflow applies; refusing here only saves a round trip.
case "$job" in
  mutants | nextest | linux-measure) ;;
  *) fail "--job must be mutants, nextest or linux-measure" ;;
esac
ref_ok "$ref" || fail "--ref must be a branch name or a full commit SHA"
ref_ok "$base" || fail "--base must be a branch name or a full commit SHA"
ref_ok "$workflow_ref" || fail "--workflow-ref must be a branch name or a full commit SHA"
[[ -n $out ]] || fail "--out is required"
[[ $shards =~ ^[0-9]{1,2}$ ]] || fail "--shards must be an integer"
((10#$shards >= 1 && 10#$shards <= 16)) || fail "--shards must be 1 to 16"
if [[ -n $package ]]; then
  [[ $package =~ ^[A-Za-z0-9_-]{1,64}$ ]] || fail "--package must be a workspace package name"
fi
if [[ $job == linux-measure ]]; then
  [[ $script =~ ^(scripts|tools)/[A-Za-z0-9._/-]{1,200}$ ]] || fail "--script must be a path below scripts/ or tools/"
  [[ $script != *..* && $script != *//* ]] || fail "--script must be a plain path"
elif [[ -n $script ]]; then
  fail "--script is only for linux-measure"
fi
command -v gh >/dev/null || fail "the GitHub CLI (gh) is required"

tag="heavy-$(date +%s)-$$"
echo "dispatching $job for $ref (tag $tag)"
gh workflow run heavy-verification.yml --ref "$workflow_ref" \
  -f "job=$job" -f "ref=$ref" -f "package=$package" -f "base=$base" \
  -f "shards=$shards" -f "script=$script" -f "tag=$tag"

# The run is found by the tag in its title, so another dispatch at the same time is not mistaken
# for it.
run_id=""
for _ in $(seq 1 60); do
  run_id=$(gh run list --workflow heavy-verification.yml --event workflow_dispatch --limit 30 \
    --json databaseId,displayTitle --jq "map(select(.displayTitle | endswith(\" $tag\"))) | .[0].databaseId // empty")
  [[ -n $run_id ]] && break
  sleep 5
done
[[ -n $run_id ]] || fail "the dispatched run did not appear within five minutes"
echo "run $run_id: $(gh run view "$run_id" --json url --jq .url)"

status=0
gh run watch "$run_id" --exit-status --interval 30 || status=$?

mkdir -p "$out"
gh run download "$run_id" --dir "$out" || echo "heavy-run: no artifacts to download" >&2
if [[ -f $out/mutants-summary/summary.md ]]; then
  cat "$out/mutants-summary/summary.md"
else
  gh run view "$run_id" --json conclusion,url --jq '"conclusion: \(.conclusion) \(.url)"'
fi
exit "$status"
