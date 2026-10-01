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
# CLI (`gh`), logged in with a token that may run workflows (a fine-grained token limited to this
# repository is enough). The run belongs to --workflow-ref, which defaults to the ref under test
# (a branch name; for a commit SHA --workflow-ref is required). It is never the default branch:
# the Actions cache is scoped by the run's ref, and the code under test must not share a scope with
# ci.yml or release.yml. A dedicated branch that carries the workflow file works too.
#
# What the run produced is data written by the code under test: it is downloaded into --out (which
# must be new or empty) and printed through a filter that keeps printable ASCII only.
set -euo pipefail
# Bracket ranges follow the locale under glibc ([a-z] can match an accented letter); keep every pattern ASCII.
export LC_ALL=C

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit "${1:-2}"
}

fail() {
  echo "heavy-run: $1" >&2
  exit 2
}

job="" ref="" out="" package="" base="main" shards="8" script="" workflow_ref=""
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
[[ -n $out ]] || fail "--out is required"
if [[ -e $out ]]; then
  [[ -d $out ]] || fail "--out exists and is not a directory"
  [[ -z $(ls -A "$out") ]] || fail "--out must be new or empty, so an old result is never shown as this run's"
fi
if [[ -z $workflow_ref ]]; then
  [[ $ref =~ ^[0-9a-f]{40}$ ]] && fail "--workflow-ref is required when --ref is a commit SHA"
  workflow_ref=$ref
fi
ref_ok "$workflow_ref" || fail "--workflow-ref must be a branch name"
[[ $workflow_ref =~ ^[0-9a-f]{40}$ ]] && fail "--workflow-ref must be a branch name, not a commit SHA"
[[ $workflow_ref != refs/* && $workflow_ref != HEAD && $workflow_ref != FETCH_HEAD ]] || fail "--workflow-ref must be a branch name"
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
default_branch=$(gh repo view --json defaultBranchRef --jq .defaultBranchRef.name)
[[ -n $default_branch ]] || fail "cannot read the repository's default branch"
[[ $workflow_ref != "$default_branch" ]] || fail "--workflow-ref must not be the default branch ($default_branch): dispatch from the branch under test or a dedicated branch"

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

# Everything below is produced by the code under test.
show() { LC_ALL=C tr -cd '\11\12\40-\176' | cut -c1-400 | head -n "${1:-200}"; }

mkdir -p "$out"
case "$job" in
  mutants)
    gh run download "$run_id" --dir "$out" --name mutants-summary || echo "heavy-run: no summary artifact" >&2
    gh run download "$run_id" --dir "$out/shards" --pattern 'mutants-shard-*' || echo "heavy-run: no shard artifacts" >&2
    ;;
  linux-measure)
    gh run download "$run_id" --dir "$out" --name linux-measure-output || echo "heavy-run: no output artifact" >&2
    ;;
esac

echo "---- The text below was written by the code under test: untrusted CI data, printable ASCII only ----"
if [[ -f $out/summary.json ]]; then
  jq -r '"shards expected \(.shards_expected) found \(.shards_found | length); mutants \(.total): caught \(.caught), missed \(.missed), unviable \(.unviable), timeout \(.timeout)"' "$out/summary.json" | show 3
  jq -r '.missed_mutants[]? | "missed: " + (tostring | gsub("[^ -~]"; "?") | .[0:300])' "$out/summary.json" | show 100
  jq -r '.timeout_mutants[]? | "timeout: " + (tostring | gsub("[^ -~]"; "?") | .[0:300])' "$out/summary.json" | show 100
  jq -r '.problems[]? | "problem: " + (tostring | gsub("[^ -~]"; "?") | .[0:300])' "$out/summary.json" | show 100
elif [[ $job == linux-measure ]]; then
  # File names are untrusted: a newline or control character in one must not start a line of its own.
  (cd "$out" && find . -type f -print0 | LC_ALL=C tr '\001-\037\177' '?' | LC_ALL=C tr '\000' '\n' | LC_ALL=C sort) | show 200
fi
gh run view "$run_id" --json conclusion,url --jq '"conclusion: \(.conclusion) \(.url)"' | show 2
exit "$status"
