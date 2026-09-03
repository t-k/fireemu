#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
publisher="$script_dir/publish-evidence"
owned_temp=$(mktemp -d "${TMPDIR:-/tmp}/fireemu-publish-evidence-test.XXXXXX")
trap 'rm -rf -- "$owned_temp"' EXIT

models=(
  AtomicCommitOutbox AtomicExportPublication AuthTotp AwaitIdle CompatibilitySelection
  EventDelivery FirestoreListenRefresh RegexAuthorization RegexEvaluationCache RegexLinearRepeat
  RulesetActivation SessionEpoch StorageGeneration TransactionConditionalLock
)

write_complete_set() {
  local directory=$1 marker=$2
  mkdir -p "$directory"
  printf '%s\n' "$marker" >"$directory/cargo-authority.json"
  for model in "${models[@]}"; do
    printf '%s:%s\n' "$marker" "$model" >"$directory/$model.json"
  done
}

source_dir="$owned_temp/source"
target_dir="$owned_temp/target"
write_complete_set "$source_dir" new
write_complete_set "$target_dir" old

"$publisher" "$source_dir" "$target_dir"
for file in cargo-authority.json "${models[@]/%/.json}"; do
  grep -q '^new' "$target_dir/$file"
done

write_complete_set "$source_dir" newer
rm "$source_dir/EventDelivery.json"
before=$(shasum -a 256 "$target_dir/EventDelivery.json")
if "$publisher" "$source_dir" "$target_dir" >/dev/null 2>&1; then
  printf 'publisher accepted an incomplete source set\n' >&2
  exit 1
fi
after=$(shasum -a 256 "$target_dir/EventDelivery.json")
[[ "$before" == "$after" ]] || {
  printf 'failed publication changed the target\n' >&2
  exit 1
}

printf 'evidence publication contract passed\n'
