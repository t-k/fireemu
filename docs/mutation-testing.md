# Local mutation testing

## Rust: bounded campaigns

The repository enables `gitignore = true` in `.cargo/mutants.toml` so mutation sandboxes do not copy ignored worktrees, dependencies, or local evidence. Keep `--gitignore true` explicit when using `--no-config` or an alternate configuration. Do not use `--in-place` in a shared checkout.

With cargo-mutants 27.1.0, `--re` and `--exclude-re` do not filter struct-literal field deletions from expressions using `..Default::default()`. Use a reviewed `--in-diff` selection, which filters every mutation genre after discovery. A file or function regex alone does not bound a focused campaign.

Create the selection from the intended change (replace `<base>` and `<crate>` with the reviewed revision and package):

```bash
mkdir -p docs.local/mutation
git diff --no-ext-diff --unified=0 <base> -- crates/ > docs.local/mutation/selection.diff
cargo mutants --gitignore true --in-diff docs.local/mutation/selection.diff -p <crate> --list --json > docs.local/mutation/selected.json
```

Inspect `selected.json` before execution: require a nonempty list, confirm every file, source span and mutation genre, and check that the chosen tests cover every listed obligation. A zero-mutant run is not evidence. If selecting unchanged validation branches, create a separate virtual diff and label it **selection artifact, not a production patch**; review its added-line positions against the current source.

Then run the same selection and package with the intended tests:

```bash
cargo mutants --gitignore true --in-diff docs.local/mutation/selection.diff -p <crate> --output docs.local/mutation -- --profile pr
```

Retain the tool version, source commit, selection diff, reviewed list, test arguments and results together. Re-list after changing source, selection or tool versions. Missed unrelated mutants from a regex-only run do not establish that their full relevant test suites are inadequate.

## Rust: scheduled runs on GitHub

`heavy-verification.yml` runs mutation testing on a schedule, on the default branch only. Both runs reuse the manual `mutants` job (shards, `--sharding slice`, the `mutants-summary` merge); they only choose what to mutate.

| Run | When | What is mutated | A missed mutant |
| --- | --- | --- | --- |
| nightly | every day, 03:23 UTC | the Rust diff from the head of the last successful scheduled nightly (else the commit of 24 hours ago) to the head of the default branch, 8 shards | fails the run |
| weekly | Saturdays, 04:41 UTC | one line of `tools/ci/mutation-weekly.txt`: line `ISO week mod number of lines`, 16 shards | is reported only (the run passes) |

- A nightly whose diff holds no `.rs` file mutates nothing and passes. A nightly that fails leaves the next one with the same base, so the survivors come back until they are killed or the diff moves past them.
- The weekly rotation walks the whole workspace in about one turn per year. A package too big for the 360-minute shard limit is split by file over several lines; the last line of a split package excludes the files of the other lines, so a new file is still mutated by it. Add a new crate to the file, and regenerate the counts in the comments with `cargo mutants --list -p <package> --file <glob>`.
- Results are in the run's step summary (the `mutants-summary` job) and in the `mutants-summary` artifact (`summary/summary.md` and the per-shard outcomes). The run title says `heavy-verification scheduled nightly` or `weekly`.
- Try either mode by hand from a pushed branch: `gh workflow run heavy-verification.yml --ref <branch> -f job=nightly -f ref=<branch>` (or `-f job=weekly -f package=<package>` to take that package's first line). A dispatch never runs from the default branch, and a nightly dispatch takes its base the same way as the scheduled one.
- Safety: only `schedule` and `workflow_dispatch` start the workflow (never `pull_request` or `pull_request_target`), the token is `contents: read`, there are no secrets, no job saves a cache, and one scheduled run goes at a time. `scripts/heavy-verification-contract.rb` pins all of this.
- GitHub starts a schedule only from the default branch, so nothing runs until the workflow is merged there. GitHub also disables scheduled workflows of a repository without activity for 60 days; a push or a manual run re-enables them.

## UI: verify mutant execution

Run `pnpm -C ui mutation:sanity` before trusting a UI mutation campaign. It uses the normal Stryker configuration and runner, selects the scope-transition guard by an exact source anchor, and requires every selected mutant to be killed. A missing or ambiguous anchor, empty selection, survivor, timeout, or infrastructure error fails the command. Results are written to `ui/test-results/mutation-sanity.json`; the exit status is checked against the current in-memory results, not an old report.

The sanity command deliberately exercises a small known behavior-changing slice. It does not claim mutation coverage for the whole UI. Run `pnpm -C ui mutation` for the configured full selection, or use `pnpm -C ui exec stryker run --mutate <source-file>` for a reviewed focused campaign. A successful initial test run alone is not evidence that mutant tests executed.

The earlier Vitest runner failure was not reproduced with the current locked dependencies: the normal runner killed the scope-transition mutants. Keep the runner and dependency versions pinned through the lockfile, and rerun the sanity command after upgrades rather than assuming the historical workaround is still necessary.
