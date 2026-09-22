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
