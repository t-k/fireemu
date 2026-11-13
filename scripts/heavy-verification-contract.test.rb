#!/usr/bin/env ruby
# Tests of scripts/heavy-verification-contract.rb: the real workflow passes, and each rule fails on a
# copy of it that breaks that rule.

require "minitest/autorun"
require_relative "heavy-verification-contract"

class HeavyVerificationContractTest < Minitest::Test
  REAL = File.read(WORKFLOW)
  CHANNEL = File.read(File.join(ROOT, "rust-toolchain.toml"))[/^channel\s*=\s*"([^"]+)"/, 1]

  def violations_of(source)
    violations(source, toolchain_channel: CHANNEL)
  end

  def assert_violation(source, fragment)
    found = violations_of(source)
    assert(found.any? { |error| error.include?(fragment) }, "expected a violation containing #{fragment.inspect}, got #{found.inspect}")
  end

  def test_the_real_workflow_satisfies_the_contract
    assert_equal [], violations_of(REAL)
  end

  def test_another_trigger_is_refused
    assert_violation(REAL.sub("on:\n  schedule:", "on:\n  pull_request:\n  schedule:"), "only triggers")
    assert_violation(REAL.sub("on:\n  schedule:", "on:\n  push:\n  schedule:"), "only triggers")
    assert_violation(REAL.sub("on:\n  schedule:", "on:\n  workflow_run:\n  schedule:"), "only triggers")
    assert_violation(REAL.sub("workflow_dispatch:", "pull_request_target:"), "pull_request_target")
    assert_violation(REAL.sub(/^  schedule:\n(?:    (?:#|- cron:).*\n)+/, ""), "only triggers")
  end

  def test_a_changed_or_extra_schedule_is_refused
    assert_violation(REAL.sub('"23 3 * * *"', '"* * * * *"'), "schedules must be exactly")
    assert_violation(REAL.sub('"41 4 * * 6"', "\"41 4 * * 6\"\n    - cron: \"0 * * * *\""), "schedules must be exactly")
    assert_violation(REAL.sub(/^    - cron: "41 4 \* \* 6"\n/, ""), "schedules must be exactly")
  end

  def test_a_scheduled_run_with_a_wider_token_is_refused
    assert_violation(REAL.sub("permissions:\n  contents: read", "permissions:\n  contents: read\n  actions: write"), "contents: read")
    assert_violation(REAL.sub("permissions:\n  contents: read", "permissions:\n  contents: read\n  contents: write"), "write permission")
  end

  def test_a_scheduled_run_that_may_cancel_or_share_a_group_is_refused
    assert_violation(REAL.sub("cancel-in-progress: false", "cancel-in-progress: true"), "must not be cancelled")
    assert_violation(REAL.sub("github.event_name == 'schedule' && 'heavy-verification-scheduled' || ", ""), "concurrency group of their own")
  end

  def test_a_run_name_or_group_that_reads_more_than_the_event_is_refused
    assert_violation(REAL.sub("run-name: ${{ github.event_name", "run-name: ${{ github.event.head_commit.message }}${{ github.event_name"), "may only read the event name")
    assert_violation(REAL.sub("format('heavy-verification-{0}-{1}', inputs.job, inputs.ref)", "format('heavy-verification-{0}-{1}', inputs.job, inputs.base)"), "may only read the event name")
  end

  def test_a_plan_that_runs_a_schedule_outside_the_default_branch_is_refused
    assert_violation(REAL.sub('[[ $GITHUB_REF == "refs/heads/$DEFAULT_BRANCH" ]]', "true"), "schedule only on the default branch")
    assert_violation(REAL.sub("[[ $EVENT_NAME == workflow_dispatch ]]", "true"), "refuse any event")
  end

  def test_a_job_condition_that_reads_an_input_or_the_event_is_refused
    assert_violation(REAL.sub("if: needs.plan.outputs.job == 'nextest'", "if: inputs.job == 'nextest'"), "validated outputs")
    assert_violation(REAL.sub("if: needs.plan.outputs.job == 'nextest'", "if: needs.plan.outputs.job == 'nextest' && github.event_name == 'schedule'"), "validated outputs")
    assert_violation(REAL.sub("if: needs.plan.outputs.job == 'nextest'", "if: needs.plan.outputs.job == 'nextest' || always()"), "validated outputs")
  end

  def test_a_schedule_that_takes_its_ref_from_anywhere_but_the_commit_is_refused
    assert_violation(REAL.sub("INPUT_REF=$GITHUB_SHA INPUT_BASE", "INPUT_REF=work/untrusted INPUT_BASE"), "must test the commit it runs on")
    assert_violation(REAL.sub('INPUT_PACKAGE="" INPUT_SCRIPT="" INPUT_TAG=""', 'INPUT_TAG=""'), "must test the commit it runs on")
  end

  def test_a_weekly_rotation_without_its_checks_is_refused
    assert_violation(REAL.sub(/ *\[\[ \$token =~ [^\n]*\n/, ""), "file tokens must be validated")
    assert_violation(REAL.sub("&& $token != *..* ", ""), "file tokens must be validated")
    assert_violation(REAL.sub("&& $token != *//* ", ""), "file tokens must be validated")
    assert_violation(REAL.sub(/ *\[\[ \$package =~ [^\n]*\n/, ""), "package name must be validated")
    assert_violation(REAL.sub("[[ $package =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]]", "[[ $package =~ ^[A-Za-z0-9_-]{1,64}$ ]]"), "package name must be validated")
    assert_violation(REAL.sub("[[ $INPUT_PACKAGE =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]]", "[[ $INPUT_PACKAGE =~ ^[A-Za-z0-9_-]{1,64}$ ]]"), "dispatched package name")
  end

  def test_nightly_history_requires_paging_and_refuses_failures
    assert_violation(REAL.sub('&page=$page', ''), "nightly history must use paging")
    assert_violation(REAL.sub('per_page=100', 'per_page=50'), "nightly history must use paging")
    assert_violation(REAL.gsub('cannot read the run history', 'history unavailable'), "nightly history must fail when unreadable")
    assert_violation(REAL.sub(') || fail "cannot read the run history; the base is not moved"', ') || listing=""'), "nightly history curl must not swallow failures")
    assert_violation(REAL.sub(') || fail "cannot read the run history; the base is not moved"', ') || true'), "nightly history curl must not swallow failures")
  end

  def test_a_summary_merge_that_never_fails_on_a_miss_is_refused
    assert_violation(REAL.sub("extra+=(--fail-on-new-critical)", "extra+=()"), "--fail-on-new-critical")
    assert_violation(REAL.sub("if [[ $FAIL_ON_NEW_CRITICAL == true ]]; then", "if [[ $FAIL_ON_NEW_CRITICAL == never ]]; then"), "--fail-on-new-critical")
    assert_violation(REAL.sub('"${extra[@]}" shards summary', "shards summary"), "--fail-on-new-critical")
    assert_violation(REAL.sub("FAIL_ON_NEW_CRITICAL: ${{ needs.plan.outputs.fail_on_new_critical }}", "FAIL_ON_NEW_CRITICAL: \"false\""), "--fail-on-new-critical")
  end

  def test_scheduled_mutation_rules
    assert_violation(REAL.sub('fail_on_new_critical: ${{ steps.validate.outputs.fail_on_new_critical }}', 'fail_on_new_critical: "false"'), "plan must expose")
    assert_violation(REAL.sub("          - critical\n", ''), "critical dispatch")
    assert_violation(REAL.sub('if [[ $MODE == critical ]]; then', 'if [[ $MODE == never ]]; then'), "critical selection")
    assert_violation(REAL.sub('args+=(--re "$REGEX")', 'args+=(--file "$REGEX")'), "critical selection")
    assert_violation(REAL.sub('args+=(-p "$PACKAGE" --re "$REGEX")', 'args+=(-p "$PACKAGE" --file "$PACKAGE")'), "weekly selection")
    assert_violation(REAL.sub('for package in $PACKAGES; do args+=(-p "$package"); done', 'true'), "critical selection")
    assert_violation(REAL.sub("      - name: check the critical list against the tree\n        if: needs.plan.outputs.mode == 'critical'\n        run: python3 tools/ci/critical-selection.py --check tools/ci/mutation-critical.txt .\n", ""), "check the critical list")
    assert_violation(REAL.sub('INPUT_JOB=critical INPUT_SHARDS=16', 'INPUT_JOB=critical INPUT_SHARDS=8'), "schedule mapping")
    assert_violation(REAL.sub('run.get("conclusion") == "success"', 'run.get("conclusion") in ("success", "failure")'), "nightly base")
    assert_violation(REAL.sub('job=mutants fail_on_new_critical=true', 'job=mutants fail_on_new_critical=false'), "nightly must enable")
    assert_violation(REAL.sub('job=mutants base_sha=""', 'job=mutants fail_on_new_critical=true base_sha=""'), "weekly must report")
    assert_violation(REAL.sub('show "$ref_sha:tools/ci/mutation-critical.txt"', 'show "HEAD:tools/ci/mutation-critical.txt"'), "critical selection must read the helper and the list from the ref")
    assert_violation(REAL.sub('|| fail "tools/ci/mutation-critical.txt is not a valid list"', '|| true'), "critical regex must be validated")
    assert_violation(REAL.sub('show "$ref_sha:tools/ci/critical-selection.py"', 'show "HEAD:tools/ci/critical-selection.py"'), "read the helper and the list from the ref")
    assert_violation(REAL.sub('--survivors tools/ci/mutation-survivors.txt', ''), "survivors and critical lists")
    assert_violation(REAL.sub('--critical tools/ci/mutation-critical.txt', ''), "survivors and critical lists")
  end

  def test_a_second_mutation_run_is_refused
    extra = "      - name: another\n        run: cargo mutants --shard 1/2 --sharding slice\n"
    assert_violation(REAL.sub("      - name: select the mutants", extra + "      - name: select the mutants"), "--sharding slice once")
  end

  def test_a_wider_token_is_refused
    assert_violation(REAL.sub("permissions:\n  contents: read", "permissions:\n  contents: write"), "contents: read")
    assert_violation(REAL.sub("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    permissions:\n      contents: read\n"), "must not widen")
    assert_violation(REAL.sub("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    permissions:\n      contents: write\n"), "write permission")
  end

  def test_a_secret_or_another_token_is_refused
    assert_violation(REAL.sub("persist-credentials: false", "token: ${{ secrets.PAT }}"), "secrets")
    assert_violation(REAL.sub("persist-credentials: false", "token: ${{ github.token }}"), "token")
  end

  def test_a_tag_pinned_action_is_refused
    assert_violation(REAL.sub(/actions\/checkout@[0-9a-f]{40}/, "actions/checkout@v4"), "pinned by a full commit SHA")
  end

  def test_a_missing_timeout_is_refused
    assert_violation(REAL.sub("    timeout-minutes: 15\n", ""), "timeout-minutes")
  end

  def test_an_input_in_a_script_is_refused
    assert_violation(REAL.sub('git fetch --no-tags origin "$BASE"', 'git fetch --no-tags origin ${{ inputs.base }}'), "interpolated into a script")
    assert_violation(REAL.sub('--shard "$SHARD/$TOTAL"', "--shard ${{ needs.plan.outputs.shards }}"), "interpolated into a script")
  end

  def test_an_env_value_from_an_unknown_context_is_refused
    assert_violation(REAL.sub("SHARD: ${{ matrix.shard }}", "SHARD: ${{ github.event.head_commit.message }}"), "unknown context")
  end

  def test_an_unvalidated_checkout_ref_is_refused
    assert_violation(REAL.sub("ref: ${{ needs.plan.outputs.ref }}", "ref: ${{ inputs.ref }}"), "validated plan output")
  end

  def test_a_job_that_skips_the_plan_is_refused
    assert_violation(REAL.sub("  mutants:\n    needs: plan\n", "  mutants:\n"), "validated plan")
  end

  def test_a_plan_that_stops_validating_an_input_is_refused
    assert_violation(REAL.sub("          INPUT_SCRIPT: ${{ inputs.script }}\n", ""), "INPUT_SCRIPT")
  end

  def test_a_different_toolchain_is_refused
    assert_violation(REAL.sub("toolchain: 1.100.0", "toolchain: stable"), "the toolchain must be")
  end

  def test_a_cache_that_saves_is_refused
    assert_violation(REAL.gsub('save-if: "false"', 'save-if: "true"'), "must not save")
    assert_violation(REAL.gsub('save-if: "false"', "save-if: ${{ github.ref == 'refs/heads/main' }}"), "must not save")
    cache = "      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n        with:\n          path: target\n          key: k\n"
    assert_violation(REAL.sub("      - uses: Swatinem/rust-cache", cache + "      - uses: Swatinem/rust-cache"), "must never be used")
  end

  def test_persisted_checkout_credentials_are_refused
    assert_violation(REAL.sub("persist-credentials: false", "persist-credentials: true"), "persist credentials")
    assert_violation(REAL.sub("          persist-credentials: false\n", ""), "persist credentials")
  end

  def test_an_action_outside_the_table_is_refused
    script = "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n        with:\n          script: console.log('${{ inputs.base }}')\n"
    assert_violation(REAL.sub("      - uses: Swatinem/rust-cache", script + "      - uses: Swatinem/rust-cache"), "not in the table")
  end

  def test_an_expression_in_another_step_field_is_refused
    assert_violation(REAL.sub("    steps:\n", "    steps:\n      - working-directory: ${{ inputs.base }}\n        run: \"true\"\n"), "working-directory")
    assert_violation(REAL.sub("name: mutants-shard-${{ matrix.shard }}", "name: mutants-${{ inputs.base }}"), "with.name")
  end

  def test_an_unsafe_runner_switch_is_refused
    assert_violation(REAL.sub("  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: always\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: \"true\"\n"), "runner switch")
    assert_violation(REAL.sub("  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: always\n  ACTIONS_STEP_DEBUG: \"true\"\n"), "runner switch")
  end

  def test_a_job_level_or_workflow_level_expression_env_is_refused
    assert_violation(REAL.sub("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    env:\n      X: ${{ inputs.base }}\n"), "env X")
    assert_violation(REAL.sub("  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: always\n  Y: ${{ inputs.base }}\n"), "env Y")
  end

  def test_an_expression_hidden_beside_an_allowed_one_is_refused
    assert_violation(REAL.sub("SHARD: ${{ matrix.shard }}", "SHARD: ${{ matrix.shard }}-${{ inputs.base }}"), "unknown context")
    assert_violation(REAL.sub("SHARD: ${{ matrix.shard }}", "SHARD: x${{ github.event.head_commit.message }}"), "unknown context")
    assert_violation(REAL.sub("HEAVY_OUT: ${{ runner.temp }}/heavy-out", "HEAVY_OUT: ${{ runner.temp }}/${{ inputs.script }}"), "unknown context")
  end

  def test_a_release_job_that_restores_a_cache_is_refused_by_the_ci_contract
    source = File.read(File.join(ROOT, "scripts", "ci-workflow-contract.rb"))
    assert_includes source, "must not restore a cache"
  end

  def test_a_guard_that_fails_open_on_an_empty_default_branch_is_refused
    assert_violation(REAL.sub(/ *\[\[ -n \$DEFAULT_BRANCH \]\] \|\| fail[^\n]*\n/, ""), "unreadable default branch")
  end

  def test_an_input_in_a_job_level_field_is_refused
    assert_violation(REAL.sub("runs-on: ${{ matrix.os }}", "runs-on: ${{ inputs.base }}"), "runs-on uses an unknown expression")
    assert_violation(REAL.sub("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    container: ${{ inputs.base }}\n"), "container uses an unknown expression")
    assert_violation(REAL.sub("shard: ${{ fromJSON(needs.plan.outputs.matrix) }}", "shard: ${{ fromJSON(inputs.base) }}"), "strategy uses an unknown expression")
  end

  def test_a_plan_that_does_not_pin_the_locale_is_refused
    assert_violation(REAL.sub(/ *export LC_ALL=C\n/, ""), "pin the locale")
  end

  # The text with the last occurrence of `old` (the nextest job's, which follows the mutants job's) replaced.
  def sub_last(source, old, new)
    index = source.rindex(old)
    source[0...index] + new + source[(index + old.length)..]
  end

  def test_a_nextest_job_without_the_locked_fetch_is_refused
    assert_violation(sub_last(REAL, "        run: cargo fetch --locked\n", "        run: \"true\"\n"), "must fetch the locked graph")
  end

  def test_a_nextest_job_without_the_conformance_install_is_refused
    assert_violation(sub_last(REAL, "        run: pnpm -C conformance install --frozen-lockfile\n", "        run: \"true\"\n"), "must install the conformance SDKs before the suite")
  end

  def test_a_mutants_job_without_the_conformance_install_or_the_ignored_files_is_refused
    install = "      - name: the pinned real SDKs for the suites that run them\n        run: pnpm -C conformance install --frozen-lockfile\n"
    assert_violation(REAL.sub(install, ""), "mutants must install the conformance SDKs")
    assert_violation(REAL.gsub("--gitignore=false", "--gitignore=true"), "--gitignore=false")
    assert_violation(REAL.gsub("--copy-vcs=true", "--copy-vcs=false"), "--copy-vcs=true")
  end

  def test_an_unpinned_pnpm_version_is_refused
    assert_violation(REAL.sub(/^          version: 10\.32\.1\n/, ""), "must pin the pnpm version")
  end

  def test_a_setup_node_that_caches_is_refused
    assert_violation(REAL.sub("          node-version: 24\n", "          node-version: 24\n          cache: pnpm\n"), "setup-node must not cache")
  end

  def test_a_summary_upload_that_skips_a_failed_merge_is_refused
    source = REAL.sub("        if: always()\n        with:\n          name: mutants-summary", "        with:\n          name: mutants-summary")
    assert_violation(source, "even when the merge failed")
  end

  def test_a_summary_merge_that_loses_the_scripts_status_is_refused
    assert_violation(REAL.sub("          exit \"$code\"\n", ""), "keep the script's status")
    assert_violation(REAL.sub(" || code=$?", ""), "keep the script's status")
  end

  def test_a_summary_merge_that_does_not_show_the_summary_is_refused
    assert_violation(REAL.sub("cat summary/summary.md >> \"$GITHUB_STEP_SUMMARY\"", "true"), "append summary/summary.md")
  end

  def test_a_summary_merge_that_does_not_pass_the_shard_job_result_is_refused
    assert_violation(REAL.sub(" --mutants-result \"$MUTANTS_RESULT\"", ""), "shard job's result")
    assert_violation(REAL.sub("MUTANTS_RESULT: ${{ needs.mutants.result }}", "MUTANTS_RESULT: success"), "shard job's result")
  end

  def test_an_expression_of_another_job_in_the_merge_step_is_refused
    assert_violation(REAL.sub("MUTANTS_RESULT: ${{ needs.mutants.result }}", "MUTANTS_RESULT: ${{ needs.mutants.outputs.anything }}"), "unknown context")
  end

  def test_a_summary_upload_that_may_find_nothing_is_refused
    assert_violation(REAL.sub("          if-no-files-found: error\n", ""), "no summary")
  end

  def test_the_sharding_must_be_slice_on_the_command_line
    assert_violation(REAL.sub(" --sharding slice", ""), "--sharding slice")
    assert_violation(REAL.sub("--sharding slice", "--sharding round-robin"), "--sharding slice")
    assert_violation(REAL.sub("--sharding slice", "--sharding slice --sharding round-robin"), "--sharding slice")
    assert_violation(REAL.sub("--shard \"$SHARD/$TOTAL\"", "--shard \"$SHARD/$TOTAL\" --sharding=round-robin"), "--sharding slice")
  end

  def test_another_sharding_anywhere_in_the_workflow_is_refused
    source = REAL.sub("cargo nextest run --workspace --profile pr --locked", "cargo nextest run --workspace --profile pr --locked --sharding round-robin")
    assert_violation(source, "no --sharding value but slice")
  end
end
