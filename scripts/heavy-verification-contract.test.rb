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
    assert_violation(REAL.sub("on:\n  workflow_dispatch:", "on:\n  pull_request:\n  workflow_dispatch:"), "only trigger")
    assert_violation(REAL.sub("workflow_dispatch:", "pull_request_target:"), "pull_request_target")
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
    assert_violation(REAL.sub("toolchain: 1.94.0", "toolchain: stable"), "the toolchain must be")
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

  def test_a_nextest_job_without_the_locked_fetch_is_refused
    assert_violation(REAL.sub("        run: cargo fetch --locked\n", "        run: \"true\"\n"), "must fetch the locked graph")
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

  def test_a_sharding_option_is_refused
    assert_violation(REAL.sub("--shard \"$SHARD/$TOTAL\"", "--shard \"$SHARD/$TOTAL\" --sharding round-robin"), "no --sharding")
  end
end
