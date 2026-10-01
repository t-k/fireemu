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
end
