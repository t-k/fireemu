#!/usr/bin/env ruby
require "minitest/autorun"
require_relative "actions-security-contract"

class ActionsSecurityContractTest < Minitest::Test
  PIN = "a" * 40
  BASE = <<~YAML
    name: fixture
    on: push
    permissions:
      contents: read
    jobs:
      latest-sdk-under-exec:
        cache-mode: read
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@#{PIN}
            with:
              persist-credentials: false
          - uses: Swatinem/rust-cache@#{PIN}
            with:
              save-if: "false"
          - run: |
              npm view firebase-admin version
              npm view firebase version
              npm install --ignore-scripts
              fireemu exec node storage.mjs
              fireemu exec node client.mjs
  YAML

  def errors(source, name = "sdk-latest.yml")
    ActionsSecurityContract.violations(source, name: name)
  end

  def test_real_workflows
    ActionsSecurityContract.check!(File.expand_path("..", __dir__))
  end

  def test_noop_baseline
    assert_empty errors(BASE)
    assert_empty errors(BASE + "# unrelated comment\n")
  end

  def test_external_action_and_reusable_workflow_must_be_commit_pinned
    assert errors(BASE.sub(PIN, "v4")).any? { |e| e.include?("full commit SHA") }
    assert errors("jobs:\n  call:\n    uses: owner/repo/.github/workflows/check.yml@main\n", "other.yml").any? { |e| e.include?("full commit SHA") }
  end

  def test_effective_cache_capability_and_overrides
    ["write", "write-only", "false", "[read]", "${{ inputs.mode }}"].each do |mode|
      refute_empty errors(BASE.sub("cache-mode: read", "cache-mode: #{mode}")), mode
    end
    refute_empty errors(BASE.sub("    cache-mode: read\n", ""))
    inherited = "cache-mode: read\n" + BASE.sub("    cache-mode: read\n", "")
    assert_empty errors(inherited)
    refute_empty errors("cache-mode: read\n" + BASE.sub("cache-mode: read", "cache-mode: write"))
    assert_empty errors(BASE.sub("cache-mode: read", "cache-mode: none"))
  end

  def test_duplicate_keys_and_wrong_locations_are_rejected
    refute_empty errors(BASE.sub("cache-mode: read", "cache-mode: read\n    cache-mode: write"))
    refute_empty errors(BASE.sub("contents: read", "contents: read\n  contents: write"))
    assert errors(BASE.sub("- run: |", "- cache-mode: read\n        run: |")).any? { |error| error.include?("invalid location") }
    refute_empty errors(BASE.sub("cache-mode: read", "cache-mode: &mode read").sub("save-if: \"false\"", "save-if: *mode"))
  end

  def test_latest_sdk_and_checkout_guards_are_preserved
    ["npm view firebase version", "npm install --ignore-scripts", "client.mjs"].each do |command|
      refute_empty errors(BASE.sub(command, "removed")), command
    end
    refute_empty errors(BASE.sub("persist-credentials: false", "persist-credentials: true"))
    refute_empty errors(BASE.sub('save-if: "false"', 'save-if: "true"'))
  end

  def test_release_cache_isolation
    source = "jobs:\n  build:\n    steps:\n      - uses: actions/setup-node@#{PIN}\n        with:\n          cache: npm\n"
    assert errors(source, "release.yml").any? { |e| e.include?("must not consume") }
  end
end
