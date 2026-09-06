#!/usr/bin/env ruby

require "yaml"

ROOT = File.expand_path("..", __dir__)

def assert(condition, message)
  raise message unless condition
end

def load_workflow(name)
  YAML.safe_load(File.read(File.join(ROOT, ".github", "workflows", name)), aliases: true)
end

workflow = load_workflow("ci.yml")
jobs = workflow.fetch("jobs")
trigger = workflow["on"] || workflow[true]
assert(trigger.key?("workflow_dispatch"), "CI must retain a manual full-suite trigger")

automatic = jobs.map do |name, definition|
  name unless definition.fetch("if", "").include?("workflow_dispatch")
end.compact
assert(automatic == ["pr"], "only the minimal pr job may run automatically, found #{automatic.join(', ')}")

pr = jobs.fetch("pr")
assert(!pr.key?("needs"), "the minimal pr job must not depend on manual jobs")
assert(pr.dig("env", "CARGO_TARGET_DIR") == "target/minimal", "the minimal pr job must use target/minimal")
pr_runs = pr.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(pr_runs.include?("ruby scripts/ci-workflow-contract.rb"), "the minimal pr job must check its workflow contract")
assert(pr_runs.include?("cargo fmt --all --check"), "the minimal pr job must check formatting")
assert(pr_runs.include?("cargo check --workspace --all-targets"), "the minimal pr job must compile every target")
%w[nextest clippy cargo\ doc cargo\ deny proto-gen fireemu-verification-loom].each do |expensive|
  assert(!pr_runs.include?(expensive), "the automatic pr job must not run #{expensive}")
end

release = load_workflow("release.yml")
release_source = File.read(File.join(ROOT, ".github", "workflows", "release.yml"))
assert(!release_source.match?(/uses:\s+[^\s]+@(v\d+|stable)\b/), "release actions must be pinned to immutable commits")
toolchain_source = File.read(File.join(ROOT, "rust-toolchain.toml"))
toolchain_channel = toolchain_source.match(/^channel\s*=\s*"([^"]+)"$/)&.captures&.first
assert(toolchain_channel, "rust-toolchain.toml must declare a channel")
release.fetch("jobs").each do |job, definition|
  definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("actions/setup-node@") }.each do |step|
    assert(step.dig("with", "node-version").to_s == "24", "release #{job} must use Node 24")
  end
  definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("pnpm/action-setup@") }.each do |step|
    assert(step.dig("with", "version"), "release #{job} must pin the pnpm version")
  end
end
release.dig("jobs", "build", "steps").select { |step| step["uses"]&.start_with?("dtolnay/rust-toolchain@") }.each do |step|
  assert(step.dig("with", "toolchain") == toolchain_channel, "release build must install targets for #{toolchain_channel}")
end
release_build = release.dig("jobs", "build")
release_build_runs = release_build.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(!release_build_runs.include?("cargo nextest"), "release platform builds must not duplicate the workspace test suite")
assert(release_build.fetch("needs").include?("test"), "release platform builds must depend on the dedicated test job")
release_test_runs = release.dig("jobs", "test", "steps").map { |step| step["run"] }.compact.join("\n")
assert(
  release_test_runs.include?("cargo nextest run --workspace --profile pr -E 'not binary(leak_fixture)'"),
  "release test job must run the workspace suite outside the process leak fixture"
)
assert(
  release_test_runs.include?("cargo nextest run -p fireemu --test leak_fixture --profile pr"),
  "release test job must run the process leak fixture in isolation"
)
assert(release.dig("jobs", "publish", "environment") == "npm-release", "release publish must use the protected npm-release environment")
assert(release.dig("concurrency", "cancel-in-progress") == false, "release publication must never be cancelled in progress")
publish_runs = release.dig("jobs", "publish", "steps").map { |step| step["run"] }.compact.join("\n")
assert(publish_runs.include?("npm@11.9.0"), "release publish must pin an npm version that supports Trusted Publishing")

%w[lint test verify platforms package ui].each do |name|
  assert(jobs.fetch(name).fetch("if") == "${{ github.event_name == 'workflow_dispatch' }}", "#{name} must be manual-only before publication")
end

jobs.each do |job, definition|
  definition.fetch("steps", []).select { |step| step["uses"] == "pnpm/action-setup@v4" }.each do |step|
    assert(step.dig("with", "version"), "#{job} must pin the pnpm version")
  end
end

%w[functions-sdk-discovery.yml quint.yml].each do |name|
  heavy = load_workflow(name)
  heavy_trigger = heavy["on"] || heavy[true]
  assert(heavy_trigger.keys == ["workflow_dispatch"], "#{name} must be manual-only before publication")
end

puts "CI workflow contract passed"
