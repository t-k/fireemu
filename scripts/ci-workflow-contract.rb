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
