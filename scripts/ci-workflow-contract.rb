#!/usr/bin/env ruby

require "yaml"

ROOT = File.expand_path("..", __dir__)
WORKFLOW = File.join(ROOT, ".github", "workflows", "ci.yml")

def assert(condition, message)
  raise message unless condition
end

workflow = YAML.safe_load(File.read(WORKFLOW), aliases: true)
jobs = workflow.fetch("jobs")

%w[lint test verify pr].each do |job|
  assert(jobs.key?(job), "CI workflow is missing the #{job} job")
end
%w[lint test].each do |job|
  assert(jobs.fetch(job).dig("env", "CARGO_TARGET_DIR") == "target/normal", "#{job} must build in target/normal")
end

terminal = jobs.fetch("pr")
assert(Array(terminal.fetch("needs")).sort == %w[lint test verify], "pr must depend on lint, test, and verify")
assert(terminal.fetch("if") == "${{ always() }}", "pr must run even when a dependency fails")
terminal_run = terminal.fetch("steps").map { |step| step["run"] }.compact.join("\n")
%w[lint test verify].each do |job|
  expected = %(test "${{ needs.#{job}.result }}" = success)
  assert(terminal_run.lines.map(&:strip).include?(expected), "pr must require the #{job} result to be success")
end

cache_steps = lambda do |job|
  jobs.fetch(job).fetch("steps").select { |step| step["uses"] == "Swatinem/rust-cache@v2" }
end
lint_caches = cache_steps.call("lint")
test_caches = cache_steps.call("test")
assert(lint_caches.length == 1, "lint must have exactly one Rust cache")
assert(test_caches.length == 1, "test must have exactly one Rust cache")
lint_cache = lint_caches.first
test_cache = test_caches.first
assert(lint_cache&.dig("with", "shared-key") == "pr-normal", "lint must restore the shared normal cache")
assert(test_cache&.dig("with", "shared-key") == "pr-normal", "test must restore the shared normal cache")
assert(lint_cache.dig("with", "save-if").to_s == "false", "lint must not race the normal cache writer")
assert(test_cache.dig("with", "save-if") == "${{ github.ref == 'refs/heads/main' }}", "test must be the main-branch normal cache writer")
assert(lint_cache.dig("with", "workspaces") == ". -> target/normal", "lint must cache only target/normal")
assert(test_cache.dig("with", "workspaces") == ". -> target/normal", "test must cache only target/normal")
assert(lint_cache.dig("with", "cache-bin") == "false", "lint must not cache installed tools")
assert(test_cache.dig("with", "cache-bin") == "false", "test must not cache installed tools")

verify_caches = cache_steps.call("verify")
assert(verify_caches.length == 1, "verify must have exactly one Rust cache")
loom_cache = verify_caches.find { |step| step.dig("with", "shared-key") == "pr-loom" }
assert(loom_cache, "verify must own a Loom cache")
assert(loom_cache.dig("with", "workspaces") == ". -> target/loom", "the Loom cache must contain only target/loom")
assert(loom_cache.dig("with", "save-if") == "${{ github.ref == 'refs/heads/main' }}", "verify must be the main-branch Loom cache writer")
assert(loom_cache.dig("with", "cache-bin") == "false", "verify must not cache installed tools")
assert(loom_cache.dig("env", "RUSTFLAGS") == "--cfg loom -D warnings", "the Loom cache key must bind the Loom compiler mode")

loom_step = jobs.fetch("verify").fetch("steps").find { |step| step["name"] == "loom scenarios" }
assert(loom_step, "verify must run the Loom scenarios")
assert(loom_step.fetch("run") == "cargo test -p fireemu-verification-loom --release --target-dir target/loom", "the Loom command must execute the tests in target/loom")
assert(loom_step.dig("env", "RUSTFLAGS") == "--cfg loom -D warnings", "the Loom command must compile all scenarios and deny warnings")

runs = %w[lint test verify].flat_map do |job|
  jobs.fetch(job).fetch("steps").map { |step| step["run"] }.compact
end.join("\n")
{
  "cargo fmt --all --check" => 1,
  "cargo clippy --workspace --all-targets --all-features" => 1,
  "cargo nextest run --workspace --profile pr" => 1,
  "cargo run -p proto-gen -- check" => 1,
  "cargo test -p fireemu-verification-loom" => 1,
}.each do |command, expected|
  actual = runs.scan(command).length
  assert(actual == expected, "#{command.inspect} must appear #{expected} time, found #{actual}")
end

puts "CI workflow contract passed"
