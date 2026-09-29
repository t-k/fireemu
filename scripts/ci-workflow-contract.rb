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

assert(trigger.key?("pull_request"), "CI must run on pull requests")
assert(trigger.dig("push", "branches") == ["main"], "CI must run on pushes to main")

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

platform_runs = jobs.fetch("platforms").fetch("steps").map { |step| step["run"] }.compact.join("\n")
windows_runs = platform_runs.split('= "Windows" ]; then', 2).last.to_s.split("else", 2).first
assert(windows_runs.include?("--exclude fireemu-verification-quint"), "Windows must exclude the Unix-only Quint supervisor")
assert(windows_runs.include?("--exclude traceability-check"), "Windows must exclude the Unix-only traceability supervisor")
assert(windows_runs.include?("cargo nextest run -p fireemu --bin fireemu --test exec_windows --profile pr"), "Windows must execute fireemu binary unit tests and native lifecycle tests")

sdk_runs = load_workflow("functions-sdk-discovery.yml").dig("jobs", "real-sdk-discovery", "steps").map { |step| step["run"] }.compact.join("\n")
assert(sdk_runs.include?("npm ci --prefix tools/sdk-smoke --ignore-scripts"), "SDK environment regressions require installed real dependencies")
assert(sdk_runs.include?("cargo test -p fireemu --test functions_environment -- --include-ignored"), "the manual SDK job must execute every environment regression including opt-in cases")

release = load_workflow("release.yml")
release_source = File.read(File.join(ROOT, ".github", "workflows", "release.yml"))
assert(!release_source.match?(/uses:\s+[^\s]+@(v\d+|stable)\b/), "release actions must be pinned to immutable commits")
toolchain_source = File.read(File.join(ROOT, "rust-toolchain.toml"))
toolchain_channel = toolchain_source.match(/^channel\s*=\s*"([^"]+)"$/)&.captures&.first
assert(toolchain_channel, "rust-toolchain.toml must declare a channel")
# Node: every release job uses Node 24, except the strict production comparison, which pins
# the runtimes its lanes recorded with (harness 24.14.0, Functions fixture 22.22.1).
node_versions = Hash.new(["24"]).merge("strict-production" => ["22.22.1", "24.14.0"])
release.fetch("jobs").each do |job, definition|
  versions = definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("actions/setup-node@") }
    .map { |step| step.dig("with", "node-version").to_s }
  versions.each do |version|
    assert(node_versions[job].include?(version), "release #{job} must use Node #{node_versions[job].join(' or ')}")
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
strict = release.dig("jobs", "strict-production")
assert(strict, "release must compare the strict profile of the installed artifact with the committed production recordings")
assert(strict.fetch("needs").include?("build"), "strict-production must test the built platform package")
assert(strict["continue-on-error"].nil?, "strict-production must block publication")
assert(release.dig("jobs", "publish", "needs").include?("strict-production"), "release publish must depend on the strict production comparison")
assert(release.dig("jobs", "publish", "needs").include?("verify-artifact"), "release publish must depend on verify-artifact")
strict_timeout = strict["timeout-minutes"]
assert(strict_timeout.is_a?(Integer) && strict_timeout.positive? && strict_timeout <= 60, "strict-production must have a timeout of at most an hour")
assert(strict["permissions"] == { "contents" => "read" }, "strict-production must only read the repository")
assert(!strict.key?("environment"), "strict-production must not use a deployment environment")
assert(!YAML.dump(strict).include?("secrets."), "strict-production must not read secrets")
strict_checkout = strict.fetch("steps").find { |step| step["uses"]&.start_with?("actions/checkout@") }
assert(strict_checkout&.dig("with", "persist-credentials") == false, "strict-production must not leave a token in the checkout")
assert(strict.fetch("steps").any? { |step| step["uses"]&.start_with?("actions/download-artifact@") && step.dig("with", "name") == "package-linux-x64" }, "strict-production must test the package publish ships")
strict_runs = strict.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(strict_runs.include?("node npm/scripts/verify-install.mjs --dist npm/dist --keep"), "strict-production must install the packed artifact as verify-artifact does")
assert(strict_runs.include?("sha256sum npm/platforms/build/linux-x64/bin/fireemu"), "strict-production must bind the installed binary to the platform package")
assert(strict_runs.include?("unshare --net"), "strict-production must run the harnesses with loopback-only networking")
assert(strict_runs.include?("node conformance/src/release-strict-regression.mjs"), "strict-production must run the committed comparison script")
assert(!strict_runs.match?(/record-production|record-|preflight/), "strict-production must never record against production")
assert(release.dig("jobs", "reproducible", "continue-on-error").nil?, "release reproducible job must block publication")
assert(release.dig("jobs", "publish", "needs").include?("reproducible"), "release publish must depend on the reproducible job")
assert(release.dig("jobs", "publish", "environment") == "npm-release", "release publish must use the protected npm-release environment")
assert(release.dig("concurrency", "cancel-in-progress") == false, "release publication must never be cancelled in progress")
publish_runs = release.dig("jobs", "publish", "steps").map { |step| step["run"] }.compact.join("\n")
assert(publish_runs.include?("npm@11.9.0"), "release publish must pin an npm version that supports Trusted Publishing")
assert(publish_runs.include?("npm publish ./npm/fireemu"), "release publish must treat the launcher as a local path")
assert(!publish_runs.include?("gh release create"), "the publish job must not create the GitHub Release: it only reads the repository")
assert(release.dig("jobs", "publish", "permissions", "contents") == "read", "the publish job must only read the repository")

# The GitHub Release is written from the CHANGELOG section after npm has the packages, in a job
# of its own so that the only job with write access to releases runs no build or test code.
github_release = release.dig("jobs", "github-release")
assert(github_release, "release must create the GitHub Release after publication")
assert(github_release.fetch("needs").sort == %w[plan publish], "the GitHub Release must wait for the npm publish")
assert(github_release["if"] == "needs.plan.outputs.publish == 'true'", "a dry run must not create a GitHub Release")
assert(github_release["permissions"] == { "contents" => "write" }, "the GitHub Release job needs contents: write and nothing else")
assert(!github_release.key?("environment"), "the GitHub Release job must not wait for another approval after publication")
assert(!YAML.dump(github_release).include?("secrets."), "the GitHub Release job must use only the workflow token")
release_checkout = github_release.fetch("steps").find { |step| step["uses"]&.start_with?("actions/checkout@") }
assert(release_checkout&.dig("with", "persist-credentials") == false, "the GitHub Release job must not leave a token in the checkout")
github_release_runs = github_release.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(github_release_runs.include?("node npm/scripts/changelog-section.mjs"), "the GitHub Release notes must come from the CHANGELOG section")
assert(github_release_runs.include?("gh release create"), "the GitHub Release job must create the release")
publish_steps = release.dig("jobs", "publish", "steps")
release_assets_upload = publish_steps.find { |step| step["uses"]&.start_with?("actions/upload-artifact@") && step.dig("with", "name") == "release-assets" }
assert(release_assets_upload, "the publish job must hand the attested archives, checksums and SBOMs to the GitHub Release job")
assert(release_assets_upload.dig("with", "path") == "dist/*", "the release assets are the attested dist directory")
assert(release_assets_upload["if"] == "needs.plan.outputs.publish == 'true'", "a dry run must not upload release assets")
assert(publish_steps.index(release_assets_upload) < publish_steps.index { |step| step["name"] == "publish the platform packages" }, "the assets must be uploaded before anything is published, so a failed upload cannot leave npm ahead of the release")
assert(publish_steps.index { |step| step["id"] == "attest" } < publish_steps.index(release_assets_upload), "the assets are uploaded after attestation, so they are the attested bytes")
assert(github_release.fetch("steps").any? { |step| step["uses"]&.start_with?("actions/download-artifact@") && step.dig("with", "name") == "release-assets" }, "the GitHub Release job must download the release assets")
assert(github_release_runs.include?("sha256sum --check SHA256SUMS"), "the release assets must match SHA256SUMS before they are attached")
assert(github_release_runs.index("gh release create") < github_release_runs.index("dist/*"), "the release assets must be attached when the release is created")
assert(github_release_runs.include?("--verify-tag"), "the GitHub Release must be created only for an existing tag")
assert(github_release_runs.include?("--notes-file"), "the GitHub Release notes must be the extracted section")
assert(github_release_runs.index("changelog-section.mjs") < github_release_runs.index("gh release create"), "the section must be extracted before the release is created, so a missing section fails first")
plan_runs = release.dig("jobs", "plan", "steps").map { |step| step["run"] }.compact.join("\n")
assert(plan_runs.include?("node npm/scripts/changelog-section.mjs"), "release plan must refuse a version without a CHANGELOG section before anything is published")
assert(load_workflow("ci.yml").dig("jobs", "package", "steps").map { |step| step["run"] }.compact.include?("node --test npm/scripts/changelog-section.test.mjs"), "CI must test the CHANGELOG section extraction")
release_source = File.read(File.join(ROOT, ".github", "workflows", "release.yml"))
assert(!release_source.include?("NPM_TOKEN"), "release publish must authenticate through Trusted Publishing")
assert(!release_source.include?("NODE_AUTH_TOKEN"), "release publish must not inject a registry token")

# The full suite runs on every trigger: pull requests, pushes to main and manual dispatch.
%w[lint test verify platforms package ui].each do |name|
  assert(!jobs.fetch(name).key?("if"), "#{name} must run on pull requests and on pushes to main, not only on manual dispatch")
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

# The paired benchmark is manual-only: it must never join the PR gate,
# must run the emulators from an immutable action set, and must build with the pinned compiler.
benchmark = load_workflow("benchmark.yml")
benchmark_trigger = benchmark["on"] || benchmark[true]
assert(benchmark_trigger.keys == ["workflow_dispatch"], "benchmark.yml must be manual-only: no schedule, no PR trigger")
benchmark_source = File.read(File.join(ROOT, ".github", "workflows", "benchmark.yml"))
assert(!benchmark_source.match?(/uses:\s+[^\s]+@(v\d+|stable)\b/), "benchmark actions must be pinned to immutable commits")
assert(benchmark.dig("concurrency", "cancel-in-progress") == false, "a benchmark series must never be cancelled in progress")
benchmark.fetch("jobs").each do |job, definition|
  assert(definition["timeout-minutes"], "benchmark #{job} must declare a timeout")
  definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("dtolnay/rust-toolchain@") }.each do |step|
    assert(step.dig("with", "toolchain") == toolchain_channel, "benchmark #{job} must build with #{toolchain_channel}")
  end
  definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("pnpm/action-setup@") }.each do |step|
    assert(step.dig("with", "version"), "benchmark #{job} must pin the pnpm version")
  end
end
measure_runs = benchmark.dig("jobs", "measure", "steps").map { |step| step["run"] }.compact.join("\n")
assert(measure_runs.include?("python3 -m unittest discover -s tools/bench"), "benchmark measure must run the harness self-tests first")
assert(measure_runs.include?("node --test tools/bench/client.test.mjs"), "benchmark measure must run the client self-tests first")
assert(measure_runs.include?("tools/bench/report.py"), "benchmark measure must render the report")
benchmark_report = benchmark.dig("jobs", "measure", "steps").find { |step| step["run"]&.include?("tools/bench/report.py") }
assert(benchmark_report["if"] == "always()", "benchmark report must run on failed trials too")

%w[ci.yml compatibility-inventory.yml conformance.yml functions-sdk-discovery.yml quint.yml].each do |name|
  bounded = load_workflow(name)
  assert(bounded.dig("concurrency", "group") == "${{ github.workflow }}-${{ github.ref }}", "#{name} must cancel stale runs for the same ref")
  assert(bounded.dig("concurrency", "cancel-in-progress") == true, "#{name} must enable stale-run cancellation")
end
assert(load_workflow("compatibility-inventory.yml").dig("jobs", "offline-acquisition-integrity", "timeout-minutes") == 120, "offline acquisition must have a two-hour timeout")
assert(load_workflow("functions-sdk-discovery.yml").dig("jobs", "real-sdk-discovery", "timeout-minutes") == 120, "manual SDK discovery must have a two-hour timeout")
{
  "ci.yml" => %w[lint test verify pr platforms package ui],
  "compatibility-inventory.yml" => %w[feature-inventory-integrity offline-acquisition-integrity],
  "conformance.yml" => %w[conformance],
  "functions-sdk-discovery.yml" => %w[real-sdk-discovery],
  "quint.yml" => %w[quint],
}.each do |name, jobs|
  workflow = load_workflow(name)
  jobs.each do |job|
    timeout = workflow.dig("jobs", job, "timeout-minutes")
    assert(timeout.is_a?(Integer) && timeout.positive? && timeout <= 180, "#{name}/#{job} must have a timeout of at most three hours")
  end
end

puts "CI workflow contract passed"
