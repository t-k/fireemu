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
# The published binary is built and tested from a clean target: no job that feeds it restores a cache
# another run may have written.
%w[test build].each do |job|
  cached = release.dig("jobs", job, "steps").select { |step| step["uses"].to_s.match?(%r{\A(Swatinem/rust-cache|actions/cache)(/|@)}) }
  assert(cached.empty?, "release #{job} must not restore a cache")
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
assert(strict_checkout.dig("with", "fetch-depth") == 0, "strict-production must fetch the whole history: the harness lineage check verifies every hop against it and refuses a shallow clone")
assert(strict.fetch("steps").any? { |step| step["uses"]&.start_with?("actions/download-artifact@") && step.dig("with", "name") == "package-linux-x64" }, "strict-production must test the package publish ships")
strict_runs = strict.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(strict_runs.include?("node npm/scripts/verify-install.mjs --dist npm/dist --keep"), "strict-production must install the packed artifact as verify-artifact does")
assert(strict_runs.include?("sha256sum npm/platforms/build/linux-x64/bin/fireemu"), "strict-production must bind the installed binary to the platform package")
assert(strict_runs.include?("npm ci --prefix conformance/src/auth-tenant-blocking/function --ignore-scripts --no-audit --no-fund"), "strict-production must install the AUTH-TENANT-BLOCKING blocking fixture's dependencies from its lockfile without running install scripts")
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
# Permissions, per job. The workflow default is read-only, and no job but these two holds more:
# `publish` mints the OIDC token that npm Trusted Publishing and the attestations need, and
# `github-release` writes the Release. The rest run build, test and third-party dependency code.
assert(release["permissions"] == { "contents" => "read" }, "the workflow default must stay read-only: the jobs that need more ask for it themselves")
# Nothing is set for every job at once: an env such as BASH_ENV or NODE_OPTIONS, or `defaults`, would
# reach the job that holds the release token. (`on:` parses as the key `true`.)
assert(
  release.keys.map { |key| key == true ? "on" : key }.sort == %w[concurrency env jobs name on permissions],
  "the release workflow has no top-level defaults and no key beyond name, on, permissions, concurrency, env and jobs"
)
assert(release["env"].keys.sort == %w[CARGO_TERM_COLOR RUSTFLAGS SOURCE_DATE_EPOCH], "the release workflow's env is exactly the reproducibility inputs")
every_use = release.fetch("jobs").values.flat_map { |definition| definition.fetch("steps", []).map { |step| step["uses"] }.compact }
assert(every_use.group_by { |use| use.split("@").first }.values.all? { |uses| uses.uniq.length == 1 }, "an action is pinned to one commit across the release workflow")
release.fetch("jobs").each do |job, definition|
  extra = definition.keys - %w[needs if runs-on outputs steps strategy timeout-minutes permissions environment]
  assert(extra.empty?, "release #{job} sets #{extra.join(', ')}: no job-level env, defaults, container, services or continue-on-error")
end
assert(every_use.all? { |use| use.match?(/\A[\w.-]+\/[\w.-]+(\/[\w.\/-]+)?@[0-9a-f]{40}\z/) }, "every action in the release workflow is pinned to a 40-hex commit, never a branch or a tag")
expected_permissions = Hash.new({ "contents" => "read" }).merge(
  "publish" => { "contents" => "read", "id-token" => "write", "attestations" => "write" },
  "github-release" => { "contents" => "write" }
)
release.fetch("jobs").each do |job, definition|
  effective = definition["permissions"] || release["permissions"]
  assert(effective == expected_permissions[job], "release #{job} must have exactly #{expected_permissions[job]} permissions, not #{effective}")
end

# The GitHub Release is written from the CHANGELOG section that `plan` checked, and from the
# attested files `publish` handed over, after npm has the packages. It is a job of its own that
# checks out nothing and installs nothing, so the only job that can write releases runs no code
# from the repository.
uploads = lambda do |job, name|
  release.dig("jobs", job, "steps").select { |step| step["uses"]&.start_with?("actions/upload-artifact@") && step.dig("with", "name") == name }
end
all_uploaders = lambda do |name|
  release.fetch("jobs").flat_map do |job, definition|
    definition.fetch("steps", []).select { |step| step["uses"]&.start_with?("actions/upload-artifact@") && step.dig("with", "name") == name }.map { job }
  end
end
assert(all_uploaders.call("release-notes") == %w[plan], "only plan may upload release-notes, exactly once")
assert(all_uploaders.call("release-assets") == %w[publish], "only publish may upload release-assets, exactly once")
notes_upload = uploads.call("plan", "release-notes").first
assert(notes_upload["if"] == "steps.version.outputs.publish == 'true'", "a dry run must not upload release notes")
assert(notes_upload.dig("with", "path") == "${{ runner.temp }}/release-notes.md", "the notes uploaded are the file the extraction wrote")
assert(notes_upload.dig("with", "if-no-files-found") == "error", "the release notes upload must fail when the notes are missing")
assert(notes_upload.dig("with", "overwrite") == true, "a re-run of plan must be able to replace the release notes")
assert(notes_upload["continue-on-error"].nil?, "the release notes upload must block publication")
plan_steps = release.dig("jobs", "plan", "steps")
extraction = plan_steps.find { |step| step["run"]&.include?("changelog-section.mjs") }
assert(extraction.keys.sort == %w[env if name run], "the extraction step has no working-directory, shell or continue-on-error")
assert(extraction["run"] == 'node npm/scripts/changelog-section.mjs "$VERSION" --out "$RUNNER_TEMP/release-notes.md"', "plan extracts the notes with exactly this command")
assert(extraction["if"] == "steps.version.outputs.publish == 'true'" && extraction["continue-on-error"].nil?, "the extraction runs for every tag and blocks the release when it fails")
assert(extraction.dig("env", "VERSION") == "${{ steps.version.outputs.version }}", "the extraction reads the version plan validated")
assert(plan_steps.index(notes_upload) > plan_steps.index(extraction), "the notes are uploaded after they are extracted")

publish_steps = release.dig("jobs", "publish", "steps")
release_assets_upload = uploads.call("publish", "release-assets").first
assert(release_assets_upload.dig("with", "path") == "dist/*", "the release assets are the attested dist directory")
assert(release_assets_upload["if"] == "needs.plan.outputs.publish == 'true'", "a dry run must not upload release assets")
assert(release_assets_upload.dig("with", "if-no-files-found") == "error", "the release assets upload must fail when a file is missing")
assert(release_assets_upload.dig("with", "overwrite") == true, "a re-run of publish must be able to replace the release assets")
assert(release_assets_upload["continue-on-error"].nil?, "the release assets upload must block publication, or npm gets ahead of the Release")
assert(publish_steps.index(release_assets_upload) < publish_steps.index { |step| step["name"] == "publish the platform packages" }, "the assets must be uploaded before anything is published, so a failed upload cannot leave npm ahead of the release")
assert(publish_steps.index { |step| step["id"] == "attest" } < publish_steps.index(release_assets_upload), "the assets are uploaded after attestation, so they are the attested bytes")
[notes_upload, release_assets_upload].each do |upload|
  assert(upload.dig("with", "retention-days").to_i >= 30, "the artifacts a re-run of github-release needs must outlive a slow recovery")
end

github_release = release.dig("jobs", "github-release")
assert(github_release, "release must create the GitHub Release after publication")
assert(release.dig("jobs", "github-release", "runs-on") == "ubuntu-latest", "the job that holds the release token runs on a hosted, ephemeral runner")
assert(github_release.keys.sort == %w[if needs permissions runs-on steps], "the GitHub Release job has no environment, no continue-on-error and no other setting")
assert(github_release.fetch("needs").sort == %w[plan publish], "the GitHub Release must wait for the npm publish")
assert(github_release["if"] == "needs.plan.outputs.publish == 'true'", "a dry run must not create a GitHub Release")
assert(!YAML.dump(github_release).include?("secrets."), "the GitHub Release job must use only the workflow token")
release_steps = github_release.fetch("steps")
assert(release_steps.length == 3, "the GitHub Release job downloads the assets, downloads the notes and creates the Release, and does nothing else")
download_assets, download_notes, create = release_steps
[[download_assets, "release-assets", "dist"], [download_notes, "release-notes", "notes"]].each do |step, name, path|
  assert(step.keys.sort == %w[uses with] && step["uses"].start_with?("actions/download-artifact@"), "#{name} is fetched by a plain download-artifact step: no if, no continue-on-error")
  assert(step["with"] == { "name" => name, "path" => path }, "#{name} is downloaded into #{path}")
end
# The create step is compared whole. Every check in it blocks the Release, and a weakened one
# (`|| true`, a comment, `--generate-notes`, another shell) is a different script.
EXPECTED_CREATE_SCRIPT = <<~'SCRIPT'
  # The files attached are the ones SHA256SUMS names (and attested), unchanged.
  (cd dist && sha256sum --check SHA256SUMS)
  test -s notes/release-notes.md
  if gh release view "$TAG" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    echo "a GitHub Release for $TAG already exists: edit it by hand and attach dist/*, or delete it and re-run this job" >&2
    exit 1
  fi
  flags=""
  # A version is a prerelease by what precedes its build metadata.
  case "${VERSION%%+*}" in *-*) flags="--prerelease" ;; esac
  # shellcheck disable=SC2086 # $flags is empty or one fixed flag
  gh release create "$TAG" --repo "$GITHUB_REPOSITORY" --verify-tag --title "Fireemu ${VERSION}" \
    --notes-file notes/release-notes.md $flags dist/*
SCRIPT
assert(create.keys.sort == %w[env name run], "the create step has no if, continue-on-error, shell or working directory")
assert(create["env"] == { "GH_TOKEN" => "${{ github.token }}", "VERSION" => "${{ needs.plan.outputs.version }}", "TAG" => "${{ github.ref_name }}" }, "the create step passes the token, the version and the tag through env")
assert(create["run"].strip == EXPECTED_CREATE_SCRIPT.strip, "the create step's script is not the reviewed one")
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
broad_runs = load_workflow("compatibility-inventory.yml").dig("jobs", "compat-broad-tests", "steps")
  .flat_map { |step| step.fetch("run", "").lines.map(&:strip) }
broad_commands = broad_runs.select { |line| line.start_with?("uv run ") }
broad_prefix = "uv run --project tools/compat-inventory --locked --python 3.12.13 "
assert(broad_commands.length == 2, "required broad tests must retain exactly two executable uv commands")
assert(broad_commands.count { |line| line.start_with?(broad_prefix + 'tools/compat-inventory/broad_shards.py --shards 7 --shard ') } == 1,
  "required broad shard planner must use the reviewed Python 3.12.13 runtime")
assert(broad_commands.count { |line| line.start_with?(broad_prefix + '-m pytest ') } == 1,
  "required broad pytest must use the reviewed Python 3.12.13 runtime")
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
