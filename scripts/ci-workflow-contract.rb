#!/usr/bin/env ruby

require "json"
require "yaml"
require "rbconfig"
require_relative "actions-security-contract"

ROOT = File.expand_path("..", __dir__)
ActionsSecurityContract.check!(ROOT)
raise "Actions security regression fixtures failed" unless system(RbConfig.ruby, File.join(__dir__, "actions-security-contract.test.rb"))

def assert(condition, message)
  raise message unless condition
end

def load_workflow(name)
  YAML.safe_load(File.read(File.join(ROOT, ".github", "workflows", name)), aliases: true)
end

%w[ci.yml conformance.yml quint.yml].each do |name|
  assert(load_workflow(name)["permissions"] == { "contents" => "read" }, "#{name} must default to contents: read only")
end

workflow = load_workflow("ci.yml")
jobs = workflow.fetch("jobs")
trigger = workflow["on"] || workflow[true]
assert(trigger.key?("workflow_dispatch"), "CI must retain a manual full-suite trigger")
lint_runs = jobs.fetch("lint").fetch("steps").map { |step| step["run"] }.compact
assert(lint_runs.include?("ruby scripts/txn04-replay-contract.test.rb"), "the lint job must check the txn04-replay job contract")
lint_conditional = jobs.fetch("lint").fetch("steps").select { |step| step["run"] == "ruby scripts/txn04-replay-contract.test.rb" && (step.key?("if") || step.key?("continue-on-error")) }
assert(lint_conditional.empty?, "the txn04-replay contract step must be unconditional")

assert(trigger.key?("pull_request"), "CI must run on pull requests")
assert(trigger.dig("push", "branches") == ["main"], "CI must run on pushes to main")

pr = jobs.fetch("pr")
assert(!pr.key?("needs"), "the minimal pr job must not depend on manual jobs")
assert(pr.dig("env", "CARGO_TARGET_DIR") == "target/minimal", "the minimal pr job must use target/minimal")
pr_runs = pr.fetch("steps").map { |step| step["run"] }.compact.join("\n")
assert(pr_runs.include?("ruby scripts/ci-workflow-contract.rb"), "the minimal pr job must check its workflow contract")
assert(pr_runs.include?("cargo fmt --all --check"), "the minimal pr job must check formatting")
assert(pr_runs.include?("cargo check --workspace --all-targets"), "the minimal pr job must compile every target")
pr_steps = pr.fetch("steps")
release_ui_steps = load_workflow("release.yml").dig("jobs", "ui", "steps")
release_pnpm_setup = release_ui_steps.find { |step| step["uses"]&.start_with?("pnpm/action-setup@") }
release_node_setup = release_ui_steps.find { |step| step["uses"]&.start_with?("actions/setup-node@") }
pnpm_setup_index = pr_steps.index { |step| step["uses"]&.start_with?("pnpm/action-setup@") }
node_setup_index = pr_steps.index { |step| step["uses"]&.start_with?("actions/setup-node@") }
dependency_install_index = pr_steps.index { |step| step["run"] == "pnpm -C conformance install --frozen-lockfile" }
selftest_index = pr_steps.index { |step| step["run"] == "pnpm -C conformance selftest" }
dependency_install_step = pr_steps[dependency_install_index] if dependency_install_index
selftest_step = pr_steps[selftest_index] if selftest_index
assert(release_pnpm_setup, "release must pin the pnpm setup used by the conformance selftest")
assert(release_node_setup, "release must pin the Node setup used by the conformance selftest")
assert(pr_steps.count { |step| step["uses"]&.start_with?("pnpm/action-setup@") } == 1, "the minimal pr job must set up pnpm exactly once")
assert(pr_steps.count { |step| step["uses"]&.start_with?("actions/setup-node@") } == 1, "the minimal pr job must set up Node exactly once")
assert(pr_steps.count { |step| step["run"] == "pnpm -C conformance install --frozen-lockfile" } == 1, "the minimal pr job must install conformance dependencies exactly once")
assert(pr_steps.count { |step| step["run"] == "pnpm -C conformance selftest" } == 1, "the minimal pr job must run selftest exactly once")
assert(pnpm_setup_index && pr_steps[pnpm_setup_index] == release_pnpm_setup, "the minimal pr job must use the pinned pnpm action and version from release")
assert(node_setup_index && pr_steps[node_setup_index]["uses"] == release_node_setup["uses"] && pr_steps[node_setup_index].dig("with", "node-version") == 24, "the minimal pr job must use the pinned Node 24 setup from release")
assert(node_setup_index && pr_steps[node_setup_index].keys.sort == %w[uses with] && pr_steps[node_setup_index]["with"] == { "node-version" => 24 }, "the minimal pr job must not add setup-node caching or other options")
assert(dependency_install_index && selftest_index, "the minimal pr job must install frozen conformance dependencies and run selftest")
assert(pnpm_setup_index < node_setup_index && node_setup_index < dependency_install_index && dependency_install_index < selftest_index, "the minimal pr job must set up pnpm and Node, install frozen conformance dependencies, then run selftest")
assert(dependency_install_step == { "name" => "install frozen conformance dependencies", "run" => "pnpm -C conformance install --frozen-lockfile" }, "the minimal pr job must install only frozen conformance dependencies")
assert(selftest_step == { "name" => "conformance selftest", "run" => "pnpm -C conformance selftest" }, "the minimal pr job must run the exact selftest as a required step")
assert(pr_steps.none? { |step| step["uses"].to_s.match?(%r{\Apnpm/action-setup@}) && step.fetch("with", {}).key?("cache") }, "the minimal pr job must not use a pnpm cache")
# The selftest verifies every hop of the harness lineage against the history and refuses a shallow clone.
pr_checkout = pr_steps.find { |step| step["uses"]&.start_with?("actions/checkout@") }
assert(pr_checkout&.dig("with", "fetch-depth") == 0, "the minimal pr job must fetch the whole history: the selftest's harness lineage check refuses a shallow clone")
# The selftest script is what the pr job runs, so a test file that no glob in it matches never runs on a pull request.
# Every conformance test file is either matched by a glob of the script or sits in a directory listed here with the
# reason it stays out. A new test directory fails this check until it is added to the script or to this list.
selftest_script = JSON.parse(File.read(File.join(ROOT, "conformance", "package.json"))).dig("scripts", "selftest").to_s
selftest_globs = selftest_script.split.select { |word| word.end_with?(".test.mjs") }
%w[src/*.test.mjs src/shared/*.test.mjs scheduled-functions/*.test.mjs].each do |required|
  assert(selftest_globs.include?(required), "the conformance selftest script must keep running #{required}")
end
selftest_not_run = {
  "functions-http" => "starts real child processes and takes about 100 s on its own",
  "production-diff/test" => "its process-supervision and G0 session tests need the locked Python 3.12 inventory runtime and real detached children",
}
conformance_dir = File.join(ROOT, "conformance")
test_files = Dir.glob("**/*.test.mjs", base: conformance_dir).reject { |path| path.start_with?("node_modules/") || path.include?("/node_modules/") }
unrun = test_files.reject do |path|
  selftest_globs.any? { |glob| File.fnmatch?(glob, path, File::FNM_PATHNAME) } ||
    selftest_not_run.keys.any? { |dir| path.start_with?("#{dir}/") }
end
assert(unrun.empty?, "conformance test files that neither the selftest script nor selftest_not_run in scripts/ci-workflow-contract.rb cover: #{unrun.first(5).join(', ')}")
assert(selftest_not_run.keys.all? { |dir| File.directory?(File.join(conformance_dir, dir)) }, "selftest_not_run names a directory that does not exist")
%w[nextest clippy cargo\ doc cargo\ deny proto-gen fireemu-verification-loom].each do |expensive|
  assert(!pr_runs.include?(expensive), "the automatic pr job must not run #{expensive}")
end

platform_steps = jobs.fetch("platforms").fetch("steps")
assert(jobs.dig("platforms", "name").to_s.start_with?("tests ("), "platform tests must retain the tests ( name prefix")
assert(jobs.dig("platforms", "strategy", "fail-fast") == false, "platform tests must run every partition without fail-fast")
platform_runs = platform_steps.map { |step| step["run"] }.compact.join("\n")
platform_matrix = jobs.dig("platforms", "strategy", "matrix")
assert(platform_matrix == { "include" => [{ "os" => "macos-latest", "shard" => "1/2" }, { "os" => "macos-latest", "shard" => "2/2" }, { "os" => "windows-latest", "shard" => "" }] }, "platform tests must run both macOS partitions and one unpartitioned Windows job")
# The Functions runner tests start a real Node and a real Python child, four at once, as the first
# executions of those interpreters on a freshly provisioned runner. Their first start pages the image in from
# disk (2026-11-09: 4 to 22 s on 24 fresh VMs, 60 s or more on two runs of 2026-11-06). Pay that before the tests,
# outside any hello deadline.
warm_index = platform_steps.index { |step| step["name"].to_s.start_with?("warm the interpreters") }
platform_tests_index = platform_steps.index { |step| step["name"] == "tests" }
assert(warm_index && platform_tests_index && warm_index < platform_tests_index, "the platform job must warm the Node and Python interpreters before the tests")
warm_step = platform_steps[warm_index]
assert(warm_step["if"] == "runner.os == 'Windows'", "the interpreter warm-up must run on Windows only")
assert(!warm_step.key?("continue-on-error"), "the interpreter warm-up must not hide a missing interpreter")
assert(warm_step["run"].to_s.match?(/^\s*(time )?node /) && warm_step["run"].to_s.match?(/^\s*(time )?python3 /), "the interpreter warm-up must start node and python3")
windows_runs = platform_runs.split('= "Windows" ]; then', 2).last.to_s.split("else", 2).first
assert(windows_runs.include?("--exclude fireemu-verification-quint"), "Windows must exclude the Unix-only Quint supervisor")
assert(windows_runs.include?("--exclude traceability-check"), "Windows must exclude the Unix-only traceability supervisor")
assert(windows_runs.include?("cargo nextest run -p fireemu --bin fireemu --test exec_windows --profile pr"), "Windows must execute fireemu binary unit tests and native lifecycle tests")
assert(!windows_runs.include?("--partition"), "Windows platform tests must not be partitioned")
assert(platform_steps[platform_tests_index]["run"].include?('cargo nextest run --workspace --profile pr --partition count:${{ matrix.shard }}'), "macOS platform tests must use the matrix partition")

latest = load_workflow("sdk-latest.yml")
latest_trigger = latest["on"] || latest[true]
assert(latest_trigger.keys.sort == %w[pull_request push schedule workflow_dispatch], "sdk-latest must have exactly the intended triggers")
assert(latest_trigger.fetch("schedule").map { |entry| entry.fetch("cron") } == ["0 4 * * *", "0 3 * * 2"], "sdk-latest must run daily and weekly")
assert(latest_trigger.dig("workflow_dispatch", "inputs", "suite", "options") == %w[light broad], "sdk-latest dispatch must offer light and broad")
assert(latest["permissions"] == { "contents" => "read" }, "sdk-latest must only read contents")
assert(latest.dig("concurrency", "group") == "${{ github.workflow }}-${{ github.event.schedule || github.ref }}", "sdk-latest must separate scheduled runs by cron")
assert(latest.dig("concurrency", "cancel-in-progress") == true, "sdk-latest must enable stale-run cancellation")
latest_jobs = latest.fetch("jobs")
assert(latest_jobs.keys.sort == %w[latest-sdk-under-exec published-broad published-light], "sdk-latest must have exactly three jobs")
latest_steps = latest_jobs.values.flat_map do |job|
  assert(!job.key?("permissions"), "sdk-latest jobs must inherit permissions")
  assert(job["cache-mode"] == "read", "sdk-latest jobs must declare read-only cache access")
  timeout = job["timeout-minutes"]
  assert(timeout.is_a?(Integer) && (1..60).cover?(timeout), "sdk-latest jobs must have a timeout at most 60 minutes")
  job.fetch("steps")
end
latest_steps.each do |step|
  text = YAML.dump(step)
  %w[secrets. git\ push gh\ pr create-pull-request actions/cache@].each do |forbidden|
    assert(!text.include?(forbidden), "sdk-latest steps must not contain #{forbidden}")
  end
  uses = step["uses"].to_s
  assert(uses.empty? || uses.match?(/@[0-9a-f]{40}\z/), "sdk-latest actions must be pinned")
  assert(!step.fetch("with", {}).key?("cache"), "sdk-latest setup-node must not cache") if uses.start_with?("actions/setup-node@")
  assert(step.dig("with", "save-if") == "false", "sdk-latest rust-cache must not save") if uses.start_with?("Swatinem/rust-cache@")
end
uploads = latest_steps.select { |step| step["uses"].to_s.start_with?("actions/upload-artifact@") }
assert(uploads.map { |step| step.dig("with", "name") }.sort == %w[sdk-latest-combination-broad sdk-latest-combination-light], "sdk-latest must upload both combinations")
uploads.each do |step|
  assert(step.dig("with", "if-no-files-found") == "error" && step.dig("with", "retention-days") == 90, "sdk-latest artifacts must be required and retained for 90 days")
end
assert(latest_jobs.dig("published-light", "if") == "(github.event_name == 'schedule' && github.event.schedule == '0 4 * * *') || (github.event_name == 'workflow_dispatch' && inputs.suite == 'light')", "light must run only on daily schedule or light dispatch")
assert(latest_jobs.dig("published-broad", "if") == "(github.event_name == 'schedule' && github.event.schedule == '0 3 * * 2') || (github.event_name == 'workflow_dispatch' && inputs.suite == 'broad')", "broad must run only on weekly schedule or broad dispatch")
assert(latest_jobs.dig("latest-sdk-under-exec", "if") == "github.event_name != 'schedule' || github.event.schedule == '0 3 * * 2'", "source build must skip the daily schedule")
assert(latest_jobs.dig("published-broad", "steps").find { |step| step["name"] == "run published package smokes" }.fetch("run").lines.map(&:strip).include?("./node_modules/.bin/fireemu exec --firebase-json listener-replacement.firebase.json --only firestore --project demo-app --hub-port 0 -- node listener-replacement.mjs"), "broad must run the Firestore listener smoke with its Firebase configuration")

sdk = load_workflow("functions-sdk-discovery.yml")
sdk_trigger = sdk["on"] || sdk[true]
assert(!sdk_trigger.key?("pull_request_target"), "SDK discovery must not use pull_request_target")
assert(sdk_trigger.keys.sort == %w[pull_request push schedule workflow_dispatch], "SDK discovery must run on manual dispatch, pull requests, pushes and a schedule only")
%w[pull_request push].each do |event|
  paths = sdk_trigger.dig(event, "paths")
  assert(paths.is_a?(Array) && !paths.empty?, "SDK discovery #{event} must have a non-empty paths list")
  %w[.github/workflows/functions-sdk-discovery.yml tools/runner-node/**].each do |path|
    assert(paths.include?(path), "SDK discovery #{event} paths must include #{path}")
  end
end
assert(sdk_trigger.dig("push", "branches") == ["main"], "SDK discovery must only run on pushes to main")
assert(sdk["permissions"] == { "contents" => "read" }, "SDK discovery permissions must stay contents: read")
sdk_runs = sdk.dig("jobs", "real-sdk-discovery", "steps").map { |step| step["run"] }.compact.join("\n")
assert(sdk_runs.include?("npm ci --prefix tools/sdk-smoke --ignore-scripts"), "SDK environment regressions require installed real dependencies")
assert(sdk_runs.include?("cargo test -p fireemu --test functions_environment -- --include-ignored"), "the SDK job must execute every environment regression including opt-in cases")

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
assert(release.dig("jobs", "publish", "needs").include?("test"), "release publish must depend on the dedicated test job")
release_test_runs = release.dig("jobs", "test", "steps").map { |step| step["run"] }.compact.join("\n")
assert(
  release_test_runs.include?("cargo nextest run --workspace --profile pr -E 'not binary(leak_fixture)'"),
  "release test job must run the workspace suite outside the process leak fixture"
)
assert(
  release_test_runs.include?("cargo nextest run -p fireemu --test leak_fixture --profile pr"),
  "release test job must run the process leak fixture in isolation"
)
# v0.11.0's first tag failed here: the Functions runtime tests need the real SDK from the
# conformance install, which ci.yml installed and the release test job did not.
release_sdk_install = release_test_runs.index("pnpm -C conformance install --frozen-lockfile")
release_workspace_suite = release_test_runs.index("cargo nextest run --workspace")
assert(
  release_sdk_install && release_workspace_suite && release_sdk_install < release_workspace_suite,
  "release test job must install the conformance SDK before the workspace suite"
)
strict = release.dig("jobs", "strict-production")
assert(strict, "release must compare the strict profile of the installed artifact with the committed production recordings")
assert(strict["name"].to_s.start_with?("strict-production"), "strict-production must retain the strict-production name prefix")
assert(strict.fetch("needs").include?("build"), "strict-production must test the built platform package")
assert(strict["continue-on-error"].nil?, "strict-production must block publication")
assert(strict.dig("strategy", "fail-fast") == false && strict.dig("strategy", "matrix", "group") == %w[eventarc transaction rtdb-a rtdb-b rest], "strict-production must run every group without fail-fast")
assert(release.dig("jobs", "publish", "needs").include?("strict-production"), "release publish must depend on the strict production comparison")
assert(release.dig("jobs", "publish", "needs").include?("verify-artifact"), "release publish must depend on verify-artifact")
strict_timeout = strict["timeout-minutes"]
assert(strict_timeout.is_a?(Integer) && strict_timeout == 180, "strict-production must retain the exact 180-minute bound for finite R20 check/export and the other replay runs")
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
assert(strict_runs.include?("npm ci --prefix tools/sdk-smoke-database --ignore-scripts --no-audit --no-fund"), "strict-production must install the locked RTDB SDK dependencies")
assert(strict_runs.include?("npm ci --prefix conformance/src/rtdb-functions/fixtures --ignore-scripts --no-audit --no-fund"), "strict-production must install the locked RTDB Functions fixture")
assert(strict_runs.include?("conformance/src/rtdb-release-replay.test.mjs"), "strict-production must test the RTDB release replay")
assert(strict_runs.include?("unshare --net --pid --fork --mount-proc --kill-child"), "strict-production must isolate the network and all descendant processes")
assert(strict_runs.include?("node conformance/src/rtdb-namespace-probe.mjs --out strict-namespace-probe"), "strict-production must prove detached timeout cleanup in a real PID namespace")
assert(strict_runs.include?("node conformance/src/release-strict-regression.mjs"), "strict-production must run the committed comparison script")
strict_replay = strict.fetch("steps").find { |step| step["run"]&.include?("node conformance/src/release-strict-regression.mjs --out") }
assert(strict_replay&.dig("env", "GROUP") == '${{ matrix.group }}' && strict_replay["run"].include?('GROUP="$GROUP"') && strict_replay["run"].include?('--group "$GROUP"'), "strict-production must pass the matrix group to the replay")
assert(strict.fetch("steps").any? { |step| step["uses"]&.start_with?("actions/upload-artifact@") && step.dig("with", "name") == 'strict-regression-${{ matrix.group }}' }, "strict-production must upload one artifact per group")
assert(!strict_runs.match?(/record-production|record-|preflight/), "strict-production must never record against production")
assert(release.dig("jobs", "reproducible", "continue-on-error").nil?, "release reproducible job must block publication")
assert(release.dig("jobs", "publish", "needs").include?("reproducible"), "release publish must depend on the reproducible job")
assert(release.dig("jobs", "publish", "environment") == "npm-release", "release publish must use the protected npm-release environment")
assert(release.dig("concurrency", "cancel-in-progress") == false, "release publication must never be cancelled in progress")
publish_runs = release.dig("jobs", "publish", "steps").map { |step| step["run"] }.compact.join("\n")
assert(publish_runs.include?("npm@11.9.0"), "release publish must pin an npm version that supports Trusted Publishing")
assert(publish_runs.include?("npm publish ./npm/fireemu"), "release publish must treat the launcher as a local path")
assert(!publish_runs.include?("gh release create"), "the publish job must not create the GitHub Release: it only reads the repository")
# Permissions, per job. The workflow default is read-only. Publication jobs mint OIDC tokens;
# release jobs write GitHub Releases; recovery additionally reads original run artifacts and attestations.
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
  allowed = %w[needs if runs-on outputs steps strategy timeout-minutes permissions environment]
  allowed << "name" if job == "strict-production" && definition["name"] == 'strict-production (${{ matrix.group }})'
  extra = definition.keys - allowed
  assert(extra.empty?, "release #{job} sets #{extra.join(', ')}: no job-level env, defaults, container, services or continue-on-error")
end
assert(every_use.all? { |use| use.match?(/\A[\w.-]+\/[\w.-]+(\/[\w.\/-]+)?@[0-9a-f]{40}\z/) }, "every action in the release workflow is pinned to a 40-hex commit, never a branch or a tag")
expected_permissions = Hash.new({ "contents" => "read" }).merge(
  "publish" => { "contents" => "read", "id-token" => "write", "attestations" => "write" },
  "github-release" => { "contents" => "write" },
  "recover-v0381" => { "contents" => "read", "actions" => "read", "attestations" => "read", "id-token" => "write" },
  "recover-v0381-github-release" => { "contents" => "write" }
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
assert(!release.dig("jobs", "publish").key?("if"), "release publish must not bypass required jobs")
assert(publish_steps.none? { |step| step.key?("continue-on-error") }, "release publish steps must not hide failures")
assert(publish_steps.none? { |step| step["if"].to_s.match?(/\b(?:always|failure|cancelled)\s*\(\s*\)/i) }, "release publish steps must not bypass failures or cancellations")
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
package_runs = jobs.fetch("package").fetch("steps").map { |step| step["run"] }.compact
types_consumer_command = "node --test npm/scripts/types-consumer.test.mjs"
assert(package_runs.include?(types_consumer_command), "package CI must type-check actual packed public subpaths")
assert(package_runs.index("pnpm -C ui install --frozen-lockfile") < package_runs.index(types_consumer_command), "type consumers must use the installed pinned UI TypeScript compiler")
release_source = File.read(File.join(ROOT, ".github", "workflows", "release.yml"))
assert(!release_source.include?("NPM_TOKEN"), "release publish must authenticate through Trusted Publishing")
assert(!release_source.include?("NODE_AUTH_TOKEN"), "release publish must not inject a registry token")

# The Functions runner's Node tests (the 44-frame Storage member-order test among them) are a gate on
# every trigger, on Linux and macOS, with the pinned real SDK installed first.
runner_node = jobs["runner-node"]
assert(runner_node, "CI must have a runner-node job for the Functions runner Node tests")
assert(runner_node.dig("strategy", "matrix", "os") == %w[ubuntu-latest macos-latest], "the runner Node tests must run on Linux and macOS")
runner_steps = runner_node.fetch("steps")
runner_runs = runner_steps.map { |step| step["run"] }
runner_install = runner_runs.index("pnpm -C conformance install --frozen-lockfile")
runner_tests = runner_runs.index("node --test tools/runner-node/*.test.mjs")
assert(runner_install && runner_tests && runner_install < runner_tests, "the runner Node tests must run after the pinned real SDK install")
assert(runner_node["runs-on"] == "${{ matrix.os }}", "the runner Node tests must run on the matrix operating system")
assert(runner_steps.any? { |step| step["uses"]&.start_with?("actions/setup-node@") && step.dig("with", "node-version").to_s == "24" }, "the runner Node tests must run on Node 24")
# The SDK inventory tests need the sdk-smoke install, and must fail rather than skip without it.
runner_sdk_install = runner_runs.index("npm ci --prefix tools/sdk-smoke --ignore-scripts")
assert(runner_sdk_install && runner_sdk_install < runner_tests, "the runner Node tests must run after the sdk-smoke install")
assert(runner_node["env"] == { "FIREEMU_REQUIRE_SDK" => "1" }, "the runner Node job must require the SDK, so the inventory tests cannot skip")
# Nothing may make the gate fail open: no continue-on-error, no step-level if, no other working
# directory, no cache, no defaults. The steps that install and test carry exactly a name and a command.
assert((runner_node.keys - %w[name runs-on timeout-minutes strategy env steps]).empty?, "the runner Node job may carry only name, runs-on, timeout-minutes, strategy, env and steps")
assert((runner_node.fetch("strategy").keys - %w[fail-fast matrix]).empty?, "the runner Node strategy may carry only fail-fast and matrix")
runner_steps.each do |step|
  if step["run"]
    assert(step.keys.sort == %w[name run], "runner Node run steps carry exactly a name and a run: #{step['name']}")
  elsif step["uses"]&.start_with?("actions/setup-node@")
    assert(step.keys.sort == %w[uses with] && step["with"].keys == %w[node-version], "the runner Node setup-node step sets only node-version (no cache)")
  elsif step["uses"]&.start_with?("pnpm/action-setup@")
    assert(step.keys.sort == %w[uses with] && step["with"].keys == %w[version], "the runner Node pnpm step sets only the version")
  else
    assert(step.keys == %w[uses] && step["uses"].start_with?("actions/checkout@"), "the runner Node job uses only checkout, pnpm, setup-node and run steps")
  end
end

# The Realtime Database smoke tests (tools/sdk-smoke-database) are a gate on every trigger. They are offline;
# the one file that needs Chromium must fail, not skip, when the browser is missing.
database_smoke = jobs["sdk-smoke-database"]
assert(database_smoke, "CI must have an sdk-smoke-database job for the Realtime Database smoke tests")
assert(database_smoke["runs-on"] == "ubuntu-latest", "the database smoke tests run on Linux")
assert(database_smoke["env"] == { "FIREEMU_REQUIRE_BROWSER" => "1" }, "the database smoke job must require the browser, so the residual page tests cannot skip")
assert((database_smoke.keys - %w[name runs-on timeout-minutes env steps]).empty?, "the database smoke job may carry only name, runs-on, timeout-minutes, env and steps")
database_steps = database_smoke.fetch("steps")
database_runs = database_steps.map { |step| step["run"] }
database_install = database_runs.index("npm ci --prefix tools/sdk-smoke-database --ignore-scripts")
database_browser = database_runs.index("npx --prefix tools/sdk-smoke-database playwright install --with-deps chromium")
database_tests = database_runs.index("npm test --prefix tools/sdk-smoke-database")
assert(database_install && database_browser && database_tests && database_install < database_browser && database_browser < database_tests, "the database smoke tests run after the install of the pinned SDKs and of Chromium")
assert(database_steps.any? { |step| step["uses"]&.start_with?("actions/setup-node@") && step.dig("with", "node-version").to_s == "24" }, "the database smoke tests run on Node 24")
database_steps.each do |step|
  if step["run"]
    assert(step.keys.sort == %w[name run], "database smoke run steps carry exactly a name and a run: #{step['name']}")
  elsif step["uses"]&.start_with?("actions/setup-node@")
    assert(step.keys.sort == %w[uses with] && step["with"].keys == %w[node-version], "the database smoke setup-node step sets only node-version")
  else
    assert(step.keys == %w[uses] && step["uses"].start_with?("actions/checkout@"), "the database smoke job uses only checkout, setup-node and run steps")
  end
end
assert(!YAML.dump(database_smoke).match?(/secrets\.|gcloud|GOOGLE_|firebase-tools/), "the database smoke tests are offline: no secret, no gcloud, no Google credential, no firebase-tools")

# The full suite runs on every trigger: pull requests, pushes to main and manual dispatch.
%w[lint test verify platforms package ui runner-node sdk-smoke-database].each do |name|
  assert(!jobs.fetch(name).key?("if"), "#{name} must run on pull requests and on pushes to main, not only on manual dispatch")
end

jobs.each do |job, definition|
  definition.fetch("steps", []).select { |step| step["uses"].to_s.start_with?("pnpm/action-setup@") }.each do |step|
    assert(step.dig("with", "version"), "#{job} must pin the pnpm version")
  end
end

%w[quint.yml].each do |name|
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
  "ci.yml" => %w[lint test verify pr platforms package ui runner-node],
  "compatibility-inventory.yml" => %w[feature-inventory-integrity offline-acquisition-integrity],
  "conformance.yml" => %w[conformance],
  "functions-sdk-discovery.yml" => %w[real-sdk-discovery],
  "quint.yml" => %w[quint],
  "sdk-latest.yml" => %w[latest-sdk-under-exec published-light published-broad],
}.each do |name, jobs|
  workflow = load_workflow(name)
  jobs.each do |job|
    timeout = workflow.dig("jobs", job, "timeout-minutes")
    assert(timeout.is_a?(Integer) && timeout.positive? && timeout <= 180, "#{name}/#{job} must have a timeout of at most three hours")
  end
end

puts "CI workflow contract passed"

recovery = release.dig("jobs", "recover-v0381")
assert(recovery["environment"] == "npm-release", "recovery must use the npm-release environment")
assert(recovery["if"] == "github.event_name == 'workflow_dispatch' && inputs.recover_v0381 == true && github.ref == 'refs/heads/main'", "recovery must require explicit dispatch on main")
assert(recovery["steps"].any? { |step| step["run"] == "node npm/scripts/recover-v0381.mjs" }, "recovery must run the guarded artifact recovery script")
recovery_release = release.dig("jobs", "recover-v0381-github-release")
assert(recovery_release["needs"] == ["recover-v0381"], "recovery release must wait for npm publication")
assert(recovery_release["steps"].none? { |step| step["uses"]&.start_with?("actions/checkout@") }, "recovery release must not check out code")
