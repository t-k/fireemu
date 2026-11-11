#!/usr/bin/env ruby
# Contract of .github/workflows/heavy-verification.yml, which runs heavy verification on a public
# repository: started only by manual dispatch and by the three pinned schedules (the nightly, weekly and critical
# mutation runs, which fire on the default branch only), read-only token, no secrets, pinned actions (from a fixed table),
# timeouts, no cache written, no run from the default branch, and no workflow input interpolated into
# a script or any other field except where the plan job validates it.
#
# `ruby scripts/heavy-verification-contract.rb` checks the real workflow; the test file next to it
# checks that each rule fails on a workflow that breaks it.

require "yaml"

ROOT = File.expand_path("..", __dir__)
WORKFLOW = File.join(ROOT, ".github", "workflows", "heavy-verification.yml")

# The only commits an action may be pinned to: commits, not tag objects (the table is shared in
# spirit with release.yml, which pins the same ones).
PINS = {
  "actions/checkout" => "11d5960a326750d5838078e36cf38b85af677262",
  "actions/upload-artifact" => "ea165f8d65b6e75b540449e92b4886f43607fa02",
  "actions/download-artifact" => "d3f86a106a0bac45b974a628896c90dbdf5c8093",
  "dtolnay/rust-toolchain" => "6bed0761d98439e5a578e2877258200ad565ba87",
  "taiki-e/install-action" => "7b8d4719ee4aaa279bdf55df38dacb9ebfe12a6c",
  "Swatinem/rust-cache" => "6323deb102c322ba6fcbdcafc7e3dddab59af2b6",
  "pnpm/action-setup" => "b906affcce14559ad1aafd4ab0e942779e9f58b1",
  "actions/setup-node" => "49933ea5288caeca8642d1e84afbd3f7d6820020",
}.freeze

# Expressions (the text inside `${{ }}`) a step may use outside a script: the plan's validated
# outputs, the matrix, a step's own output, and the runner's temp directory. The plan's own env may also
# read the inputs, the default branch and the repository URL parts; no other job may read an input.
STEP_EXPRESSION = /\A(fromJSON\(needs\.plan\.outputs\.[a-z_]+\)|needs\.plan\.outputs\.[a-z_]+|needs\.mutants\.result|matrix\.[a-z_]+|steps\.[a-z_]+\.outputs\.[a-z_]+|runner\.temp)\z/
PLAN_EXPRESSION = /\A(inputs\.[a-z_]+|github\.event\.repository\.default_branch|github\.server_url|github\.repository|github\.event_name|github\.event\.schedule)\z/
# The nightly diff, weekly crate rotation and critical file schedules.
SCHEDULES = ["23 3 * * *", "41 4 * * 6", "17 5 * * 1,3,5"].freeze
# What a job may test: the plan's validated outputs and the plan's result.
JOB_IF_EXPRESSION = /\A(always\(\)|needs\.plan\.result\s*==\s*'success'|needs\.plan\.outputs\.(job|skip)\s*(==|!=)\s*'[a-z-]+'|needs\.mutants\.outputs\.count\s*!=\s*'0')\z/
# What the run name and the concurrency group are made of: string literals, format(), the event name,
# the schedule and the inputs that label a run, joined with && || == and parentheses.
NAMING_TOKENS = /'[^']*'|format|github\.event_name|github\.event\.schedule|inputs\.(?:job|tag|ref)|&&|\|\||==|[(),\s]/

# The expressions of `text` that use anything but NAMING_TOKENS.
def unnamed_expressions(text)
  text.scan(/\$\{\{(.*?)\}\}/m).flatten.reject { |expression| expression.gsub(NAMING_TOKENS, "").empty? }
end
FORBIDDEN_ENV = /\bACTIONS_(ALLOW_UNSECURE_COMMANDS|RUNNER_DEBUG|STEP_DEBUG)\b/

# The expressions inside a text that do not match `allowed`.
def unknown_expressions(text, *allowed)
  text.scan(/\$\{\{(.*?)\}\}/m).flatten.map(&:strip).reject { |expression| allowed.any? { |pattern| expression.match?(pattern) } }
end

def strings_in(value)
  case value
  when String then [value]
  when Hash then value.values.flat_map { |v| strings_in(v) }
  when Array then value.flat_map { |v| strings_in(v) }
  else []
  end
end

# Returns the list of violations of the contract in `source` (the workflow's YAML text).
def violations(source, toolchain_channel: nil)
  errors = []
  workflow = YAML.safe_load(source, aliases: true)
  code = source.lines.reject { |line| line.strip.start_with?("#") }.join
  trigger = workflow["on"] || workflow[true]
  errors << "the only triggers must be schedule and workflow_dispatch" unless trigger.is_a?(Hash) && trigger.keys.sort == %w[schedule workflow_dispatch]
  crons = trigger.is_a?(Hash) ? Array(trigger["schedule"]).map { |entry| entry.is_a?(Hash) ? entry["cron"] : nil } : []
  errors << "the schedules must be exactly #{SCHEDULES.inspect}" unless crons == SCHEDULES
  errors << "top-level permissions must be exactly contents: read" unless workflow["permissions"] == { "contents" => "read" }
  errors << "a concurrency group per ref is required" unless workflow.dig("concurrency", "group").to_s.include?("inputs.ref")
  errors << "the scheduled runs need one concurrency group of their own" unless workflow.dig("concurrency", "group").to_s.include?("'heavy-verification-scheduled'")
  errors << "the concurrency group and the run name may only read the event name, the schedule and the inputs" unless
    [workflow.dig("concurrency", "group"), workflow["run-name"]].all? { |text| unnamed_expressions(text.to_s).empty? }
  errors << "a running scheduled mutation run must not be cancelled by another" if workflow.dig("concurrency", "cancel-in-progress") == true
  errors << "pull_request_target must never appear" if code.include?("pull_request_target")
  errors << "secrets must never be used" if code.match?(/\bsecrets\b/)
  errors << "no token other than the read-only default may be used" if code.match?(/\b(github\.token|GITHUB_TOKEN|GH_TOKEN)\b/)
  errors << "only the read-only default token is allowed: no write permission" if code.match?(/^\s*[a-z-]+:\s*write\s*$/)
  errors << "no unsafe or debug runner switch may be set" if code.match?(FORBIDDEN_ENV)
  errors << "actions/cache must never be used: no job may write a cache" if code.match?(%r{actions/cache(/|@|\s)})
  # Workflow-level and job-level env: literal values only.
  [["workflow", workflow["env"]]].concat(workflow.fetch("jobs").map { |name, job| [name, job["env"]] }).each do |where, env|
    (env || {}).each do |key, value|
      errors << "#{where}: env #{key} must be a literal, not an expression" if value.to_s.include?("${{")
    end
  end
  workflow.fetch("jobs").each do |name, job|
    errors << "#{name}: a timeout-minutes is required" unless job["timeout-minutes"].is_a?(Integer)
    errors << "#{name}: a job must not widen the permissions" if job.key?("permissions")
    errors << "#{name}: an if condition may only test the plan's validated outputs" if job["if"] && job["if"].to_s.split("&&").map(&:strip).any? { |term| !term.match?(JOB_IF_EXPRESSION) }
    errors << "#{name}: an if condition must not read an input or the event" if job["if"].to_s.match?(/inputs\.|github\./)
    # Job-level fields that take an expression (where the job runs, its container, its matrix): the same
    # allow-list as a step, so an input can never choose a runner or an image.
    %w[runs-on container services strategy environment name].each do |key|
      next unless job.key?(key)
      strings_in(job[key]).each do |text|
        unknown_expressions(text, STEP_EXPRESSION).each do |expression|
          errors << "#{name}: #{key} uses an unknown expression: #{expression}"
        end
      end
    end
    Array(job["steps"]).each_with_index do |step, index|
      label = "#{name} step #{index + 1}"
      action = nil
      if step["uses"]
        action, ref = step["uses"].split("@", 2)
        if PINS.key?(action)
          errors << "#{label}: #{action} must be pinned by a full commit SHA (#{PINS[action]})" unless ref == PINS[action]
        else
          errors << "#{label}: #{action} is not in the table of allowed actions"
        end
      end
      if step["run"]
        step["run"].to_s.scan(/\$\{\{(.*?)\}\}/m).flatten.each do |expression|
          errors << "#{label}: ${{ #{expression.strip} }} is interpolated into a script"
        end
      end
      errors << "#{label}: a checkout must not persist credentials" if action == "actions/checkout" && step.dig("with", "persist-credentials") != false
      errors << "#{label}: rust-cache must not save (save-if: \"false\")" if action == "Swatinem/rust-cache" && step.dig("with", "save-if").to_s != "false"
      errors << "#{label}: pnpm/action-setup must pin the pnpm version" if action == "pnpm/action-setup" && step.dig("with", "version").to_s.empty?
      errors << "#{label}: setup-node must not cache (a cache would be written)" if action == "actions/setup-node" && step.dig("with", "cache")
      # Every other field of a step that can carry an expression.
      fields = {}
      (step["with"] || {}).each { |key, value| fields["with.#{key}"] = value }
      %w[working-directory shell name if].each { |key| fields[key] = step[key] if step.key?(key) }
      fields.each do |key, value|
        next if key == "if"
        strings_in(value).each do |text|
          unknown_expressions(text, STEP_EXPRESSION).each do |expression|
            errors << "#{label}: #{key} uses an unknown expression: #{expression}"
          end
        end
      end
      plan_step = name == "plan" && step["id"] == "validate"
      (step["env"] || {}).each do |key, value|
        next unless value.is_a?(String)
        allowed = plan_step ? [STEP_EXPRESSION, PLAN_EXPRESSION] : [STEP_EXPRESSION]
        unknown_expressions(value, *allowed).each do |expression|
          errors << "#{label}: env #{key} uses an unknown context: #{expression}"
        end
      end
      if name != "plan" && strings_in(step["env"]).any? { |text| text.match?(/inputs\.|github\.event/) }
        errors << "#{label}: only the plan may read the inputs"
      end
    end
    next unless toolchain_channel
    Array(job["steps"]).each do |step|
      next unless step["uses"].to_s.start_with?("dtolnay/rust-toolchain@")
      errors << "#{name}: the toolchain must be #{toolchain_channel}" unless step.dig("with", "toolchain").to_s == toolchain_channel
    end
  end
  # The summary replaces any artifact a shard created under its name, and takes its script from the
  # workflow's own commit.
  summary = workflow.dig("jobs", "mutants-summary", "steps") || []
  upload = summary.find { |step| step["uses"].to_s.start_with?("actions/upload-artifact@") }
  errors << "the summary upload must overwrite an artifact of its name" unless upload && upload.dig("with", "overwrite") == true
  errors << "the summary upload must run even when the merge failed (if: always())" unless upload && upload["if"].to_s.strip == "always()"
  merge = summary.find { |step| step["name"] == "merge the shards" }
  errors << "the summary merge must pass the shard job's result (--mutants-result \"$MUTANTS_RESULT\")" unless merge && merge["run"].to_s.include?('--mutants-result "$MUTANTS_RESULT"') && merge.dig("env", "MUTANTS_RESULT").to_s.gsub(/\s+/, "") == "${{needs.mutants.result}}"
  errors << "the summary merge must pass the survivors and critical lists" unless merge &&
    merge["run"].to_s.include?("--survivors tools/ci/mutation-survivors.txt") && merge["run"].to_s.include?("--critical tools/ci/mutation-critical.txt")
  errors << "the summary merge must pass --fail-on-new-critical only when the plan says so" unless merge &&
    merge.dig("env", "FAIL_ON_NEW_CRITICAL").to_s.gsub(/\s+/, "") == "${{needs.plan.outputs.fail_on_new_critical}}" &&
    merge["run"].to_s.scan("--fail-on-new-critical").length == 1 &&
    merge["run"].to_s.include?('if [[ $FAIL_ON_NEW_CRITICAL == true ]]; then extra+=(--fail-on-new-critical); fi') &&
    merge["run"].to_s.include?('"${extra[@]}"')
  errors << "the summary upload must fail when there is no summary (if-no-files-found: error)" unless upload && upload.dig("with", "if-no-files-found") == "error"
  mutate_runs = (workflow.dig("jobs", "mutants", "steps") || []).map { |step| step["run"].to_s }.select { |run| run.include?("cargo mutants") }
  selection = (workflow.dig("jobs", "mutants", "steps") || []).find { |step| step["id"] == "select" }
  errors << "critical selection must use files without a package" unless selection && selection["run"].to_s.include?('if [[ $MODE == weekly || $MODE == critical ]]; then') && selection["run"].to_s.include?('if [[ $MODE == weekly ]]; then args+=(-p "$PACKAGE"); fi')
  # The selection step only lists the mutants (--list); the shard run is the one that mutates.
  mutate_runs = mutate_runs.reject { |run| run.include?("--list") && !run.include?("--shard") }
  shardings = mutate_runs.flat_map { |run| run.scan(/--sharding[= ]\S*/) }
  errors << "the shards must say --sharding slice once on the command line (the summary checks that layout, whatever the ref's mutants.toml says)" unless mutate_runs.size == 1 && shardings == ["--sharding slice"]
  errors << "no --sharding value but slice may appear anywhere in the workflow" if code.scan(/--sharding[= ]\S*/).any? { |text| text != "--sharding slice" }
  errors << "the summary merge must append summary/summary.md to the step summary" unless merge && merge["run"].to_s.include?('cat summary/summary.md >> "$GITHUB_STEP_SUMMARY"')
  errors << "the summary merge must keep the script's status (exit \"$code\") after showing the summary" unless merge && merge["run"].to_s.include?('exit "$code"') && merge["run"].to_s.include?("|| code=$?")
  checkout = summary.find { |step| step["uses"].to_s.start_with?("actions/checkout@") }
  errors << "the summary job must check out the workflow's own commit, not the verified ref" if checkout && checkout.dig("with", "ref")
  nextest_runs = (workflow.dig("jobs", "nextest", "steps") || []).map { |step| step["run"].to_s }
  fetched = nextest_runs.index { |run| run.include?("cargo fetch --locked") }
  suite = nextest_runs.index { |run| run.include?("cargo nextest run") }
  errors << "nextest must fetch the locked graph before the suite (offline authority checks)" unless fetched && suite && fetched < suite
  # The suites that run the real SDKs need the pinned conformance install (run 39458079082 stopped
  # at eventarc_authentication without it), as ci.yml and release.yml install it.
  installed = nextest_runs.index { |run| run.include?("pnpm -C conformance install --frozen-lockfile") }
  errors << "nextest must install the conformance SDKs before the suite (pnpm -C conformance install --frozen-lockfile)" unless installed && suite && installed < suite
  # The mutation baseline runs the same suites, so the shard job installs the SDKs before it mutates.
  mutants_runs = (workflow.dig("jobs", "mutants", "steps") || []).map { |step| step["run"].to_s }
  installed_for_mutants = mutants_runs.index { |run| run.include?("pnpm -C conformance install --frozen-lockfile") }
  mutating = mutants_runs.index { |run| run.include?("--shard ") }
  errors << "mutants must install the conformance SDKs before the shards mutate (pnpm -C conformance install --frozen-lockfile)" unless installed_for_mutants && mutating && installed_for_mutants < mutating
  errors << "mutants must keep ignored files in the copy under test (--gitignore=false) and the git history (--copy-vcs=true) so the suites find the SDKs and the commit" unless mutants_runs.any? { |run| run.include?("--shard ") && run.include?("--gitignore=false") && run.include?("--copy-vcs=true") }
  # Inputs are validated where they enter, and everything downstream takes the validated outputs.
  plan = workflow.dig("jobs", "plan", "steps") || []
  validate = plan.find { |step| step["id"] == "validate" }
  errors << "a plan job must validate the inputs" unless validate
  if validate
    %w[INPUT_REF INPUT_BASE INPUT_SHARDS INPUT_PACKAGE INPUT_SCRIPT INPUT_JOB DEFAULT_BRANCH REPO_URL EVENT_NAME EVENT_SCHEDULE REPOSITORY].each do |variable|
      errors << "plan must validate #{variable}" unless validate["run"].to_s.include?(variable) && validate.fetch("env", {}).key?(variable)
    end
    script = validate["run"].to_s
    errors << "plan must expose fail_on_new_critical" unless workflow.dig("jobs", "plan", "outputs", "fail_on_new_critical") == "${{ steps.validate.outputs.fail_on_new_critical }}" && script.include?('echo "fail_on_new_critical=$fail_on_new_critical"')
    errors << "critical dispatch must be allowed" unless Array(trigger.dig("workflow_dispatch", "inputs", "job", "options")).include?("critical") && script.include?("mutants | nextest | linux-measure | nightly | weekly | critical)")
    { "23 3 * * *" => "nightly INPUT_SHARDS=8", "41 4 * * 6" => "weekly INPUT_SHARDS=16", "17 5 * * 1,3,5" => "critical INPUT_SHARDS=16" }.each do |cron, mapping|
      errors << "schedule mapping must assign #{cron} to #{mapping}" unless script.include?(%Q{"#{cron}") INPUT_JOB=#{mapping} ;;})
    end
    errors << "nightly base must require conclusion == success and reject failure" unless script.include?('run.get("conclusion") == "success"') && !script.include?('"failure"')
    nightly = script[/^  nightly\)\n(.*?)^    ;;/m, 1].to_s
    weekly = script[/^  weekly\)\n(.*?)^    ;;/m, 1].to_s
    critical = script[/^  critical\)\n(.*?)^    ;;/m, 1].to_s
    errors << "nightly must enable fail_on_new_critical" unless nightly.include?("job=mutants fail_on_new_critical=true") && script.include?("skip=false fail_on_new_critical=false")
    errors << "weekly must report only" if weekly.include?("fail_on_new_critical=true")
    errors << "critical files must come from the ref and be nonempty" unless critical.include?('show "$ref_sha:tools/ci/mutation-critical.txt"') && critical.include?('(( ${#entries[@]} > 0 )) || fail') && critical.include?('job=mutants base_sha="" package="" fail_on_new_critical=true')
    errors << "critical file tokens must be validated" unless critical.include?('[[ $token =~ ^!?[A-Za-z0-9_./*-]{1,200}$ && $token != *..* && $token != *//* ]] || fail "the critical list names a bad file"')
    errors << "plan must refuse a run from the default branch and from a tag" unless script.include?("$GITHUB_REF") && script.include?("refs/heads/$DEFAULT_BRANCH") && script.include?("refs/tags/")
    errors << "plan must resolve the ref and the base inside this repository" unless script.include?("for-each-ref --contains") && script.include?("refs/heads/$value")
    errors << "plan must pin the locale (export LC_ALL=C) before it matches a pattern" unless script.include?("export LC_ALL=C")
    errors << "plan must refuse an unreadable default branch" unless script.include?('[[ -n $DEFAULT_BRANCH ]]')
    errors << "a scheduled run must test the commit it runs on and nothing an input names (INPUT_REF=$GITHUB_SHA, no package, script or tag)" unless script.include?('INPUT_REF=$GITHUB_SHA INPUT_BASE=$DEFAULT_BRANCH INPUT_PACKAGE="" INPUT_SCRIPT="" INPUT_TAG=""')
    errors << "the weekly rotation's package name must be validated before it is used" unless script.include?('[[ $package =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || fail "the rotation names a bad package"')
    errors << "the weekly rotation's file tokens must be validated before they are used (no .., no //)" unless script.include?('[[ $token =~ ^!?[A-Za-z0-9_./*-]{1,200}$ && $token != *..* && $token != *//* ]] || fail "the rotation names a bad file"')
    errors << "the dispatched package name must be validated" unless script.include?('[[ $INPUT_PACKAGE =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || fail')
    errors << "plan must start a schedule only on the default branch" unless script.include?('[[ $GITHUB_REF == "refs/heads/$DEFAULT_BRANCH" ]]')
    errors << "plan must refuse any event but schedule and workflow_dispatch" unless script.include?('[[ $EVENT_NAME == workflow_dispatch ]]')
    errors << "plan must refuse refs/, HEAD and FETCH_HEAD" unless script.include?("refs/*") && script.include?("FETCH_HEAD")
  end
  workflow.fetch("jobs").each do |name, job|
    next if name == "plan"
    errors << "#{name}: must depend on the validated plan" unless Array(job["needs"]).include?("plan")
    Array(job["steps"]).each do |step|
      ref = step.dig("with", "ref")
      errors << "#{name}: a checkout ref must be the validated plan output" if ref && ref != "${{ needs.plan.outputs.ref }}"
    end
  end
  errors
end

if $PROGRAM_NAME == __FILE__
  channel = File.read(File.join(ROOT, "rust-toolchain.toml"))[/^channel\s*=\s*"([^"]+)"/, 1]
  errors = violations(File.read(WORKFLOW), toolchain_channel: channel)
  abort(errors.map { |e| "heavy-verification contract: #{e}" }.join("\n")) unless errors.empty?
  puts "heavy-verification contract: ok"
end
