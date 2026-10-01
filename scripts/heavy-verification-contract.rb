#!/usr/bin/env ruby
# Contract of .github/workflows/heavy-verification.yml, which runs heavy verification on a public
# repository: manual dispatch only, read-only token, no secrets, pinned actions (from a fixed table),
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
}.freeze

# Expressions (the text inside `${{ }}`) a step may use outside a script: the plan's validated
# outputs, the matrix, a step's own output, and the runner's temp directory. The plan's own env may also
# read the inputs, the default branch and the repository URL parts; no other job may read an input.
STEP_EXPRESSION = /\A(fromJSON\(needs\.plan\.outputs\.[a-z_]+\)|needs\.plan\.outputs\.[a-z_]+|needs\.mutants\.result|matrix\.[a-z_]+|steps\.[a-z_]+\.outputs\.[a-z_]+|runner\.temp)\z/
PLAN_EXPRESSION = /\A(inputs\.[a-z_]+|github\.event\.repository\.default_branch|github\.server_url|github\.repository)\z/
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
  errors << "the only trigger must be workflow_dispatch" unless trigger.is_a?(Hash) && trigger.keys == ["workflow_dispatch"]
  errors << "top-level permissions must be exactly contents: read" unless workflow["permissions"] == { "contents" => "read" }
  errors << "a concurrency group per ref is required" unless workflow.dig("concurrency", "group").to_s.include?("inputs.ref")
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
    errors << "#{name}: an if condition may only test the job input" if job["if"] && job["if"].gsub(/inputs\.job\s*==\s*'[a-z-]+'/, "").match?(/inputs\.|github\.event/)
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
  errors << "the summary upload must fail when there is no summary (if-no-files-found: error)" unless upload && upload.dig("with", "if-no-files-found") == "error"
  errors << "the shards must use cargo-mutants' default slice sharding (the summary checks it): no --sharding" if code.include?("--sharding")
  errors << "the summary merge must append summary/summary.md to the step summary" unless merge && merge["run"].to_s.include?('cat summary/summary.md >> "$GITHUB_STEP_SUMMARY"')
  errors << "the summary merge must keep the script's status (exit \"$code\") after showing the summary" unless merge && merge["run"].to_s.include?('exit "$code"') && merge["run"].to_s.include?("|| code=$?")
  checkout = summary.find { |step| step["uses"].to_s.start_with?("actions/checkout@") }
  errors << "the summary job must check out the workflow's own commit, not the verified ref" if checkout && checkout.dig("with", "ref")
  nextest_runs = (workflow.dig("jobs", "nextest", "steps") || []).map { |step| step["run"].to_s }
  fetched = nextest_runs.index { |run| run.include?("cargo fetch --locked") }
  suite = nextest_runs.index { |run| run.include?("cargo nextest run") }
  errors << "nextest must fetch the locked graph before the suite (offline authority checks)" unless fetched && suite && fetched < suite
  # Inputs are validated where they enter, and everything downstream takes the validated outputs.
  plan = workflow.dig("jobs", "plan", "steps") || []
  validate = plan.find { |step| step["id"] == "validate" }
  errors << "a plan job must validate the inputs" unless validate
  if validate
    %w[INPUT_REF INPUT_BASE INPUT_SHARDS INPUT_PACKAGE INPUT_SCRIPT INPUT_JOB DEFAULT_BRANCH REPO_URL].each do |variable|
      errors << "plan must validate #{variable}" unless validate["run"].to_s.include?(variable) && validate.fetch("env", {}).key?(variable)
    end
    script = validate["run"].to_s
    errors << "plan must refuse a run from the default branch and from a tag" unless script.include?("$GITHUB_REF") && script.include?("refs/heads/$DEFAULT_BRANCH") && script.include?("refs/tags/")
    errors << "plan must resolve the ref and the base inside this repository" unless script.include?("for-each-ref --contains") && script.include?("refs/heads/$value")
    errors << "plan must pin the locale (export LC_ALL=C) before it matches a pattern" unless script.include?("export LC_ALL=C")
    errors << "plan must refuse an unreadable default branch" unless script.include?('[[ -n $DEFAULT_BRANCH ]]')
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
