#!/usr/bin/env ruby
# Contract of .github/workflows/heavy-verification.yml, which runs heavy verification on a public
# repository: manual dispatch only, read-only token, no secrets, pinned actions, timeouts, and no
# workflow input interpolated into a script.
#
# `ruby scripts/heavy-verification-contract.rb` checks the real workflow; the test file next to it
# checks that each rule fails on a workflow that breaks it.

require "yaml"

ROOT = File.expand_path("..", __dir__)
WORKFLOW = File.join(ROOT, ".github", "workflows", "heavy-verification.yml")
SHA = /\A[0-9a-f]{40}\z/

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
  workflow.fetch("jobs").each do |name, job|
    errors << "#{name}: a timeout-minutes is required" unless job["timeout-minutes"].is_a?(Integer)
    errors << "#{name}: a job must not widen the permissions" if job.key?("permissions")
    Array(job["steps"]).each_with_index do |step, index|
      label = "#{name} step #{index + 1}"
      if step["uses"]
        action, ref = step["uses"].split("@", 2)
        errors << "#{label}: #{action} must be pinned by a full commit SHA" unless ref.to_s.match?(SHA)
      end
      if step["run"]
        step["run"].scan(/\$\{\{(.*?)\}\}/m).flatten.each do |expression|
          errors << "#{label}: ${{ #{expression.strip} }} is interpolated into a script"
        end
      end
      (step["env"] || {}).each do |key, value|
        next unless value.is_a?(String) && value.include?("${{")
        errors << "#{label}: env #{key} uses an unknown context" unless value.match?(/\$\{\{\s*(inputs\.[a-z_]+|needs\.plan\.outputs\.[a-z_]+|matrix\.[a-z_]+|steps\.[a-z_.]+|runner\.temp)\s*\}\}/)
      end
    end
    next unless toolchain_channel
    Array(job["steps"]).each do |step|
      next unless step["uses"].to_s.start_with?("dtolnay/rust-toolchain@")
      errors << "#{name}: the toolchain must be #{toolchain_channel}" unless step.dig("with", "toolchain").to_s == toolchain_channel
    end
  end
  # Inputs are validated where they enter, and everything downstream takes the validated outputs.
  plan = workflow.dig("jobs", "plan", "steps") || []
  validate = plan.find { |step| step["id"] == "validate" }
  errors << "a plan job must validate the inputs" unless validate
  if validate
    %w[INPUT_REF INPUT_BASE INPUT_SHARDS INPUT_PACKAGE INPUT_SCRIPT INPUT_JOB].each do |variable|
      errors << "plan must validate #{variable}" unless validate["run"].to_s.include?(variable) && validate.fetch("env", {}).key?(variable)
    end
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
