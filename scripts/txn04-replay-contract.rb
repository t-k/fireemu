#!/usr/bin/env ruby

# The txn04-replay job of ci.yml decides whether a commit's binary still answers the Txn-04 production
# recordings as recorded (tools/compat-broad/fs-write-txn/txn04_current_replay.py). It replaced a stored
# per-commit binary digest, so it must take part in the conclusion of every ci.yml run:
#
# - main is fast-forwarded only to a SHA whose ci.yml run, dispatched (workflow_dispatch) on the integration
#   branch at that exact SHA, concluded success; a dispatched run has no path filter, so the job runs on every
#   such SHA, site-only commits included;
# - a failing leg fails the run, and nothing lets the job be skipped (no `if`, no `needs`) or pass while a
#   step fails (no `continue-on-error`), so a run that concluded success replayed that SHA on both OSes;
# - pull_request and main-push runs skip site-only changes and may be cancelled by a later push; neither
#   admits anything, since admission reads the dispatched run, and a site-only change does not change the
#   binary inputs.
#
# This contract parses the workflow and refuses any shape that breaks one of those statements.

require "yaml"

module Txn04ReplayContract
  ROOT = File.expand_path("..", __dir__)
  JOB = "txn04-replay"
  OSES = %w[ubuntu-24.04 macos-latest].freeze
  BUILD = "cargo build --locked -p fireemu --bin fireemu"
  CHECKER = "tools/compat-broad/fs-write-txn/txn04_current_replay.py"
  CHECKER_ARGS = "--binary target/debug/fireemu --dep-info target/debug/fireemu.d"
  UPLOAD_IF = "${{ !cancelled() }}"

  module_function

  def validate_file(path = File.join(ROOT, ".github", "workflows", "ci.yml"))
    validate_hash(YAML.safe_load(File.read(path), aliases: true))
  rescue Psych::Exception, SystemCallError => error
    ["cannot read or parse workflow: #{error.message}"]
  end

  def validate_hash(workflow)
    errors = []
    return ["workflow must be a YAML mapping"] unless workflow.is_a?(Hash)

    events = workflow["on"] || workflow[true]
    if events.is_a?(Hash)
      check(errors, events.key?("workflow_dispatch"), "ci.yml must keep its workflow_dispatch trigger: admission reads the dispatched run")
      dispatch = events["workflow_dispatch"]
      check(errors, dispatch.nil? || dispatch == {}, "the workflow_dispatch trigger must take no inputs or filters")
      check(errors, events.key?("pull_request"), "ci.yml must run on pull requests")
      check(errors, events.dig("push", "branches") == ["main"], "ci.yml must run on pushes to main")
    else
      errors << "ci.yml must declare its triggers as a mapping"
    end
    check(errors, !workflow.key?("if"), "the workflow must not be conditional")

    job = workflow.dig("jobs", JOB)
    unless job.is_a?(Hash)
      errors << "ci.yml must define the #{JOB} job"
      return errors
    end
    check(errors, !job.key?("if"), "#{JOB} must not have an if: a skipped job does not fail the run")
    check(errors, !job.key?("needs"), "#{JOB} must not need another job: a failed dependency skips it without failing it")
    check(errors, !job.key?("continue-on-error"), "#{JOB} must not continue on error")
    timeout = job["timeout-minutes"]
    check(errors, timeout.is_a?(Integer) && timeout.positive? && timeout <= 180, "#{JOB} needs a timeout of at most three hours")
    check(errors, job["runs-on"] == "${{ matrix.os }}", "#{JOB} must run on its matrix OS")
    # docs.local/tools/ci admit (the coordinator's merge check) reads the legs by these names.
    check(errors, job["name"] == "Txn-04 replay (${{ matrix.os }})", "#{JOB} must keep the name the merge check reads: Txn-04 replay (<os>)")
    strategy = job["strategy"]
    if strategy.is_a?(Hash)
      check(errors, strategy.keys.sort == %w[fail-fast matrix], "#{JOB} strategy may set only fail-fast and matrix")
      check(errors, strategy["fail-fast"] == false, "#{JOB} must run every leg to its own result")
      check(errors, strategy["matrix"] == { "os" => OSES }, "#{JOB} matrix must be exactly os: #{OSES.join(', ')}")
    else
      errors << "#{JOB} must have a matrix strategy"
    end
    env = job["env"] || {}
    check(errors, env.is_a?(Hash) && !env.key?("CARGO_TARGET_DIR") && !env.key?("CARGO_BUILD_TARGET"), "#{JOB} must build into target/debug")

    steps = job["steps"]
    unless steps.is_a?(Array) && steps.all?(Hash)
      errors << "#{JOB} must list its steps"
      return errors
    end
    check(errors, steps.first.to_h["uses"].to_s.start_with?("actions/checkout@") && steps.first.dig("with", "persist-credentials") == false, "#{JOB} must start with a checkout without persisted credentials")
    steps.each_with_index do |step, index|
      check(errors, !step.key?("continue-on-error"), "#{JOB} step #{index} must not continue on error")
      check(errors, !step.key?("if") || (step["uses"].to_s.start_with?("actions/upload-artifact@") && step["if"] == UPLOAD_IF), "#{JOB} step #{index} must not be conditional (only the result upload runs if not cancelled)")
      check(errors, !step.key?("env") || !step["env"].to_h.key?("CARGO_TARGET_DIR"), "#{JOB} step #{index} must not move the target directory")
    end
    builds = steps.each_index.select { |index| steps[index]["run"] == BUILD }
    replays = steps.each_index.select { |index| steps[index]["run"].to_s.include?(CHECKER) }
    check(errors, builds.size == 1, "#{JOB} must build exactly once with `#{BUILD}`")
    check(errors, replays.size == 1, "#{JOB} must run #{CHECKER} exactly once")
    if builds.size == 1 && replays.size == 1
      check(errors, builds.first < replays.first, "#{JOB} must build before it replays")
      replay = steps[replays.first]["run"]
      check(errors, replay.include?(CHECKER_ARGS), "#{JOB} must replay the binary it built (#{CHECKER_ARGS})")
      check(errors, !replay.match?(/\|\||;\s*true|set \+e|exit 0/), "#{JOB} must not swallow the checker's exit status")
      check(errors, steps.each_index.none? { |index| index > builds.first && index < replays.first && steps[index]["run"].to_s.match?(/cargo|target\/debug/) }, "#{JOB} must not rebuild or replace the binary between building and replaying")
    end
    errors
  end

  def check(errors, condition, message)
    errors << message unless condition
  end
end

if $PROGRAM_NAME == __FILE__
  errors = Txn04ReplayContract.validate_file
  abort(errors.join("\n")) unless errors.empty?
  puts "txn04-replay workflow contract passed"
end
