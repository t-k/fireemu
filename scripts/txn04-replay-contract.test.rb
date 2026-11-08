#!/usr/bin/env ruby

# Guarantee under test (see txn04-replay-contract.rb): every SHA main is fast-forwarded to has a ci.yml run,
# dispatched on that exact SHA, that concluded success, and such a run cannot conclude success unless the
# txn04-replay job built that SHA's fireemu and replayed both profiles successfully on ubuntu and macOS.
# Dispatched runs have no path filter, so site-only commits are replayed there too (and do not change the
# binary inputs). pull_request and main-push runs may skip site-only changes or be cancelled by a later push;
# admission never reads them, and a main SHA was replayed by its dispatched run before the push.

require "minitest/autorun"
require "tmpdir"
require "yaml"
require_relative "txn04-replay-contract"

class Txn04ReplayContractTest < Minitest::Test
  JOB = Txn04ReplayContract::JOB

  def real
    YAML.safe_load(File.read(File.join(Txn04ReplayContract::ROOT, ".github", "workflows", "ci.yml")), aliases: true)
  end

  def job(workflow)
    workflow.dig("jobs", JOB)
  end

  def step(workflow, pattern)
    job(workflow)["steps"].find { |s| s["run"].to_s.include?(pattern) }
  end

  def assert_rejected(label)
    workflow = real
    yield workflow
    errors = Dir.mktmpdir("txn04-replay-contract-") do |directory|
      path = File.join(directory, "ci.yml")
      File.write(path, YAML.dump(workflow))
      Txn04ReplayContract.validate_file(path)
    end
    refute_empty errors, "contract accepted #{label}"
  end

  def test_the_committed_workflow_satisfies_the_contract
    assert_equal [], Txn04ReplayContract.validate_file
  end

  def test_the_round_trip_of_the_committed_workflow_is_accepted
    # the fixtures below go through YAML.dump; the unmodified dump must pass, or every rejection is vacuous
    Dir.mktmpdir("txn04-replay-contract-") do |directory|
      path = File.join(directory, "ci.yml")
      File.write(path, YAML.dump(real))
      assert_equal [], Txn04ReplayContract.validate_file(path)
    end
  end

  def test_a_missing_job_is_rejected
    assert_rejected("no job") { |w| w["jobs"].delete(JOB) }
  end

  def test_a_disabled_or_conditional_job_is_rejected
    assert_rejected("if: false") { |w| job(w)["if"] = false }
    assert_rejected("skip on dispatch") { |w| job(w)["if"] = "github.event_name != 'workflow_dispatch'" }
    assert_rejected("skip on main") { |w| job(w)["if"] = "github.ref != 'refs/heads/main'" }
    assert_rejected("workflow if") { |w| w["if"] = "false" }
  end

  def test_continue_on_error_is_rejected_on_the_job_and_every_step
    assert_rejected("job continue-on-error") { |w| job(w)["continue-on-error"] = true }
    assert_rejected("matrix continue-on-error") { |w| job(w)["continue-on-error"] = "${{ matrix.os == 'macos-latest' }}" }
    job(real)["steps"].each_index do |index|
      assert_rejected("step #{index} continue-on-error") { |w| job(w)["steps"][index]["continue-on-error"] = true }
    end
  end

  def test_a_dependency_that_could_skip_the_job_is_rejected
    assert_rejected("needs") { |w| job(w)["needs"] = ["lint"] }
  end

  def test_triggers_are_kept
    assert_rejected("no dispatch") { |w| (w["on"] || w[true]).delete("workflow_dispatch") }
    assert_rejected("dispatch inputs") { |w| (w["on"] || w[true])["workflow_dispatch"] = { "inputs" => { "skip" => { "type" => "boolean" } } } }
    assert_rejected("no pull_request") { |w| (w["on"] || w[true]).delete("pull_request") }
    assert_rejected("no main push") { |w| (w["on"] || w[true])["push"]["branches"] = ["release"] }
  end

  def test_the_matrix_keeps_both_oses_and_runs_every_leg
    assert_rejected("one os") { |w| job(w)["strategy"]["matrix"]["os"] = ["ubuntu-24.04"] }
    assert_rejected("exclude") { |w| job(w)["strategy"]["matrix"]["exclude"] = [{ "os" => "macos-latest" }] }
    assert_rejected("fail-fast") { |w| job(w)["strategy"]["fail-fast"] = true }
    assert_rejected("max-parallel") { |w| job(w)["strategy"]["max-parallel"] = 1 }
    assert_rejected("fixed runner") { |w| job(w)["runs-on"] = "ubuntu-24.04" }
    assert_rejected("no strategy") { |w| job(w).delete("strategy") }
  end

  def test_the_build_and_replay_steps_are_exact_and_unconditional
    assert_rejected("build changed") { |w| step(w, "cargo build")["run"] = "cargo build -p fireemu" }
    assert_rejected("release build") { |w| step(w, "cargo build")["run"] = "cargo build --release --locked -p fireemu --bin fireemu" }
    assert_rejected("build if") { |w| step(w, "cargo build")["if"] = "false" }
    assert_rejected("replay if") { |w| step(w, Txn04ReplayContract::CHECKER)["if"] = "github.event_name == 'pull_request'" }
    assert_rejected("replay removed") { |w| job(w)["steps"].delete(step(w, Txn04ReplayContract::CHECKER)) }
    assert_rejected("replay swallowed") { |w| step(w, Txn04ReplayContract::CHECKER)["run"] += " || true" }
    assert_rejected("other binary") { |w| s = step(w, Txn04ReplayContract::CHECKER); s["run"] = s["run"].sub("--binary target/debug/fireemu", "--binary /usr/local/bin/fireemu") }
    assert_rejected("replay before build") do |w|
      steps = job(w)["steps"]
      b = steps.index(step(w, "cargo build"))
      r = steps.index(step(w, Txn04ReplayContract::CHECKER))
      steps[b], steps[r] = steps[r], steps[b]
    end
    assert_rejected("binary replaced") do |w|
      steps = job(w)["steps"]
      steps.insert(steps.index(step(w, Txn04ReplayContract::CHECKER)), { "run" => "cp /tmp/old target/debug/fireemu" })
    end
    assert_rejected("target moved") { |w| job(w)["env"] = { "CARGO_TARGET_DIR" => "target/other" } }
    assert_rejected("build step target moved") { |w| step(w, "cargo build")["env"] = { "CARGO_TARGET_DIR" => "target/other" } }
    assert_rejected("upload any if") { |w| job(w)["steps"].last["if"] = "always()" }
  end

  def test_the_job_name_read_by_the_merge_check_is_kept
    assert_rejected("renamed") { |w| job(w)["name"] = "txn04 (${{ matrix.os }})" }
  end

  def test_the_checkout_does_not_keep_credentials
    assert_rejected("credentials") { |w| job(w)["steps"].first["with"] = {} }
  end

  def test_the_timeout_is_bounded
    assert_rejected("no timeout") { |w| job(w).delete("timeout-minutes") }
    assert_rejected("huge timeout") { |w| job(w)["timeout-minutes"] = 600 }
  end
end
