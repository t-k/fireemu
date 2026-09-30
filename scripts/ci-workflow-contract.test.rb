#!/usr/bin/env ruby

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"
require "yaml"

class CiWorkflowCacheContractTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  MAIN_ONLY = "${{ github.ref == 'refs/heads/main' }}"

  def cache(job, key)
    job.fetch("steps").find { |step| step.dig("with", "shared-key") == key }
  end

  def proto(job)
    job.fetch("steps").find { |step| step["run"]&.include?("cargo run -p proto-gen -- check") }
  end

  def proposed_workflow
    workflow = YAML.safe_load(File.read(File.join(ROOT, ".github/workflows/ci.yml")), aliases: true)
    verify = workflow.fetch("jobs").fetch("verify")
    unless cache(verify, "pr-normal")
      verify.fetch("steps").insert(3, {
        "uses" => "Swatinem/rust-cache@v2",
        "env" => { "CARGO_TARGET_DIR" => "target/normal" },
        "with" => { "shared-key" => "pr-normal", "workspaces" => ". -> target/normal", "cache-bin" => "false", "save-if" => "false" }
      })
    end
    proto(verify).fetch("env")["CARGO_TARGET_DIR"] = "target/normal"
    workflow
  end

  def validate(workflow)
    Dir.mktmpdir("ci-contract-") do |root|
      FileUtils.mkdir_p(File.join(root, "scripts"))
      FileUtils.mkdir_p(File.join(root, ".github"))
      FileUtils.cp_r(File.join(ROOT, ".github/workflows"), File.join(root, ".github"))
      FileUtils.cp(File.join(ROOT, "rust-toolchain.toml"), root)
      FileUtils.cp(File.join(ROOT, "scripts/ci-workflow-contract.rb"), File.join(root, "scripts"))
      File.write(File.join(root, ".github/workflows/ci.yml"), YAML.dump(workflow))
      Open3.capture3(RbConfig.ruby, File.join(root, "scripts/ci-workflow-contract.rb"))
    end
  end

  def assert_refused(message)
    workflow = proposed_workflow
    yield workflow.fetch("jobs")
    stdout, stderr, status = validate(workflow)
    refute status.success?, "invalid workflow accepted: #{stdout}"
    assert_includes stderr, message
  end

  def test_current_workflow_is_valid
    workflow = YAML.safe_load(File.read(File.join(ROOT, ".github/workflows/ci.yml")), aliases: true)
    stdout, stderr, status = validate(workflow)
    assert status.success?, stderr
    assert_includes stdout, "CI workflow contract passed"
  end

  def test_proposed_cache_topology_is_valid
    stdout, stderr, status = validate(proposed_workflow)
    assert status.success?, stderr
    assert_includes stdout, "CI workflow contract passed"
  end

  def test_old_uncached_proto_layout_is_refused
    assert_refused("verify must restore pr-normal") do |jobs|
      jobs["verify"]["steps"].delete(cache(jobs["verify"], "pr-normal"))
      proto(jobs["verify"])["env"]["CARGO_TARGET_DIR"] = "target/verify"
    end
  end

  def test_normal_cache_key_mismatch_is_refused
    assert_refused("lint must restore pr-normal") { |jobs| cache(jobs["lint"], "pr-normal")["with"]["shared-key"] = "lint-normal" }
  end

  def test_normal_cache_path_mismatch_is_refused
    assert_refused("test normal cache must map target/normal") { |jobs| cache(jobs["test"], "pr-normal")["with"]["workspaces"] = ". -> target/test" }
  end

  def test_normal_target_mismatch_is_refused
    assert_refused("lint normal cache must use target/normal") { |jobs| jobs["lint"]["env"]["CARGO_TARGET_DIR"] = "target/lint" }
  end

  def test_verify_cache_environment_mismatch_is_refused
    assert_refused("verify normal cache must use target/normal") { |jobs| cache(jobs["verify"], "pr-normal")["env"].delete("CARGO_TARGET_DIR") }
  end

  def test_proto_target_mismatch_is_refused
    assert_refused("proto-gen must use target/normal") { |jobs| proto(jobs["verify"])["env"]["CARGO_TARGET_DIR"] = "target/verify" }
  end

  def test_normal_cache_must_not_use_loom_flags
    assert_refused("verify normal cache must not set RUSTFLAGS") { |jobs| cache(jobs["verify"], "pr-normal")["env"]["RUSTFLAGS"] = "--cfg loom -D warnings" }
  end

  def test_verify_cannot_save_normal_cache
    assert_refused("verify must only restore the normal cache") { |jobs| cache(jobs["verify"], "pr-normal")["with"]["save-if"] = MAIN_ONLY }
  end

  def test_lint_cannot_save_normal_cache
    assert_refused("lint must only restore the normal cache") { |jobs| cache(jobs["lint"], "pr-normal")["with"].delete("save-if") }
  end

  def test_test_can_only_save_normal_cache_on_main
    assert_refused("test must save the normal cache only on main") { |jobs| cache(jobs["test"], "pr-normal")["with"]["save-if"] = "true" }
  end

  def test_duplicate_normal_cache_is_refused
    assert_refused("test must have exactly one normal cache") { |jobs| jobs["test"]["steps"] << cache(jobs["test"], "pr-normal").dup }
  end

  def test_another_job_cannot_own_normal_cache
    assert_refused("normal cache consumers must be lint, test and verify") { |jobs| jobs["pr"]["steps"] << cache(jobs["test"], "pr-normal").dup }
  end

  def test_loom_cache_must_remain_separate
    assert_refused("loom cache must map target/loom") { |jobs| cache(jobs["verify"], "pr-loom")["with"]["workspaces"] = ". -> target/normal" }
  end

  def test_loom_flags_must_remain_on_cache_and_test
    assert_refused("loom cache must use the loom flags") { |jobs| cache(jobs["verify"], "pr-loom")["env"].delete("RUSTFLAGS") }
  end

  def test_normal_cache_does_not_cache_installed_binaries
    assert_refused("test normal cache must not cache installed binaries") { |jobs| cache(jobs["test"], "pr-normal")["with"]["cache-bin"] = "true" }
  end

  def test_proto_cannot_inherit_loom_flags
    assert_refused("proto-gen must not use loom flags") { |jobs| proto(jobs["verify"])["env"]["RUSTFLAGS"] = "--cfg loom" }
  end

  def test_loom_test_and_cache_flags_must_match
    assert_refused("verify must retain the separate release loom test and flags") do |jobs|
      jobs["verify"]["steps"].find { |step| step["name"] == "loom scenarios" }["env"]["RUSTFLAGS"] = ""
    end
  end

  def test_loom_cache_saves_only_on_main
    assert_refused("verify must save the loom cache only on main") { |jobs| cache(jobs["verify"], "pr-loom")["with"]["save-if"] = "true" }
  end

  def test_cache_restore_must_precede_proto_build
    assert_refused("normal cache restore must precede proto-gen") do |jobs|
      step = cache(jobs["verify"], "pr-normal")
      jobs["verify"]["steps"].delete(step)
      jobs["verify"]["steps"] << step
    end
  end

  def test_runtime_jobs_remain_parallel
    assert_refused("verify must remain an independent automatic job") { |jobs| jobs["verify"]["needs"] = ["test"] }
  end

  def test_runtime_jobs_remain_automatic
    assert_refused("test must remain an independent automatic job") { |jobs| jobs["test"]["if"] = "github.event_name == 'workflow_dispatch'" }
  end
end
