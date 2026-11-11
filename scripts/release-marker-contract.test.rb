#!/usr/bin/env ruby
# frozen_string_literal: true

require "minitest/autorun"
require "yaml"
require_relative "release-marker-contract"

class ReleaseMarkerContractTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  RELEASE = File.read(File.join(ROOT, ".github", "workflows", "release.yml"))
  M = ReleaseMarkerContract::MARKER

  def errors(source = RELEASE, others = {})
    ReleaseMarkerContract.violations(source, others)
  end

  # A mutation of the real workflow that must change it, so a stale fixture cannot pass silently.
  def mutate(old, new)
    refute_equal old, new
    assert_includes RELEASE, old, "the fixture text is no longer in release.yml"
    RELEASE.sub(old, new)
  end

  def edit
    doc = YAML.safe_load(RELEASE, aliases: false)
    yield doc
    YAML.dump(doc)
  end

  def refused(source, others = {})
    refute_empty errors(source, others)
  end

  def test_the_real_repository_passes
    ReleaseMarkerContract.check!(ROOT)
  end

  def test_noop_baseline
    assert_empty errors
    assert_empty errors(RELEASE + "\n# an unrelated comment\n")
    assert_empty errors(edit { |doc| doc["name"] = "release" })
  end

  def test_the_marker_may_be_named_only_in_the_three_pinned_steps
    # Workflow-level and job-level env, which every build in scope would inherit.
    refused(edit { |doc| (doc["env"] ||= {})[M] = "1" })
    refused(edit { |doc| doc["jobs"]["test"]["env"] = { M => "1" } })
    refused(edit { |doc| doc["jobs"]["build"]["env"] = { M => "1" } })
    refused(edit { |doc| doc["jobs"]["reproducible"]["env"] = { M => "1" } })
    # An ordinary step of another job.
    refused(edit { |doc| doc["jobs"]["test"]["steps"].first["env"] = { M => "1" } })
    # A fourth step in a pinned job, and a `with` value or a name that mentions it.
    refused(edit { |doc| doc["jobs"]["build"]["steps"].first["env"] = { M => "1" } })
    refused(edit { |doc| doc["jobs"]["build"]["steps"].first["with"] = { "x" => M } })
    refused(mutate("name: build the daemon", "name: build the daemon with #{M}"))
  end

  def test_a_run_may_not_export_unset_or_persist_the_marker
    refused(edit { |doc| doc["jobs"]["test"]["steps"].last["run"] = "export #{M}=1\n" })
    refused(edit { |doc| doc["jobs"]["test"]["steps"].last["run"] = "echo \"#{M}=1\" >> \"$GITHUB_ENV\"\n" })
    refused(edit { |doc| doc["jobs"]["test"]["steps"].last["run"] = "echo \"X=1\" >> \"$GITHUB_ENV\"\n" })
    refused(edit { |doc| doc["jobs"]["test"]["steps"].last["run"] = "name=#{M.sub('FIREEMU', 'FIRE')}; echo \"$name=1\" >> \"$GITHUB_ENV\"\n" })
    refused(edit { |doc| doc["jobs"]["build"]["steps"].find { |s| s["name"] == "build the daemon" }["run"] = "unset #{M}\ncargo build --release --locked -p fireemu --target ${{ matrix.platform.target }}" })
    refused(edit { |doc| doc["jobs"]["build"]["steps"].find { |s| s["name"] == "build the daemon" }["run"] = "env -u #{M} cargo build --release --locked -p fireemu --target ${{ matrix.platform.target }}" })
    refused(edit { |doc| doc["jobs"]["build"]["steps"].find { |s| s["name"] == "build the daemon" }["run"] = "#{M}= cargo build --release --locked -p fireemu --target ${{ matrix.platform.target }}" })
  end

  def test_each_pinned_build_keeps_its_marker_and_command
    [
      ["build", "build the daemon"],
      ["reproducible", "first build, in the checkout"],
      ["reproducible", "second build, from a copy under another path"]
    ].each do |job, name|
      find = ->(doc) { doc["jobs"][job]["steps"].find { |s| s["name"] == name } }
      refused(edit { |doc| find.(doc).delete("env") })
      refused(edit { |doc| find.(doc)["env"][M] = "0" })
      refused(edit { |doc| find.(doc)["env"][M] = 1 })
      refused(edit { |doc| find.(doc)["env"]["EXTRA"] = "1" })
      refused(edit { |doc| find.(doc)["run"] += "true\n" })
      refused(edit { |doc| find.(doc)["if"] = "github.event_name == 'push'" })
      refused(edit { |doc| find.(doc)["continue-on-error"] = true })
      refused(edit { |doc| find.(doc)["shell"] = "bash" })
      refused(edit { |doc| find.(doc)["working-directory"] = "." })
      refused(edit { |doc| doc["jobs"][job]["steps"].delete(find.(doc)) })
    end
  end

  def test_a_step_with_a_pinned_name_must_be_unique
    # A same-named step that does nothing harmful still makes "the build step" ambiguous.
    refused(edit { |doc| doc["jobs"]["build"]["steps"] << { "name" => "build the daemon", "run" => "true" } })
    refused(edit { |doc| doc["jobs"]["build"]["steps"] << { "name" => "the binary writes the schema URL of its own release tag", "run" => "true" } })
    refused(edit { |doc| doc["jobs"]["reproducible"]["steps"] << { "name" => "first build, in the checkout", "run" => "true" } })
  end

  def test_a_second_cargo_build_could_replace_the_checked_binary
    refused(edit { |doc| doc["jobs"]["build"]["steps"] << { "name" => "rebuild", "run" => "cargo build --release -p fireemu" } })
    refused(edit { |doc| doc["jobs"]["build"]["steps"] << { "name" => "toolchain", "run" => "rustup default nightly" } })
    refused(edit { |doc| doc["jobs"]["reproducible"]["steps"] << { "name" => "rebuild", "run" => "cargo build --release -p fireemu" } })
  end

  def test_the_url_check_is_pinned_and_cannot_be_replaced_by_an_echo
    find = ->(doc) { doc["jobs"]["build"]["steps"].find { |s| s["name"] == "the binary writes the schema URL of its own release tag" } }
    refused(edit { |doc| find.(doc)["run"] = "echo \"init --yes\"\n" })
    refused(edit { |doc| find.(doc)["run"] = ReleaseMarkerContract::CHECK_RUN.sub('test "$(head', 'true "$(head') })
    refused(edit { |doc| find.(doc)["run"] = ReleaseMarkerContract::CHECK_RUN.sub("v${workspace}", "main") })
    refused(edit { |doc| find.(doc)["if"] = "false" })
    refused(edit { |doc| find.(doc)["continue-on-error"] = true })
    refused(edit { |doc| find.(doc)["shell"] = "sh" })
    refused(edit { |doc| find.(doc).delete("shell") })
    refused(edit { |doc| doc["jobs"]["build"]["steps"].delete(find.(doc)) })
    # Moved before the build it is meant to check.
    refused(edit { |doc| steps = doc["jobs"]["build"]["steps"]; check = steps.delete(find.(doc)); steps.unshift(check) })
  end

  def test_no_other_file_under_dot_github_may_name_the_marker
    refused(RELEASE, ".github/workflows/ci.yml" => "env:\n  #{M}: \"1\"\n")
    refused(RELEASE, ".github/workflows/other.yaml" => "# #{M}\n")
    refused(RELEASE, ".github/actions/build/action.yml" => "runs:\n  using: composite\n  steps:\n    - run: export #{M}=1\n      shell: bash\n")
    assert_empty errors(RELEASE, ".github/workflows/ci.yml" => "name: ci\n")
  end

  def test_yaml_aliases_and_merge_keys_cannot_smuggle_the_marker
    aliased = RELEASE.sub("jobs:\n", "x-marker: &marker\n  #{M}: \"1\"\njobs:\n")
    # An alias resolves to the marker where it is used, and the anchor that defines it names the
    # marker too: both are refused.
    refused(aliased.sub(/^  test:\n/, "  test:\n    env: *marker\n"))
    refused(aliased.sub(/^  build:\n/, "  build:\n    env: *marker\n"))
    refused(aliased.sub("env:\n  CARGO_TERM_COLOR", "env:\n  <<: *marker\n  CARGO_TERM_COLOR"))
    refused(aliased)
    refused("[1, 2")
    refused("- not a mapping\n")
  end

  def test_real_repository_check_runs_against_a_copy_with_a_bypass
    require "tmpdir"
    require "fileutils"
    Dir.mktmpdir("fireemu-marker-contract") do |root|
      FileUtils.mkdir_p(File.join(root, ".github", "workflows"))
      File.write(File.join(root, ".github", "workflows", "release.yml"), RELEASE)
      ReleaseMarkerContract.check!(root)
      File.write(File.join(root, ".github", "workflows", "ci.yaml"), "env:\n  #{M}: \"1\"\n")
      assert_raises(RuntimeError) { ReleaseMarkerContract.check!(root) }
    end
  end
end
