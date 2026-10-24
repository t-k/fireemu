#!/usr/bin/env ruby

require "yaml"

module KaniCiContract
  ROOT = File.expand_path("..", __dir__)
  CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
  RUST_TOOLCHAIN = "dtolnay/rust-toolchain@b725eda525362e7cf34af9a7243cac1e3f01a7ec"
  TOOLCHAIN_VERSION = "1.94.0"
  INSTALL_KANI = "cargo install --locked kani-verifier --version 0.68.0"
  SETUP_KANI = "cargo kani setup"
  RUN_PROOFS = "python3 verification/kani/run.py"
  VERIFY_TOOLCHAIN = %(rustc --version | tee /dev/stderr | grep -q "$(sed -n 's/^channel = \\"\\(.*\\)\\"/\\1/p' rust-toolchain.toml)")

  module_function

  def validate_file(path = File.join(ROOT, ".github", "workflows", "kani.yml"))
    validate_hash(YAML.safe_load(File.read(path), aliases: true))
  rescue Psych::Exception, SystemCallError => error
    ["cannot read or parse workflow: #{error.message}"]
  end

  def validate_hash(workflow)
    errors = []
    assert(errors, workflow.is_a?(Hash), "workflow must be a YAML mapping")
    return errors unless workflow.is_a?(Hash)

    normalized_keys = workflow.keys.map { |key| key == true ? "on" : key }
    assert(errors, exact_keys?(normalized_keys, %w[jobs name on permissions]), "workflow keys must be exactly name, on, permissions and jobs")
    assert(errors, workflow["name"] == "kani", "workflow name must be kani")

    events = workflow["on"] || workflow[true]
    assert(errors, events.is_a?(Hash), "workflow must declare event triggers")
    if events.is_a?(Hash)
      assert(errors, exact_keys?(events.keys, %w[pull_request push workflow_dispatch]), "workflow must run on pull requests, main pushes and manual dispatch only")
      assert(errors, events["pull_request"].nil? || events["pull_request"] == {}, "pull_request must not have filters that can skip proofs")
      assert(errors, events["push"] == { "branches" => ["main"] }, "push must run on main without path filters")
      assert(errors, events["workflow_dispatch"].nil? || events["workflow_dispatch"] == {}, "workflow_dispatch must not have filters")
    end
    assert(errors, workflow["permissions"] == { "contents" => "read" }, "workflow permissions must be contents: read only")

    jobs = workflow["jobs"]
    assert(errors, jobs.is_a?(Hash) && jobs.keys == ["kani"], "workflow must contain only the kani job")
    return errors unless jobs.is_a?(Hash) && jobs["kani"].is_a?(Hash)

    job = jobs.fetch("kani")
    assert(errors, exact_keys?(job.keys, %w[permissions runs-on steps timeout-minutes]), "kani job may only set runner, timeout, permissions and steps")
    assert(errors, job["runs-on"] == "ubuntu-24.04", "kani job must use the ubuntu-24.04 x86_64 runner")
    assert(errors, job["timeout-minutes"] == 30, "kani job must have a 30-minute timeout")
    assert(errors, job["permissions"] == { "contents" => "read" }, "kani job permissions must be contents: read only")

    steps = job["steps"]
    assert(errors, steps.is_a?(Array) && steps.length == 6, "kani job must have exactly six required steps")
    return errors unless steps.is_a?(Array)

    checkout, toolchain, verify, install, setup, proofs = steps
    assert(errors, checkout.is_a?(Hash) && exact_keys?(checkout.keys, %w[uses with]) && checkout["uses"] == CHECKOUT,
      "checkout must use the pinned actions/checkout commit")
    checkout_with = checkout.is_a?(Hash) ? checkout["with"] : nil
    assert(errors, checkout_with.is_a?(Hash) && checkout_with == { "persist-credentials" => false },
      "checkout must disable persisted credentials")
    assert(errors, toolchain.is_a?(Hash) && exact_keys?(toolchain.keys, %w[uses with]) && toolchain["uses"] == RUST_TOOLCHAIN,
      "Rust toolchain setup must use the pinned dtolnay action commit")
    assert(errors, toolchain.is_a?(Hash) && toolchain["with"] == { "toolchain" => TOOLCHAIN_VERSION },
      "Rust toolchain setup must use the repository's fixed toolchain")
    assert_step(errors, verify, "verify the pinned toolchain", VERIFY_TOOLCHAIN)
    assert_step(errors, install, "install Kani", INSTALL_KANI)
    assert_step(errors, setup, "set up Kani", SETUP_KANI)
    assert_step(errors, proofs, "run bounded proofs", RUN_PROOFS)
    errors
  end

  def assert_step(errors, step, name, command)
    assert(errors, step.is_a?(Hash) && exact_keys?(step.keys, %w[name run]) && step["name"] == name && step["run"] == command,
      "#{name} must run exactly #{command} without conditions or failure swallowing")
  end
  private_class_method :assert_step

  def exact_keys?(keys, expected)
    keys.all? { |key| key.is_a?(String) } && keys.sort == expected
  end
  private_class_method :exact_keys?

  def assert(errors, condition, message)
    errors << message unless condition
  end
  private_class_method :assert
end

if $PROGRAM_NAME == __FILE__
  errors = KaniCiContract.validate_file(ARGV.fetch(0, File.join(KaniCiContract::ROOT, ".github", "workflows", "kani.yml")))
  if errors.empty?
    puts "Kani workflow contract passed"
  else
    warn errors.map { |error| "- #{error}" }.join("\n")
    exit 1
  end
end
