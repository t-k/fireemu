#!/usr/bin/env ruby
# frozen_string_literal: true

# FIREEMU_RELEASE_BUILD=1 is read by rustc (`option_env!`) and makes `fireemu init` write the schema
# URL of the release tag. Only the binary that the release workflow publishes may carry it: every
# other build embeds the schema of `main`, which differs from the tag's schema between releases.
#
# Threat model: this guards against a maintainer's mistake in our own workflow files, such as a
# stray workflow-level `env`, a replaced check or a marker copied into a test build. It is not a
# defence against a deliberately obfuscated workflow (a split variable name, a `fromJSON` object,
# shell tricks); a wrong marker in an ordinary build only makes that test binary write a tag URL,
# and it cannot reach the published binary, whose URL the release workflow checks and whose bytes
# the reproducibility builds compare. The checks stay cheap and structural: no shell parsing.
#
# The contract is closed: the marker is allowed in exactly three places (the step-level `env` of the
# daemon build and of the two reproducibility builds), those steps run pinned commands, and the step
# that checks the written URL is pinned too. Anything else that names the marker, in any workflow
# file or composite action, fails, so a workflow-level or job-level `env`, a `run:` that exports or
# unsets it, a write to `$GITHUB_ENV` and a replaced check cannot pass.
require "yaml"

module ReleaseMarkerContract
  MARKER = "FIREEMU_RELEASE_BUILD"
  RELEASE = "release.yml"

  BUILD_STEP = ["build", "build the daemon"].freeze
  FIRST_STEP = ["reproducible", "first build, in the checkout"].freeze
  SECOND_STEP = ["reproducible", "second build, from a copy under another path"].freeze
  CHECK_STEP = ["build", "the binary writes the schema URL of its own release tag"].freeze

  BUILD_RUN = "cargo build --release --locked -p fireemu --target ${{ matrix.platform.target }}"
  FIRST_RUN = <<~'RUN'
    cargo build --release --locked -p fireemu --target x86_64-unknown-linux-musl
    sha256sum target/x86_64-unknown-linux-musl/release/fireemu | tee first.sha256
  RUN
  SECOND_RUN = <<~'RUN'
    rsync -a --exclude target --exclude .git ./ /tmp/fireemu-rebuild/
    cd /tmp/fireemu-rebuild
    cargo build --release --locked -p fireemu --target x86_64-unknown-linux-musl
    sha256sum target/x86_64-unknown-linux-musl/release/fireemu | awk '{print $1}' > "$GITHUB_WORKSPACE/second.sha256"
  RUN
  SECOND_RUSTFLAGS = "--remap-path-prefix=/tmp/fireemu-rebuild=/src --remap-path-prefix=/home/runner/.cargo=/cargo -D warnings"
  CHECK_RUN = <<~'RUN'
    if [ "${{ matrix.platform.cross }}" = "true" ]; then
      echo "cross-compiled: checked on the host build of the same commit"
    else
      binary="$PWD/target/${{ matrix.platform.target }}/release/fireemu${{ matrix.platform.exe }}"
      scratch="$(mktemp -d)"
      (cd "$scratch" && "$binary" init --yes)
      workspace=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
      expected="#:schema https://raw.githubusercontent.com/fireemu/fireemu/v${workspace}/spec/config/fireemu.schema.json"
      test "$(head -n 1 "$scratch/fireemu.toml")" = "$expected"
    fi
  RUN

  # The only lines of the release workflow that write to $GITHUB_ENV, and so could set or clear a
  # variable for the steps after them.
  GITHUB_ENV_LINES = [
    'echo "FIREEMU_NODE=$(command -v node)" >> "$GITHUB_ENV"',
    'echo "FIREEMU_FEDERATION_OPENSSL_DIR=$RUNNER_TEMP/fireemu-federation-openssl/bin" >> "$GITHUB_ENV"'
  ].freeze

  def self.step(doc, (job, name))
    doc.dig("jobs", job, "steps")&.find { |candidate| candidate.is_a?(Hash) && candidate["name"] == name }
  end

  # Every place the marker is named in the parsed release workflow: keys and string values.
  def self.occurrences(node, path = [], found = [])
    case node
    when Hash
      node.each do |key, value|
        found << [path + [key], value] if key.to_s.include?(MARKER)
        occurrences(value, path + [key], found)
      end
    when Array
      node.each_with_index { |value, index| occurrences(value, path + [index], found) }
    when String
      found << [path, node] if node.include?(MARKER)
    end
    found
  end

  # Every `env` of the workflow, the jobs and the steps.
  def self.each_env(doc)
    yield ["env"], doc["env"] if doc.key?("env")
    doc.fetch("jobs", {}).each do |job, body|
      yield ["jobs", job, "env"], body["env"] if body.key?("env")
      Array(body["steps"]).each_with_index do |step, index|
        yield ["jobs", job, "steps", index, "env"], step["env"] if step.is_a?(Hash) && step.key?("env")
      end
    end
  end

  def self.each_run(doc)
    doc.fetch("jobs", {}).each do |job, body|
      Array(body["steps"]).each_with_index do |step, index|
        yield job, index, step if step.is_a?(Hash) && step["run"].is_a?(String)
      end
    end
  end

  def self.violations(release_source, others = {})
    errors = []
    begin
      doc = YAML.safe_load(release_source, aliases: true)
    rescue Psych::Exception => e
      return ["#{RELEASE} must parse: #{e.message}"]
    end
    return ["#{RELEASE} must be a mapping"] unless doc.is_a?(Hash)

    others.each do |name, source|
      errors << "only #{RELEASE} may name #{MARKER} (#{name})" if source.include?(MARKER)
    end

    pinned = {
      BUILD_STEP => [BUILD_RUN, { MARKER => "1" }],
      FIRST_STEP => [FIRST_RUN, { MARKER => "1" }],
      SECOND_STEP => [SECOND_RUN, { MARKER => "1", "RUSTFLAGS" => SECOND_RUSTFLAGS }]
    }
    allowed = []
    pinned.each do |(job, name), (run, env)|
      candidates = Array(doc.dig("jobs", job, "steps")).select { |s| s.is_a?(Hash) && s["name"] == name }
      errors << "#{job} must have exactly one step named #{name.inspect}" unless candidates.size == 1
      found = candidates.first
      next unless found

      errors << "#{name.inspect} must carry exactly name, env and run" unless found.keys.sort == %w[env name run]
      errors << "#{name.inspect} must set env #{env.inspect} and nothing else" unless found["env"] == env
      errors << "#{name.inspect} must run exactly the pinned command" unless found["run"] == run
      index = doc.dig("jobs", job, "steps").index(found)
      allowed << ["jobs", job, "steps", index, "env", MARKER]
    end

    check = Array(doc.dig("jobs", CHECK_STEP[0], "steps")).select { |s| s.is_a?(Hash) && s["name"] == CHECK_STEP[1] }
    if check.size != 1
      errors << "#{CHECK_STEP[0]} must have exactly one step named #{CHECK_STEP[1].inspect}"
    else
      errors << "the URL check must carry exactly name, shell and run" unless check.first.keys.sort == %w[name run shell]
      errors << "the URL check must use shell: bash" unless check.first["shell"] == "bash"
      errors << "the URL check must run exactly the pinned command" unless check.first["run"] == CHECK_RUN
      steps = doc.dig("jobs", CHECK_STEP[0], "steps")
      errors << "the URL check must come after the daemon build" unless steps.index(check.first) > steps.index(step(doc, BUILD_STEP) || check.first)
    end

    # Every occurrence in the raw text, comments included (YAML parsing discards them), is a pinned
    # `env` line; how many there are is checked through the parsed placement below.
    raw = release_source.each_line.select { |line| line.include?(MARKER) }
    errors << "#{MARKER} may appear in #{RELEASE} only as a pinned env line, never in a comment or another line: #{raw.map(&:strip).uniq.inspect}" unless raw.all? { |line| line.strip.match?(/\A#{MARKER}: ["']1["']\z/) }

    # An `env` that is an expression instead of a mapping could carry the marker unseen.
    each_env(doc) do |path, value|
      errors << "env at #{path.join('.')} must be a mapping, not an expression" unless value.is_a?(Hash)
    end

    seen = occurrences(doc)
    seen.each do |path, value|
      errors << "#{MARKER} may only be set to \"1\" in the step-level env of the three pinned build steps, found at #{path.join('.')}" unless allowed.include?(path)
    end

    # No other build step can replace the checked binary, and the three builds are the only ones.
    reproducible_builds = Array(doc.dig("jobs", "reproducible", "steps")).sum { |s| s.is_a?(Hash) ? s["run"].to_s.scan(/\bcargo build\b/).size : 0 }
    errors << "the reproducible job must run cargo build exactly twice" unless reproducible_builds == 2
    cargo_steps = Array(doc.dig("jobs", "build", "steps")).count { |s| s.is_a?(Hash) && s["run"].to_s.match?(/\b(cargo|rustc|rustup)\b/) }
    errors << "the build job may not run cargo, rustc or rustup outside the daemon build" unless cargo_steps == 1

    # No write to $GITHUB_ENV that could set or clear a variable for a later step.
    each_run(doc) do |job, index, step|
      step["run"].each_line do |line|
        next unless line.include?("GITHUB_ENV")

        errors << "jobs.#{job}.steps.#{index} writes $GITHUB_ENV with an unpinned line: #{line.strip}" unless GITHUB_ENV_LINES.include?(line.strip.sub(/\Arun: /, ""))
      end
    end
    errors
  end

  def self.check!(root)
    workflows = File.join(root, ".github")
    release = File.read(File.join(workflows, "workflows", RELEASE))
    others = Dir.glob(File.join(workflows, "**", "*"), File::FNM_DOTMATCH).select { |path| File.file?(path) }
                .reject { |path| path == File.join(workflows, "workflows", RELEASE) }
                .to_h { |path| [path.delete_prefix("#{root}/"), File.read(path, mode: "rb").force_encoding("UTF-8").scrub] }
    errors = violations(release, others)
    raise "release marker contract: #{errors.join('; ')}" unless errors.empty?
  end
end
