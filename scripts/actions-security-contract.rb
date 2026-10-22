#!/usr/bin/env ruby
# Validate original workflow YAML; action-level save settings do not bound cache tokens.
require "yaml"

module ActionsSecurityContract
  MODES = %w[read write write-only none].freeze
  SDK_JOB = "latest-sdk-under-exec"

  def self.inspect_node(node, path, errors)
    case node
    when Psych::Nodes::Mapping
      seen = []
      node.children.each_slice(2) do |key, value|
        unless key.is_a?(Psych::Nodes::Scalar)
          errors << "mapping keys must be scalars"
          next
        end
        name = key.value
        errors << "duplicate key #{(path + [name]).join('.')}" if seen.include?(name)
        seen << name
        errors << "YAML merge keys are forbidden" if name == "<<"
        if name == "cache-mode"
          allowed = path.empty? || (path.length == 2 && path.first == "jobs")
          errors << "cache-mode has an invalid location" unless allowed
          errors << "cache-mode must be a literal mode" unless value.is_a?(Psych::Nodes::Scalar) && MODES.include?(value.value)
        end
        inspect_node(value, path + [name], errors)
      end
    when Psych::Nodes::Alias
      errors << "YAML aliases are forbidden"
    else
      node.children&.each_with_index { |child, index| inspect_node(child, path + [index], errors) }
    end
  end

  def self.violations(source, name:)
    errors = []
    tree = Psych.parse(source)
    return ["workflow must be a mapping"] unless tree&.root.is_a?(Psych::Nodes::Mapping)
    inspect_node(tree.root, [], errors)
    return errors unless errors.empty?
    workflow = YAML.safe_load(source, aliases: false)
    jobs = workflow.fetch("jobs")
    return ["jobs must be a mapping"] unless jobs.is_a?(Hash)
    jobs.each do |job_name, job|
      next unless job.is_a?(Hash)
      uses = [job["uses"], *job.fetch("steps", []).map { |step| step["uses"] }].compact
      uses.each do |use|
        next if use.is_a?(String) && use.start_with?("./")
        errors << "#{job_name}: external uses must pin a full commit SHA: #{use}" unless use.is_a?(String) && use.match?(%r{\A[^\s@]+/[^\s@]+@[0-9a-f]{40}\z})
      end
    end
    if name == "sdk-latest.yml"
      job = jobs.fetch(SDK_JOB)
      effective = job.fetch("cache-mode", workflow["cache-mode"])
      errors << "SDK execution must have effective read-only cache access" unless %w[read none].include?(effective)
      steps = job.fetch("steps")
      checkout = steps.find { |step| step["uses"].to_s.start_with?("actions/checkout@") }
      errors << "SDK checkout must not persist credentials" unless checkout&.dig("with", "persist-credentials") == false
      cache = steps.find { |step| step["uses"].to_s.start_with?("Swatinem/rust-cache@") }
      errors << "SDK cache action must not save" unless cache&.dig("with", "save-if").to_s == "false"
      runs = steps.map { |step| step.fetch("run", "") }.join("\n")
      ["npm view firebase-admin version", "npm view firebase version", "npm install --ignore-scripts", "storage.mjs", "client.mjs"].each do |command|
        errors << "SDK latest smoke must retain #{command}" unless runs.include?(command)
      end
    end
    if name == "release.yml"
      jobs.each do |job_name, job|
        job.fetch("steps", []).each do |step|
          action = step["uses"].to_s.split("@").first
          errors << "#{job_name}: release must not consume dependency caches" if ["actions/cache", "actions/cache/restore", "Swatinem/rust-cache"].include?(action) || (action == "actions/setup-node" && step.dig("with", "cache"))
        end
      end
    end
    errors
  rescue Psych::Exception, KeyError, TypeError, NoMethodError => error
    ["invalid workflow: #{error.message}"]
  end

  def self.check!(root)
    errors = Dir.glob(File.join(root, ".github/workflows/*.{yml,yaml}")).sort.flat_map do |path|
      violations(File.read(path), name: File.basename(path)).map { |error| "#{File.basename(path)}: #{error}" }
    end
    raise errors.join("\n") unless errors.empty?
  end
end

if $PROGRAM_NAME == __FILE__
  ActionsSecurityContract.check!(File.expand_path("..", __dir__))
  puts "Actions security contract passed"
end
