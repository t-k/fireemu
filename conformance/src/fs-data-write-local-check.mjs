import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const config = "conformance/fs-data-write-sandbox.fireemu.json";
const runner = "conformance/src/fs-data-write-sandbox-run.mjs";

async function run(command, args, capture = false, allowedCodes = [0], cwd = process.cwd()) {
  const child = spawn(command, args, {
    cwd,
    stdio: ["inherit", capture ? "pipe" : "inherit", "inherit"],
  });
  let output = "";
  if (capture) {
    child.stdout.setEncoding("utf8");
    for await (const chunk of child.stdout) output += chunk;
  }
  const code = await new Promise((done, reject) => {
    child.once("error", reject);
    child.once("close", done);
  });
  if (!allowedCodes.includes(code)) throw new Error(`${command} exited ${code}`);
  return { output, code };
}

const sha256 = async (path) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");

async function commandVersion(runCommand, command, args) {
  const { output } = await runCommand(command, args, true);
  return output.trim();
}

export async function runLocalCheck({ root, run: runCommand = run }) {
  const runInRoot = (command, args, capture, allowedCodes) =>
    runCommand(command, args, capture, allowedCodes, root);
  await runInRoot("cargo", ["build", "--locked", "-p", "fireemu"]);
  const sourceHead = await commandVersion(runInRoot, "git", ["rev-parse", "HEAD"]);
  const status = await commandVersion(runInRoot, "git", [
    "status",
    "--porcelain",
    "--untracked-files=no",
  ]);
  if (status)
    throw new Error("tracked source worktree is dirty; refusing to run the local checker");

  const binary = join(root, "target/debug/fireemu");
  const executableSha256 = await sha256(binary);
  const configSha256 = await sha256(join(root, config));
  const runtimeInputs = Object.fromEntries(
    await Promise.all(
      [
        "Cargo.toml",
        "Cargo.lock",
        runner,
        "conformance/src/firestore-probe/sandbox-session.mjs",
      ].map(async (path) => [path, await sha256(join(root, path))]),
    ),
  );
  const commandVersions = {
    cargo: await commandVersion(runInRoot, "cargo", ["--version"]),
    node: await commandVersion(runInRoot, "node", ["--version"]),
    rustc: await commandVersion(runInRoot, "rustc", ["--version"]),
  };
  const { output } = await runCommand(
    join(root, "target/debug/fireemu"),
    [
      "exec",
      "--config",
      config,
      "--project",
      "fireemu-oracle-sbx",
      "--only",
      "firestore",
      "--firestore-port",
      "0",
      "--http-port",
      "0",
      "--storage-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      "node",
      runner,
      "local-child",
    ],
    true,
    undefined,
    root,
  );
  process.stdout.write(output);
  const result = JSON.parse(output.trim().split("\n").at(-1));
  const runDir = resolve(result.runDir);
  if (!runDir.startsWith(join(root, "conformance/.runs/fs-data-write-local-"))) {
    throw new Error("local runner returned a run directory outside the expected location");
  }

  const sourceHeadAfter = await commandVersion(runInRoot, "git", ["rev-parse", "HEAD"]);
  if (sourceHead !== sourceHeadAfter) {
    throw new Error("source HEAD changed during local run; refusing to create local-run bindings");
  }
  const statusAfter = await commandVersion(runInRoot, "git", [
    "status",
    "--porcelain",
    "--untracked-files=no",
  ]);
  if (statusAfter) {
    throw new Error(
      "tracked source worktree changed during local run; refusing to create local-run bindings",
    );
  }
  const executableSha256After = await sha256(binary);
  if (executableSha256 !== executableSha256After) {
    throw new Error("executable changed during local run; refusing to create a local-run binding");
  }
  await writeFile(
    join(runDir, "local-run-binding.json"),
    `${JSON.stringify(
      {
        sourceHead,
        executablePath: "target/debug/fireemu",
        executableSha256,
        executableSha256After,
        config,
        configSha256,
        runtimeInputs,
        commandVersions,
      },
      null,
      2,
    )}\n`,
  );
  await writeFile(
    join(runDir, "local-config-sha256.json"),
    `${JSON.stringify({ config, configSha256 }, null, 2)}\n`,
  );
  const compare = await runCommand(
    "node",
    [runner, "compare-local", runDir],
    false,
    [0, 1, 2],
    root,
  );
  return compare.code;
}

const scriptPath = resolve(fileURLToPath(import.meta.url));
if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const root = resolve(dirname(scriptPath), "../..");
  process.exitCode = await runLocalCheck({ root });
}
