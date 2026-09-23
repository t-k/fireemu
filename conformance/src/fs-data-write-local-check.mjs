import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const config = "conformance/fs-data-write-sandbox.fireemu.json";
const runner = "conformance/src/fs-data-write-sandbox-run.mjs";

async function run(command, args, capture = false, allowedCodes = [0]) {
  const child = spawn(command, args, {
    cwd: root,
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

await run("cargo", ["build", "-p", "fireemu"]);
const { output } = await run(
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
);
process.stdout.write(output);
const result = JSON.parse(output.trim().split("\n").at(-1));
const runDir = resolve(result.runDir);
if (!runDir.startsWith(join(root, "conformance/.runs/fs-data-write-local-"))) {
  throw new Error("local runner returned a run directory outside the expected location");
}
const configSha256 = createHash("sha256")
  .update(await readFile(join(root, config)))
  .digest("hex");
await writeFile(
  join(runDir, "local-config-sha256.json"),
  `${JSON.stringify({ config, configSha256 }, null, 2)}\n`,
);
const comparison = await run("node", [runner, "compare-local", runDir], false, [0, 1, 2]);
process.exitCode = comparison.code;
