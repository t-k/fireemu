import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { runLocalCheck } from "./fs-data-write-local-check.mjs";

async function createSourceRoot() {
  const root = await mkdtemp(join(tmpdir(), "fs-local-binding-"));
  await mkdir(join(root, "conformance/src/firestore-probe"), { recursive: true });
  await mkdir(join(root, "target/debug"), { recursive: true });
  await mkdir(join(root, "conformance/.runs/fs-data-write-local-run"), { recursive: true });
  await writeFile(join(root, "conformance/fs-data-write-sandbox.fireemu.json"), "{}\n");
  await writeFile(join(root, "conformance/src/fs-data-write-sandbox-run.mjs"), "// runner\n");
  await writeFile(
    join(root, "conformance/src/firestore-probe/sandbox-session.mjs"),
    "// session\n",
  );
  await writeFile(join(root, "Cargo.toml"), "[workspace]\n");
  await writeFile(join(root, "Cargo.lock"), "version = 4\n");
  await writeFile(join(root, "target/debug/fireemu"), "binary bytes\n");
  execFileSync("git", ["init", "-q"], { cwd: root });
  execFileSync("git", ["add", "Cargo.toml", "Cargo.lock", "conformance"], { cwd: root });
  execFileSync(
    "git",
    ["-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "fixture"],
    { cwd: root },
  );
  return root;
}

test("persists source, executable, config, and runtime bindings before preserving compare exit code", async () => {
  const root = await createSourceRoot();
  const calls = [];
  try {
    const code = await runLocalCheck({
      root,
      run: async (command, args, _capture = false, allowedCodes = [0]) => {
        calls.push({ command, args });
        if (command === "git") {
          const output = execFileSync(command, args, { cwd: root, encoding: "utf8" });
          return { output, code: 0 };
        }
        if (args[0] === "--version") {
          return { output: `${command} test version\n`, code: 0 };
        }
        let output = "";
        if (args[0] === "exec") {
          output = `${JSON.stringify({ runDir: join(root, "conformance/.runs/fs-data-write-local-run") })}\n`;
        }
        if (args.includes("compare-local")) {
          await readFile(
            join(root, "conformance/.runs/fs-data-write-local-run/local-run-binding.json"),
          );
          await readFile(
            join(root, "conformance/.runs/fs-data-write-local-run/local-config-sha256.json"),
          );
        }
        const resultCode = args.includes("compare-local") ? 1 : 0;
        assert.ok(allowedCodes.includes(resultCode));
        return { output, code: resultCode };
      },
    });

    assert.equal(code, 1);
    assert.equal(calls.at(-1).args[1], "compare-local");
    assert.deepEqual(calls[0], { command: "cargo", args: ["build", "--locked", "-p", "fireemu"] });
    const binding = JSON.parse(
      await readFile(
        join(root, "conformance/.runs/fs-data-write-local-run/local-run-binding.json"),
        "utf8",
      ),
    );
    const legacyBinding = JSON.parse(
      await readFile(
        join(root, "conformance/.runs/fs-data-write-local-run/local-config-sha256.json"),
        "utf8",
      ),
    );
    assert.equal(
      binding.sourceHead,
      execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(),
    );
    assert.match(binding.executableSha256, /^[a-f0-9]{64}$/);
    assert.equal(binding.configSha256.length, 64);
    assert.deepEqual(legacyBinding, {
      config: "conformance/fs-data-write-sandbox.fireemu.json",
      configSha256: binding.configSha256,
    });
    assert.equal(binding.runtimeInputs["conformance/src/fs-data-write-sandbox-run.mjs"].length, 64);
    assert.equal(
      binding.runtimeInputs["conformance/src/firestore-probe/sandbox-session.mjs"].length,
      64,
    );
    assert.ok(binding.commandVersions.node);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("refuses to launch from a tracked dirty source worktree", async () => {
  const root = await createSourceRoot();
  let launched = false;
  try {
    await writeFile(join(root, "Cargo.toml"), "[workspace]\n# changed\n");
    await assert.rejects(
      runLocalCheck({
        root,
        run: async (command, args) => {
          if (command === "git") {
            return {
              output: execFileSync(command, args, { cwd: root, encoding: "utf8" }),
              code: 0,
            };
          }
          if (args[0] === "exec") launched = true;
          return { output: "", code: 0 };
        },
      }),
      /tracked source worktree is dirty/,
    );
    assert.equal(launched, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an executable changed by the local child before writing a binding", async () => {
  const root = await createSourceRoot();
  try {
    await assert.rejects(
      runLocalCheck({
        root,
        run: async (_command, args) => {
          if (args[0] === "exec") {
            await writeFile(join(root, "target/debug/fireemu"), "changed binary\n");
            return {
              output: `${JSON.stringify({ runDir: join(root, "conformance/.runs/fs-data-write-local-run") })}\n`,
              code: 0,
            };
          }
          return { output: "", code: 0 };
        },
      }),
      /executable changed during local run/,
    );
    await assert.rejects(
      readFile(join(root, "conformance/.runs/fs-data-write-local-run/local-run-binding.json")),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects tracked source edits made by the local child before writing bindings", async () => {
  const root = await createSourceRoot();
  try {
    await assert.rejects(
      runLocalCheck({
        root,
        run: async (command, args) => {
          if (command === "git") {
            return {
              output: execFileSync(command, args, { cwd: root, encoding: "utf8" }),
              code: 0,
            };
          }
          if (args[0] === "exec") {
            await writeFile(join(root, "Cargo.toml"), "[workspace]\n# modified during child\n");
            return {
              output: `${JSON.stringify({ runDir: join(root, "conformance/.runs/fs-data-write-local-run") })}\n`,
              code: 0,
            };
          }
          return { output: "", code: 0 };
        },
      }),
      /tracked source worktree changed during local run/,
    );
    await assert.rejects(
      readFile(join(root, "conformance/.runs/fs-data-write-local-run/local-run-binding.json")),
    );
    await assert.rejects(
      readFile(join(root, "conformance/.runs/fs-data-write-local-run/local-config-sha256.json")),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a source HEAD change made by the local child before writing bindings", async () => {
  const root = await createSourceRoot();
  try {
    await assert.rejects(
      runLocalCheck({
        root,
        run: async (command, args) => {
          if (command === "git") {
            return {
              output: execFileSync(command, args, { cwd: root, encoding: "utf8" }),
              code: 0,
            };
          }
          if (args[0] === "exec") {
            await writeFile(join(root, "Cargo.toml"), "[workspace]\n# committed during child\n");
            execFileSync("git", ["add", "Cargo.toml"], { cwd: root });
            execFileSync(
              "git",
              [
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "mid-run",
              ],
              { cwd: root },
            );
            return {
              output: `${JSON.stringify({ runDir: join(root, "conformance/.runs/fs-data-write-local-run") })}\n`,
              code: 0,
            };
          }
          return { output: "", code: 0 };
        },
      }),
      /source HEAD changed during local run/,
    );
    await assert.rejects(
      readFile(join(root, "conformance/.runs/fs-data-write-local-run/local-run-binding.json")),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
