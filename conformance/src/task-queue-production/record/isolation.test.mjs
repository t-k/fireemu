import "./isolation.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { FORBIDDEN, ISOLATED_HOME, TRAP_MARK } from "./isolation.mjs";
import { PACKET_FILES, envProblems, main, packetDigest, realDeps } from "./main.mjs";

const here = new URL(".", import.meta.url).pathname;

test("a test process has an empty HOME and no credential, project or emulator variable", () => {
  assert.equal(process.env.HOME, ISOLATED_HOME);
  assert.equal(homedir(), ISOLATED_HOME);
  assert.deepEqual(readdirSync(ISOLATED_HOME), []);
  assert.equal(existsSync(join(ISOLATED_HOME, ".config/gcloud")), false);
  assert.deepEqual(
    Object.keys(process.env).filter((key) => FORBIDDEN.some((re) => re.test(key))),
    [],
  );
  assert.deepEqual(envProblems(process.env), []);
});

test("every variable the recorder refuses is also one this isolation removes", () => {
  for (const name of [
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIREBASE_TOKEN",
    "CLOUDSDK_CONFIG",
    "GCLOUD_PROJECT",
    "FIRESTORE_EMULATOR_HOST",
    "GOOGLE_CLOUD_PROJECT",
  ])
    assert.ok(
      FORBIDDEN.some((re) => re.test(name)),
      name,
    );
});

test("fetch, gcloud and firebase refuse in a test, and the real client's send and token cannot get through", async () => {
  await assert.rejects(
    fetch("https://cloudtasks.googleapis.com/v2/projects/x"),
    /refused in a test/,
  );
  await assert.rejects(
    realDeps.send({ url: "https://cloudtasks.googleapis.com/v2/x", method: "GET" }),
    /refused in a test/,
  );
  assert.throws(() => realDeps.token());
  assert.match(readFileSync(TRAP_MARK, "utf8"), /gcloud ran in a test/);
  for (const tool of ["firebase", "gsutil"]) {
    const result = spawnSync(tool, ["x"], { encoding: "utf8" });
    assert.equal(result.status, 97, tool);
  }
});

test("the recorder sends nothing without --send and the approved digest, in any of the ways to leave one out", async () => {
  const digest = packetDigest();
  const lines = [];
  const io = { out: (l) => lines.push(l), err: (l) => lines.push(l) };
  const base = [
    "--run-dir",
    "/nonexistent",
    "--project-number",
    "123",
    "--source-commit",
    "a".repeat(40),
  ];
  for (const extra of [
    [],
    ["--send"],
    ["--send", "--expect-digest", "wrong"],
    ["--expect-digest", digest],
  ]) {
    for (const command of ["record", "readback"]) {
      let touched = false;
      const trap = () => {
        touched = true;
        throw new Error("a dependency was used");
      };
      const deps = new Proxy({}, { get: () => trap });
      const code = await main([command, ...base, ...extra], { env: {}, deps, digest, ...io });
      assert.notEqual(code, 0, `${command} ${extra.join(" ")}`);
      assert.equal(touched, false, `${command} ${extra.join(" ")}`);
    }
  }
});

test("no test file reaches the real client: none imports realDeps (but this one), all import the isolation first, and --send always comes with an injected world", () => {
  const files = readdirSync(here).filter((name) => name.endsWith(".test.mjs"));
  assert.ok(files.length >= 8);
  for (const name of files) {
    const text = readFileSync(join(here, name), "utf8");
    const imports = [...text.matchAll(/^import .*$/gm)].map((m) => m[0]);
    if (name !== "isolation.test.mjs")
      assert.equal(/\brealDeps\b/.test(text), false, `${name} uses realDeps`);
    assert.equal(imports[0], 'import "./isolation.mjs";', `${name} imports the isolation first`);
    if (/--send/.test(text) && name !== "isolation.test.mjs")
      assert.ok(
        /deps:\s*okDeps\(|deps\b/.test(text) && /createWorld|world/.test(text),
        `${name} sends only to a world`,
      );
  }
  assert.ok(PACKET_FILES.length > 0);
});

test("the other test files of the recording import the isolation first too, but the loopback replay", () => {
  const dir = join(here, "..");
  for (const name of readdirSync(dir).filter(
    (n) => n.endsWith(".test.mjs") && n !== "strict-replay.test.mjs",
  )) {
    const first = readFileSync(join(dir, name), "utf8").match(/^import .*$/m)?.[0];
    assert.equal(first, 'import "./record/isolation.mjs";', name);
  }
});

test("the recorder holds no path to a private root: it reads no ledger or docs.local file", () => {
  for (const name of readdirSync(here).filter(
    (n) => n.endsWith(".mjs") && !n.endsWith(".test.mjs"),
  )) {
    const text = readFileSync(join(here, name), "utf8");
    assert.equal(
      /docs\.local|sandbox-oracles|agmsg|ledger/i.test(text.replace(/\/\/.*$/gm, "")),
      false,
      name,
    );
  }
});
