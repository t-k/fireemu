// Guards against a test or a mutation run reaching the real service (coordinator safety notice, 2026-11-11).
// The first three tests run everywhere. The last one runs under the mutation harness only
// (NEGCACHE_MUTATION=1) and asserts the isolation the harness promises before any mutant runs.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { main, SEND_FLAG, SEND_FLAG_VALUE } from "./run.mjs";
import { createTransport } from "./transport.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const id = "abcdef123456";

test("the production transport is refused without the launch script's flag", () => {
  assert.throws(
    () => createTransport({ getToken: () => "t", clock: { now: () => 0 } }),
    /launch script's flag/,
  );
});

test("record and a2 refuse to start real clients without the flag, before any credential is read", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-guard-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "lock"),
    JSON.stringify({ pid: process.pid, packetId: "PUBSUB-NEGCACHE" }),
  );
  fs.writeFileSync(path.join(root, "packet"), "packet");
  let credentialsAsked = 0;
  const deps = {
    root,
    env: {},
    print() {},
    createCredentials: () => (credentialsAsked++, async () => "t"),
  };
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], deps),
    new RegExp(SEND_FLAG),
  );
  fs.mkdirSync(path.join(root, "from"));
  await assert.rejects(
    main(["a2", "--run-id", id, "--from", "from", "--out", "o2", "--lock", "lock"], deps),
    new RegExp(SEND_FLAG),
  );
  // A wrong value is no flag either.
  await assert.rejects(
    main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
      ...deps,
      env: { [SEND_FLAG]: "1" },
    }),
    new RegExp(SEND_FLAG),
  );
  assert.equal(credentialsAsked, 0);
  assert.equal(SEND_FLAG_VALUE, "launch-script");
});

test("no test sets the production flag", () => {
  for (const file of fs
    .readdirSync(here)
    .filter((f) => f.endsWith(".test.mjs") && f !== "guard.test.mjs")) {
    const text = fs.readFileSync(path.join(here, file), "utf8");
    assert.ok(
      !text.includes(SEND_FLAG) && !text.includes(SEND_FLAG_VALUE),
      `${file} mentions the production flag`,
    );
    assert.ok(!text.includes("allowProduction"), `${file} asks for a production transport`);
  }
});

test(
  "under the mutation harness: an empty temp HOME, no credentials, its own git root",
  { skip: process.env.NEGCACHE_MUTATION !== "1" && "runs under the mutation harness only" },
  () => {
    const home = process.env.HOME;
    assert.ok(
      (home && path.resolve(home).startsWith(fs.realpathSync(os.tmpdir()))) ||
        path.resolve(home).startsWith(os.tmpdir()),
      `HOME ${home} is not under the temp directory`,
    );
    assert.deepEqual(fs.readdirSync(home), [], "HOME must be empty");
    for (const name of Object.keys(process.env)) {
      assert.ok(
        !/^(GOOGLE_APPLICATION_CREDENTIALS|FIREBASE_TOKEN|CLOUDSDK_.*|GCLOUD_.*|GOOGLE_CLOUD_.*)$/.test(
          name,
        ),
        `${name} must not be set`,
      );
    }
    assert.ok(!process.env[SEND_FLAG]);
    assert.ok(!fs.existsSync(path.join(home, ".config", "gcloud")));
    // The work copy is its own git root, and no ancestor directory holds the private docs.local.
    const top = fs.realpathSync(
      execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: here, encoding: "utf8" }).trim(),
    );
    assert.ok(here.startsWith(top), "git root must contain the work copy");
    assert.ok(!fs.existsSync(path.join(top, "docs.local")));
    for (let dir = here; dir !== path.dirname(dir); dir = path.dirname(dir))
      assert.ok(!fs.existsSync(path.join(dir, "docs.local")), `${dir} contains docs.local`);
    assert.ok(
      !fs.realpathSync(here).includes(`${path.sep}.worktree${path.sep}`),
      "the work copy must be outside the repository",
    );
  },
);
