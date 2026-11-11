import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, afterEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  LAUNCH_FLAG,
  armSending,
  disarmSending,
  fetchNet,
  isArmed,
} from "./storage-rules-s9/deps.mjs";
import {
  adcToken,
  newOutDir,
  readbackRun,
  recordProductionRun,
  recoverRun,
} from "./storage-rules-s9/run.mjs";
import { CASE_PLAN } from "./storage-rules-s9/plan-case.mjs";

// What this file guards: a test run, a mutation run or a stray import can never send to production
// or read a credential, whatever the machine holds. (2026-11-11: a mutation pass of another lane
// reached real production APIs and wrote to the sandbox ledger through a work copy.)

const scratch = mkdtempSync(join(tmpdir(), "case-safety-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
afterEach(() => disarmSending());
let counter = 0;
const fresh = () => join(scratch, `d${(counter += 1)}`);
const run = fileURLToPath(new URL("./storage-rules-s9/run.mjs", import.meta.url));
const SOURCES = fileURLToPath(new URL("./storage-rules-s9/", import.meta.url));

describe("the launch flag", () => {
  it("arms only for exactly the family's id", () => {
    assert.equal(isArmed(), false);
    for (const bad of [undefined, "", "1", "true", "s9", "CASE", "case ", "case,s9"]) {
      assert.throws(() => armSending({ [LAUNCH_FLAG]: bad }, "case"), /production sending needs/);
      assert.equal(isArmed(), false);
    }
    assert.throws(() => armSending(undefined, "case"), /production sending needs/);
    assert.throws(() => armSending({ [LAUNCH_FLAG]: "" }, ""), /production sending needs/);
    assert.throws(
      () => armSending({ [LAUNCH_FLAG]: "case" }, undefined),
      /production sending needs/,
    );
    armSending({ [LAUNCH_FLAG]: "case" }, "case");
    assert.equal(isArmed(), true);
    disarmSending();
    assert.equal(isArmed(), false);
  });

  it("makes the client refuse a host outside loopback before any I/O, and lets loopback through", async () => {
    const attempts = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (input) => {
      attempts.push(String(input?.url ?? input));
      return new Response("{}", { status: 200 });
    };
    try {
      for (const url of [
        "https://storage.googleapis.com/storage/v1/b/x",
        "https://firebaserules.googleapis.com/v1/projects/p/rulesets",
        "https://firebasestorage.googleapis.com/v0/b/x/o",
        "http://example.test/",
        "https://localhost.evil.test/",
      ])
        await assert.rejects(
          fetchNet({ method: "GET", url, headers: {} }),
          /without FIREEMU_STORAGE_RULES_LAUNCH/,
        );
      assert.deepEqual(attempts, []);
      for (const url of ["http://127.0.0.1:1/x", "http://localhost:1/x", "http://[::1]:1/x"])
        assert.equal((await fetchNet({ method: "GET", url, headers: {} })).status, 200);
      assert.equal(attempts.length, 3);
      armSending({ [LAUNCH_FLAG]: "case" }, "case");
      assert.equal(
        (await fetchNet({ method: "GET", url: "https://storage.googleapis.com/x", headers: {} }))
          .status,
        200,
      );
      assert.equal(attempts.length, 4);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("makes the credential read refuse before it runs a command", () => {
    let ran = 0;
    assert.throws(() => adcToken(() => (ran += 1)), /only after the launch flag/);
    assert.equal(ran, 0);
    armSending({ [LAUNCH_FLAG]: "case" }, "case");
    assert.equal(
      adcToken(() => "tok\n"),
      "tok",
    );
  });

  it("makes the three sending commands refuse without it, before they touch anything", async () => {
    const touched = [];
    const spy =
      (name) =>
      (...args) => {
        touched.push(name);
        return args;
      };
    const dir = fresh();
    mkdirSync(dir);
    const out = newOutDir(join(dir, "run"));
    out.save("run-header.json", { runId: "sr-0123abcd", baseline: "absent", plan: "case" });
    out.save("entry.json", { baseline: "absent", entryRulesets: [] });
    const before = readdirSync(dir).toSorted();
    const common = {
      exec: spy("exec"),
      guardEgress: spy("egress"),
      locks: spy("locks"),
      log: { log() {}, error() {} },
    };
    for (const env of [{}, { PATH: "/bin" }, { [LAUNCH_FLAG]: "s9" }, { [LAUNCH_FLAG]: "" }]) {
      await assert.rejects(
        recordProductionRun({
          ...common,
          plan: CASE_PLAN,
          baseline: "absent",
          outPath: join(dir, "new"),
          env,
        }),
        /production sending needs/,
      );
      await assert.rejects(
        readbackRun({ ...common, dir: join(dir, "run"), env, net: spy("net") }),
        /production sending needs/,
      );
      await assert.rejects(
        recoverRun({ ...common, dir: join(dir, "run"), env }),
        /production sending needs/,
      );
    }
    assert.deepEqual(touched, []);
    assert.deepEqual(readdirSync(dir).toSorted(), before);
    assert.deepEqual(readdirSync(join(dir, "run")).toSorted(), ["entry.json", "run-header.json"]);
    assert.equal(isArmed(), false);
  });
});

describe("a process without the launch flag, with credentials around it", () => {
  /** A fake gcloud on PATH that logs each call, a HOME with a gcloud configuration, and a working directory. */
  function world() {
    const root = fresh();
    mkdirSync(root);
    const bin = join(root, "bin");
    const home = join(root, "home");
    const cwd = join(root, "cwd");
    for (const d of [bin, cwd, join(home, ".config", "gcloud")]) mkdirSync(d, { recursive: true });
    const log = join(root, "gcloud.log");
    writeFileSync(join(bin, "gcloud"), `#!/bin/sh\necho "$@" >> '${log}'\necho ya29.fake\n`);
    chmodSync(join(bin, "gcloud"), 0o755);
    writeFileSync(join(home, ".config", "gcloud", "application_default_credentials.json"), "{}");
    const env = { PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin`, HOME: home };
    return { root, cwd, log, env };
  }
  const child = (args, w, extra = {}) =>
    spawnSync(process.execPath, [run, ...args], {
      cwd: w.cwd,
      encoding: "utf8",
      env: { ...w.env, ...extra },
    });

  it("refuses to record, reads no credential, creates nothing and leaves the working directory empty", () => {
    const w = world();
    const result = child(
      ["record-production", "--plan", "case", "--baseline", "absent", "--out", join(w.root, "out")],
      w,
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /production sending needs FIREEMU_STORAGE_RULES_LAUNCH=case/);
    assert.equal(existsSync(w.log), false, "gcloud was never run");
    assert.equal(existsSync(join(w.root, "out")), false);
    assert.deepEqual(readdirSync(w.cwd), []);
  });

  it("refuses the other two commands the same way", () => {
    const w = world();
    const runDir = join(w.root, "run");
    const out = newOutDir(runDir);
    out.save("run-header.json", { runId: "sr-0123abcd", baseline: "absent", plan: "case" });
    out.save("entry.json", { baseline: "absent", entryRulesets: [] });
    for (const command of ["readback", "recover"]) {
      const result = child([command, "--run-dir", runDir], w);
      assert.notEqual(result.status, 0, command);
      assert.match(result.stderr, /production sending needs/, command);
    }
    assert.equal(existsSync(w.log), false);
    assert.deepEqual(readdirSync(runDir).toSorted(), ["entry.json", "run-header.json"]);
    assert.deepEqual(readdirSync(w.cwd), []);
  });

  it("refuses a flag for another family, and ambient credentials even with the flag", () => {
    const w = world();
    const wrong = child(
      ["record-production", "--plan", "case", "--baseline", "absent", "--out", join(w.root, "o1")],
      w,
      { [LAUNCH_FLAG]: "s9" },
    );
    assert.match(wrong.stderr, /production sending needs FIREEMU_STORAGE_RULES_LAUNCH=case/);
    for (const name of ["GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN", "CLOUDSDK_CONFIG"]) {
      const ambient = child(
        [
          "record-production",
          "--plan",
          "case",
          "--baseline",
          "absent",
          "--out",
          join(w.root, "o2"),
        ],
        w,
        { [LAUNCH_FLAG]: "case", [name]: "x" },
      );
      assert.match(ambient.stderr, new RegExp(`refusing to start with ${name} set`));
    }
    assert.equal(existsSync(w.log), false);
    assert.equal(existsSync(join(w.root, "o1")) || existsSync(join(w.root, "o2")), false);
  });

  it("does not need the flag to record against a local server, and never reads a credential for it", () => {
    const w = world();
    const result = child(
      [
        "record-local",
        "--plan",
        "case",
        "--origin",
        "http://127.0.0.1:1",
        "--out",
        join(w.root, "l"),
      ],
      w,
    );
    // Nothing listens on port 1: the run fails on its own, which is all this checks.
    assert.equal(existsSync(w.log), false);
    assert.notEqual(result.stderr, undefined);
  });
});

describe("the recorder's sources", () => {
  const files = readdirSync(SOURCES).filter((f) => f.endsWith(".mjs") && f !== "world.fake.mjs");
  const text = (f) => readFileSync(join(SOURCES, f), "utf8");

  it("name docs.local only as the two relative lock defaults of the commands that send", () => {
    const hits = files.flatMap((f) =>
      [...text(f).matchAll(/.*docs\.local.*/g)].map((m) => `${f}: ${m[0].trim()}`),
    );
    const allowed =
      /^run\.mjs: (lockDir|legacyLock) = "docs\.local\/runs\/sandbox-(locks|ledger\.jsonl\.lock)",$/;
    for (const hit of hits) assert.match(hit, allowed, hit);
    assert.equal(hits.length, 4);
  });

  it("never reads HOME, a home directory or a gcloud configuration, and takes its only token from gcloud", () => {
    for (const f of files) {
      const source = text(f);
      assert.ok(
        !/process\.env\.HOME|homedir|\.config\/gcloud|application_default_credentials|GOOGLE_APPLICATION_CREDENTIALS_JSON/.test(
          source.replace(/FORBIDDEN_ENV[^;]*;/s, ""),
        ),
        f,
      );
    }
    assert.equal(files.filter((f) => /"gcloud"/.test(text(f))).join(), "run.mjs");
  });

  it("opens no socket and calls no fetch except through fetchNet", () => {
    for (const f of files.filter((f) => f !== "deps.mjs")) {
      const source = text(f);
      assert.ok(
        !/\bfetch\(|node:https?|node:net|node:tls|node:dgram/.test(source.replace(/\/\/.*$/gm, "")),
        f,
      );
    }
  });
});
