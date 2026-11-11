import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import net from "node:net";
import {
  accessSync,
  chmodSync,
  constants,
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
import { after, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { LAUNCH_FLAG, LAUNCH_FAMILIES, fetchNet, requireLaunch } from "./storage-rules-s9/deps.mjs";
import { CASE_PLAN } from "./storage-rules-s9/plan-case.mjs";
import {
  adcToken,
  newOutDir,
  productionTarget,
  readbackRun,
  recordProductionRun,
  recoverRun,
} from "./storage-rules-s9/run.mjs";
import { createWire } from "./storage-rules-s9/wire.mjs";

// What this file guards: a test run, a mutation run or a stray import can never send to production
// or read a credential, whatever the machine holds. (2026-11-11: a mutation pass of another lane
// reached real production APIs and wrote to the sandbox ledger through a work copy.) The gate is the
// real process environment, read at the moment a client sends or a credential is read; no test sets
// the flag in this process, and this is the only test file that names it.

const scratch = mkdtempSync(join(tmpdir(), "case-safety-"));
after(() => rmSync(scratch, { recursive: true, force: true }));
let counter = 0;
const fresh = () => join(scratch, `d${(counter += 1)}`);
const HERE = dirname(fileURLToPath(import.meta.url));
const run = join(HERE, "storage-rules-s9", "run.mjs");
const SOURCES = join(HERE, "storage-rules-s9");
const depsUrl = pathToFileURL(join(SOURCES, "deps.mjs")).href;
const quiet = { log() {}, error() {} };

/** Runs a module script in a child with exactly the given environment, so the flag never touches this process. */
function child(script, env = {}) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", script], {
    encoding: "utf8",
    env: { PATH: dirname(process.execPath), ...env },
  });
}

describe("this process", () => {
  it("has no launch flag, so every production client in it is refused", () => {
    assert.equal(process.env[LAUNCH_FLAG], undefined);
    assert.throws(() => requireLaunch(), /production sending needs/);
    assert.throws(() => requireLaunch("case"), /production sending needs/);
    assert.deepEqual(LAUNCH_FAMILIES, ["s9", "case"]);
  });
});

describe("the launch flag, read from the real environment at every call", () => {
  const probe = (family, env) =>
    child(
      `import { requireLaunch } from ${JSON.stringify(depsUrl)};
       try { requireLaunch(${JSON.stringify(family)}); console.log("allowed"); } catch (e) { console.log("refused: " + e.message); }`,
      env,
    ).stdout.trim();

  it("allows exactly the family's own id, and any known id when no family is named", () => {
    assert.equal(probe("case", { [LAUNCH_FLAG]: "case" }), "allowed");
    assert.equal(probe("s9", { [LAUNCH_FLAG]: "s9" }), "allowed");
    assert.equal(probe(undefined, { [LAUNCH_FLAG]: "case" }), "allowed");
    assert.equal(probe(undefined, { [LAUNCH_FLAG]: "s9" }), "allowed");
    for (const value of [undefined, "", "1", "true", "CASE", "case ", "case,s9", "s9"])
      assert.match(
        probe("case", value === undefined ? {} : { [LAUNCH_FLAG]: value }),
        /^refused: production sending needs/,
        String(value),
      );
    for (const value of [undefined, "", "1", "other", "Case"])
      assert.match(
        probe(undefined, value === undefined ? {} : { [LAUNCH_FLAG]: value }),
        /^refused/,
        String(value),
      );
    assert.match(
      probe("nope", { [LAUNCH_FLAG]: "nope" }),
      /^refused/,
      "an unknown family is never allowed",
    );
  });

  it("says what it needs, with the family when one is named", () => {
    assert.throws(
      () => requireLaunch(),
      (e) => e.message === `production sending needs ${LAUNCH_FLAG}`,
    );
    assert.throws(
      () => requireLaunch("case"),
      (e) => e.message === `production sending needs ${LAUNCH_FLAG}=case`,
    );
    assert.throws(
      () => requireLaunch("s9"),
      (e) => e.message === `production sending needs ${LAUNCH_FLAG}=s9`,
    );
  });

  it("is read at each call: unsetting it in a running process refuses the next send", () => {
    const out = child(
      `import { requireLaunch } from ${JSON.stringify(depsUrl)};
       const log = [];
       const attempt = () => { try { requireLaunch("case"); return "ok"; } catch { return "refused"; } };
       log.push(attempt());
       delete process.env.${LAUNCH_FLAG};
       log.push(attempt());
       process.env.${LAUNCH_FLAG} = "case";
       log.push(attempt());
       console.log(log.join());`,
      { [LAUNCH_FLAG]: "case" },
    ).stdout.trim();
    assert.equal(out, "ok,refused,ok");
  });
});

describe("the real clients", () => {
  it("refuses a host outside loopback before any I/O, and lets loopback through", async () => {
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
          /production sending needs/,
        );
      assert.deepEqual(attempts, []);
      for (const url of ["http://127.0.0.1:1/x", "http://localhost:1/x", "http://[::1]:1/x"])
        assert.equal((await fetchNet({ method: "GET", url, headers: {} })).status, 200);
      assert.equal(attempts.length, 3);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("lets the real client send under the flag (in a child, with fetch stubbed: nothing leaves the machine)", () => {
    const script = `
      import { fetchNet } from ${JSON.stringify(depsUrl)};
      const seen = [];
      globalThis.fetch = async (url) => { seen.push(String(url)); return new Response("{}", { status: 200 }); };
      const r = await fetchNet({ method: "GET", url: "https://storage.googleapis.com/x", headers: {} });
      console.log(r.status + " " + seen.length);`;
    assert.equal(child(script, { [LAUNCH_FLAG]: "case" }).stdout.trim(), "200 1");
    const refused = child(script, {});
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /production sending needs/);
  });

  it("refuses the real gcloud before it runs, and lets a fake command runner stand in", () => {
    assert.throws(() => adcToken(), /production sending needs/);
    let ran = 0;
    assert.equal(
      adcToken(() => ((ran += 1), "tok\n")),
      "tok",
    );
    assert.equal(ran, 1);
  });

  it("refuses a production request at the wire whatever transport the deps hold, unless the target is a rehearsal", async () => {
    let sent = 0;
    const deps = {
      net: async () => ((sent += 1), { status: 200, headers: {}, body: Buffer.alloc(0) }),
      adminHeaders: () => ({}),
    };
    const request = {
      method: "GET",
      url: "https://firebasestorage.googleapis.com/v0/b/fireemu-oracle-query.firebasestorage.app/o/storage-rules-case%2Fsr-0123abcd%2Frec1%2Fmk%2Fa",
    };
    const state = {
      runId: "sr-0123abcd",
      root: "storage-rules-case/sr-0123abcd/",
      prefixRoot: "storage-rules-case",
      family: "case",
      ownRulesets: new Set(),
      baseline: "absent",
    };
    const target = {
      name: "production",
      bucket: "fireemu-oracle-query.firebasestorage.app",
      project: "fireemu-oracle-query",
    };
    const budget = { take: () => 1 };
    const out = { journal() {} };
    const real = createWire({ target, state, budget, deps, out });
    await assert.rejects(real.wire("x", request, { read: true }), /production sending needs/);
    assert.equal(sent, 0);
    const rehearsal = createWire({
      target: { ...target, rehearsal: true },
      state,
      budget,
      deps,
      out,
    });
    assert.equal((await rehearsal.wire("x", request, { read: true })).status, 200);
    assert.equal(sent, 1);
  });
});

describe("the target of a run", () => {
  it("is marked as a rehearsal only when the caller says exactly `true`, so a real run passes the wire's launch check", () => {
    const real = {
      name: "production",
      bucket: "fireemu-oracle-query.firebasestorage.app",
      project: "fireemu-oracle-query",
    };
    assert.deepEqual(productionTarget(true), { ...real, rehearsal: true });
    for (const value of [false, undefined, null, 1, "true", {}, 0, ""])
      assert.deepEqual(productionTarget(value), real, String(value));
    assert.ok(!("rehearsal" in productionTarget(false)));
  });
});

describe("the commands that send", () => {
  const spies = () => {
    const touched = [];
    const spy =
      (name) =>
      (...args) => {
        touched.push(name);
        return args;
      };
    return {
      touched,
      exec: spy("exec"),
      makeDeps: spy("makeDeps"),
      observer: spy("observer"),
      locks: spy("locks"),
      guardEgress: spy("egress"),
      net: spy("net"),
      reader: spy("reader"),
    };
  };

  it("refuse without the flag, ignore every collaborator they are handed, and touch nothing", async () => {
    const dir = fresh();
    mkdirSync(dir);
    const out = newOutDir(join(dir, "run"));
    out.save("run-header.json", { runId: "sr-0123abcd", baseline: "absent", plan: "case" });
    out.save("entry.json", { baseline: "absent", entryRulesets: [] });
    const before = readdirSync(dir).toSorted();
    const s = spies();
    const common = {
      exec: s.exec,
      guardEgress: s.guardEgress,
      locks: s.locks,
      makeDeps: s.makeDeps,
      observer: s.observer,
      net: s.net,
      reader: s.reader,
      log: quiet,
    };
    await assert.rejects(
      recordProductionRun({
        ...common,
        plan: CASE_PLAN,
        baseline: "absent",
        outPath: join(dir, "new"),
      }),
      /production sending needs/,
    );
    await assert.rejects(
      readbackRun({ ...common, dir: join(dir, "run") }),
      /production sending needs/,
    );
    await assert.rejects(
      recoverRun({ ...common, dir: join(dir, "run") }),
      /production sending needs/,
    );
    assert.deepEqual(s.touched, []);
    assert.deepEqual(readdirSync(dir).toSorted(), before);
    assert.deepEqual(readdirSync(join(dir, "run")).toSorted(), ["entry.json", "run-header.json"]);
  });

  it("validate the baseline before they ask for the flag, and refuse a flag-less valid one", async () => {
    const dir = fresh();
    mkdirSync(dir);
    await assert.rejects(
      recordProductionRun({ plan: CASE_PLAN, baseline: "present", outPath: join(dir, "a") }),
      /baseline is neither/,
    );
    await assert.rejects(
      recordProductionRun({ plan: CASE_PLAN, baseline: "absent", outPath: join(dir, "a") }),
      /production sending needs/,
    );
    assert.deepEqual(readdirSync(dir), []);
  });

  it("let a rehearsal run only with a fake credential command and a fake transport", async () => {
    const dir = fresh();
    mkdirSync(dir);
    const s = spies();
    await assert.rejects(
      recordProductionRun({
        rehearsal: true,
        plan: CASE_PLAN,
        baseline: "absent",
        outPath: join(dir, "a"),
        makeDeps: s.makeDeps,
      }),
      /a rehearsal needs an injected exec/,
    );
    await assert.rejects(
      recordProductionRun({
        rehearsal: true,
        plan: CASE_PLAN,
        baseline: "absent",
        outPath: join(dir, "a"),
        exec: s.exec,
      }),
      /a rehearsal needs an injected makeDeps/,
    );
    const { execFileSync } = await import("node:child_process");
    await assert.rejects(
      recordProductionRun({
        rehearsal: true,
        plan: CASE_PLAN,
        baseline: "absent",
        outPath: join(dir, "a"),
        exec: execFileSync,
        makeDeps: s.makeDeps,
      }),
      /a rehearsal needs an injected exec/,
    );
    assert.deepEqual(readdirSync(dir), []);
    assert.deepEqual(s.touched, []);
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
  const cli = (args, w, extra = {}) =>
    spawnSync(process.execPath, [run, ...args], {
      cwd: w.cwd,
      encoding: "utf8",
      env: { ...w.env, ...extra },
    });

  it("refuses to record, reads no credential, creates nothing and leaves the working directory empty", () => {
    const w = world();
    const result = cli(
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
      const result = cli([command, "--run-dir", runDir], w);
      assert.notEqual(result.status, 0, command);
      assert.match(result.stderr, /production sending needs/, command);
    }
    assert.equal(existsSync(w.log), false);
    assert.deepEqual(readdirSync(runDir).toSorted(), ["entry.json", "run-header.json"]);
    assert.deepEqual(readdirSync(w.cwd), []);
  });

  it("refuses a flag for another family, and ambient credentials even with the flag", () => {
    const w = world();
    const args = [
      "record-production",
      "--plan",
      "case",
      "--baseline",
      "absent",
      "--out",
      join(w.root, "o1"),
    ];
    assert.match(
      cli(args, w, { [LAUNCH_FLAG]: "s9" }).stderr,
      /production sending needs FIREEMU_STORAGE_RULES_LAUNCH=case/,
    );
    for (const name of ["GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN", "CLOUDSDK_CONFIG"])
      assert.match(
        cli([...args.slice(0, -1), join(w.root, "o2")], w, { [LAUNCH_FLAG]: "case", [name]: "x" })
          .stderr,
        new RegExp(`refusing to start with ${name} set`),
      );
    assert.equal(existsSync(w.log), false);
    assert.equal(existsSync(join(w.root, "o1")) || existsSync(join(w.root, "o2")), false);
  });

  it("does not need the flag to record against a local server, and never reads a credential for it", () => {
    const w = world();
    cli(
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
    assert.equal(existsSync(w.log), false);
  });
});

describe("the sources of the recorder and of its tests", () => {
  const files = readdirSync(SOURCES).filter((f) => f.endsWith(".mjs") && f !== "world.fake.mjs");
  const text = (f) => readFileSync(join(SOURCES, f), "utf8");
  const stripComments = (source) => source.replace(/\/\/.*$/gm, "");

  it("name docs.local only as the two relative lock defaults of the commands that send", () => {
    const hits = files.flatMap((f) =>
      [...text(f).matchAll(/.*docs\.local.*/g)].map((m) => `${f}: ${m[0].trim()}`),
    );
    const allowed =
      /^run\.mjs: (lockDir|legacyLock) = "docs\.local\/runs\/sandbox-(locks|ledger\.jsonl\.lock)",$/;
    for (const hit of hits) assert.match(hit, allowed, hit);
    assert.equal(hits.length, 4);
  });

  it("never read HOME, a home directory or a gcloud configuration, and take their only token from gcloud", () => {
    for (const f of files)
      assert.ok(
        !/process\.env\.HOME|homedir|\.config\/gcloud|application_default_credentials/.test(
          stripComments(text(f)).replace(/FORBIDDEN_ENV[^;]*;/s, ""),
        ),
        f,
      );
    assert.equal(files.filter((f) => /"gcloud"/.test(text(f))).join(), "run.mjs");
  });

  it("read the process environment only for the launch flag and the ambient-credential check", () => {
    const uses = files.flatMap((f) =>
      [...stripComments(text(f)).matchAll(/process\.env\b[^\n]*/g)].map(
        (m) => `${f}: ${m[0].trim()}`,
      ),
    );
    assert.deepEqual(uses.toSorted(), [
      "deps.mjs: process.env[LAUNCH_FLAG];",
      "run.mjs: process.env,",
      "run.mjs: process.env,",
      "run.mjs: process.env.FIREBASE_STORAGE_EMULATOR_HOST;",
    ]);
    assert.ok(uses.some((u) => u.startsWith("deps.mjs")));
  });

  it("open no socket and call no fetch except through fetchNet", () => {
    for (const f of files.filter((f) => f !== "deps.mjs"))
      assert.ok(
        !/\bfetch\(|node:https?|node:net|node:tls|node:dgram/.test(stripComments(text(f))),
        f,
      );
  });

  it("keep the flag out of every test file but this one, and no test arms, disarms or asks for a real client", () => {
    const tests = readdirSync(HERE).filter(
      (f) =>
        /^storage-rules-(s9|case)-.*\.test\.mjs$/.test(f) &&
        f !== "storage-rules-case-safety.test.mjs",
    );
    assert.ok(tests.length >= 17);
    for (const f of tests) {
      const source = readFileSync(join(HERE, f), "utf8");
      assert.ok(
        !source.includes("FIREEMU_STORAGE_RULES_LAUNCH") && !source.includes("LAUNCH_FLAG"),
        `${f} names the launch flag`,
      );
      assert.ok(!/armSending|disarmSending|isArmed/.test(source), `${f} arms the client`);
      assert.ok(!/rehearsal:\s*false/.test(source), `${f} asks for a real run`);
    }
  });
});

describe("under the mutation sandbox", () => {
  // The harness runs every test file under docs.local/tools/mutant-sandbox/run and sets
  // STORAGE_RULES_CASE_MUTATION=1; then the barrier must hold from the inside.
  const mutation = process.env.STORAGE_RULES_CASE_MUTATION === "1";
  const sandboxed = process.env.NEGCACHE_SANDBOX === "1";

  it("is the sandbox when the harness says it is a mutation run", { skip: !mutation }, () => {
    assert.equal(sandboxed, true, "a mutation run must run under mutant-sandbox");
  });

  it(
    "denies a connection outside localhost, a write outside the work copy, and the private files",
    { skip: !sandboxed },
    async () => {
      const outside = await new Promise((resolve) => {
        const socket = net.connect({ host: "192.0.2.1", port: 9, timeout: 1500 });
        socket.on("connect", () => (socket.destroy(), resolve("connected")));
        socket.on("timeout", () => (socket.destroy(), resolve("timeout")));
        socket.on("error", (error) => resolve(error.code ?? "error"));
      });
      assert.notEqual(outside, "connected");
      assert.ok(["EPERM", "EACCES", "error"].includes(outside), outside);
      const docsLocal = process.env.NEGCACHE_REAL_DOCS_LOCAL;
      assert.ok(docsLocal);
      assert.throws(() => readdirSync(docsLocal));
      assert.throws(() => writeFileSync(join(docsLocal, ".sandbox-probe"), "x"));
      assert.throws(() => writeFileSync(join(homedir(), ".sandbox-probe"), "x"));
      const realHome = process.env.NEGCACHE_REAL_HOME;
      assert.throws(() => accessSync(join(realHome, ".config"), constants.R_OK));
      assert.throws(() => readdirSync(join(realHome, ".ssh")));
    },
  );
});
