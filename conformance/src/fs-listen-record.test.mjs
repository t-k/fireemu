import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { tempDir } from "./test-tmpdir.mjs";

import {
  accessToken,
  admit,
  browserProduction,
  checkProject,
  nativeProduction,
  newRunId,
  openJournal,
  localProvenance,
  buildInputsDigest,
  BUILD_INPUTS_SCHEME,
  isBuildInput,
  originPortOf,
  parseArgs,
  readbackProduction,
  recordNative,
  sdkProduction,
  validToken,
} from "./fs-listen/record.mjs";

test("a recording may address only the sandbox that owns its kind", () => {
  checkProject("native", "fireemu-oracle-txn");
  checkProject("sdk", "fireemu-oracle-query");
  for (const [kind, project] of [
    ["native", "fireemu-oracle-query"],
    ["sdk", "fireemu-oracle-txn"],
    ["native", "fireemu-35fe6"],
    ["sdk", "fireemu-35fe6"],
    ["native", "fireemu-oracle-idp"],
    ["native", ""],
    ["other", "fireemu-oracle-txn"],
  ])
    assert.throws(() => checkProject(kind, project), /may address only/, `${kind} ${project}`);
});

test("parseArgs reads a command and --name value pairs, and refuses a stray word", () => {
  assert.deepEqual(parseArgs(["native", "--target", "local", "--out", "f.json"]), {
    command: "native",
    target: "local",
    out: "f.json",
  });
  assert.throws(() => parseArgs(["native", "stray"]), /unexpected argument stray/);
});

test("newRunId is a lower-case document id that differs between moments", () => {
  assert.match(newRunId(1_700_000_000_000), /^n[0-9a-z]+$/);
  assert.notEqual(newRunId(1_700_000_000_000), newRunId(1_700_000_000_001));
});

/** A clock only sleeping moves, so a wait that nothing satisfies runs out at once. */
function fakeClock() {
  const state = { t: 0 };
  return {
    sleep: async (ms) => {
      state.t += ms;
    },
    now: () => state.t,
  };
}

/** A client whose first write fails: the programs end in errors, the cleanup must still run. */
/** The code of the first commit's failure: 3 is a definite refusal, none is an unknown answer. */
function failingClient(code = 3) {
  failingClient.code = code;
  const calls = [];
  // The documents the client holds: a Commit that succeeded leaves them, a delete removes them.
  const held = new Set();
  return {
    calls,
    held,
    async commit({ writes }) {
      calls.push(["commit", writes.length]);
      if (calls.filter(([name]) => name === "commit").length === 1)
        throw Object.assign(new Error("boom"), { code: failingClient.code });
      for (const write of writes) {
        if (write.delete) held.delete(write.delete);
        else held.add(write.update.name);
      }
    },
    async beginTransaction() {
      return Buffer.from("t");
    },
    openStream() {
      return { frames: [], ended: () => ({ reason: "ended" }), send() {}, async close() {} };
    },
    async missing(names) {
      calls.push(["missing", names.length]);
      return names.map((name) => ({ name, exists: held.has(name) }));
    },
    async listIds() {
      calls.push(["list"]);
      return [];
    },
  };
}

test("recordNative reports a failing program and still cleans up and reads back", async () => {
  const client = failingClient();
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.version, 1);
  assert.equal(recording.kind, "native");
  assert.ok(Object.keys(recording.errors).length > 0);
  assert.ok(
    client.calls.some(([name]) => name === "missing"),
    "the read-back ran",
  );
  assert.equal(recording.cleanup.complete, true);
  assert.equal(typeof recording.cleanup.deleted, "number");
});

test("recordNative marks the cleanup incomplete when the read-back itself fails", async () => {
  const client = failingClient();
  client.missing = async () => {
    throw new Error("read-back unavailable");
  };
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.cleanup.complete, false);
  assert.match(recording.cleanup.error, /read-back unavailable/);
});

test("parseArgs: no arguments is an empty command; a flag without a value has none; the last one wins", () => {
  assert.deepEqual(parseArgs([]), { command: undefined });
  assert.deepEqual(parseArgs(["sdk", "--out"]), { command: "sdk", out: undefined });
  assert.deepEqual(parseArgs(["sdk", "--out", "a", "--out", "b"]), { command: "sdk", out: "b" });
  assert.throws(() => parseArgs(["sdk", "--out", "a", "stray", "b"]), /unexpected argument stray/);
  assert.throws(() => parseArgs(["sdk", "-o", "a"]), /unexpected argument -o/);
});

test("checkProject names the one project a kind may address", () => {
  // The allowed lists hold one project each, so the message shows exactly that one.
  assert.throws(
    () => checkProject("native", "x"),
    (error) => !error.message.includes(","),
  );

  assert.throws(
    () => checkProject("native", "x"),
    /native recordings may address only fireemu-oracle-txn$/,
  );
  assert.throws(
    () => checkProject("sdk", "x"),
    /sdk recordings may address only fireemu-oracle-query$/,
  );
});

test("newRunId: the same moment gives the same id, and the default is now", () => {
  assert.equal(newRunId(36), "n10");
  assert.equal(newRunId(0), "n0");
  assert.match(newRunId(), /^n[0-9a-z]{8,}$/);
});

test("recordNative returns a recording with its facts and a clean cleanup: what the programs left is deleted and read back", async () => {
  const client = failingClient();
  const before = Date.now();
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.node, process.version);
  assert.ok(Date.parse(recording.startedAt) >= before - 1000);
  assert.equal(typeof recording.requests, "number");
  assert.ok(recording.requests > 0);
  assert.deepEqual(recording.cleanup.stillPresent, []);
  assert.equal(recording.cleanup.complete, true);
  assert.ok(recording.cleanup.deleted > 0);
  assert.equal(client.held.size, 0);
  assert.ok(recording.cleanup.checked > 0);
  assert.ok(
    client.calls.some(([name]) => name === "list"),
    "the run's prefix is swept",
  );
});

test("recordNative runs the programs on the clock it is given", async () => {
  const reads = [];
  await recordNative({
    client: failingClient(),
    project: "p",
    run: "r1",
    clock: {
      sleep: async () => {},
      now: () => {
        reads.push(1);
        return reads.length * 1000;
      },
    },
  });
  assert.ok(reads.length > 0, "the supplied clock is read");
});

test("recordNative reports a cleanup failure by its message, or by the value when it has none", async () => {
  const withMissing = async (thrown) => {
    const client = failingClient();
    client.missing = async () => {
      throw thrown;
    };
    return recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  };
  assert.deepEqual((await withMissing(new Error("gone"))).cleanup, {
    complete: false,
    error: "gone",
  });
  assert.deepEqual((await withMissing("plain text")).cleanup, {
    complete: false,
    error: "plain text",
  });
});

test("recordNative: a first write whose answer was unknown cannot be settled by finding nothing", async () => {
  const client = failingClient(null);
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.cleanup.complete, false);
  assert.equal(recording.cleanup.unsettled.length, 1);
  assert.match(
    recording.cleanup.unsettled[0],
    /^projects\/p\/databases\/\(default\)\/documents\/lsn_native\/r1-/,
  );
  assert.equal(recording.cleanup.unknownDeletes.length, 0);
  const refused = await recordNative({
    client: failingClient(3),
    project: "p",
    run: "r1",
    clock: fakeClock(),
  });
  assert.equal(refused.cleanup.complete, true, "a definite refusal left nothing behind");
});

test("recordNative can record the long program too, and defaults to the short ones", async () => {
  const { programsFor } = await import("./fs-listen/record.mjs");
  const { LONG_PROGRAMS, NATIVE_PROGRAMS } = await import("./fs-listen/native-programs.mjs");
  assert.deepEqual(programsFor({}), NATIVE_PROGRAMS);
  assert.deepEqual(programsFor({ "include-long": "no" }), NATIVE_PROGRAMS);
  assert.deepEqual(programsFor({ "include-long": "yes" }), [...NATIVE_PROGRAMS, ...LONG_PROGRAMS]);
});

// ---- the production wiring order (S6), the token check (S4), the journal and the read-back ----

test("validToken accepts one token and refuses an empty or whitespace-bearing output without printing it", () => {
  assert.equal(validToken("ya29.abc\n"), "ya29.abc");
  assert.equal(validToken("  ya29.abc  "), "ya29.abc");
  for (const bad of ["", "   \n", undefined, null, "two words", "ya29.a\nya29.b", "a\tb"]) {
    assert.throws(
      () => validToken(bad),
      (error) =>
        /empty or malformed/.test(error.message) && !String(error.message).includes("ya29"),
      JSON.stringify(bad),
    );
  }
});

test("accessToken runs gcloud with fixed arguments and validates what it prints", async () => {
  const calls = [];
  const run = async (command, args) => {
    calls.push([command, args]);
    return { stdout: "ya29.token\n" };
  };
  assert.equal(await accessToken(run), "ya29.token");
  assert.deepEqual(calls, [["gcloud", ["auth", "application-default", "print-access-token"]]]);
  await assert.rejects(
    accessToken(async () => ({ stdout: "\n" })),
    /empty or malformed/,
  );
  await assert.rejects(
    accessToken(async () => ({ stdout: "a b" })),
    /empty or malformed/,
  );
});

/** Dependencies that record the order of the calls; `refuse` makes one step throw. */
function deps(order, { refuse } = {}) {
  const step =
    (name, value) =>
    async (...args) => {
      order.push(name);
      if (refuse === name) throw new Error(`refused at ${name}`);
      return typeof value === "function" ? value(...args) : value;
    };
  const journal = { append() {}, close: () => order.push("journal.close") };
  return {
    checkProject: (...args) => {
      order.push("checkProject");
      if (refuse === "checkProject") throw new Error("refused at checkProject");
      return args;
    },
    admit: step("admit"),
    loadApiKey: step("loadApiKey", "KEYKEYKEYKEYKEYKEYKEYKEYKEY"),
    accessToken: step("accessToken", "TOKEN"),
    newRunId: () => {
      order.push("newRunId");
      return "rid";
    },
    openJournal: (options, kind, run) => {
      order.push(`openJournal:${kind}:${run}`);
      if (refuse === "openJournal") throw new Error("refused at openJournal");
      return journal;
    },
    createClient: () => {
      order.push("createClient");
      return { close: () => order.push("client.close") };
    },
    recordNative: step("recordNative", { rows: {} }),
    recordSdk: step("recordSdk", { rows: {} }),
  };
}
const NATIVE_OPTIONS = {
  project: "fireemu-oracle-txn",
  envelope: "E",
  ledger: "L",
  out: "o.json",
};
const SDK_OPTIONS = {
  project: "fireemu-oracle-query",
  envelope: "E",
  ledger: "L",
  out: "o.json",
  "api-key-file": "K",
};

test("native production: project, admission, token, run id, journal, and only then the client and the recording", async () => {
  const order = [];
  await nativeProduction(NATIVE_OPTIONS, deps(order));
  assert.deepEqual(order, [
    "checkProject",
    "admit",
    "accessToken",
    "newRunId",
    "openJournal:native:rid",
    "createClient",
    "recordNative",
    "client.close",
    "journal.close",
  ]);
});

test("native production: a refusal at any step makes no later call", async () => {
  const steps = ["checkProject", "admit", "accessToken", "openJournal"];
  for (const [index, refuse] of steps.entries()) {
    const order = [];
    await assert.rejects(nativeProduction(NATIVE_OPTIONS, deps(order, { refuse })), /refused at/);
    assert.equal(order.at(-1), refuse === "openJournal" ? "openJournal:native:rid" : refuse);
    assert.ok(!order.includes("createClient"), refuse);
    assert.ok(!order.includes("recordNative"), refuse);
    if (index < 2)
      assert.ok(!order.includes("accessToken"), `${refuse}: no token before admission`);
  }
});

test("sdk production: project, admission, key file, token, run id, journal, then the recording", async () => {
  const order = [];
  await sdkProduction(SDK_OPTIONS, deps(order));
  assert.deepEqual(order, [
    "checkProject",
    "admit",
    "loadApiKey",
    "accessToken",
    "newRunId",
    "openJournal:sdk:rid",
    "recordSdk",
    "journal.close",
  ]);
});

test("sdk production: a refusal at any step makes no later call, and the key file is never read before admission", async () => {
  for (const refuse of ["checkProject", "admit", "loadApiKey", "accessToken", "openJournal"]) {
    const order = [];
    await assert.rejects(sdkProduction(SDK_OPTIONS, deps(order, { refuse })), /refused at/);
    assert.ok(!order.includes("recordSdk"), refuse);
    if (refuse === "checkProject" || refuse === "admit")
      assert.ok(!order.includes("loadApiKey") && !order.includes("accessToken"), refuse);
    if (refuse === "loadApiKey") assert.ok(!order.includes("accessToken"));
    if (refuse !== "openJournal") assert.ok(!order.includes("openJournal:sdk:rid"), refuse);
  }
  // A missing key file option is refused after admission and before any token.
  const order = [];
  const { "api-key-file": _omitted, ...withoutKey } = SDK_OPTIONS;
  await assert.rejects(sdkProduction(withoutKey, deps(order)), /--api-key-file/);
  assert.deepEqual(order, ["checkProject", "admit"]);
});

test("the journal is closed even when the recording throws", async () => {
  const order = [];
  const d = deps(order);
  d.recordNative = async () => {
    throw new Error("boom");
  };
  await assert.rejects(nativeProduction(NATIVE_OPTIONS, d), /boom/);
  assert.deepEqual(order.slice(-2), ["client.close", "journal.close"]);
});

test("a native production client refreshes its token through the same checked command", async () => {
  let options;
  const d = deps([]);
  d.createClient = (o) => {
    options = o;
    return { close() {} };
  };
  await nativeProduction(NATIVE_OPTIONS, d);
  assert.equal(options.refreshToken, d.accessToken);
  assert.equal(options.token, "TOKEN");
  assert.deepEqual(options.target, { kind: "production" });
});

test("recordNative returns the run, the end time, the issued names and the request count, and journals an end line", async () => {
  const lines = [];
  const client = {
    ...failingClient(3),
    requestCount: () => 42,
  };
  const recording = await recordNative({
    client,
    project: "p",
    run: "r9",
    clock: fakeClock(),
    journal: { append: (line) => lines.push(line), close() {} },
  });
  assert.equal(recording.run, "r9");
  assert.equal(recording.productionRequests, 42);
  assert.ok(
    Array.isArray(recording.issued) && recording.issued.every((n) => n.includes("/lsn_native")),
  );
  assert.match(recording.endedAt, /^\d{4}-\d\d-\d\dT/);
  assert.deepEqual(lines.at(-1), { type: "end", productionRequests: 42 });
  const local = await recordNative({
    client: failingClient(3),
    project: "p",
    run: "r9",
    clock: fakeClock(),
  });
  assert.equal(local.productionRequests, null);
});

test("readback: a native journal is read through the client and nothing is deleted", async () => {
  const dir = tempDir("rb-");
  const journal = join(dir, "j.jsonl");
  writeFileSync(
    journal,
    [
      { type: "run", runId: "r1", kind: "native", project: "fireemu-oracle-txn" },
      { type: "names", phase: "before", names: [{ name: "n/a", op: "create" }] },
      { type: "names", phase: "after", outcome: "ok", names: [{ name: "n/a", op: "create" }] },
    ]
      .map((r) => JSON.stringify(r))
      .join("\n"),
  );
  const calls = [];
  const d = {
    accessToken: async () => "T",
    createClient: () => ({
      missing: async (names) => {
        calls.push(["missing", names]);
        return names.map((name) => ({ name, exists: false }));
      },
      commit: async () => calls.push(["commit"]),
      close: () => calls.push(["close"]),
    }),
  };
  const report = await readbackProduction({ journal, project: "fireemu-oracle-txn" }, d);
  assert.equal(report.clean, true);
  assert.deepEqual(calls, [["missing", ["n/a"]], ["close"]]);
  assert.deepEqual(report.unconfirmed, []);
  // The same journal with no answer line (a crash in the Commit) is an unknown create: absence does not settle it.
  const crashed = join(dir, "crashed.jsonl");
  writeFileSync(
    crashed,
    [
      { type: "run", runId: "r1", kind: "native", project: "fireemu-oracle-txn" },
      { type: "names", phase: "before", names: [{ name: "n/a", op: "create" }] },
    ]
      .map((r) => JSON.stringify(r))
      .join("\n"),
  );
  const open = await readbackProduction({ journal: crashed, project: "fireemu-oracle-txn" }, d);
  assert.equal(open.clean, false);
  assert.deepEqual(open.unconfirmed, ["n/a"]);
  // The journal's own project and kind decide: another project is refused before any token.
  let tokenAsked = false;
  await assert.rejects(
    readbackProduction(
      { journal, project: "fireemu-oracle-query" },
      { accessToken: async () => (tokenAsked = true) },
    ),
    /may address only|another project/,
  );
  assert.equal(tokenAsked, false);
  await assert.rejects(readbackProduction({ project: "fireemu-oracle-txn" }, d), /--journal/);
});

test("admit needs the ledger and the envelope, and reads the real lock and ledger files for that envelope", async () => {
  const dir = tempDir("admit-");
  const ledger = join(dir, "sandbox-ledger.jsonl");
  mkdirSync(join(dir, "sandbox-locks"));
  writeFileSync(ledger, "");
  const project = "fireemu-oracle-txn";
  writeFileSync(
    join(dir, "sandbox-locks", `${project}.lock`),
    JSON.stringify({ taskId: "FS-LISTEN-SDK-SANDBOX", envelopeId: "E1" }),
  );
  await assert.rejects(admit({ project, envelope: "E1" }), /--ledger/);
  await assert.rejects(admit({ project, ledger }), /--envelope/);
  await assert.rejects(admit({ project, ledger, envelope: "E2" }), /not held for envelope E2/);
  await admit({ project, ledger, envelope: "E1" });
});

test("a crash during the third Commit leaves a journal that names the run and every name sent, and the read-back finds them", async () => {
  const { createJournal, issuedFromJournal, readbackJournal } =
    await import("./fs-listen/journal.mjs");
  const dir = tempDir("crash-");
  const path = join(dir, "run.journal.jsonl");
  const journal = createJournal(path);
  journal.append({ type: "run", runId: "r1", kind: "native", project: "p" });
  const docs = new Set();
  let snapshot;
  let commits = 0;
  const client = {
    ...failingClient(3),
    async commit({ writes }) {
      commits += 1;
      if (commits === 3) {
        // The process dies here: what is on disk now is all that survives.
        snapshot = readFileSync(path, "utf8");
        throw Object.assign(new Error("killed"), { code: 14 });
      }
      for (const w of writes) {
        if (w.update) docs.add(w.update.name);
      }
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: docs.has(name) }));
    },
  };
  await recordNative({ client, project: "p", run: "r1", clock: fakeClock(), journal });
  const issued = issuedFromJournal(snapshot);
  assert.equal(issued.run.runId, "r1");
  assert.equal(issued.ended, false);
  assert.ok(
    issued.names.length >= 1,
    "the names of the commits sent so far, including the one in flight",
  );
  assert.ok(issued.names.every((name) => name.includes("/lsn_native/r1-")));
  const report = await readbackJournal({
    text: snapshot,
    client: { missing: async (names) => names.map((name) => ({ name, exists: docs.has(name) })) },
    accountClient: { lookup: async () => [] },
  });
  assert.equal(
    report.clean,
    false,
    "a name the run created is still there and the read-back says so",
  );
  assert.ok(report.names.some((entry) => entry.exists));
});

// ---- the arguments the wiring passes, the published messages and the read-back wiring ----

function argDeps(order) {
  const base = deps(order);
  const seen = {};
  return {
    seen,
    d: {
      ...base,
      checkProject: (kind, project) => {
        seen.checked = [kind, project];
        order.push("checkProject");
      },
      loadApiKey: async (path) => {
        seen.keyPath = path;
        return "KEYKEYKEYKEYKEYKEYKEYKEYKEY";
      },
      openJournal: (options, kind, run) => {
        seen.journal = [options.out, kind, run];
        return { append() {}, close() {} };
      },
      programProblems: (programs) => {
        seen.programs = programs.length;
        return seen.problems ?? [];
      },
      recordNative: async (args) => {
        seen.native = args;
        return {};
      },
      recordSdk: async (args) => {
        seen.sdk = args;
        return {};
      },
      recordBrowser: async (args) => {
        seen.browser = args;
        return {};
      },
    },
  };
}

test("native production hands the recorder its client, project, run id, programs and journal; the project is checked as native", async () => {
  const { d, seen } = argDeps([]);
  await nativeProduction({ ...NATIVE_OPTIONS, "include-long": "yes" }, d);
  assert.deepEqual(seen.checked, ["native", "fireemu-oracle-txn"]);
  assert.deepEqual(seen.journal, ["o.json", "native", "rid"]);
  assert.equal(seen.native.project, "fireemu-oracle-txn");
  assert.equal(seen.native.run, "rid");
  assert.ok(seen.native.client);
  assert.ok(seen.native.journal);
  assert.equal(typeof seen.native.log, "function");
  assert.equal(seen.native.programs.length, 6, "the long program is included");
  assert.ok(seen.programs > 0, "the programs were checked");
});

test("malformed programs stop the run before a token is requested, with the problems listed", async () => {
  const order = [];
  const { d, seen } = argDeps(order);
  seen.problems = ["p1 is bad", "p2 is bad"];
  await assert.rejects(nativeProduction(NATIVE_OPTIONS, d), /malformed:\np1 is bad\np2 is bad/);
  assert.ok(!order.includes("accessToken"));
});

test("native production does not return before the recording finishes, and closes after it", async () => {
  const order = [];
  const { d } = argDeps(order);
  d.recordNative = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    order.push("recorded");
    return {};
  };
  await nativeProduction(NATIVE_OPTIONS, d);
  assert.ok(order.indexOf("recorded") < order.indexOf("client.close"));
});

test("sdk production reads the key file named by --api-key-file and hands the recorder the production target", async () => {
  const { d, seen } = argDeps([]);
  await sdkProduction(SDK_OPTIONS, d);
  assert.deepEqual(seen.checked, ["sdk", "fireemu-oracle-query"]);
  assert.equal(seen.keyPath, "K");
  assert.deepEqual(seen.journal, ["o.json", "sdk", "rid"]);
  assert.deepEqual(seen.sdk.target, {
    kind: "production",
    project: "fireemu-oracle-query",
    token: "TOKEN",
    web: {
      apiKey: "KEYKEYKEYKEYKEYKEYKEYKEYKEY",
      authDomain: "fireemu-oracle-query.firebaseapp.com",
      projectId: "fireemu-oracle-query",
    },
  });
  assert.equal(seen.sdk.run, "rid");
  assert.ok(seen.sdk.journal);
  assert.equal(typeof seen.sdk.log, "function");
});

test("sdk production does not close the journal before the recording finishes", async () => {
  const order = [];
  const { d } = argDeps(order);
  d.openJournal = () => ({ append() {}, close: () => order.push("journal.close") });
  d.recordSdk = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    order.push("recorded");
    return {};
  };
  await sdkProduction(SDK_OPTIONS, d);
  assert.deepEqual(order.slice(-2), ["recorded", "journal.close"]);
});

test("admit prints which task holds the lock and for which envelope", async () => {
  const dir = tempDir("admit-msg-");
  const ledger = join(dir, "sandbox-ledger.jsonl");
  mkdirSync(join(dir, "sandbox-locks"));
  writeFileSync(ledger, "");
  writeFileSync(
    join(dir, "sandbox-locks", "fireemu-oracle-txn.lock"),
    JSON.stringify({ taskId: "FS-LISTEN-SDK-SANDBOX", envelopeId: "E1" }),
  );
  const lines = [];
  const original = console.error;
  console.error = (line) => lines.push(line);
  try {
    await admit({ project: "fireemu-oracle-txn", ledger, envelope: "E1" });
  } finally {
    console.error = original;
  }
  assert.deepEqual(lines, ["admitted: lock held by FS-LISTEN-SDK-SANDBOX for E1"]);
});

test("openJournal creates <out>.journal.jsonl, heads it with the run and prints the run id", async () => {
  const dir = tempDir("open-journal-");
  const out = join(dir, "rec.json");
  const lines = [];
  const original = console.error;
  console.error = (line) => lines.push(line);
  let journal;
  try {
    journal = openJournal({ out, project: "fireemu-oracle-txn", envelope: "E1" }, "native", "rid");
  } finally {
    console.error = original;
  }
  journal.close();
  assert.deepEqual(lines, ["run rid"]);
  const header = JSON.parse(readFileSync(`${out}.journal.jsonl`, "utf8").trim());
  assert.equal(header.type, "run");
  assert.equal(header.runId, "rid");
  assert.equal(header.kind, "native");
  assert.equal(header.project, "fireemu-oracle-txn");
  assert.equal(header.envelopeId, "E1");
  assert.ok(Number.isFinite(Date.parse(header.startedAt)));
  assert.equal(statSync(`${out}.journal.jsonl`).mode & 0o777, 0o600);
});

const journalOf = (run, extra = []) => {
  const dir = tempDir("rbj-");
  const path = join(dir, "j.jsonl");
  writeFileSync(path, [run, ...extra].map((r) => JSON.stringify(r)).join("\n"));
  return path;
};

test("readback refuses a journal of another kind's project before asking for a token, and one of another project", async () => {
  let tokenAsked = false;
  const d = { accessToken: async () => (tokenAsked = true), createClient: () => ({ close() {} }) };
  // kind native may address txn only: --project query is refused by the allowlist.
  const nativeJournal = journalOf({
    type: "run",
    runId: "r",
    kind: "native",
    project: "fireemu-oracle-txn",
  });
  await assert.rejects(
    readbackProduction({ journal: nativeJournal, project: "fireemu-oracle-query" }, d),
    /native recordings may address only fireemu-oracle-txn/,
  );
  // The journal says another project than --project although the allowlist is satisfied.
  const odd = journalOf({
    type: "run",
    runId: "r",
    kind: "native",
    project: "fireemu-oracle-query",
  });
  await assert.rejects(
    readbackProduction({ journal: odd, project: "fireemu-oracle-txn" }, d),
    /another project than --project/,
  );
  assert.equal(tokenAsked, false);
});

test("readback waits for the read before it closes the client, asks with the token and builds the right clients", async () => {
  const order = [];
  const seen = {};
  const sdkJournal = journalOf(
    { type: "run", runId: "r", kind: "sdk", project: "fireemu-oracle-query" },
    [
      { type: "names", phase: "before", maybe: true, names: [{ name: "n/a", op: "create" }] },
      { type: "names", phase: "after", outcome: "known", names: [{ name: "n/a", op: "create" }] },
      {
        type: "account",
        phase: "after",
        name: "a",
        email: "a@example.com",
        state: "created",
        uid: "u1",
      },
    ],
  );
  const d = {
    accessToken: async () => "TOK",
    createClient: (options) => {
      seen.client = options;
      return {
        missing: async (names) => {
          await new Promise((resolve) => setTimeout(resolve, 5));
          order.push("missing");
          return names.map((name) => ({ name, exists: false }));
        },
        close: () => order.push("close"),
      };
    },
    createAccountClient: (options) => {
      seen.account = options;
      return {
        lookup: async () => {
          order.push("lookup");
          return [];
        },
      };
    },
  };
  const report = await readbackProduction(
    { journal: sdkJournal, project: "fireemu-oracle-query" },
    d,
  );
  assert.equal(report.clean, true);
  assert.deepEqual(order, ["missing", "lookup", "lookup", "close"]);
  assert.deepEqual(seen.client, {
    project: "fireemu-oracle-query",
    target: { kind: "production" },
    token: "TOK",
  });
  assert.deepEqual(seen.account, {
    base: "https://identitytoolkit.googleapis.com",
    project: "fireemu-oracle-query",
    headers: { authorization: "Bearer TOK", "x-goog-user-project": "fireemu-oracle-query" },
  });
});

test("a native journal lists no accounts: one that does is refused, not looked up", async () => {
  const bad = journalOf(
    { type: "run", runId: "r", kind: "native", project: "fireemu-oracle-txn" },
    [{ type: "account", phase: "before", name: "a", email: "a@example.com" }],
  );
  const d = {
    accessToken: async () => "TOK",
    createClient: () => ({ missing: async () => [], close() {} }),
  };
  await assert.rejects(
    readbackProduction({ journal: bad, project: "fireemu-oracle-txn" }, d),
    /lists no accounts/,
  );
});

/** A fake git that answers by the arguments it is given. */
const fakeGit =
  (answers) =>
  async (...args) => {
    const key = args.join(" ");
    if (!(key in answers)) throw new Error(`unexpected git ${key}`);
    const value = answers[key];
    if (value instanceof Error) throw value;
    return value;
  };
const SOURCES = "crates Cargo.toml Cargo.lock rust-toolchain.toml .cargo";
const NOT_TEST_ONLY = [
  ":(exclude,glob)crates/*/tests/**",
  ":(exclude,glob)crates/*/benches/**",
  ":(exclude,glob)crates/*/examples/**",
  ":(exclude,glob)crates/*/proptest-regressions/**",
].join(" ");
const LS_TREE = [
  "100644 blob aaa111\tCargo.lock",
  "100644 blob bbb222\tCargo.toml",
  "100644 blob ccc333\tcrates/x/src/lib.rs",
  "100644 blob ddd444\tcrates/x/tests/it.rs",
].join("\n");
const GIT = {
  "rev-parse HEAD": "abc123",
  [`ls-tree -r HEAD -- ${SOURCES}`]: LS_TREE,
  [`status --porcelain -- ${SOURCES} ${NOT_TEST_ONLY}`]: "",
  [`log -1 --format=%ct -- ${SOURCES} ${NOT_TEST_ONLY}`]: "1000",
};

test("localProvenance binds a binary to the inputs of its build: the commit, the tree of crates, the lock file, whether they are clean, and whether the binary is newer than their last change", async () => {
  const bytes = { "/b/fireemu": Buffer.from("binary bytes"), "/r/Cargo.lock": Buffer.from("lock") };
  const sha = (buffer) => createHashHex(buffer);
  const read = [];
  const fireemu = await localProvenance({
    target: "local",
    binaryPath: "/b/fireemu",
    lockPath: "/r/Cargo.lock",
    readBytes: async (path) => {
      read.push(path);
      return bytes[path];
    },
    git: fakeGit(GIT),
    mtimeSecondsOf: async () => 1000,
  });
  assert.deepEqual(fireemu, {
    target: "local",
    sourceCommit: "abc123",
    buildInputs: {
      scheme: BUILD_INPUTS_SCHEME,
      inputsSha256: buildInputsDigest(LS_TREE),
      cargoLockSha256: sha(bytes["/r/Cargo.lock"]),
      dirty: false,
    },
    binarySha256: sha(bytes["/b/fireemu"]),
    binaryBuiltAfterSource: true,
  });
  assert.deepEqual(read.toSorted(), ["/b/fireemu", "/r/Cargo.lock"]);
  // A binary older than the last change of the sources cannot be of them; a change not yet
  // committed is reported.
  const stale = await localProvenance({
    target: "local",
    binaryPath: "/b/fireemu",
    lockPath: "/r/Cargo.lock",
    readBytes: async (path) => bytes[path],
    git: fakeGit({
      ...GIT,
      [`status --porcelain -- ${SOURCES} ${NOT_TEST_ONLY}`]: " M crates/x/src/lib.rs",
    }),
    mtimeSecondsOf: async () => 999,
  });
  assert.equal(stale.binaryBuiltAfterSource, false);
  assert.equal(stale.buildInputs.dirty, true);
  // Newer by a second is newer; equal is built after (the commit time has second resolution).
  assert.equal(
    (
      await localProvenance({
        target: "local",
        binaryPath: "/b/fireemu",
        lockPath: "/r/Cargo.lock",
        readBytes: async (path) => bytes[path],
        git: fakeGit(GIT),
        mtimeSecondsOf: async () => 1001,
      })
    ).binaryBuiltAfterSource,
    true,
  );
});

test("localProvenance for the official emulator has no binary, and outside a git tree names no commit", async () => {
  const official = await localProvenance({
    target: "official",
    binaryPath: null,
    lockPath: "/r/Cargo.lock",
    readBytes: async () => {
      throw new Error("no lock here");
    },
    git: fakeGit(GIT),
    mtimeSecondsOf: async () => {
      throw new Error("must not stat");
    },
  });
  assert.equal(official.binarySha256, null);
  assert.equal(official.binaryBuiltAfterSource, null);
  assert.equal(official.buildInputs.cargoLockSha256, null);
  assert.equal(official.sourceCommit, "abc123");
  const outside = await localProvenance({
    target: "local",
    binaryPath: "/b/fireemu",
    lockPath: "/r/Cargo.lock",
    readBytes: async () => Buffer.from("x"),
    git: async () => {
      throw new Error("not a git tree");
    },
    mtimeSecondsOf: async () => 5,
  });
  assert.deepEqual(outside.buildInputs, {
    scheme: BUILD_INPUTS_SCHEME,
    inputsSha256: null,
    cargoLockSha256: createHashHex("x"),
    dirty: null,
  });
  assert.equal(outside.sourceCommit, null);
  assert.equal(outside.binaryBuiltAfterSource, null);
  assert.equal(outside.binarySha256, createHashHex("x"));
});

function createHashHex(text) {
  return createHash("sha256").update(text).digest("hex");
}

test("localProvenance asks the real git of this tree for the same answers the commands give (none outside a git tree)", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const root = new URL("../../", import.meta.url).pathname;
  let head = null;
  try {
    head = (await promisify(execFile)("git", ["rev-parse", "HEAD"], { cwd: root })).stdout.trim();
  } catch {
    // Not a git tree (the mutation harness runs a copy): everything is null.
  }
  const out = await localProvenance({
    target: "local",
    binaryPath: "/b/fireemu",
    readBytes: async () => Buffer.from("x"),
    mtimeSecondsOf: async () => 4_000_000_000,
  });
  assert.equal(out.sourceCommit, head);
  if (head !== null) {
    const listing = (
      await promisify(execFile)(
        "git",
        [
          "ls-tree",
          "-r",
          "HEAD",
          "--",
          "crates",
          "Cargo.toml",
          "Cargo.lock",
          "rust-toolchain.toml",
          ".cargo",
        ],
        { cwd: root },
      )
    ).stdout.trim();
    assert.match(out.buildInputs.inputsSha256, /^[0-9a-f]{64}$/);
    assert.equal(out.buildInputs.inputsSha256, buildInputsDigest(listing));
    assert.equal(out.binaryBuiltAfterSource, true);
    assert.equal(typeof out.buildInputs.dirty, "boolean");
  }
});

test("localProvenance with its own defaults reads the binary, the lock file of this tree and the modification time exactly", async () => {
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const root = new URL("../../", import.meta.url).pathname;
  const dir = tempDir("provenance-defaults-");
  const binary = join(dir, "fireemu");
  writeFileSync(binary, "binary bytes");
  const lock = join(root, "Cargo.lock");
  const defaults = await localProvenance({ target: "local", binaryPath: binary });
  assert.equal(defaults.binarySha256, createHashHex("binary bytes"));
  assert.equal(
    defaults.buildInputs.cargoLockSha256,
    existsSync(lock) ? createHashHex(readFileSync(lock)) : null,
  );
  let changedAt = null;
  try {
    const out = await promisify(execFile)(
      "git",
      ["log", "-1", "--format=%ct", "--", ...SOURCES.split(" "), ...NOT_TEST_ONLY.split(" ")],
      { cwd: root },
    );
    changedAt = Number(out.stdout.trim());
  } catch {
    // Not a git tree (the mutation harness runs a copy): the time is not compared.
  }
  if (Number.isFinite(changedAt) && changedAt > 0) {
    // A binary written 0.5 s after the last change is built after it; 0.5 s before it is not.
    utimesSync(binary, changedAt + 0.5, changedAt + 0.5);
    assert.equal(
      (await localProvenance({ target: "local", binaryPath: binary })).binaryBuiltAfterSource,
      true,
    );
    utimesSync(binary, changedAt - 0.5, changedAt - 0.5);
    assert.equal(
      (await localProvenance({ target: "local", binaryPath: binary })).binaryBuiltAfterSource,
      false,
    );
  }
});

test("isBuildInput: only the test-only trees directly under a crate are left out", () => {
  for (const path of [
    "crates/x/src/lib.rs",
    "crates/x/Cargo.toml",
    "crates/x/build.rs",
    "crates/x/src/tests/mod.rs",
    "crates/x/src/tests.rs",
    "crates/x/tests.rs",
    "crates/x/tests",
    "crates/tests/src/lib.rs",
    "crates/x/y/tests/it.rs",
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    ".cargo/config.toml",
    "docs/crates/x/tests/it.rs",
  ])
    assert.equal(isBuildInput(path), true, path);
  for (const path of [
    "crates/x/tests/it.rs",
    "crates/x/tests/fixtures/a.json",
    "crates/x/benches/b.rs",
    "crates/x/examples/e.rs",
    "crates/x/proptest-regressions/p.txt",
    "crates/fireemu-adapter-grpc/tests/streams.proptest-regressions",
  ])
    assert.equal(isBuildInput(path), false, path);
});

test("buildInputsDigest: a test-only change does not move it, any other change, a rename or a manifest does, order does not", () => {
  const entry = (blob, path) => `100644 blob ${blob}\t${path}`;
  const base = [
    entry("a1", "Cargo.lock"),
    entry("b2", "Cargo.toml"),
    entry("c3", "crates/x/src/lib.rs"),
    entry("d4", "crates/x/Cargo.toml"),
    entry("e5", "crates/x/tests/it.rs"),
  ];
  const digest = (lines) => buildInputsDigest(lines.join("\n"));
  const reference = digest(base);
  assert.match(reference, /^[0-9a-f]{64}$/);
  // Test-only: changed, added, removed.
  assert.equal(
    digest(base.map((l) => (l.includes("tests/") ? entry("zz", "crates/x/tests/it.rs") : l))),
    reference,
  );
  assert.equal(
    digest([...base, entry("f6", "crates/x/benches/b.rs"), entry("g7", "crates/y/examples/e.rs")]),
    reference,
  );
  assert.equal(digest(base.filter((l) => !l.includes("tests/"))), reference);
  // Order does not matter.
  assert.equal(digest(base.toReversed()), reference);
  // A source, a manifest, the lock, a rename or a removed or added input does.
  for (const changed of [
    base.map((l) => (l.includes("lib.rs") ? entry("zz", "crates/x/src/lib.rs") : l)),
    base.map((l) => (l.includes("crates/x/Cargo.toml") ? entry("zz", "crates/x/Cargo.toml") : l)),
    base.map((l) => (l.includes("Cargo.lock") ? entry("zz", "Cargo.lock") : l)),
    base.map((l) => (l.includes("lib.rs") ? entry("c3", "crates/x/src/main.rs") : l)),
    base.filter((l) => !l.includes("lib.rs")),
    [...base, entry("h8", "crates/x/src/new.rs")],
    [...base, entry("h8", "crates/x/src/tests/mod.rs")],
  ])
    assert.notEqual(digest(changed), reference);
  // Nothing listed: no digest.
  assert.equal(buildInputsDigest(null), null);
  assert.equal(buildInputsDigest(""), null);
  assert.equal(digest([entry("e5", "crates/x/tests/it.rs")]), null);
});

test("buildInputsDigest is invariant under any order and any test-only noise, over random listings", () => {
  let seed = 12345;
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % n;
  };
  const paths = [
    "Cargo.lock",
    "crates/a/src/lib.rs",
    "crates/b/src/main.rs",
    "crates/b/Cargo.toml",
    ".cargo/config.toml",
  ];
  const noise = [
    "crates/a/tests/t.rs",
    "crates/b/benches/x.rs",
    "crates/a/examples/e.rs",
    "crates/b/proptest-regressions/r",
  ];
  for (let round = 0; round < 200; round += 1) {
    const inputs = paths
      .filter(() => next(3) !== 0)
      .map((path) => `100644 blob ${next(1000)}\t${path}`);
    if (inputs.length === 0) continue;
    const extra = noise
      .filter(() => next(2) === 0)
      .map((path) => `100644 blob ${next(1000)}\t${path}`);
    const shuffled = [...inputs, ...extra].toSorted(() => next(3) - 1);
    assert.equal(buildInputsDigest(shuffled.join("\n")), buildInputsDigest(inputs.join("\n")));
    const touched = inputs.map((line, index) =>
      index === 0 ? line.replace(/blob \d+/, "blob changed") : line,
    );
    assert.notEqual(buildInputsDigest(touched.join("\n")), buildInputsDigest(inputs.join("\n")));
  }
});

test("--programs resume-variants selects the L1b programs alone, holds them to their request ceiling, and refuses another name or a mix with the long program", async () => {
  const { programsFor, requestCeilingFor } = await import("./fs-listen/record.mjs");
  const { RESUME_VARIANT_PROGRAMS, RESUME_VARIANT_REQUEST_CEILING } =
    await import("./fs-listen/native-resume-variants.mjs");
  assert.deepEqual(programsFor({ programs: "resume-variants" }), RESUME_VARIANT_PROGRAMS);
  assert.deepEqual(
    programsFor({ programs: "resume-variants", "include-long": "no" }),
    RESUME_VARIANT_PROGRAMS,
  );
  assert.throws(
    () => programsFor({ programs: "resume-variants", "include-long": "yes" }),
    /cannot be combined/,
  );
  for (const bad of ["", "all", "Resume-Variants", "resume-variants "])
    assert.throws(() => programsFor({ programs: bad }), /--programs/, JSON.stringify(bad));
  assert.equal(requestCeilingFor({ programs: "resume-variants" }), RESUME_VARIANT_REQUEST_CEILING);
  assert.equal(requestCeilingFor({}), undefined);
  assert.equal(requestCeilingFor({ "include-long": "yes" }), undefined);
});

test("a production recording of the resume variants checks every program, records only them, and runs under their ceiling", async () => {
  const { nativeProduction: production } = await import("./fs-listen/record.mjs");
  const { RESUME_VARIANT_PROGRAMS, RESUME_VARIANT_REQUEST_CEILING } =
    await import("./fs-listen/native-resume-variants.mjs");
  const order = [];
  const { d, seen } = argDeps(order);
  const checked = [];
  d.programProblems = (programs) => {
    checked.push(...programs.map((p) => p.id));
    return [];
  };
  await production(
    {
      project: "fireemu-oracle-txn",
      envelope: "E",
      ledger: "L",
      out: "o.json",
      programs: "resume-variants",
    },
    d,
  );
  assert.deepEqual(seen.native.programs, RESUME_VARIANT_PROGRAMS);
  assert.equal(seen.native.clock.maxRequests, RESUME_VARIANT_REQUEST_CEILING);
  for (const program of RESUME_VARIANT_PROGRAMS)
    assert.ok(checked.includes(program.id), program.id);
  // A malformed variant program stops the run before a token is read.
  const stopped = [];
  const refusing = argDeps(stopped);
  refusing.d.programProblems = () => ["native/resume-grid-g0#3 (save): unknown save kind x"];
  await assert.rejects(
    production(
      {
        project: "fireemu-oracle-txn",
        envelope: "E",
        ledger: "L",
        out: "o.json",
        programs: "resume-variants",
      },
      refusing.d,
    ),
    /malformed/,
  );
  assert.ok(!stopped.includes("accessToken"));
});

test("without --programs the production recording keeps the default request ceiling of the runner", async () => {
  const { nativeProduction: production } = await import("./fs-listen/record.mjs");
  const order = [];
  const { d, seen } = argDeps(order);
  await production({ project: "fireemu-oracle-txn", envelope: "E", ledger: "L", out: "o.json" }, d);
  assert.equal(Object.hasOwn(seen.native, "clock"), false);
});

test("a recording carries the provenance of every token its programs saved, and the rows of resumed streams say where theirs came from", async () => {
  const frames = [
    { kind: "targetChange", targetChange: { targetChangeType: "ADD", targetIds: [1] } },
    {
      kind: "targetChange",
      targetChange: { targetChangeType: "CURRENT", targetIds: [1], resumeToken: Buffer.from("TC") },
    },
  ];
  const client = {
    async commit() {},
    async beginTransaction() {
      return Buffer.from("t");
    },
    openStream() {
      const sent = [];
      return {
        frames: [],
        ended: () => undefined,
        send(request) {
          sent.push(request);
          this.frames.push(...frames);
        },
        async close() {},
      };
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: false }));
    },
    async listIds() {
      return [];
    },
  };
  const program = {
    id: "native/p",
    conditions: ["x"],
    docs: { a: "lsn_native/{run}-p-a" },
    steps: [
      { do: "open", stream: "s", targets: [{ id: 1, doc: "a" }] },
      { do: "save", stream: "s", id: 1, token: "T", kind: "current" },
      { do: "open", stream: "r", targets: [{ id: 1, doc: "a", resume: "T" }] },
      { do: "record", row: "native/p/r", stream: "r" },
    ],
  };
  const recording = await recordNative({
    client,
    project: "p",
    run: "r1",
    clock: fakeClock(),
    programs: [program],
  });
  assert.equal(recording.saves.length, 1);
  assert.equal(recording.saves[0].kind, "current");
  assert.equal(recording.saves[0].token.frameIndex, 1);
  assert.equal(recording.rows["native/p/r"].resumedFrom[0].type, "CURRENT");
  // A run with no save step still carries the (empty) list.
  const none = await recordNative({
    client: failingClient(3),
    project: "p",
    run: "r1",
    clock: fakeClock(),
  });
  assert.ok(Array.isArray(none.saves));
});

const BROWSER_OPTIONS = {
  project: "fireemu-oracle-query",
  envelope: "E",
  ledger: "L",
  out: "o.json",
  "api-key-file": "K",
  "origin-port": "47853",
};

test("a browser recording may address only the query sandbox", () => {
  checkProject("browser", "fireemu-oracle-query");
  for (const project of ["fireemu-oracle-txn", "fireemu-35fe6", "fireemu-oracle-idp", ""])
    assert.throws(() => checkProject("browser", project), /may address only/, project);
});

test("originPortOf: the key is restricted to http://localhost:<port>, so the port is required, whole and unprivileged", () => {
  assert.equal(originPortOf({ "origin-port": "47853" }), 47853);
  assert.equal(originPortOf({ "origin-port": "1024" }), 1024);
  assert.equal(originPortOf({ "origin-port": "65535" }), 65535);
  for (const bad of [undefined, "", "0", "80", "1023", "65536", "4.5", "abc", "-5", "47853x"])
    assert.throws(() => originPortOf({ "origin-port": bad }), /--origin-port/, String(bad));
});

test("browser production: project, admission, key file, port, token, run id, journal, then the recording", async () => {
  const order = [];
  const d = deps(order);
  let seen;
  d.recordBrowser = async (args) => {
    order.push("recordBrowser");
    seen = args;
    return {};
  };
  await browserProduction(BROWSER_OPTIONS, d);
  assert.deepEqual(order, [
    "checkProject",
    "admit",
    "loadApiKey",
    "accessToken",
    "newRunId",
    "openJournal:browser:rid",
    "recordBrowser",
    "journal.close",
  ]);
  assert.deepEqual(seen.target, {
    kind: "production",
    project: "fireemu-oracle-query",
    token: "TOKEN",
    originPort: 47853,
    web: {
      apiKey: "KEYKEYKEYKEYKEYKEYKEYKEYKEY",
      authDomain: "fireemu-oracle-query.firebaseapp.com",
      projectId: "fireemu-oracle-query",
    },
  });
  assert.equal(seen.run, "rid");
  assert.ok(seen.journal);
  assert.equal(typeof seen.log, "function");
});

test("browser production: a refusal at any step makes no later call; a missing key file or port is refused after admission and before any token", async () => {
  for (const refuse of ["checkProject", "admit", "loadApiKey", "accessToken", "openJournal"]) {
    const order = [];
    const d = deps(order, { refuse });
    d.recordBrowser = async () => order.push("recordBrowser");
    await assert.rejects(browserProduction(BROWSER_OPTIONS, d), /refused at/);
    assert.ok(!order.includes("recordBrowser"), refuse);
    if (refuse === "checkProject" || refuse === "admit")
      assert.ok(!order.includes("loadApiKey") && !order.includes("accessToken"), refuse);
  }
  for (const [options, pattern] of [
    [{ ...BROWSER_OPTIONS, "api-key-file": undefined }, /--api-key-file/],
    [{ ...BROWSER_OPTIONS, "origin-port": undefined }, /--origin-port/],
  ]) {
    const order = [];
    await assert.rejects(browserProduction(options, deps(order)), pattern);
    assert.ok(!order.includes("accessToken") && !order.includes("loadApiKey"));
  }
});

test("browser production closes the journal after the recording, and when it throws", async () => {
  const order = [];
  const d = deps(order);
  d.recordBrowser = async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    order.push("recorded");
    throw new Error("boom");
  };
  await assert.rejects(browserProduction(BROWSER_OPTIONS, d), /boom/);
  assert.deepEqual(order.slice(-2), ["recorded", "journal.close"]);
});

test("readback of a browser journal looks accounts up like an SDK journal", async () => {
  const path = journalOf(
    { type: "run", runId: "r", kind: "browser", project: "fireemu-oracle-query" },
    [
      { type: "names", phase: "before", maybe: true, names: [{ name: "n/a", op: "create" }] },
      { type: "names", phase: "after", outcome: "known", names: [{ name: "n/a", op: "create" }] },
      {
        type: "account",
        phase: "after",
        name: "a",
        email: "a@example.com",
        state: "created",
        uid: "u1",
      },
    ],
  );
  const looked = [];
  const report = await readbackProduction(
    { journal: path, project: "fireemu-oracle-query" },
    {
      accessToken: async () => "TOK",
      createClient: () => ({
        missing: async (names) => names.map((name) => ({ name, exists: false })),
        close() {},
      }),
      createAccountClient: (options) => {
        looked.push(options.project);
        return { lookup: async () => [] };
      },
    },
  );
  assert.equal(report.clean, true);
  assert.deepEqual(looked, ["fireemu-oracle-query"]);
});

test("browser production checks the project as a browser recording and reads the key file it was given", async () => {
  const { d, seen } = argDeps([]);
  await browserProduction(BROWSER_OPTIONS, d);
  assert.deepEqual(seen.checked, ["browser", "fireemu-oracle-query"]);
  assert.equal(seen.keyPath, "K");
  assert.deepEqual(seen.journal, ["o.json", "browser", "rid"]);
});
