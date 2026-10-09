import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { test } from "node:test";
import { PassThrough } from "node:stream";
import { localConfig, runLocalRetry, scenarioComplete, versionKey } from "./web_sdk_retry.mjs";

function fixture(scenario, salt = 0) {
  const path = `s5b_unit/doc${salt}`,
    other = `${path}_other`,
    name = `case${salt}`;
  const document = `projects/demo-web-retry/databases/(default)/documents/${path}`;
  const attempts = scenario === "conflict" ? 2 : 1;
  const events = [];
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const version = `2026-10-07T00:00:0${attempt}.${String(salt).padStart(9, "0")}Z`;
    const n = (attempt - 1) * 2 + 1;
    events.push(
      { event: "wire", n },
      {
        event: "transaction-wire",
        n,
        method: "BatchGetDocuments",
        complete: true,
        request: { documents: [document] },
        response: { documents: [{ name: document, updateTime: version }] },
      },
      {
        event: "transaction-read",
        name,
        attempt,
        docs: [{ path, data: { value: attempt === 1 ? 1 : 2 } }],
      },
      { event: "wire", n: n + 1 },
      {
        event: "transaction-wire",
        n: n + 1,
        method: "Commit",
        complete: true,
        request: {
          writes: [{ update: { name: document }, currentDocument: { updateTime: version } }],
        },
        response:
          scenario === "conflict" && attempt === 1
            ? { error: { code: 9 } }
            : {
                commitTime: "2026-10-07T00:00:03Z",
                writeResults: [{ updateTime: "2026-10-07T00:00:03Z" }],
              },
      },
    );
  }
  return {
    scenario,
    name,
    path,
    other,
    document,
    events,
    answer: { ok: true, attempts },
    seed: {
      status: 200,
      path,
      updateTime: `2026-10-07T00:00:01.${String(salt).padStart(9, "0")}Z`,
    },
    final: { status: 200, value: 3, updateTime: "2026-10-07T00:00:03Z" },
    witness: {
      status: 200,
      path: scenario === "conflict" ? path : other,
      value: 2,
      updateTime: `2026-10-07T00:00:02.${String(salt).padStart(9, "0")}Z`,
    },
    cleanup: Array.from({ length: scenario === "control" ? 2 : 1 }, (_, i) => ({
      path: i ? other : path,
      readStatus: 200,
      updateTime: "version",
      deleteStatus: 200,
      absenceStatus: 404,
      deleted: true,
      absent: true,
    })),
  };
}

test("S5b pure admission rejects remote and non-demo targets before transport", async () => {
  const local = {
    projectId: "demo-web-retry",
    firestoreHost: "127.0.0.1:12345",
    authHost: "127.0.0.1:12346",
  };
  assert.equal(localConfig(local).web.apiKey, "fake-local-key");
  for (const host of [
    "example.com:443",
    "127.0.0.1:65536",
    "127.0.0.1:0",
    "127.0.0.1:1?key=secret",
    "user@127.0.0.1:1234",
    "localhost:1234",
  ]) {
    assert.throws(() => localConfig({ ...local, firestoreHost: host }));
    assert.throws(() => localConfig({ ...local, authHost: host }));
  }
  for (const projectId of ["production", "demo-other", "demo-web-retry/other"])
    await assert.rejects(runLocalRetry({ ...local, projectId }), /demo-web-retry/);
});

test("S5b pure generated lineage and response permutations match the reference schedule", () => {
  for (let salt = 0; salt < 64; salt += 1) {
    for (const scenario of ["control", "conflict"]) {
      const value = fixture(scenario, salt);
      assert.equal(scenarioComplete(value), true);
      for (const event of value.events.filter((e) => e.method === "Commit")) {
        event.request.writes[0].currentDocument.updateTime =
          event.request.writes[0].currentDocument.updateTime
            .replace(/0+Z$/, "Z")
            .replace(".Z", "Z");
      }
      assert.equal(
        scenarioComplete(value),
        true,
        "SDK fractional zero-padding preserves the version",
      );
      // Preserve callback order while reversing response completion order.
      const completed = value.events.filter((e) => e.event === "transaction-wire").reverse();
      value.events = [...value.events.filter((e) => e.event !== "transaction-wire"), ...completed];
      assert.equal(scenarioComplete(value), true);
      const commit = value.events.find((e) => e.method === "Commit");
      commit.request.writes[0].currentDocument.updateTime = "another-attempt";
      assert.equal(scenarioComplete(value), false);
    }
  }
});

test("S5b pure incomplete, fabricated and unrelated witnesses fail closed", () => {
  for (const mutate of [
    (v) => {
      v.events = v.events.filter((e) => e.method !== "BatchGetDocuments");
    },
    (v) => {
      v.events.find((e) => e.method === "Commit").complete = false;
    },
    (v) => {
      v.events.find((e) => e.method === "BatchGetDocuments").complete = false;
    },
    (v) => {
      v.events.find((e) => e.method === "Commit").response = { commitTime: "fabricated" };
    },
    (v) => {
      v.events.find((e) => e.method === "Commit").request.writes[0].currentDocument = null;
    },
    (v) => {
      v.events.find((e) => e.method === "Commit").n = 1;
    },
    (v) => {
      v.answer.attempts = 1;
    },
    (v) => {
      v.events.find((e) => e.event === "transaction-read").attempt = 2;
    },
    (v) => {
      v.witness.path = v.other;
    },
    (v) => {
      v.final.value = 2;
    },
    (v) => {
      v.cleanup[0].absent = false;
    },
    (v) => {
      v.events.push({ event: "wire-refused" });
    },
    (v) => {
      v.final.status = 404;
    },
    (v) => {
      v.cleanup[0].path = "foreign/doc";
    },
    (v) => {
      v.cleanup[0].deleteStatus = 503;
    },
    (v) => {
      v.cleanup[0].updateTime = null;
    },
    (v) => {
      v.events.find((e) => e.method === "Commit").request.transactionPresent = true;
    },
  ]) {
    const value = fixture("conflict");
    mutate(value);
    assert.equal(scenarioComplete(value), false);
  }
  const control = fixture("control");
  control.answer.attempts = 2;
  assert.equal(scenarioComplete(control), false);
});

test("S5b actual Node and browser", { skip: !process.env.FIRESTORE_EMULATOR_HOST }, async (t) => {
  await mkdir("target/codex-out", { recursive: true });
  const receipt = await runLocalRetry(
    {
      projectId: process.env.GOOGLE_CLOUD_PROJECT,
      firestoreHost: process.env.FIRESTORE_EMULATOR_HOST,
      authHost: process.env.FIREBASE_AUTH_EMULATOR_HOST,
    },
    {
      artifact: process.env.S5B_FIREEMU,
      artifactSource: process.env.S5B_ARTIFACT_SOURCE,
      receiptPath: "target/codex-out/s5b-receipt.json",
    },
  );
  for (const report of receipt.transports)
    await t.test(report.transport, () => {
      assert.equal(report.closed, true, "driver did not exit cleanly");
      assert.equal(report.scenarios.length, 2);
      for (const scenario of report.scenarios)
        assert.equal(
          scenario.complete,
          true,
          `${report.transport}/${scenario.scenario}: incomplete actual wire/lineage/final-state/cleanup`,
        );
    });
  assert.equal(receipt.complete, true);
});

test("S5b pure version equivalence preserves nanoseconds and rejects malformed input", () => {
  for (let nanos = 0; nanos < 100; nanos += 1) {
    const iso = `2026-10-07T00:00:00.${String(nanos).padStart(9, "0")}Z`;
    assert.equal(versionKey(iso), versionKey({ seconds: "1791331200", nanos }));
    assert.notEqual(versionKey(iso), versionKey({ seconds: "1791331200", nanos: nanos + 1 }));
  }
  for (const value of [
    "2026-02-31T00:00:00Z",
    "2026-10-07T00:00:00.1234567890Z",
    "secret",
    {},
    { seconds: "secret", nanos: 0 },
    { seconds: "1", nanos: -1 },
    { seconds: "1", nanos: 1000000000 },
  ])
    assert.equal(versionKey(value), null);
});

for (const [label, corrupt] of [
  [
    "stale retry version",
    (scenario) => {
      const wire = scenario.events
        .filter((e) => e.event === "transaction-wire")
        .toSorted((a, b) => a.n - b.n);
      if (scenario.scenario !== "conflict") return;
      wire[2].response.documents[0].updateTime = wire[0].response.documents[0].updateTime;
      wire[3].request.writes[0].currentDocument.updateTime =
        wire[1].request.writes[0].currentDocument.updateTime;
    },
  ],
  [
    "disconnected seed version",
    (scenario) => {
      scenario.seed.updateTime = "1970-01-01T00:00:00Z";
    },
  ],
  [
    "missing seed version",
    (scenario) => {
      delete scenario.seed.updateTime;
    },
  ],
  [
    "missing witness version",
    (scenario) => {
      delete scenario.witness.updateTime;
    },
  ],
  [
    "disconnected final version",
    (scenario) => {
      scenario.final.updateTime = "1970-01-01T00:00:00Z";
    },
  ],
  [
    "non-advancing witness version",
    (scenario) => {
      if (scenario.scenario !== "conflict") return;
      scenario.witness.updateTime = scenario.seed.updateTime;
      const wire = scenario.events
        .filter((e) => e.event === "transaction-wire")
        .toSorted((a, b) => a.n - b.n);
      wire[2].response.documents[0].updateTime = wire[0].response.documents[0].updateTime;
      wire[3].request.writes[0].currentDocument.updateTime =
        wire[1].request.writes[0].currentDocument.updateTime;
    },
  ],

  [
    "non-advancing final version",
    (scenario) => {
      const wire = scenario.events
        .filter((e) => e.event === "transaction-wire")
        .toSorted((a, b) => a.n - b.n);
      const previous = wire.at(-2).response.documents[0].updateTime;
      wire.at(-1).response.writeResults[0].updateTime = previous;
      scenario.final.updateTime = previous;
    },
  ],
]) {
  test(`S5b pure reviewed lineage rejects ${label}`, async () => {
    const scenarios = process.env.S5B_REVIEW_RECEIPT
      ? JSON.parse(await readFile(process.env.S5B_REVIEW_RECEIPT, "utf8")).transports.flatMap(
          (r) => r.scenarios,
        )
      : [fixture("control"), fixture("conflict")];
    for (const original of scenarios) {
      assert.equal(scenarioComplete(original), true, "successful original evidence remains valid");
      if (
        ["stale retry version", "non-advancing witness version"].includes(label) &&
        original.scenario !== "conflict"
      )
        continue;
      const changed = structuredClone(original);
      corrupt(changed);
      assert.equal(scenarioComplete(changed), false, label);
    }
  });
}

for (const failedPhase of ["read", "delete", "absence"]) {
  test(`S5b pure cleanup continues after first owned resource ${failedPhase} failure`, async () => {
    const source = await readFile(new URL("./web_sdk_retry.mjs", import.meta.url), "utf8");
    const body = source.slice(
      source.indexOf("export async function runLocalRetry"),
      source.indexOf("export async function recordWebRetries"),
    );
    const calls = [],
      saved = [];
    const reads = new Map();
    const fakeFetch = async (url, init = {}) => {
      const path = new URL(url).pathname.split("/documents/")[1];
      const method = init.method ?? "GET";
      calls.push({ path, method, query: new URL(url).search });
      const count = (reads.get(path) ?? 0) + (method === "GET" ? 1 : 0);
      if (method === "GET") reads.set(path, count);
      const first = path.endsWith("_control");
      if (
        first &&
        ((failedPhase === "read" && method === "GET" && count === 2) ||
          (failedPhase === "delete" && method === "DELETE") ||
          (failedPhase === "absence" && method === "GET" && count === 3))
      )
        throw new Error("injected cleanup timeout");
      const absent = method === "GET" && (path.endsWith("_other") ? count === 2 : count >= 3);
      return {
        status: absent ? 404 : 200,
        json: async () => ({
          updateTime: "2026-10-07T00:00:01Z",
          fields: { value: { integerValue: "3" } },
        }),
      };
    };
    const fakeSdk = () => {
      let resolve;
      const events = [];
      return {
        events,
        ready: async () => {},
        waitFor: async (match) => events.find(match) ?? { event: "exit", code: 0 },
        close: async () => ({ code: 0 }),
        async send(op, command = {}) {
          if (op === "transaction") {
            events.push({ event: "transaction-read", name: command.name, attempt: 1 });
            return new Promise((r) => {
              resolve = r;
            });
          }
          if (op === "continueTransaction") resolve({ ok: true, attempts: 1 });
          return { ok: true };
        },
      };
    };
    const run = new Function(
      "localConfig",
      "SOURCE_PATHS",
      "sha",
      "readFile",
      "ROOT",
      "spawnSdk",
      "randomUUID",
      "DRIVERS",
      "fetch",
      "writeFile",
      "scenarioComplete",
      `return (${body.replace("export ", "")})`,
    )(
      localConfig,
      [],
      () => "hash",
      async () => new Uint8Array(),
      import.meta.url,
      fakeSdk,
      () => "unit",
      { "node-sdk": "node", browser: "browser" },
      fakeFetch,
      async (_, text) => saved.push(JSON.parse(text)),
      scenarioComplete,
    );
    const receipt = await run(
      {
        projectId: "demo-web-retry",
        firestoreHost: "127.0.0.1:12345",
        authHost: "127.0.0.1:12346",
      },
      { artifact: "fixture", artifactSource: "0".repeat(40), receiptPath: "fixture-receipt" },
    );
    assert.equal(receipt.complete, false);
    for (const report of receipt.transports) {
      const control = report.scenarios[0];
      assert.equal(control.cleanup.length, 2, "both known resources have durable cleanup records");
      assert.equal(control.cleanup[0].failure, "cleanup-request-failed");
      assert.equal(control.cleanup[0].phase, failedPhase);
      assert.equal(control.cleanup[1].deleted, true, "accessible second owned resource is deleted");
      assert.equal(control.cleanup[1].absent, true);
      assert.ok(
        calls.some(
          (c) =>
            c.path === control.other &&
            c.method === "DELETE" &&
            c.query === "?currentDocument.updateTime=2026-10-07T00%3A00%3A01Z",
        ),
      );
      assert.equal(report.closed, true);
    }
    assert.deepEqual(saved[0], receipt, "cleanup failures are durable in the written receipt");
  });
}

test("production Web entry refuses missing admission before driver or parent call", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  let sends = 0;
  await assert.rejects(recordWebRetries({ admission: {}, parentCall: () => { sends += 1; }, spawn: () => { sends += 1; } }), /admission/);
  assert.equal(sends, 0);
});

function productionFixture({ refuseProbe = false, afterTransaction = () => {} } = {}) {
  const nonce = "a".repeat(32), ownerId = "b".repeat(32);
  const database = "projects/fireemu-oracle-query/databases/(default)";
  const docs = new Map(), parent = [], sdkCalls = [], drivers = [], journals = [], sdkCommands = [];
  let clock = 0;
  const version = () => `2030-01-01T00:00:${String(++clock).padStart(2, "0")}.000000001Z`;
  const fields = (data) => Object.fromEntries(Object.entries(data).map(([key, value]) => [key, typeof value === "number" ? { integerValue: String(value) } : { stringValue: value }]));
  const data = (field) => Object.fromEntries(Object.entries(field).map(([key, value]) => [key, value.stringValue ?? Number(value.integerValue)]));
  const spawn = (config, options) => {
    const pid = 4041 + drivers.length;
    const events = [{ event: "ready" }, ...(config.s5bAdmission.transport === "browser" ? [{ event: "browser-processes", origin: config.origin, driverPid: pid, processes: [{ pid: pid + 100, type: "browser" }] }] : [])], waiters = [], paused = new Map();
    let n = 0, exit;
    const emit = (event) => { events.push(event); for (const waiter of [...waiters]) if (waiter.match(event)) { waiters.splice(waiters.indexOf(waiter), 1); waiter.resolve(event); } };
    const waitFor = (match) => {
      const event = events.find(match);
      if (event) return Promise.resolve(event);
      return new Promise((resolve) => waiters.push({ match, resolve }));
    };
    const wire = async (method, request, response, code = 0) => {
      const number = ++n;
      const path = config.s5bAdmission.transport === "node" ? `/google.firestore.v1.Firestore/${method}` : `/v1/${database}/documents:${method === "Commit" ? "commit" : "batchGet"}`;
      const event = { event: "transaction-dispatch", id: `s5b-${number}`, method, request, record: { n: number, host: "firestore.googleapis.com", path, bearer: null } };
      assert.equal(await options.onTransactionAdmission(event), true);
      sdkCalls.push({ client: config.s5bAdmission, method, request });
      emit({ event: "wire", n: number, host: event.record.host, path, principal: null });
      const shapedRequest = method === "Commit" ? { transactionPresent: false, writes: request.writes.map((write) => ({ update: { name: write.update.name, updateTime: null }, currentDocument: write.currentDocument })) } : { transactionPresent: false, documents: request.documents };
      emit({ event: "transaction-wire", n: number, method, complete: true, status: config.s5bAdmission.transport === "node" || code === 0 ? 200 : 400, ...(config.s5bAdmission.transport === "node" ? { grpcCode: code } : {}), request: shapedRequest, response });
    };
    const sdk = {
      pid, events, waitFor, ready: async () => {}, close: async () => exit,
      send: async (op, command = {}, sendOptions) => {
        sdkCommands.push({ op, client: config.s5bAdmission, command, options: sendOptions });
        if (op === "shutdown") { exit = { code: 0 }; emit({ event: "exit", code: 0 }); return { ok: true }; }
        if (op === "continueTransaction") { assert.equal(config.s5bAdmission.probe, false); paused.get(command.name)(); paused.delete(command.name); return { ok: true }; }
        assert.equal(op, "transaction"); assert.equal(command.maxAttempts, 2);
        if (refuseProbe && config.s5bAdmission.probe) throw new Error("fixture probe refused");
        for (let attempt = 1; attempt <= 2; attempt += 1) {
          const name = `${database}/documents/${command.reads[0]}`;
          const found = docs.get(name), readVersion = found?.updateTime;
          await wire("BatchGetDocuments", { documents: [name], database }, { documents: found ? [{ name, updateTime: readVersion }] : [{ missing: name }] });
          const continueRead = attempt === 1 ? new Promise((resolve) => paused.set(command.name, resolve)) : Promise.resolve();
          emit({ event: "transaction-read", name: command.name, attempt, docs: [{ path: command.reads[0], exists: Boolean(found), data: found ? data(found.fields) : null }] });
          await continueRead;
          const write = { update: { name, fields: fields(command.write.data) }, currentDocument: { updateTime: readVersion } };
          const conflict = docs.get(name)?.updateTime !== readVersion;
          const updated = conflict ? null : version();
          await wire("Commit", { database, writes: [write] }, conflict ? { error: { code: 9, status: "FAILED_PRECONDITION" } } : { writeResults: [{ updateTime: updated }], commitTime: updated }, conflict ? 9 : 0);
          if (!conflict) { docs.set(name, { name, fields: write.update.fields, updateTime: updated }); await afterTransaction(command); return { ok: true, attempts: attempt }; }
        }
        return { ok: false, attempts: 2 };
      },
    };
    drivers.push({ sdk, config });
    return sdk;
  };
  const parentCall = async (call) => {
    parent.push(call);
    if (call.method === "GetDocument") { const doc = docs.get(call.request.name); return { complete: true, code: doc ? 0 : 5, response: doc ? structuredClone(doc) : null }; }
    if (call.method === "Commit") {
      const write = call.request.writes[0], old = docs.get(write.update.name);
      assert.equal(write.currentDocument.exists === false ? Boolean(old) : old.updateTime !== write.currentDocument.updateTime, false);
      const updateTime = version(); docs.set(write.update.name, { ...structuredClone(write.update), updateTime });
      return { complete: true, code: 0, response: { writeResults: [{ updateTime }], commitTime: updateTime } };
    }
    assert.equal(call.method, "DeleteDocument"); assert.equal(docs.get(call.request.name).updateTime, call.request.currentDocument.updateTime);
    docs.delete(call.request.name); return { complete: true, code: 0, response: {} };
  };
  return { admission: { authorized: true, nonce, ownerId, web: { apiKey: "fixture-key", projectId: "fireemu-oracle-query", authDomain: "fixture.invalid" }, origin: "http://127.0.0.1:4567", observationDeadlineMs: performance.now() + 180_000, bindings: { corpus: "fixture" } }, parentCall, spawn,
    authorizeSdk: async () => true, statusSdk: async () => {}, journal: async (event) => journals.push(structuredClone(event)), check: async () => {}, parent, sdkCalls, sdkCommands, drivers, docs, journals };
}

test("production fixed corpus accounts for 52 data calls plus 11 management/credential slots", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  const fixture = productionFixture();
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, true);
  assert.equal(fixture.parent.length, 38);
  assert.equal(fixture.parent.filter((call) => call.phase === "observation").length, 20);
  assert.equal(fixture.parent.filter((call) => call.phase === "documentCleanup").length, 18);
  assert.equal(fixture.sdkCalls.length, 14);
  assert.equal(fixture.parent.length + fixture.sdkCalls.length + 11, 63);
  assert.equal(fixture.drivers.length, 4);
  assert.equal(fixture.docs.size, 0);
  assert.equal(Object.keys(receipt.documents).length, 6);
  assert.equal(fixture.sdkCalls.filter((call) => call.client.probe && call.method === "Commit").length, 0);
  assert.equal(fixture.sdkCalls.slice(0, 2).every((call) => call.client.probe), true);
  assert.equal(JSON.stringify(receipt).includes("fixture-key"), false);
});

test("production parent calls rely on receiver guards while SDK admission still checks", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  const fixture = productionFixture();
  let checked = false, checks = 0, startups = 0, admissions = 0;
  const missingChecks = [];
  fixture.check = async () => { checked = true; checks += 1; };
  const spawn = fixture.spawn;
  fixture.spawn = (...args) => {
    if (!checked) missingChecks.push("SDK startup");
    checked = false; startups += 1;
    return spawn(...args);
  };
  fixture.authorizeSdk = async () => {
    if (!checked) missingChecks.push("SDK admission");
    checked = false; admissions += 1;
    return true;
  };
  const parentCall = fixture.parentCall;
  fixture.parentCall = async (call) => {
    assert.equal(checked, false, "parent receiver performs the before-send guard");
    return parentCall(call);
  };
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, true);
  assert.equal(startups, 4);
  assert.equal(admissions, 14);
  assert.deepEqual(missingChecks, []);
  assert.equal(checks, startups + admissions);
  assert.equal(fixture.parent.length, 38);
  assert.equal(fixture.docs.size, 0);
});

test("production cleanup continues across an ownership mismatch without deleting that name", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  const fixture = productionFixture();
  const call = fixture.parentCall;
  let foreign;
  fixture.parentCall = async (request) => {
    const answer = await call(request);
    if (request.phase === "documentCleanup" && request.method === "GetDocument" && !foreign) {
      foreign = request.request.name;
      answer.response.fields.owner.stringValue = "foreign-owner";
    }
    return answer;
  };
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, false);
  assert.equal(fixture.parent.filter((request) => request.method === "DeleteDocument").length, 5);
  assert.equal(fixture.parent.some((request) => request.method === "DeleteDocument" && request.request.name === foreign), false);
  assert.equal(fixture.docs.size, 1);
  assert.equal(receipt.cleanup.length, 6);
});

test("production probe refusal stops before seed writes and never resumes either probe", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  const fixture = productionFixture();
  fixture.statusSdk = async ({ client }) => { if (client.endsWith("probe")) throw new Error("fixture capture refused"); };
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, false);
  assert.equal(fixture.parent.some((call) => call.method !== "GetDocument"), false);
  assert.equal(fixture.sdkCalls.length, 1);
  assert.equal(fixture.sdkCalls[0].method, "BatchGetDocuments");
  assert.equal(fixture.drivers.length, 1);
  assert.equal(fixture.docs.size, 0);
});

for (const stage of ["ready", "transaction-read", "transaction-wire-status"]) {
  test(`production probe retains safe diagnostics after ${stage} failure`, async () => {
    const { recordWebRetries } = await import("./web_sdk_retry.mjs");
    const fixture = productionFixture();
    const spawn = fixture.spawn;
    const secret = "fixture-key bearer-secret https://fixture.invalid/?key=secret";
    const failure = stage === "transaction-read" ? new Error("timed out waiting for the sdk driver")
      : Object.assign(new Error(secret), { name: "FirebaseError", code: "unavailable" });
    fixture.spawn = (...args) => {
      const sdk = spawn(...args);
      sdk.events.push({ event: "connection", n: 1, host: secret },
        { event: "driver-error", message: secret, name: "FirebaseError", code: "unavailable" },
        { event: "result", ok: false, code: "unavailable", error: secret },
        { event: "wire-refused", reason: secret, path: secret },
        { event: "page-error", message: secret },
        { event: "unparsable-output", length: 42 },
        { event: secret, code: secret });
      if (stage === "ready") sdk.ready = async () => { throw failure; };
      if (stage === "transaction-read") {
        const waitFor = sdk.waitFor;
        sdk.waitFor = (match) => match({ event: "transaction-read", name: "node_probe", attempt: 1 })
          ? Promise.reject(failure) : waitFor(match);
      }
      return sdk;
    };
    if (stage === "transaction-wire-status") fixture.statusSdk = async () => { throw failure; };
    const receipt = await recordWebRetries(fixture);
    const probe = receipt.transports[0].probe;
    assert.deepEqual(probe.failure, stage === "transaction-read" ? { stage, name: "Error" }
      : { stage, name: "FirebaseError", code: "unavailable" });
    assert.equal(probe.closed, true);
    assert.equal(receipt.failure, "observation-incomplete");
    assert.equal(receipt.complete, false);
    assert.equal(fixture.parent.length, 8);
    assert.equal(fixture.parent.every((call) => call.method === "GetDocument"), true);
    assert.equal(fixture.drivers.length, 1);
    assert.equal(fixture.docs.size, 0);
    assert.equal(JSON.stringify(receipt).includes(secret), false);
    assert.deepEqual(probe.diagnostics.slice(0, 7), [
      { event: "ready" }, { event: "connection", n: 1 },
      { event: "driver-error", name: "FirebaseError", code: "unavailable" },
      { event: "result", ok: false, code: "unavailable" },
      { event: "wire-refused" }, { event: "page-error" },
      { event: "unparsable-output", length: 42 },
    ]);
    assert.equal(probe.diagnostics.some((event) => event.event === "exit" && event.code === 0), true);
  });
}

test("production probe diagnostic projection rejects arbitrary error labels and bounds events", async () => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  for (const secret of ["secret", "unavailable-secret", "Error-secret", "https://fixture.invalid/?key=secret", "\nsecret"]) {
    const fixture = productionFixture();
    const spawn = fixture.spawn;
    fixture.spawn = (...args) => {
      const sdk = spawn(...args);
      const waitFor = sdk.waitFor;
      sdk.waitFor = (match) => waitFor((event) => event != null && match(event));
      sdk.events.push(null, false, 42, "untrusted-output", ...Array.from({ length: 100 }, (_, n) => ({ event: "connection", n, host: secret })));
      sdk.ready = async () => { throw { name: secret, code: secret, message: secret }; };
      return sdk;
    };
    const receipt = await recordWebRetries(fixture);
    const probe = receipt.transports[0].probe;
    assert.deepEqual(probe.failure, { stage: "ready", name: "Error" });
    assert.equal(probe.diagnostics.length, 32);
    assert.deepEqual(probe.diagnostics.at(-1), { event: "exit", code: 0 });
    assert.equal(JSON.stringify(probe).includes(secret), false);
  }
});

test("fixed parent transport validates only six marked writes and version-bound deletes", async () => {
  const { validateCall } = await import("./txn_program_transport.mjs");
  const nonce = "a".repeat(32), ownerId = "b".repeat(32);
  const database = "projects/fireemu-oracle-query/databases/(default)";
  const spec = { kind: "txn-program-call-v1", transport: "grpc", target: { kind: "production" }, projectId: "fireemu-oracle-query", nonce, ownerId, slug: "txn-s5b", documents: ["node", "browser"].flatMap((transport) => ["control", "control-other", "conflict", "probe"].map((role) => `${transport}-${role}`)), states: ["seed", "witness", "final"], method: "Commit", deadlineMs: 10000, bearer: "fixture-bearer", request: { database, writes: [{ update: { name: `${database}/documents/conf_txn/s5b_${nonce}_node_conflict`, fields: { owner: { stringValue: ownerId }, nonce: { stringValue: nonce }, case: { stringValue: "conflict" }, value: { integerValue: "1" } } }, currentDocument: { exists: false } }] } };
  validateCall(spec);
  const update = structuredClone(spec);
  update.request.writes[0].update.fields.value.integerValue = "2";
  update.request.writes[0].currentDocument = { updateTime: { seconds: "1", nanos: 1 } };
  validateCall(update);
  const deletion = { ...spec, method: "DeleteDocument", request: { name: spec.request.writes[0].update.name, currentDocument: { updateTime: { seconds: "1", nanos: 1 } } } };
  validateCall(deletion);
  for (const changed of [
    { ...spec, projectId: "fireemu-oracle-sbx" },
    { ...spec, method: "BeginTransaction", request: { database, options: { readWrite: {} } } },
    { ...deletion, request: { ...deletion.request, name: deletion.request.name.replace("node_conflict", "node_probe") } },
    { ...deletion, request: { ...deletion.request, currentDocument: { exists: true } } },
  ]) assert.throws(() => validateCall(changed));
});


test("production main command uses the original remaining window after more than fifteen seconds", async (t) => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  let now = 1000;
  t.mock.method(performance, "now", () => now);
  const fixture = productionFixture({ afterTransaction: () => { now += 18_000; } });
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, true);
  assert.equal(fixture.docs.size, 0);
  const main = fixture.sdkCommands.filter((row) => row.op === "transaction" && !row.client.probe);
  assert.deepEqual(main.map((row) => row.options?.timeout), [180_000, 162_000, 144_000, 126_000]);
  for (const row of receipt.transports.flatMap((report) => report.scenarios)) {
    assert.equal(row.command.deadlineMs, 181_000);
    assert.equal(row.command.result.resultMs - row.command.startedMs, 18_000);
    assert.equal(row.command.result.state, "resolved");
  }
  assert.equal(fixture.sdkCommands.filter((row) => row.op === "transaction" && row.client.probe).every((row) => row.options === undefined), true);
  assert.equal(fixture.sdkCommands.filter((row) => row.op === "continueTransaction").every((row) => row.options === undefined), true);
  assert.equal(fixture.sdkCommands.filter((row) => row.op === "shutdown").every((row) => row.options.timeout === 3000), true);
});

for (const lateMs of [0, 1]) {
  test(`production result at observation deadline plus ${lateMs}ms fails and still cleans owned names`, async (t) => {
    const { recordWebRetries } = await import("./web_sdk_retry.mjs");
    let now = 1000;
    t.mock.method(performance, "now", () => now);
    const fixture = productionFixture({ afterTransaction: () => { now = 181_000 + lateMs; } });
    const receipt = await recordWebRetries(fixture);
    assert.equal(receipt.complete, false);
    assert.equal(fixture.docs.size, 0);
    assert.equal(fixture.sdkCommands.filter((row) => row.op === "transaction" && !row.client.probe).length, 1);
    const report = receipt.transports[0], outcome = report.scenarios[0];
    assert.equal(outcome.command.result.state, "rejected");
    assert.equal(outcome.command.result.reason, "observation-deadline");
    assert.equal(report.failure.stage, "transaction-result");
    assert.equal(report.closed, true);
    assert.equal(receipt.cleanup.length, 2);
    assert.equal(receipt.cleanup.every((row) => row.deleted && row.absent), true);
    assert.equal(fixture.parent.filter((row) => row.method === "DeleteDocument").every((row) => row.phase === "documentCleanup"), true);
  });
}

test("production deadline admission refuses missing invalid expired and expanded windows before I/O", async (t) => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  t.mock.method(performance, "now", () => 1000);
  for (const deadline of [undefined, null, NaN, Infinity, -Infinity, 0, 1000, 181_001, "181000"]) {
    const fixture = productionFixture();
    fixture.admission.observationDeadlineMs = deadline;
    await assert.rejects(recordWebRetries(fixture), /admission/);
    assert.equal(fixture.parent.length, 0);
    assert.equal(fixture.drivers.length, 0);
  }
});

test("production expired remaining command budget sends no transaction and cleans the seed", async (t) => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  let now = 1000;
  t.mock.method(performance, "now", () => now);
  const fixture = productionFixture(), parentCall = fixture.parentCall;
  fixture.parentCall = async (row) => {
    const answer = await parentCall(row);
    if (row.method === "Commit" && row.phase === "observation") now = 181_000;
    return answer;
  };
  const receipt = await recordWebRetries(fixture);
  assert.equal(receipt.complete, false);
  assert.equal(fixture.sdkCommands.filter((row) => row.op === "transaction" && !row.client.probe).length, 0);
  assert.equal(fixture.docs.size, 0);
  assert.equal(receipt.transports[0].failure.stage, "transaction-send");
  assert.equal(receipt.cleanup.length, 1);
});

test("production existing receipt channel durably retains safe main diagnostics and conservative ready anchor", async (t) => {
  const { recordWebRetries } = await import("./web_sdk_retry.mjs");
  let now = 1000;
  t.mock.method(performance, "now", () => now);
  const secret = "fixture-key bearer-secret https://fixture.invalid/?key=secret sensitive-body";
  const fixture = productionFixture({ afterTransaction: () => { throw Object.assign(new Error(secret), { name: "FirebaseError", code: "unavailable" }); } });
  const spawn = fixture.spawn;
  fixture.spawn = (...args) => {
    const sdk = spawn(...args);
    if (!args[0].s5bAdmission.probe) sdk.events.push(...Array.from({ length: 40 }, (_, n) => ({ event: "driver-error", n, name: "FirebaseError", code: "unavailable", message: secret, host: secret, body: secret })));
    sdk.stderr = () => secret;
    return sdk;
  };
  const source = await readFile(new URL("./web_sdk_retry.mjs", import.meta.url), "utf8");
  const body = source.slice(source.indexOf("async function productionEntry()"), source.indexOf("\n\n\nif (process.argv"));
  const stdin = new PassThrough(), rows = [];
  const processStub = { stdin, stdout: { write(text) {
    const row = JSON.parse(text); rows.push(row);
    if (row.event === "ready") {
      now = 4000;
      const { observationDeadlineMs, ...admission } = fixture.admission;
      stdin.write(JSON.stringify({ ...admission, observationRemaining: 177, id: row.id }) + "\n");
    }
  } }, exitCode: undefined };
  let receivedDeadline;
  const entry = new Function("process", "recordWebRetries", "performance", `return (${body})`)(processStub, async ({ admission }) => {
    receivedDeadline = admission.observationDeadlineMs;
    return recordWebRetries({ ...fixture, admission });
  }, performance);
  await entry(); stdin.destroy();
  assert.equal(receivedDeadline, 178_000, "the IPC duration is conservatively deducted without a fresh180s window");
  assert.deepEqual(rows.map((row) => row.event), ["ready", "receipt"]);
  assert.equal(processStub.exitCode, 1);
  const saved = JSON.parse(JSON.stringify(rows[1].receipt));
  const report = saved.transports[0], command = report.scenarios[0].command;
  assert.deepEqual(report.failure, { stage: "transaction-result", name: "FirebaseError", code: "unavailable" });
  assert.equal(command.startedMs, 4000);
  assert.equal(command.deadlineMs, 178_000);
  assert.equal(command.timeoutMs, 174_000);
  assert.equal(command.result.state, "rejected");
  assert.equal(command.result.reason, "sdk-result-rejected");
  assert.equal(report.diagnostics.length <= 32, true);
  assert.equal(report.diagnostics.some((row) => row.event === "driver-error" && row.code === "unavailable"), true);
  for (const word of secret.split(" ")) assert.equal(JSON.stringify(saved).includes(word), false);
  assert.equal(fixture.docs.size, 0);
});
