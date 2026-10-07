import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { test } from "node:test";
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
            : { commitTime: version },
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
    final: { status: 200, value: 3 },
    witness: { path: scenario === "conflict" ? path : other, value: 2 },
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
