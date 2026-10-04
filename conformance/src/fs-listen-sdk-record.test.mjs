import assert from "node:assert/strict";
import { test } from "node:test";

import {
  conditionsOf,
  projectEvent,
  ranOut,
  recordSdk,
  rowsFromReceipt,
  sweepDocuments,
} from "./fs-listen/sdk-record.mjs";

test("every SDK case maps to exactly one closure condition", () => {
  const expected = {
    "FS-LISTEN-SDK-101": "document-event-order",
    "FS-LISTEN-SDK-101C": "document-event-order",
    "FS-LISTEN-SDK-102C": "pending-writes",
    "FS-LISTEN-SDK-103": "query-change-order",
    "FS-LISTEN-SDK-103L": "query-change-order",
    "FS-LISTEN-SDK-103T": "query-change-order",
    "FS-LISTEN-SDK-104C": "reconnect-resume",
    "FS-LISTEN-SDK-105": "unsubscribe",
    "FS-LISTEN-SDK-106N": "initial-unauthenticated-refusal",
    "FS-LISTEN-SDK-107C": "default-subscription",
    "FS-LISTEN-SDK-108": "cross-principal-rules",
    "FS-LISTEN-SDK-108C": "cross-principal-rules",
    "FS-LISTEN-SDK-111": "existence-filter-reconnect",
  };
  for (const [id, condition] of Object.entries(expected))
    assert.deepEqual(conditionsOf(id), [`FS-LISTEN-SDK/${condition}`], id);
  assert.throws(() => conditionsOf("FS-LISTEN-SDK-999"), /no condition/);
});

test("ranOut recognises the failures that mean a wait did not finish", () => {
  for (const f of [
    "step-timeout",
    "deadline-exceeded",
    "snapshot-budget-exhausted",
    "budget-exceeded:reads",
  ])
    assert.equal(ranOut([f]), true, f);
  assert.equal(ranOut([]), false);
  assert.equal(ranOut(["unsubscribe-failed:primary"]), false);
});

test("rowsFromReceipt keys rows by case and carries the observation, not the verdict", () => {
  const rows = rowsFromReceipt({
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: null,
        observed: [{ docs: ["alpha"] }],
        failures: [],
        invariantViolations: [],
      },
      {
        caseId: "FS-LISTEN-SDK-105",
        comparedFields: null,
        observed: [],
        failures: ["step-timeout"],
        invariantViolations: [{ invariant: "x" }],
      },
    ],
  });
  assert.deepEqual(Object.keys(rows), ["sdk/101", "sdk/105"]);
  assert.equal(rows["sdk/101"].timedOut, false);
  assert.equal(rows["sdk/105"].timedOut, true);
  assert.deepEqual(rows["sdk/101"].observed, [{ docs: ["alpha"] }]);
  assert.deepEqual(rows["sdk/105"].conditions, ["FS-LISTEN-SDK/unsubscribe"]);
});

test("projectEvent keeps the compared fields and the cache transitions, nothing else", () => {
  const event = {
    listener: "primary",
    docs: ["a"],
    fromCache: true,
    hasPendingWrites: false,
    fromCacheTransitions: [true, false],
  };
  assert.deepEqual(projectEvent(event, ["listener", "docs"]), {
    listener: "primary",
    docs: ["a"],
    fromCacheTransitions: [true, false],
  });
  assert.deepEqual(projectEvent(event, null), event);
  assert.deepEqual(projectEvent(event, ["fromCache"]), {
    fromCache: true,
    fromCacheTransitions: [true, false],
  });
});

test("rowsFromReceipt projects each event to its case's compared fields", () => {
  const rows = rowsFromReceipt({
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: ["docs"],
        observed: [{ docs: ["alpha"], fromCache: true }],
        failures: [],
        invariantViolations: [],
      },
    ],
  });
  assert.deepEqual(rows["sdk/101"].observed, [{ docs: ["alpha"] }]);
});

test("sweepDocuments deletes the run's documents and the accounts' owner documents, then reads back", async () => {
  const present = new Set([
    "projects/p/databases/(default)/documents/conf_listen/r1-alpha",
    "projects/p/databases/(default)/documents/conf_rules_owner/uB",
  ]);
  const client = {
    async listIds() {
      return ["projects/p/databases/(default)/documents/conf_listen/r1-alpha"];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: present.has(name) }));
    },
    async commit({ writes }) {
      for (const w of writes) present.delete(w.delete);
    },
  };
  const report = await sweepDocuments({
    client,
    project: "p",
    run: "r1",
    accounts: { a: { uid: "uA" }, b: { uid: "uB" } },
  });
  assert.deepEqual(report, { complete: true, deleted: 2, stillPresent: 0, checked: 3 });
  assert.equal(present.size, 0);
  const stubborn = {
    ...client,
    async commit() {},
    async listIds() {
      return [];
    },
  };
  present.add("projects/p/databases/(default)/documents/conf_rules_owner/uB");
  const bad = await sweepDocuments({
    client: stubborn,
    project: "p",
    run: "r1",
    accounts: { b: { uid: "uB" } },
  });
  assert.equal(bad.complete, false);
});

test("recordSdk: a driver that fails leaves an error row and still cleans up the accounts", async () => {
  const calls = [];
  const fetchStub = async (url) => {
    calls.push(url.split("/").at(-1));
    return { status: 200, json: async () => ({ localId: `u${calls.length}` }) };
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = fetchStub;
  try {
    const recording = await recordSdk({
      target: {
        kind: "local",
        project: "demo",
        firestore: { host: "127.0.0.1", port: 1 },
        auth: "http://127.0.0.1:2",
      },
      run: "r1",
      runDriverImpl: async () => {
        throw new Error("driver exploded");
      },
    });
    assert.equal(recording.errors["sdk/run"], "driver exploded");
    assert.equal(recording.cleanup.complete, false);
    assert.deepEqual(recording.rows, {});
    assert.ok(
      calls.includes("accounts:delete"),
      "the accounts are deleted even though the driver failed",
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});
