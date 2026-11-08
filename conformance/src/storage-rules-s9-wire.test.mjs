import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { GuardError, RequestBudget } from "./storage-rules-s9/guard.mjs";
import { REQUEST_TIMEOUT_MS, recordingPrefix, runRoot } from "./storage-rules-s9/plan.mjs";
import { UnknownAnswer, createWire } from "./storage-rules-s9/wire.mjs";

const project = "fireemu-oracle-query";
const bucket = "fireemu-oracle-query.firebasestorage.app";
const root = runRoot("sr-0123abcd");
const name = `${recordingPrefix("sr-0123abcd", 1)}/pub/x`;
const target = { name: "production", bucket, project };
const state = { runId: "sr-0123abcd", root, ownRulesets: new Set(), baseline: "absent" };
const owner = { authorization: "Bearer secret-token", "x-goog-user-project": project };
const v0 = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o/${encodeURIComponent(name)}`;
const gcs = `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;

function setup({ answer, cap = 10 } = {}) {
  const journal = [];
  const sent = [];
  const budget = new RequestBudget(cap, cap);
  const deps = {
    adminHeaders: () => owner,
    net: async (request) => {
      sent.push(request);
      if (answer === "transport") throw new Error("socket closed");
      return (
        answer ?? {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from('{"ok":1}'),
        }
      );
    },
  };
  const wired = createWire({
    target,
    state,
    budget,
    deps,
    out: { journal: (entry) => journal.push(entry) },
  });
  return { ...wired, journal, sent, budget };
}

describe("storage rules s9 wire", () => {
  it("journals before and after, sends the owner headers without journaling them, and returns the answer", async () => {
    const { wire, journal, sent, budget } = setup();
    const answer = await wire(
      "gcs/get",
      { method: "GET", url: gcs, headers: { "x-extra": "1" } },
      { admin: true },
    );
    assert.deepEqual(answer.status, 200);
    assert.deepEqual(answer.headers, { "content-type": "application/json" });
    assert.equal(answer.body.toString(), '{"ok":1}');
    assert.equal(answer.unknown, false);
    assert.equal(answer.kind, "gcs-get");
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].headers, { ...owner, "x-extra": "1" });
    assert.equal(sent[0].timeoutMs, REQUEST_TIMEOUT_MS);
    assert.equal(sent[0].method, "GET");
    assert.equal(sent[0].url, gcs);
    assert.equal(sent[0].body, undefined);
    assert.deepEqual(journal[0], {
      phase: "before",
      n: 1,
      label: "gcs/get",
      kind: "gcs-get",
      method: "GET",
      url: gcs,
      headers: { "x-extra": "1" },
      bodyBytes: 0,
    });
    assert.deepEqual(journal[1], {
      phase: "after",
      n: 1,
      label: "gcs/get",
      status: 200,
      headers: { "content-type": "application/json" },
      bodyBytes: 8,
      bodyBase64: Buffer.from('{"ok":1}').toString("base64"),
    });
    assert.equal(journal.length, 2);
    assert.equal(
      JSON.stringify(journal).includes("secret-token"),
      false,
      "a credential never reaches the journal",
    );
    assert.equal(budget.count, 1);
  });

  it("sends anonymous requests without the owner headers and counts the body", async () => {
    const { wire, journal, sent } = setup();
    await wire("v0/get", { method: "GET", url: v0 });
    assert.deepEqual(sent[0].headers, {});
    assert.deepEqual(journal[0].headers, {});
    const upload = `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${encodeURIComponent(name)}&ifGenerationMatch=0`;
    await wire(
      "create",
      { method: "POST", url: upload, body: Buffer.from("abc") },
      { admin: true },
    );
    assert.equal(journal.find((e) => e.label === "create" && e.phase === "before").bodyBytes, 3);
    assert.deepEqual(sent[1].body, Buffer.from("abc"));
  });

  it("throws an unknown answer to a write, records its label, and never retries", async () => {
    for (const status of [199, 301, 500, 503]) {
      const { wire, journal, unknownLabels, unknownReads, sent } = setup({
        answer: { status, headers: {}, body: Buffer.from("x") },
      });
      await assert.rejects(
        wire("w", { method: "GET", url: gcs }, { admin: true }),
        (error) =>
          error instanceof UnknownAnswer &&
          error.label === "w" &&
          error.status === status &&
          error.message === `unknown answer: w (${status})`,
      );
      assert.deepEqual(unknownLabels, ["w"]);
      assert.deepEqual(unknownReads, []);
      assert.equal(sent.length, 1);
      assert.equal(journal.at(-1).phase, "after", "the unknown answer is journaled as it came");
    }
    const { wire, unknownLabels } = setup({ answer: "transport" });
    await assert.rejects(
      wire("t", { method: "GET", url: gcs }, { admin: true }),
      (error) =>
        error instanceof UnknownAnswer &&
        Number.isNaN(error.status) &&
        error.message === "unknown answer: t (transport)",
    );
    assert.deepEqual(unknownLabels, ["t"]);
  });

  it("returns an unknown answer to a read, and records it", async () => {
    const { wire, journal, unknownLabels, unknownReads } = setup({
      answer: { status: 503, headers: { a: "b" }, body: Buffer.from("down") },
    });
    const answer = await wire("r", { method: "GET", url: v0 }, { read: true });
    assert.equal(answer.unknown, true);
    assert.equal(answer.status, 503);
    assert.deepEqual(answer.headers, { a: "b" });
    assert.equal(answer.body.toString(), "down");
    assert.equal(answer.kind, "v0-meta");
    assert.deepEqual(unknownReads, ["r"]);
    assert.deepEqual(unknownLabels, []);
    assert.equal(journal.at(-1).status, 503);
    const lost = setup({ answer: "transport" });
    const none = await lost.wire("r2", { method: "GET", url: v0 }, { read: true });
    assert.equal(none.unknown, true);
    assert.ok(Number.isNaN(none.status));
    assert.deepEqual(none.headers, {});
    assert.equal(none.body.length, 0);
    assert.equal(none.kind, "v0-meta");
    assert.deepEqual(lost.unknownReads, ["r2"]);
    assert.deepEqual(
      lost.journal.map((e) => e.phase),
      ["before", "unknown"],
    );
    assert.deepEqual(lost.journal[1], { phase: "unknown", n: 1, label: "r2", reason: "transport" });
  });

  it("refuses an unguarded request before it counts or sends, and stops at the budget", async () => {
    const { wire, sent, budget, journal } = setup();
    await assert.rejects(wire("bad", { method: "GET", url: "https://evil.example/x" }), GuardError);
    await assert.rejects(
      wire("bad2", { method: "GET", url: gcs }),
      /owner request without Authorization/,
    );
    assert.equal(sent.length, 0);
    assert.equal(budget.count, 0);
    assert.equal(journal.length, 0);
    const small = setup({ cap: 1 });
    await small.wire("one", { method: "GET", url: v0 });
    await assert.rejects(small.wire("two", { method: "GET", url: v0 }), /request budget exhausted/);
    assert.equal(small.sent.length, 1);
  });

  it("treats 2xx and 4xx as answers, not unknowns", async () => {
    for (const status of [200, 204, 400, 403, 404, 409, 412, 429]) {
      const { wire } = setup({ answer: { status, headers: {}, body: Buffer.alloc(0) } });
      const answer = await wire("a", { method: "GET", url: gcs }, { admin: true });
      assert.equal(answer.status, status);
      assert.equal(answer.unknown, false);
    }
    const missing = setup({ answer: { status: 200 } });
    const answer = await missing.wire("a", { method: "GET", url: gcs }, { admin: true });
    assert.deepEqual(answer.headers, {});
    assert.equal(answer.body.length, 0);
  });
});
