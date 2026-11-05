import { test } from "node:test";
import assert from "node:assert/strict";
import { rulesFor, createRtdb } from "./breadth-rtdb.mjs";

test("rules limit user writes to the two groups", () => {
  const rules = rulesFor("g9-rtdb", "nonce").rules;
  assert.equal(rules[".write"], false);
  assert.equal(rules[".read"], false);
  const prefix = rules["g9-rtdb"];
  assert.equal(prefix[".write"], undefined);
  assert.equal(prefix.gu[".write"], "auth != null");
  assert.equal(prefix.gu.$other[".validate"], false);
  assert.equal(prefix.gv.items.$id[".write"], "auth != null");
  for (const group of ["gu", "gv"])
    assert.equal(prefix[group].items.$id[".validate"], "newData.child('run').val() === 'nonce'");
});

test("user writes redact URLs on success and error and are never retried", async () => {
  const rows = [],
    urls = [];
  const client = createRtdb({
    packet: {},
    nonce: "nonce",
    userToken: "sentinel-token",
    log: (row) => rows.push(row),
    fetchImpl: async (url) => {
      urls.push(url);
      if (urls.length === 2) throw Error(url);
      return { status: 200, text: async () => "{}" };
    },
  });
  assert.equal(
    (
      await client.write({
        id: "w7",
        context: "user-rest",
        method: "PUT",
        path: "gv/items/u1",
        body: {},
      })
    ).outcome,
    "ok",
  );
  assert.equal(
    (
      await client.write({
        id: "w8",
        context: "user-rest",
        method: "PATCH",
        path: "gv/items/u1",
        body: {},
      })
    ).outcome,
    "unknown",
  );
  assert.equal(urls.length, 2);
  assert.ok(rows.every((r) => r.url.includes("auth=***")));
  assert.ok(!JSON.stringify(rows).includes("sentinel-token"));
});

test("a write identifier cannot be sent twice after an unknown answer", async () => {
  let calls = 0;
  const client = createRtdb({
    packet: {},
    nonce: "n",
    userToken: "u",
    log: () => {},
    fetchImpl: async () => {
      calls++;
      throw Error("timeout");
    },
  });
  const step = { id: "w7", context: "user-rest", method: "PUT", path: "gv/items/u1", body: {} };
  assert.equal((await client.write(step)).outcome, "unknown");
  await assert.rejects(client.write(step));
  assert.equal(calls, 1);
});
