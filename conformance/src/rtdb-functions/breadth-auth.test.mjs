import { test } from "node:test";
import assert from "node:assert/strict";
import { createAuth } from "./breadth-auth.mjs";

test("creates, signs in, deletes and proves absence without exposing secrets", async () => {
  const rows = [],
    calls = [];
  const responses = [{ localId: "uid" }, { localId: "uid", idToken: "token-sentinel" }, {}, {}];
  const auth = createAuth({
    projectId: "demo",
    apiKey: "key-sentinel",
    email: "user@example.test",
    password: "password-sentinel",
    log: (row) => rows.push(row),
    fetchImpl: async (url, init) => {
      calls.push([url, init]);
      return { status: 200, text: async () => JSON.stringify(responses.shift()) };
    },
  });
  const created = await auth.create();
  assert.equal(auth.uid, "uid");
  const signed = await auth.signIn();
  assert.equal(created.outcome, "ok");
  assert.equal(signed.outcome, "ok");
  assert.equal(await auth.delete(), "ok");
  assert.equal(await auth.confirmGone(), true);
  assert.equal(calls.length, 4);
  assert.ok(calls[1][0].includes("key=key-sentinel"));
  const visible = JSON.stringify([rows, created, signed]);
  for (const secret of ["key-sentinel", "password-sentinel", "token-sentinel"])
    assert.ok(!visible.includes(secret));
  assert.equal(auth.idToken, "token-sentinel");
});

test("unknown answers stop further state changes and never expose secrets", async () => {
  const rows = [];
  let calls = 0;
  const auth = createAuth({
    projectId: "demo",
    apiKey: "key-sentinel",
    email: "user@example.test",
    password: "password-sentinel",
    log: (r) => rows.push(r),
    fetchImpl: async () => {
      calls++;
      throw Error("key-sentinel password-sentinel token-sentinel");
    },
  });
  assert.equal((await auth.create()).outcome, "unknown");
  await assert.rejects(auth.signIn(), (e) => !e.message.includes("sentinel"));
  assert.equal(await auth.delete(), "skipped");
  assert.equal(calls, 1);
  assert.ok(!JSON.stringify(rows).includes("sentinel"));
});
