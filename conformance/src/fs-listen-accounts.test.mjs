import assert from "node:assert/strict";
import { test } from "node:test";

import { createAccountClient, createAccountSession } from "./fs-listen/accounts.mjs";

/** A fetch that answers by route from a script; each entry is [status, body] or "throw". */
function scripted(script) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const route = url.split("/accounts").at(-1);
    const body = JSON.parse(init.body);
    calls.push([`/accounts${route}`, body]);
    const queue = script[`/accounts${route}`];
    const next = queue.length > 1 ? queue.shift() : queue[0];
    if (next === "throw") throw new Error("network");
    const [status, json] = next;
    return {
      status,
      json: async () => {
        if (json === undefined) throw new Error("unreadable");
        return json;
      },
    };
  };
  return { fetchImpl, calls };
}
const session = (script) => {
  const { fetchImpl, calls } = scripted(script);
  const client = createAccountClient({ base: "https://x", project: "p", headers: {}, fetchImpl });
  return { calls, s: createAccountSession({ client, run: "r1" }) };
};

test("create returns the uids; cleanup deletes both and reads each back", async () => {
  const { s, calls } = session({
    "/accounts": [
      [200, { localId: "u1" }],
      [200, { localId: "u2" }],
    ],
    "/accounts:delete": [[200, {}]],
    "/accounts:lookup": [[200, { kind: "x" }]],
  });
  const made = await s.create(["a", "b"]);
  assert.equal(made.a.uid, "u1");
  assert.equal(made.b.email, "fsl-r1-b@example.com");
  const report = await s.cleanup();
  assert.equal(report.complete, true);
  assert.deepEqual(
    calls.filter(([r]) => r === "/accounts:delete").map(([, b]) => b),
    [{ localId: "u1" }, { localId: "u2" }],
  );
});

test("a delete that the lookup still shows is not settled", async () => {
  const { s } = session({
    "/accounts": [[200, { localId: "u1" }]],
    "/accounts:delete": [[200, {}]],
    "/accounts:lookup": [[200, { users: [{ localId: "u1" }] }]],
  });
  await s.create(["a"]);
  const report = await s.cleanup();
  assert.equal(report.complete, false);
  assert.equal(report.rows[0].why, "still-present");
});

test("an unreadable or failing lookup never settles a delete", async () => {
  for (const lookup of [[500, {}], [200, undefined], "throw", [404, {}]]) {
    const { s } = session({
      "/accounts": [[200, { localId: "u1" }]],
      "/accounts:delete": [[200, {}]],
      "/accounts:lookup": [lookup],
    });
    await s.create(["a"]);
    const report = await s.cleanup();
    assert.equal(report.complete, false, JSON.stringify(lookup));
  }
});

test("a 400 USER_NOT_FOUND lookup is a read of absence; any other 4xx is not", async () => {
  const done = session({
    "/accounts": [[200, { localId: "u1" }]],
    "/accounts:delete": [[200, {}]],
    "/accounts:lookup": [[400, { error: { message: "USER_NOT_FOUND" } }]],
  });
  await done.s.create(["a"]);
  assert.equal((await done.s.cleanup()).complete, true);
  const other = session({
    "/accounts": [[200, { localId: "u1" }]],
    "/accounts:delete": [[200, {}]],
    "/accounts:lookup": [[403, { error: { message: "PERMISSION_DENIED" } }]],
  });
  await other.s.create(["a"]);
  assert.equal((await other.s.cleanup()).complete, false);
});

test("an unknown delete answer is sticky even when the lookup then finds nobody", async () => {
  for (const del of [[500, {}], [302, undefined], "throw", [200, undefined]]) {
    const { s } = session({
      "/accounts": [[200, { localId: "u1" }]],
      "/accounts:delete": [del],
      "/accounts:lookup": [[200, { kind: "x" }]],
    });
    await s.create(["a"]);
    const report = await s.cleanup();
    assert.equal(report.rows[0].settled, true, JSON.stringify(del));
    assert.equal(report.rows[0].unknownDelete, true, JSON.stringify(del));
    assert.equal(report.complete, false, JSON.stringify(del));
  }
});

test("an unknown create is looked up by email: found it is deleted, not found it stays unsettled", async () => {
  for (const create of [[500, {}], "throw", [200, undefined], [200, { kind: "no uid" }]]) {
    const found = session({
      "/accounts": [create],
      "/accounts:delete": [[200, {}]],
      "/accounts:lookup": [
        [200, { users: [{ localId: "u9" }] }],
        [200, { kind: "x" }],
      ],
    });
    await assert.rejects(found.s.create(["a"]), /not created: unknown/);
    const foundReport = await found.s.cleanup();
    assert.ok(
      found.calls.some(([r, b]) => r === "/accounts:delete" && b.localId === "u9"),
      JSON.stringify(create),
    );
    assert.equal(foundReport.rows[0].settled, true);

    const absent = session({
      "/accounts": [create],
      "/accounts:lookup": [[200, { kind: "x" }]],
    });
    await assert.rejects(absent.s.create(["a"]), /not created/);
    const report = await absent.s.cleanup();
    assert.equal(report.complete, false, `404 or silence never settles: ${JSON.stringify(create)}`);
    assert.equal(report.rows[0].why, "create-unknown-not-found");
  }
});

test("a refused create (4xx) has made nothing and needs no cleanup", async () => {
  const { s, calls } = session({ "/accounts": [[400, { error: { message: "EMAIL_EXISTS" } }]] });
  await assert.rejects(s.create(["a"]), /refused 400/);
  const report = await s.cleanup();
  assert.equal(report.complete, true);
  assert.equal(calls.length, 1);
});
