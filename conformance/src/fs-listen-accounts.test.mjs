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

/** A fetch that records each request and answers from `answer(route, body)`. */
function recording(answer) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({ url, init, body: JSON.parse(init.body) });
    return answer(url.split("/accounts").at(-1), JSON.parse(init.body));
  };
  return { requests, fetchImpl };
}
const reply = (status, json) => ({
  status,
  json: async () => {
    if (json === undefined) throw new Error("unreadable");
    return json;
  },
});

test("requests go to the project's routes with the headers, a manual redirect and the exact bodies", async () => {
  const { requests, fetchImpl } = recording((route) =>
    reply(200, route === "" ? { localId: "u1" } : {}),
  );
  const client = createAccountClient({
    base: "https://host",
    project: "p9",
    headers: { authorization: "Bearer t", "x-goog-user-project": "p9" },
    fetchImpl,
  });
  assert.deepEqual(await client.create({ email: "e@example.com", password: "pw" }), {
    kind: "created",
    uid: "u1",
  });
  await client.lookup({ localId: ["u1"] });
  await client.remove("u1");
  assert.deepEqual(
    requests.map((r) => r.url),
    [
      "https://host/v1/projects/p9/accounts",
      "https://host/v1/projects/p9/accounts:lookup",
      "https://host/v1/projects/p9/accounts:delete",
      "https://host/v1/projects/p9/accounts:lookup",
    ],
  );
  assert.deepEqual(requests[0].body, {
    email: "e@example.com",
    password: "pw",
    emailVerified: true,
  });
  assert.deepEqual(requests[1].body, { localId: ["u1"] });
  assert.deepEqual(requests[2].body, { localId: "u1" });
  assert.deepEqual(requests[3].body, { localId: ["u1"] });
  for (const request of requests) {
    assert.equal(request.init.method, "POST");
    assert.equal(request.init.redirect, "manual");
    assert.equal(request.init.headers.authorization, "Bearer t");
    assert.equal(request.init.headers["x-goog-user-project"], "p9");
    assert.equal(request.init.headers["content-type"], "application/json");
    assert.ok(request.init.signal instanceof AbortSignal);
  }
});

test("an answer is a create, a refusal or unknown by its status and body, nothing else", async () => {
  const create = async (status, json) => {
    const { fetchImpl } = recording(() => reply(status, json));
    return createAccountClient({ base: "b", project: "p", headers: {}, fetchImpl }).create({
      email: "e",
      password: "p",
    });
  };
  assert.deepEqual(await create(200, { localId: "u" }), { kind: "created", uid: "u" });
  assert.deepEqual(await create(299, { localId: "u" }), { kind: "created", uid: "u" });
  assert.deepEqual(await create(400, { error: {} }), { kind: "refused", status: 400 });
  assert.deepEqual(await create(499, undefined), { kind: "refused", status: 499 });
  assert.deepEqual(await create(409, undefined), { kind: "refused", status: 409 });
  assert.deepEqual(await create(200, { localId: 7 }), { kind: "unknown", why: "no-localId" });
  assert.deepEqual(await create(200, {}), { kind: "unknown", why: "no-localId" });
  assert.deepEqual(await create(200, undefined), { kind: "unknown", why: "unreadable-body" });
  assert.deepEqual(await create(500, undefined), { kind: "unknown", why: "status-500" });
  assert.deepEqual(await create(500, { error: {} }), { kind: "unknown", why: "status-500" });
  assert.deepEqual(await create(302, undefined), { kind: "unknown", why: "status-302" });
  assert.deepEqual(await create(302, {}), { kind: "unknown", why: "status-302" });
  assert.deepEqual(await create(199, {}), { kind: "unknown", why: "status-199" });
  assert.deepEqual(await create(300, {}), { kind: "unknown", why: "status-300" });
});

test("lookup lists the uids found, nothing for no users, and null for anything unreadable", async () => {
  const lookup = async (status, json) => {
    const { fetchImpl } = recording(() => reply(status, json));
    return createAccountClient({ base: "b", project: "p", headers: {}, fetchImpl }).lookup({
      email: ["e"],
    });
  };
  assert.deepEqual(await lookup(200, { users: [{ localId: "a" }, { localId: "b" }] }), ["a", "b"]);
  assert.deepEqual(await lookup(200, {}), []);
  assert.deepEqual(await lookup(200, { users: [] }), []);
  assert.equal(await lookup(200, undefined), null);
  assert.equal(await lookup(500, { error: { message: "USER_NOT_FOUND" } }), null);
  assert.deepEqual(await lookup(400, { error: { message: "USER_NOT_FOUND" } }), []);
  assert.equal(await lookup(400, { error: { message: "INVALID" } }), null);
  assert.equal(await lookup(400, undefined), null);
});

test("remove: gone is settled, still-present and unreadable lookups are not, and the delete answer is kept apart", async () => {
  const remove = async (del, lookupAnswer) => {
    const { fetchImpl } = recording((route) => (route === ":delete" ? del : lookupAnswer));
    return createAccountClient({ base: "b", project: "p", headers: {}, fetchImpl }).remove("u1");
  };
  assert.deepEqual(await remove(reply(200, {}), reply(200, {})), {
    settled: true,
    unknownDelete: false,
    why: null,
  });
  assert.deepEqual(await remove(reply(400, {}), reply(200, {})), {
    settled: true,
    unknownDelete: false,
    why: null,
  });
  assert.deepEqual(await remove(reply(500, {}), reply(200, {})), {
    settled: true,
    unknownDelete: true,
    why: null,
  });
  assert.deepEqual(await remove(reply(200, {}), reply(200, { users: [{ localId: "u1" }] })), {
    settled: false,
    unknownDelete: false,
    why: "still-present",
  });
  assert.deepEqual(await remove(reply(200, {}), reply(200, { users: [{ localId: "other" }] })), {
    settled: true,
    unknownDelete: false,
    why: null,
  });
  assert.deepEqual(await remove(reply(200, {}), reply(500, {})), {
    settled: false,
    unknownDelete: false,
    why: "lookup-unknown",
  });
});

test("a session makes the accounts one by one with the names it derives, and only the first failure stops it", async () => {
  const seen = [];
  const client = {
    async create(entry) {
      seen.push(entry);
      return { kind: "created", uid: `u-${entry.email}` };
    },
  };
  const s = createAccountSession({ client, run: "rr" });
  const made = await s.create(["a", "b"]);
  assert.deepEqual(
    seen.map((e) => e.email),
    ["fsl-rr-a@example.com", "fsl-rr-b@example.com"],
  );
  assert.match(seen[0].password, /^Fsl-rr-a-/);
  assert.notEqual(seen[0].password, seen[1].password);
  assert.deepEqual(made.a, {
    email: "fsl-rr-a@example.com",
    password: seen[0].password,
    uid: "u-fsl-rr-a@example.com",
  });
  assert.equal(Object.keys(made).length, 2);
});

test("cleanup of a refused create needs no read; a created account is removed through the client", async () => {
  const calls = [];
  const client = {
    async create({ email }) {
      return email.includes("-a@")
        ? { kind: "created", uid: "ua" }
        : { kind: "refused", status: 400 };
    },
    async lookup(selector) {
      calls.push(["lookup", selector]);
      return [];
    },
    async remove(uid) {
      calls.push(["remove", uid]);
      return { settled: true, unknownDelete: false, why: null };
    },
  };
  const s = createAccountSession({ client, run: "rr" });
  await assert.rejects(s.create(["a", "b"]), /account b was not created: refused 400/);
  const report = await s.cleanup();
  assert.deepEqual(calls, [["remove", "ua"]]);
  assert.deepEqual(report.rows, [
    { name: "a", settled: true, unknownDelete: false, why: null },
    { name: "b", settled: true, why: "refused" },
  ]);
  assert.equal(report.complete, true);
});

test("cleanup keeps going after an account it cannot settle, and reports every account", async () => {
  const client = {
    async create({ email }) {
      return email.includes("-a@")
        ? { kind: "unknown", why: "transport" }
        : { kind: "created", uid: "ub" };
    },
    async lookup() {
      return null;
    },
    async remove() {
      return { settled: true, unknownDelete: false, why: null };
    },
  };
  const s = createAccountSession({ client, run: "rr" });
  await assert.rejects(s.create(["a"]), /unknown transport/);
  const report = await s.cleanup();
  assert.deepEqual(report.rows, [
    { name: "a", settled: false, why: "create-unknown-lookup-unknown" },
  ]);
  assert.equal(report.complete, false);
});
