import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
    {
      name: "a",
      email: "fsl-rr-a@example.com",
      uid: "ua",
      settled: true,
      unknownDelete: false,
      why: null,
    },
    { name: "b", email: "fsl-rr-b@example.com", settled: true, why: "refused" },
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
    {
      name: "a",
      email: "fsl-rr-a@example.com",
      settled: false,
      why: "create-unknown-lookup-unknown",
    },
  ]);
  assert.equal(report.complete, false);
});

test("every status is told apart whether or not the body can be read", async () => {
  const create = async (status, json) => {
    const { fetchImpl } = recording(() => reply(status, json));
    return createAccountClient({ base: "b", project: "p", headers: {}, fetchImpl }).create({
      email: "e",
      password: "p",
    });
  };
  const unreadable = [
    [199, { kind: "unknown", why: "status-199" }],
    [200, { kind: "unknown", why: "unreadable-body" }],
    [299, { kind: "unknown", why: "unreadable-body" }],
    [300, { kind: "unknown", why: "status-300" }],
    [399, { kind: "unknown", why: "status-399" }],
    [400, { kind: "refused", status: 400 }],
    [499, { kind: "refused", status: 499 }],
    [500, { kind: "unknown", why: "status-500" }],
  ];
  for (const [status, expected] of unreadable)
    assert.deepEqual(await create(status, undefined), expected, `${status}`);
  const readable = [
    [199, { kind: "unknown", why: "status-199" }],
    [200, { kind: "unknown", why: "no-localId" }],
    [299, { kind: "unknown", why: "no-localId" }],
    [300, { kind: "unknown", why: "status-300" }],
    [399, { kind: "unknown", why: "status-399" }],
    [400, { kind: "refused", status: 400 }],
    [499, { kind: "refused", status: 499 }],
    [500, { kind: "unknown", why: "status-500" }],
  ];
  for (const [status, expected] of readable)
    assert.deepEqual(await create(status, {}), expected, `${status}`);
});

test("a transport failure is unknown with the reason transport; the request carries a live deadline", async () => {
  const failing = createAccountClient({
    base: "b",
    project: "p",
    headers: {},
    fetchImpl: async () => {
      throw new Error("network");
    },
  });
  assert.deepEqual(await failing.create({ email: "e", password: "p" }), {
    kind: "unknown",
    why: "transport",
  });
  let signal;
  const probe = createAccountClient({
    base: "b",
    project: "p",
    headers: {},
    fetchImpl: async (url, init) => {
      signal = init.signal;
      return reply(200, { localId: "u" });
    },
  });
  await probe.create({ email: "e", password: "p" });
  assert.equal(signal.aborted, false, "the deadline has not already passed");
});

test("an unknown create is looked up by its email, and a refused one is not looked up at all", async () => {
  const selectors = [];
  const client = {
    async create() {
      return { kind: "unknown", why: "transport" };
    },
    async lookup(selector) {
      selectors.push(selector);
      return [];
    },
    async remove() {
      throw new Error("nothing to remove");
    },
  };
  const s = createAccountSession({ client, run: "rr" });
  await assert.rejects(s.create(["a"]));
  await s.cleanup();
  assert.deepEqual(selectors, [{ email: ["fsl-rr-a@example.com"] }]);
});

test("a create that throws leaves the account to be looked up, like an unknown one", async () => {
  const selectors = [];
  const client = {
    async create() {
      throw new Error("surprise");
    },
    async lookup(selector) {
      selectors.push(selector);
      return ["found"];
    },
    async remove(uid) {
      selectors.push(uid);
      return { settled: true, unknownDelete: false, why: null };
    },
  };
  const s = createAccountSession({ client, run: "rr" });
  await assert.rejects(s.create(["a"]), /surprise/);
  const report = await s.cleanup();
  assert.deepEqual(selectors, [{ email: ["fsl-rr-a@example.com"] }, "found"]);
  assert.equal(report.complete, true);
});

test("the request deadline is a real one: it has not passed at once, and it passes", async () => {
  let signal;
  const client = createAccountClient({
    base: "b",
    project: "p",
    headers: {},
    fetchImpl: async (url, init) => {
      signal = init.signal;
      return reply(200, { localId: "u" });
    },
  });
  await client.create({ email: "e", password: "p" });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(signal.aborted, false, "a deadline of 0 or a few ms would have passed by now");
});

// The answers production recorded for the same routes (conformance/auth-account-production.json,
// the Identity Platform sandbox): the client must read exactly these.
const recordedAccounts = JSON.parse(
  readFileSync(new URL("../auth-account-production.json", import.meta.url), "utf8"),
);
const recordedStep = (program, step) => recordedAccounts.programs[program].steps[step];

test("the account client reads the recorded production answers: create, delete, delete again, lookup of nobody", async () => {
  const created = recordedStep("auth-account/admin/delete", "create");
  const deleted = recordedStep("auth-account/admin/delete", "delete");
  const again = recordedStep("auth-account/admin/delete", "delete-again");
  const nobody = recordedStep("auth-account/admin/batch-delete", "lookup-after-force");
  const present = recordedStep("auth-account/admin/batch-delete", "lookup-after-without-force");
  assert.equal(created.body.kind, "identitytoolkit#SignupNewUserResponse");
  assert.equal(again.status, 400);
  const clientFor = (...steps) => {
    const queue = [...steps];
    return createAccountClient({
      base: "b",
      project: "p",
      headers: {},
      fetchImpl: async () => {
        const next = queue.length > 1 ? queue.shift() : queue[0];
        return { status: next.status, json: async () => structuredClone(next.body) };
      },
    });
  };
  assert.deepEqual(await clientFor(created).create({ email: "e", password: "p" }), {
    kind: "created",
    uid: created.body.localId,
  });
  assert.deepEqual(await clientFor(nobody).lookup({ localId: ["x"] }), []);
  assert.deepEqual(
    await clientFor(present).lookup({ localId: ["x"] }),
    present.body.users.map((u) => u.localId),
  );
  // Delete then a lookup of nobody: gone and settled; the delete's own answer was a clean 200.
  assert.deepEqual(await clientFor(deleted, nobody).remove("u"), {
    settled: true,
    unknownDelete: false,
    why: null,
  });
  // Deleting an account that is already gone is a definite 400 refusal, not an unknown answer.
  assert.deepEqual(await clientFor(again, nobody).remove("u"), {
    settled: true,
    unknownDelete: false,
    why: null,
  });
});

const memoryJournal = () => {
  const lines = [];
  return { lines, append: (record) => lines.push(record), close() {} };
};

test("the journal gets the email before the create and the uid after it, then the delete before and after", async () => {
  const journal = memoryJournal();
  const seenBeforeCreate = [];
  const client = {
    async create() {
      seenBeforeCreate.push(journal.lines.map((l) => [l.type, l.phase, l.email]));
      return { kind: "created", uid: "ua" };
    },
    async lookup() {
      return [];
    },
    async remove() {
      return { settled: true, unknownDelete: false, why: null };
    },
  };
  const s = createAccountSession({ client, run: "rr", journal });
  await s.create(["a"]);
  assert.deepEqual(seenBeforeCreate, [[["account", "before", "fsl-rr-a@example.com"]]]);
  await s.cleanup();
  assert.deepEqual(
    journal.lines.map((l) => [l.type, l.phase, l.state ?? l.outcome]),
    [
      ["account", "before", undefined],
      ["account", "after", "created"],
      ["account-delete", "before", undefined],
      ["account-delete", "after", "answered"],
    ],
  );
  assert.equal(journal.lines[1].uid, "ua");
  assert.equal(journal.lines[2].uid, "ua");
  const text = JSON.stringify(journal.lines);
  assert.ok(!text.includes("Fsl-rr-a-"), "the password never reaches the journal");
});

test("a create that throws is journaled as unknown, and an unknown delete as unknown", async () => {
  const journal = memoryJournal();
  const throwing = createAccountSession({
    client: {
      async create() {
        throw new Error("boom");
      },
    },
    run: "rr",
    journal,
  });
  await assert.rejects(throwing.create(["a"]), /boom/);
  assert.equal(journal.lines.at(-1).state, "unknown");
  const deleting = memoryJournal();
  const s = createAccountSession({
    client: {
      async create() {
        return { kind: "created", uid: "ua" };
      },
      async remove() {
        return { settled: true, unknownDelete: true, why: null };
      },
    },
    run: "rr",
    journal: deleting,
  });
  await s.create(["a"]);
  await s.cleanup();
  assert.equal(deleting.lines.at(-1).outcome, "unknown");
});

test("an unknown create found by email journals the uid it learned, and every cleanup row names email and uid", async () => {
  const journal = memoryJournal();
  const client = {
    async create() {
      return { kind: "unknown", why: "transport" };
    },
    async lookup() {
      return ["uf"];
    },
    async remove(uid) {
      return { settled: false, unknownDelete: true, why: "still-present", uid };
    },
  };
  const s = createAccountSession({ client, run: "rr", journal });
  await assert.rejects(s.create(["a"]), /unknown transport/);
  const report = await s.cleanup();
  assert.ok(journal.lines.some((l) => l.state === "found-by-email" && l.uid === "uf"));
  assert.deepEqual(report.rows[0].uid, "uf");
  assert.deepEqual(report.rows[0].email, "fsl-rr-a@example.com");
  const notFound = createAccountSession({
    client: { ...client, lookup: async () => [] },
    run: "rr",
  });
  await assert.rejects(notFound.create(["a"]), /unknown/);
  const rows = (await notFound.cleanup()).rows;
  assert.equal(rows[0].why, "create-unknown-not-found");
  assert.equal(rows[0].email, "fsl-rr-a@example.com");
  assert.ok(!("uid" in rows[0]));
});

test("the account client counts every request it sends, whatever the answer", async () => {
  const { fetchImpl } = scripted({
    "/accounts": [[200, { localId: "u" }]],
    "/accounts:lookup": ["throw"],
    "/accounts:delete": [[500, {}]],
  });
  const client = createAccountClient({ base: "https://x", project: "p", headers: {}, fetchImpl });
  assert.equal(client.requestCount(), 0);
  await client.create({ email: "e", password: "p" });
  await client.lookup({ localId: ["u"] });
  assert.equal(client.requestCount(), 2);
  await client.remove("u");
  assert.equal(client.requestCount(), 4, "remove sends a delete and a lookup");
});

test("journal lines of an account carry their type and phase in every path", async () => {
  const journal = memoryJournal();
  const s = createAccountSession({
    client: {
      async create() {
        throw new Error("boom");
      },
      async lookup() {
        return ["uf"];
      },
      async remove() {
        return { settled: true, unknownDelete: false, why: null };
      },
    },
    run: "rr",
    journal,
  });
  await assert.rejects(s.create(["a"]), /boom/);
  assert.deepEqual(
    journal.lines.map((l) => [l.type, l.phase, l.state]),
    [
      ["account", "before", undefined],
      ["account", "after", "unknown"],
    ],
  );
  await s.cleanup();
  const found = journal.lines.find((l) => l.state === "found-by-email");
  assert.equal(found.type, "account");
  assert.equal(found.phase, "after");
  assert.equal(found.uid, "uf");
});

test("a refused create is journaled without a uid", async () => {
  const journal = memoryJournal();
  const s = createAccountSession({
    client: {
      async create() {
        return { kind: "refused", status: 400 };
      },
    },
    run: "rr",
    journal,
  });
  await assert.rejects(s.create(["a"]), /refused/);
  const after = journal.lines.at(-1);
  assert.equal(after.state, "refused");
  assert.equal("uid" in after, false);
});

test("account admission refuses before fetch and sent count increment", async () => {
  let sent = 0;
  const c = createAccountClient({
    base: "https://x",
    project: "p",
    headers: {},
    beforeSend: () => {
      throw new Error("parent work cap");
    },
    fetchImpl: async () => {
      sent++;
      return { status: 200, json: async () => ({ localId: "u" }) };
    },
  });
  await assert.rejects(c.create({ email: "a@example.com", password: "p" }), /parent work cap/);
  assert.equal(sent, 0);
  assert.equal(c.requestCount(), 0);
});

test("selected account cancellation bounds a hung response body and retains deadline reason", async () => {
  const controller = new AbortController();
  const c = createAccountClient({
    base: "https://x",
    project: "p",
    headers: {},
    beforeSend: () => ({ signal: controller.signal, timeoutMs: 30_000 }),
    fetchImpl: async () => ({ status: 200, json: () => new Promise(() => {}) }),
  });
  const pending = c.create({ email: "a@example.com", password: "p" });
  await Promise.resolve();
  controller.abort(new Error("parent work deadline"));
  assert.deepEqual(await pending, { kind: "unknown", why: "parent work deadline" });
  assert.equal(c.requestCount(), 1);
});

test("account session retains exact uncertain email and UID without credentials for incomplete cleanup", async () => {
  const s = createAccountSession({
    run: "r1",
    client: {
      create: async () => ({ kind: "created", uid: "u1" }),
      remove: async () => {
        throw new Error("parent cleanup deadline");
      },
    },
  });
  await s.create(["a"]);
  await assert.rejects(s.cleanup(), /parent cleanup deadline/);
  assert.deepEqual(s.entries(), [
    { name: "a", email: "fsl-r1-a@example.com", uid: "u1", state: "created" },
  ]);
  assert.equal(Object.hasOwn(s.entries()[0], "password"), false);
});
