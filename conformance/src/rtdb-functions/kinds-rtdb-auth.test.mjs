import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createAuth } from "./breadth-auth.mjs";
import { createRtdb } from "./breadth-rtdb.mjs";
import { KINDS_CLAIMS, KINDS_SCENARIO, rulesFor } from "./kinds-scenario.mjs";
import { STEPS } from "./kinds-sequence.mjs";

const BASELINE = '{\r\n  "rules": { ".read": false, ".write": false }\r\n}\r\n';

function rtdbWorld() {
  const calls = [];
  let installed;
  const client = createRtdb({
    nonce: "nonce",
    prefix: KINDS_SCENARIO.prefix,
    rulesFor: KINDS_SCENARIO.rulesFor,
    userToken: () => "user-token",
    log: () => {},
    sleep: async () => {},
    packet: {
      projectNumber: "123456789012",
      baselineRulesSha256: createHash("sha256").update(BASELINE).digest("hex"),
    },
    fetchImpl: async (url, init) => {
      calls.push([init.method, url, init.body]);
      let value;
      if (url.includes("serviceusage"))
        value = { name: client.run.u.serviceName, state: "ENABLED" };
      else if (url.includes("firebasedatabase")) {
        const instance = {
          name: client.run.u.instanceName,
          type: "USER_DATABASE",
          state: "ACTIVE",
        };
        value = url.endsWith("/instances") ? { instances: [instance] } : instance;
      } else if (url.includes(".settings/rules")) {
        if (init.method === "PUT") {
          installed = init.body;
          value = { status: "ok" };
        } else return { status: 200, text: async () => installed ?? BASELINE };
      } else value = null;
      return { status: 200, text: async () => JSON.stringify(value) };
    },
  });
  return { client, calls, installed: () => installed };
}

test("the RTDB client of the kinds scenario reads, installs and clears its own prefix", async () => {
  const { client, calls, installed } = rtdbWorld();
  await client.setup();
  assert.ok(calls.some(([m, url]) => m === "GET" && url.endsWith("/k9-rtdb.json")));
  assert.deepEqual(JSON.parse(installed()), rulesFor("k9-rtdb", "nonce"));
  assert.ok(!calls.some(([, url]) => url.includes("g9-rtdb")));
  const result = await client.cleanup();
  assert.equal(result.closed, true);
  assert.ok(calls.some(([m, url]) => m === "DELETE" && url.endsWith("/k9-rtdb.json")));
  assert.equal(installed(), BASELINE);
});

test("admin writes of the plan go to the prefix and the root PATCH goes to the prefix node", async () => {
  const { client, calls } = rtdbWorld();
  await client.setup();
  const before = calls.length;
  for (const step of STEPS.filter((s) => s.context === "admin")) await client.write(step);
  const sent = calls.slice(before).map(([method, url]) => `${method} ${new URL(url).pathname}`);
  assert.equal(sent.length, 14);
  assert.equal(sent[0], "PUT /k9-rtdb/ga/items/a1.json");
  assert.equal(sent[4], "PATCH /k9-rtdb.json");
  assert.equal(sent[7], "PUT /k9-rtdb/gp/items/p1/.priority.json");
  assert.ok(sent.every((line) => line.includes("/k9-rtdb")));
  // the priority-only write carries the bare number
  assert.equal(calls.slice(before)[7][2], "9");
});

test("user REST writes carry the token in the URL only", async () => {
  const { client, calls } = rtdbWorld();
  await client.setup();
  const before = calls.length;
  for (const step of STEPS.filter((s) => s.context === "user-rest")) await client.write(step);
  const sent = calls.slice(before);
  assert.equal(sent.length, 3);
  assert.ok(sent.every(([, url]) => url.includes("auth=user-token")));
});

test("the default RTDB client is still the breadth one", async () => {
  const { createRtdb: create } = await import("./breadth-rtdb.mjs");
  const urls = [];
  const client = create({
    nonce: "nonce",
    userToken: () => "t",
    log: () => {},
    packet: { projectNumber: "123456789012", baselineRulesSha256: "0".repeat(64) },
    fetchImpl: async (url) => {
      urls.push(url);
      return { status: 200, text: async () => "null" };
    },
  });
  await assert.rejects(client.setup());
  assert.ok(urls.length > 0);
});

function authWorld({ update = { status: 200, body: {} } } = {}) {
  const calls = [];
  const rows = [];
  const auth = createAuth({
    projectId: "demo",
    apiKey: "key-sentinel",
    email: "user@example.test",
    password: "password-sentinel",
    claims: KINDS_CLAIMS,
    log: (row) => rows.push(row),
    fetchImpl: async (url, init) => {
      calls.push([url, init]);
      if (url.includes("signInWithPassword"))
        return {
          status: 200,
          text: async () => JSON.stringify({ localId: "uid", idToken: "token-sentinel" }),
        };
      if (url.endsWith("/accounts"))
        return { status: 200, text: async () => JSON.stringify({ localId: "uid" }) };
      if (url.endsWith("accounts:update"))
        return { status: update.status, text: async () => JSON.stringify(update.body) };
      return { status: 200, text: async () => "{}" };
    },
  });
  return { auth, calls, rows };
}

test("claims are set on the created user before the first sign-in", async () => {
  const { auth, calls, rows } = authWorld();
  await auth.create();
  assert.equal((await auth.signIn()).outcome, "ok");
  assert.deepEqual(
    calls.map(([url]) => url.split("/").at(-1).split("?")[0]),
    ["accounts", "accounts:update", "accounts:signInWithPassword"],
  );
  const update = JSON.parse(calls[1][1].body);
  assert.equal(update.localId, "uid");
  assert.deepEqual(JSON.parse(update.customAttributes), KINDS_CLAIMS);
  assert.equal(auth.idToken, "token-sentinel");
  assert.ok(!JSON.stringify(rows).includes("k9role"), "the claims body is not journaled");
});

test("a refused or unknown claims update stops before any sign-in and leaves the user deletable", async () => {
  for (const [status, outcome] of [
    [400, "refused"],
    [500, "unknown"],
  ]) {
    const { auth, calls } = authWorld({ update: { status, body: {} } });
    await auth.create();
    const signed = await auth.signIn();
    assert.equal(signed.outcome, outcome);
    assert.equal(auth.idToken, undefined);
    assert.ok(!calls.some(([url]) => url.includes("signInWithPassword")));
    // the user exists, so it is still deleted and read back
    assert.equal(await auth.delete(), "ok");
    assert.equal(await auth.confirmGone(), true);
    await assert.rejects(auth.signIn());
  }
});

test("without claims the sign-in is the breadth one: no update request", async () => {
  const calls = [];
  const auth = createAuth({
    projectId: "demo",
    apiKey: "k",
    email: "e@example.test",
    password: "p",
    log: () => {},
    fetchImpl: async (url) => {
      calls.push(url);
      return {
        status: 200,
        text: async () => JSON.stringify({ localId: "uid", idToken: "t" }),
      };
    },
  });
  await auth.create();
  await auth.signIn();
  assert.equal(calls.length, 2);
});
