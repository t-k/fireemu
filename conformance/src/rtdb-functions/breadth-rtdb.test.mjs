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
  let token;
  const client = createRtdb({
    packet: {},
    nonce: "nonce",
    userToken: () => token,
    log: (row) => rows.push(row),
    fetchImpl: async (url) => {
      urls.push(url);
      if (urls.length === 2) throw Error(url);
      return { status: 200, text: async () => "{}" };
    },
  });
  token = "sentinel-token";
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
  assert.ok(urls.every((url) => url.includes("auth=sentinel-token")));
  assert.ok(rows.every((r) => r.url.includes("auth=***")));
  assert.ok(!JSON.stringify(rows).includes("sentinel-token"));
});

test("a write identifier cannot be sent twice after an unknown answer", async () => {
  let calls = 0;
  const client = createRtdb({
    packet: {},
    nonce: "n",
    userToken: () => "u",
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

test("verified raw baseline Rules are saved privately before installation", async () => {
  const { mkdtemp, readFile, rm, stat } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { createHash } = await import("node:crypto");
  const dir = await mkdtemp(join(tmpdir(), "breadth-rules-"));
  const baseline = '{\r\n  "rules": { ".read": false, ".write": false }\r\n}\r\n';
  let api = "DISABLED",
    instance = "DELETED",
    installed,
    savedBeforePut = false;
  const client = createRtdb({
    runDir: dir,
    nonce: "nonce",
    log: () => {},
    sleep: async () => {},
    packet: {
      projectNumber: "123456789012",
      baselineRulesSha256: createHash("sha256").update(baseline).digest("hex"),
    },
    fetchImpl: async (url, init) => {
      let value;
      if (url.includes("serviceusage")) {
        if (url.endsWith(":enable")) {
          api = "ENABLED";
          value = { name: "operations/enable", done: true };
        } else value = { name: client.run.u.serviceName, state: api };
      } else if (url.includes("firebasedatabase")) {
        if (url.endsWith(":undelete")) instance = "ACTIVE";
        value = url.endsWith("/instances")
          ? {}
          : { name: client.run.u.instanceName, type: "USER_DATABASE", state: instance };
      } else if (url.includes(".settings/rules")) {
        if (init.method === "PUT") {
          savedBeforePut = (await readFile(join(dir, "baseline.rules.json"), "utf8")) === baseline;
          assert.equal((await stat(join(dir, "baseline.rules.json"))).mode & 0o777, 0o600);
          installed = init.body;
          value = { status: "ok" };
        } else return { status: 200, text: async () => installed ?? baseline };
      } else value = null;
      return { status: 200, text: async () => JSON.stringify(value) };
    },
  });
  try {
    await client.setup();
    assert.equal(savedBeforePut, true);
    assert.equal(await readFile(join(dir, "baseline.rules.json"), "utf8"), baseline);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
