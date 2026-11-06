import { createHash } from "node:crypto";
import { createBreadthBudget } from "./breadth-wiring.mjs";
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
  const dir = await mkdtemp(join(tmpdir(), "breadth-rules-"));
  const baseline = '{\r\n  "rules": { ".read": false, ".write": false }\r\n}\r\n';
  const rows = [];
  const budget = createBreadthBudget();
  let installed,
    savedBeforePut = false;
  const client = createRtdb({
    runDir: dir,
    nonce: "nonce",
    log: (row) => rows.push(row),
    sleep: async () => {},
    packet: {
      projectNumber: "123456789012",
      baselineRulesSha256: createHash("sha256").update(baseline).digest("hex"),
    },
    fetchImpl: async (url, init) => {
      budget.take("rtdbAdmin");
      assert.equal(client.run.state.api, "baseline");
      assert.equal(client.run.state.instance, "baseline");
      let value;
      if (url.includes("serviceusage")) {
        assert.equal(init.method, "GET");
        value = { name: client.run.u.serviceName, state: "ENABLED" };
      } else if (url.includes("firebasedatabase")) {
        assert.equal(init.method, "GET");
        const instance = {
          name: client.run.u.instanceName,
          type: "USER_DATABASE",
          state: "ACTIVE",
        };
        value = url.endsWith("/instances") ? { instances: [instance] } : instance;
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
    assert.deepEqual(
      rows.map((row) => row.step),
      [
        "api-before",
        "instance-before",
        "active-before",
        "rules-before",
        "prefix-before",
        "rules-install-put",
        "rules-install-read",
      ],
    );
    budget.startCleanup();
    const result = await client.cleanup();
    assert.equal(result.closed, true);
    assert.equal(installed, baseline);
    assert.deepEqual(
      rows.slice(7).map((row) => [row.step, row.method]),
      [
        ["prefix-delete", "DELETE"],
        ["prefix-null", "GET"],
        ["rules-restore", "PUT"],
        ["rules-restored", "GET"],
      ],
    );
    assert.deepEqual(result.state, {
      api: "baseline",
      instance: "baseline",
      rules: "baseline",
      data: "baseline",
    });
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.unresolved, []);
    assert.deepEqual(result.counts.admin, {
      observe: 7,
      cleanup: 4,
      mutations: 3,
      unknown: 0,
      logFailures: 0,
    });
    assert.equal(budget.snapshot().rtdbAdmin, rows.length);
    assert.equal(budget.snapshot().total, 11);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

for (const [step, invalid] of [
  ["api-before", { state: "DISABLED" }],
  ["api-before", { name: "other" }],
  ["instance-before", { state: "DELETED" }],
  ["instance-before", { name: "other" }],
  ["instance-before", { type: "DEFAULT_DATABASE" }],
  ["active-before", { instances: [] }],
  ["active-before", { second: true }],
  ["active-before", { name: "other" }],
  ["active-before", { state: "DELETED" }],
  ["active-before", { type: "DEFAULT_DATABASE" }],
  ["active-before", { nextPageToken: "next-page" }],
  ["rules-before", { text: '{"rules":{}}' }],
  ["prefix-before", { text: "{}" }],
  ...["api-before", "instance-before", "active-before", "rules-before"].map((step) => [
    step,
    { unknown: true },
  ]),
  ["prefix-null", { text: "{}" }],
  ["rules-restored", { text: '{"rules":{}}' }],
  ["prefix-delete", { unknown: true }],
  ["rules-restore", { unknown: true }],
]) {
  test(`${step} rejects ${JSON.stringify(invalid)} without unsafe mutations`, async () => {
    const baseline = '{ "rules": { ".read": false, ".write": false } }\n';
    const rows = [];
    let installed;
    const client = createRtdb({
      nonce: "nonce",
      packet: {
        projectNumber: "123456789012",
        baselineRulesSha256: createHash("sha256").update(baseline).digest("hex"),
      },
      log: (row) => rows.push(row),
      sleep: async () => {},
      fetchImpl: async (url, init) => {
        assert.equal(client.run.state.api, "baseline");
        assert.equal(client.run.state.instance, "baseline");
        const current =
          url === client.run.u.service
            ? "api-before"
            : url === client.run.u.instance
              ? "instance-before"
              : url === client.run.u.list
                ? "active-before"
                : url.includes(".settings/rules")
                  ? init.method === "PUT"
                    ? installed === undefined
                      ? "rules-install-put"
                      : "rules-restore"
                    : installed === undefined
                      ? "rules-before"
                      : installed === baseline
                        ? "rules-restored"
                        : "rules-install-read"
                  : init.method === "DELETE"
                    ? "prefix-delete"
                    : installed === undefined
                      ? "prefix-before"
                      : "prefix-null";
        if (url === client.run.u.service || url.includes("firebasedatabase"))
          assert.equal(init.method, "GET");
        if (current === step && invalid.unknown) throw Error("offline unknown answer");
        const instance = {
          name: client.run.u.instanceName,
          type: "USER_DATABASE",
          state: "ACTIVE",
        };
        let value =
          current === "api-before"
            ? { name: client.run.u.serviceName, state: "ENABLED" }
            : current === "instance-before"
              ? instance
              : current === "active-before"
                ? { instances: [instance] }
                : init.method === "PUT"
                  ? { status: "ok" }
                  : null;
        let text;
        if (current === step) {
          if (invalid.text) text = invalid.text;
          else if (current === "active-before") {
            if (invalid.second) value.instances.push({ ...instance, name: "other" });
            else if (invalid.instances) value.instances = invalid.instances;
            else if (invalid.nextPageToken) value.nextPageToken = invalid.nextPageToken;
            else Object.assign(value.instances[0], invalid);
          } else Object.assign(value, invalid);
        }
        if (init.method === "PUT") installed = init.body;
        if (url.includes(".settings/rules") && init.method === "GET")
          text ??= installed ?? baseline;
        return { status: 200, text: async () => text ?? JSON.stringify(value) };
      },
    });
    if (["prefix-null", "rules-restored", "prefix-delete", "rules-restore"].includes(step)) {
      await client.setup();
      const result = await client.cleanup();
      assert.equal(result.closed, false);
      assert.equal(result.errors.length, 1);
      assert.match(result.errors[0], new RegExp(`^${step}:`));
      assert.equal(rows.filter((row) => row.step === step).length, 1);
      if (step.startsWith("prefix")) assert.equal(client.run.state.rules, "baseline");
    } else {
      await assert.rejects(client.setup(), new RegExp(`^Error: ${step}:`));
      assert.ok(rows.every((row) => row.method === "GET"));
      assert.equal(rows.at(-1).step, step);
      assert.equal((await client.cleanup()).closed, false);
      assert.ok(rows.every((row) => row.method === "GET"));
    }
    assert.equal(client.run.state.api, "baseline");
    assert.equal(client.run.state.instance, "baseline");
  });
}
