// Closure rules of the blocking check: the inventory compared by identity in the run and in A2, the configuration forms the
// CLI leaves, the CLI's own writes, the sign-up that the key refuses, and the journal that must not keep the API key.
import assert from "node:assert/strict";
import { closeSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  INVENTORY_KINDS,
  cliWritesFromOutput,
  iamUnexpected,
  inventoryDifferences,
  redactCliText,
} from "./deploy.mjs";
import { readbackRun, READBACK_MAX_REQUESTS } from "./readback.mjs";
import { lastActivity, main, redactRow, resultOf, writeAll } from "./main.mjs";
import { sourceBuckets } from "./plan.mjs";
import { configDifference, record } from "./run.mjs";
import { tempDir } from "./testtmp.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const [UPLOADS, SOURCES] = sourceBuckets(NUMBER);
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send, wrapCli = (cli) => cli) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: wrapSend(world.send, world),
    runCli: wrapCli((args) => world.runCli(args), world),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, journal, result };
}
const a2 = (world, result, over = {}) =>
  readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: over.send ?? world.send,
    localId: result.signUp.localId,
    accountsBefore: result.inventory.before.accounts,
    configBeforeDigest: result.configBefore.sha256,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
    baseline: world.baseline,
    ...over,
  });

// ---- the configuration forms the CLI leaves -----------------------------------------------------------------------

test("the CLI leaves forwardInboundCredentials: {} behind and the run still closes; the form is recorded", async () => {
  const { result, world } = await go();
  assert.deepEqual(world.config.blockingFunctions, { forwardInboundCredentials: {} });
  assert.equal(result.cleanup.configRestored, true);
  assert.deepEqual(result.cleanup.configDifference, []);
  assert.equal(result.cleanup.blockingForm.before, "null");
  assert.equal(result.cleanup.blockingForm.after, '{"forwardInboundCredentials":{}}');
  assert.equal(result.outcome, "pcblock-recorded");
  assert.equal(result.closureReady, true);
  const rb = await a2(world, result);
  assert.equal(rb.allAbsent, true, JSON.stringify(rb));
  assert.equal(rb.config.blockingEmpty, true);
  assert.equal(rb.config.digestMatches, true);
});

test("forwarding that forwards nothing, in any of its forms, is the baseline; a member set to true, a trigger left or another key is a failed cleanup", async () => {
  for (const [label, forwardInbound] of [
    ["absent", undefined],
    ["empty", {}],
    ["all false", { idToken: false, accessToken: false, refreshToken: false }],
  ]) {
    const { result } = await go({ forwardInbound });
    assert.equal(result.cleanup.verified, true, label);
    assert.deepEqual(result.cleanup.configDifference, [], label);
  }
  for (const [label, forwardInbound] of [
    ["an id token forwarded", { idToken: true }],
    ["a refresh token forwarded", { idToken: false, refreshToken: true }],
  ]) {
    const { result, world } = await go({ forwardInbound });
    assert.deepEqual(result.cleanup.configDifference, ["blockingFunctions"], label);
    assert.equal(result.cleanup.verified, false, label);
    assert.equal(result.outcome, "pcblock-needs-recovery", label);
    assert.equal(result.closureReady, false, label);
    assert.equal(
      world.calls.filter((c) => /config/.test(c) && !c.startsWith("GET ")).length,
      0,
      "never written",
    );
    const rb = await a2(world, result);
    assert.equal(rb.allAbsent, false, label);
    assert.equal(rb.config.blockingEmpty, false, label);
  }
  const left = await go({ leaveTrigger: true });
  assert.equal(left.result.cleanup.verified, false);
  const other = await go({ deleteLeaves: { forwardInboundCredentials: {}, somethingElse: 1 } });
  assert.equal(other.result.cleanup.verified, false);
});

test("the function's address may be its own url or the Cloud Run service's; either is recorded and judged as the function's address", async () => {
  for (const registerWith of ["url", "run"]) {
    const { result } = await go({ registerWith });
    assert.equal(result.judged.cases["trigger-registered"].status, "as-expected", registerWith);
    assert.equal(result.judged.cases["blocking-claims"].status, "as-expected", registerWith);
  }
});

// ---- the inventory in the run and in A2 ----------------------------------------------------------------------------

test("a service added, a stray trigger, subscription, topic or image, or an unreadable list keeps the cleanup unverified", async () => {
  const cases = [
    ["services", (w) => w.services.add("extra.googleapis.com")],
    ["triggers", (w) => w.triggers.add("stray")],
    ["subscriptions", (w) => w.subscriptions.add("stray")],
    ["topics", (w) => w.topics.add("stray")],
    ["packages", (w) => w.packages.add("somebody-else")],
  ];
  for (const [kind, change] of cases) {
    const { result } = await go({}, (send, w) => async (request) => {
      if (w.cliRuns.includes("delete")) change(w);
      return send(request);
    });
    assert.ok(
      result.inventory.differences.some((d) => d.kind === kind),
      kind + JSON.stringify(result.inventory),
    );
    assert.equal(result.cleanup.verified, false, kind);
    assert.equal(result.closureReady, false, kind);
    assert.equal(result.outcome, "pcblock-needs-recovery", kind);
  }
  for (const needle of ["/triggers", "/subscriptions", "/topics", "services?filter"]) {
    const { result } = await go(
      {},
      (send, w) => async (request) =>
        request.method === "GET" && request.url.includes(needle) && w.cliRuns.includes("delete")
          ? error(500, "INTERNAL")
          : send(request),
    );
    assert.equal(result.inventory.complete, false, needle);
    assert.equal(result.cleanup.verified, false, needle);
  }
  const same = await go({ foreignSubscriptions: 2 });
  assert.deepEqual(same.result.inventory.differences, []);
  assert.equal(same.result.inventory.before.subscriptions.length, 2);
});

test("only a service-agent addition to the project IAM is expected; a removal or any other member blocks the closure", async () => {
  const base = [{ role: "roles/owner", members: ["user:a@example.com"] }];
  const wrap = (members) => (send, w) => async (request) => {
    if (request.url.includes("cloudresourcemanager") && request.url.endsWith(":getIamPolicy"))
      return reply(200, {
        version: 1,
        etag: "e",
        bindings: w.cliRuns.includes("delete") ? members : base,
      });
    return send(request);
  };
  const agent = await go(
    {},
    wrap([
      ...base,
      { role: "roles/run.invoker", members: ["serviceAccount:x@y.iam.gserviceaccount.com"] },
    ]),
  );
  assert.deepEqual(agent.result.inventory.differences, []);
  const removed = await go({}, wrap([]));
  assert.ok(removed.result.inventory.differences.some((d) => d.kind === "iam"));
  assert.equal(removed.result.cleanup.verified, false);
  const user = await go(
    {},
    wrap([...base, { role: "roles/viewer", members: ["user:b@example.com"] }]),
  );
  assert.ok(user.result.inventory.differences.some((d) => d.kind === "iam"));
});

test("the A2 read-back compares the inventory with the preflight's by identity and carries the open obligations", async () => {
  const { world, result } = await go();
  const clean = await a2(world, result, { carried: ["upload:no-receipt"] });
  assert.equal(clean.allAbsent, true);
  assert.deepEqual(clean.inventory, {
    baseline: true,
    complete: true,
    missing: [],
    differences: [],
  });
  assert.deepEqual(clean.carried, ["upload:no-receipt"]);
  assert.ok(clean.attempted <= READBACK_MAX_REQUESTS, String(clean.attempted));
  const changes = [
    ["services", (w) => w.services.add("extra.googleapis.com")],
    ["triggers", (w) => w.triggers.add("stray")],
    ["subscriptions", (w) => w.subscriptions.add("stray")],
    ["topics", (w) => w.topics.add("stray")],
    ["packages", (w) => w.packages.add("stray")],
    ["uploadObjects", (w) => w.sourceBuckets.get(UPLOADS).push("stray.zip")],
    ["sourceObjects", (w) => w.sourceBuckets.get(SOURCES).push("pcblock/other.zip")],
  ];
  for (const [kind, change] of changes) {
    const fresh = await go();
    change(fresh.world);
    const rb = await a2(fresh.world, fresh.result);
    assert.equal(rb.allAbsent, false, kind);
    assert.ok(
      rb.inventory.differences.some((d) => d.kind === kind),
      kind,
    );
  }
  for (const needle of [
    "/triggers",
    "/subscriptions",
    "/topics",
    "services?filter",
    "gcf-v2-uploads",
    "gcf-v2-sources",
  ]) {
    const fresh = await go();
    const rb = await a2(fresh.world, fresh.result, {
      send: async (request) =>
        request.method === "GET" &&
        request.url.includes(needle) &&
        fresh.world.cliRuns.includes("delete")
          ? error(500, "INTERNAL")
          : fresh.world.send(request),
    });
    assert.equal(rb.allAbsent, false, needle);
    assert.equal(rb.inventory.complete, false, needle);
  }
  const none = await a2(world, result, { baseline: null });
  assert.equal(none.allAbsent, false);
  assert.deepEqual(none.inventory.missing, ["baseline"]);
});

test("resultOf hands the baseline and every open obligation to the read-back", () => {
  const d = tempDir("pcb-cl-");
  const path = join(d, "r.json");
  writeFileSync(
    path,
    JSON.stringify({
      unconfirmedCreates: [],
      inventory: {
        before: { accounts: 3, triggers: [] },
        complete: false,
        differences: [{ kind: "topics", added: ["t"], removed: [] }],
      },
      cleanup: {
        uploadReasons: ["no-receipt"],
        uploadObjectsUnexplained: [{ bucket: "b", name: "n.zip" }],
        configDifference: ["blockingFunctions"],
      },
    }),
  );
  const judged = resultOf(path);
  assert.deepEqual(judged.baseline, { accounts: 3, triggers: [] });
  assert.deepEqual(judged.carried, [
    "upload:no-receipt",
    "unexplained-upload-object:n.zip",
    'inventory:{"kind":"topics","added":["t"],"removed":[]}',
    "inventory-incomplete",
    "config-difference:blockingFunctions",
  ]);
  writeFileSync(
    path,
    JSON.stringify({ unconfirmedCreates: [], cleanup: { configDifference: [] } }),
  );
  assert.deepEqual(resultOf(path).carried, []);
  assert.equal(configDifference(null, null), null);
});

// ---- the CLI's own writes -------------------------------------------------------------------------------------------

test("every CLI write is journaled; one that was retried, unanswered or refused is an unknown write that only A2 closes", async () => {
  const ok = {
    method: "PATCH",
    url: "identitytoolkit.googleapis.com/admin/v2/projects/p/config",
    requests: 1,
    statuses: [200],
    class: "ok",
  };
  const clean = await go({ cliWrites: [ok] });
  assert.equal(clean.journal.filter((r) => r.state === "cli-write").length, 3);
  assert.equal(clean.result.closureReady, true);
  for (const cls of ["retried", "unanswered", "non-2xx"]) {
    const bad = {
      ...ok,
      class: cls,
      statuses: cls === "unanswered" ? [] : [503, 200],
      requests: cls === "retried" ? 2 : 1,
    };
    const { result, journal } = await go({ cliWrites: [ok, bad] });
    assert.equal(result.closureReady, false, cls);
    assert.equal(result.readBackRequired, true, cls);
    assert.ok(
      result.unknownMutationList.some((m) => m.class === "cli-write-" + cls),
      cls,
    );
    assert.ok(
      journal.some((r) => r.state === "cli-write" && r.class === cls),
      cls,
    );
  }
  const { result } = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({ ...(await cli(args)), cliWrites: null }),
  );
  assert.equal(
    result.unknownMutationList.filter((m) => m.class === "cli-log-unreadable").length,
    2,
  );
  assert.equal(result.closureReady, false);
});

// ---- malformed JSON ------------------------------------------------------------------------------------------------------

test("a 200, 201 or 202 whose JSON body does not parse is an unknown answer; an empty 204 and an object are answers", async () => {
  for (const status of [200, 201, 202]) {
    let sent = 0;
    const { result } = await go({}, (send) => async (request) => {
      if (request.url.endsWith("accounts:delete") || request.url.includes("/accounts:delete")) {
        sent += 1;
        await send(request);
        return new Response("not-json", { status });
      }
      return send(request);
    });
    assert.equal(sent, 1, String(status));
    assert.equal(result.closureReady, false, String(status));
    assert.equal(result.readBackRequired, true, String(status));
    assert.ok(
      result.unknownMutationList.some((m) => m.class === "unreadable"),
      String(status),
    );
  }
  const empty = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" &&
      request.url.includes("gcf-v2-uploads") &&
      request.url.includes("ifGenerationMatch")
        ? (await send(request), new Response(null, { status: 204 }))
        : send(request),
  );
  assert.equal(empty.result.unknownMutationList.length, 0);
});

// ---- the API key and the journal -------------------------------------------------------------------------------------

test("the identity configuration's API key never reaches the journal: the row keeps the body without it and says so", () => {
  const body = {
    name: "projects/p/config",
    client: { apiKey: "SECRET-KEY-VALUE", permissions: {} },
    mfa: {},
  };
  const row = (id, b = body) => ({
    id,
    state: "response-persisted",
    bodyBase64: Buffer.from(JSON.stringify(b)).toString("base64"),
    bodyBytes: 99,
  });
  for (const id of ["config-before", "config-after-deploy", "config-after", "read-config"]) {
    const redacted = redactRow(row(id));
    const stored = JSON.parse(Buffer.from(redacted.bodyBase64, "base64").toString());
    assert.equal(stored.client.apiKey, "[REDACTED]", id);
    assert.deepEqual(stored.client.permissions, {}, id);
    assert.deepEqual(redacted.bodyRedacted, ["client.apiKey"], id);
    assert.equal(redacted.bodyBytes, 99, "the raw size is kept");
    assert.ok(!JSON.stringify(redacted).includes("SECRET-KEY-VALUE"));
    assert.ok(!Buffer.from(redacted.bodyBase64, "base64").toString().includes("SECRET-KEY-VALUE"));
  }
  const same = row("op-sign-up");
  assert.equal(redactRow(same), same, "another row is untouched");
  const noKey = row("config-before", { name: "x", client: {} });
  assert.equal(redactRow(noKey), noKey);
  const notJson = { id: "config-before", bodyBase64: Buffer.from("<html>").toString("base64") };
  assert.equal(redactRow(notJson), notJson);
  const keyNotText = row("config-before", { client: { apiKey: 5 } });
  assert.equal(redactRow(keyNotText), keyNotText);
  assert.equal(redactRow({ id: "config-before" }).bodyBase64, undefined);
  assert.equal(redactRow(null), null);
  assert.equal(
    redactRow({ id: "preconfig-before", bodyBase64: row("x").bodyBase64 }).bodyRedacted,
    undefined,
  );
});

test("the record command writes configuration rows through the redaction, a production-sized row survives, and the key is not on disk", async () => {
  const d = tempDir("pcb-cl-");
  const big = Buffer.alloc(9 * 1024 * 1024, "b").toString("base64");
  const config = Buffer.from(JSON.stringify({ client: { apiKey: "SECRET-KEY-VALUE" } })).toString(
    "base64",
  );
  const SHA = "a".repeat(40);
  const deps = {
    nodeVersion: () => "22.22.1",
    firebaseToolsVersion: () => "15.28.2",
    gitHead: () => SHA,
    gitDirty: () => false,
    adcExists: () => true,
    sdkProblems: () => [],
    repoRoot: () => "/repo",
    prepareSource: () => ({ configPath: "/s/firebase.json", fixtureDir: "/s/fixture" }),
    sourceProblems: () => [],
    token: () => "tok-abcdefgh12345",
    send: async () => new Response("{}"),
    runCli: async () => ({}),
    signals: () => {},
    readFile: () =>
      JSON.stringify({ projectId: "fireemu-oracle-idp", apiKey: "AIza" + "x".repeat(35) }),
    record: async (o) => {
      await o.save({
        id: "config-before",
        state: "response-persisted",
        dispatchAt: "2026-11-05T00:00:00.000Z",
        bodyBase64: config,
      });
      await o.save({
        id: "logs-final-frames",
        state: "response-persisted",
        responseAt: "2026-11-05T00:30:00.000Z",
        bodyBase64: big,
      });
      return { outcome: "x", closureReady: true, attempted: 2, unconfirmedCreates: [] };
    },
  };
  const out = [];
  const err = [];
  const code = await main(
    [
      "record",
      "--run-dir",
      d,
      "--project-number",
      "123456789012",
      "--source-commit",
      SHA,
      "--venv-dir",
      "/v",
      "--node",
      "/n/node",
      "--firebase-js",
      "/f/lib/bin.js",
      "--web-config",
      "/w/config.json",
      "--send",
      "--expect-digest",
      "d".repeat(64),
    ],
    {
      env: { HOME: "/h", PATH: "/usr/bin" },
      deps,
      out: (m) => out.push(m),
      err: (m) => err.push(m),
      digest: "d".repeat(64),
    },
  );
  assert.equal(code, 0, err.join("\n"));
  const { readdirSync } = await import("node:fs");
  const journal = readdirSync(d).find((f) => f.startsWith("journal-"));
  const text = readFileSync(join(d, journal), "utf8");
  assert.ok(!text.includes("SECRET-KEY-VALUE"));
  assert.ok(
    !Buffer.from(text.split("\n")[0].match(/"bodyBase64":"([^"]+)"/)[1], "base64")
      .toString()
      .includes("SECRET-KEY-VALUE"),
  );
  assert.equal(text.trimEnd().split("\n").length, 2);
  assert.equal(lastActivity(join(d, journal)), Date.parse("2026-11-05T00:30:00.000Z"));
});

test("writeAll writes everything even when the descriptor takes a few bytes at a time, and refuses to spin", () => {
  const taken = [];
  writeAll(1, "héllo wörld", (fd, bytes, offset, length) => {
    const n = Math.min(3, length);
    taken.push(Buffer.from(bytes.subarray(offset, offset + n)));
    return n;
  });
  assert.deepEqual(Buffer.concat(taken), Buffer.from("héllo wörld"));
  assert.throws(() => writeAll(1, "x", () => 0), /no progress/);
  assert.throws(() => writeAll(1, "x", () => undefined), /no progress/);
  writeAll(1, "", () => assert.fail("nothing to write"));
  const d = tempDir("pcb-cl-");
  const path = join(d, "j");
  const fd = openSync(path, "a");
  writeAll(fd, "x".repeat(12 * 1024 * 1024));
  closeSync(fd);
  assert.equal(readFileSync(path, "utf8").length, 12 * 1024 * 1024);
});

// ---- the pure parts of the closure -----------------------------------------------------------------------------------

const REQ = (m, u, q = "[none]") => `[t] >>> [apiv2][query] ${m} https://${u} ${q}`;
const STAT = (m, u, c) => `[t] <<< [apiv2][status] ${m} https://${u} ${c}`;

test("the CLI log parser gives every mutating request with its answers, keeps PUTs to other hosts, and draws the 2xx line at 200 and 299", () => {
  const text = [
    REQ("PUT", "identitytoolkit.googleapis.com/admin/v2/projects/p/config"),
    STAT("PUT", "identitytoolkit.googleapis.com/admin/v2/projects/p/config", 200),
    REQ(
      "PUT",
      "storage.googleapis.com/gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com/u.zip",
    ),
    REQ("POST", "x.appspot.com.example/a"),
    STAT("POST", "x.appspot.com.example/a", 200),
    REQ("POST", "iam.example/r"),
    STAT("POST", "iam.example/r", 299),
    REQ("DELETE", "iam.example/r"),
    STAT("DELETE", "iam.example/r", 300),
    REQ("PATCH", "iam.example/s"),
    STAT("PATCH", "iam.example/s", 199),
    REQ("PUT", "iam.example/t"),
    STAT("PUT", "iam.example/t", 201),
    REQ("PUT", "iam.example/u"),
    REQ("PUT", "iam.example/u"),
    STAT("PUT", "iam.example/u", 503),
    STAT("PUT", "iam.example/u", 200),
    REQ("PUT", "iam.example/v"),
    REQ("PUT", "iam.example/v"),
    STAT("PUT", "iam.example/v", 200),
    STAT("PUT", "iam.example/v", 201),
    REQ("POST", "iam.example/w:getIamPolicy"),
    REQ("POST", "iam.example/entries:list"),
    REQ("POST", "iam.example/w:testIamPermissions"),
    REQ("POST", "iam.example/w:generateUploadUrl"),
    REQ("GET", "iam.example/g"),
    "not a log line",
    "[t] >>> [apiv2][query] POST not-a-url x",
  ].join("\n");
  const found = Object.fromEntries(
    cliWritesFromOutput(text).map((w) => [`${w.method} ${w.url}`, w]),
  );
  assert.deepEqual(Object.keys(found), [
    "PUT identitytoolkit.googleapis.com/admin/v2/projects/p/config",
    "POST x.appspot.com.example/a",
    "POST iam.example/r",
    "DELETE iam.example/r",
    "PATCH iam.example/s",
    "PUT iam.example/t",
    "PUT iam.example/u",
    "PUT iam.example/v",
  ]);
  assert.equal(found["POST iam.example/r"].class, "ok");
  assert.equal(found["DELETE iam.example/r"].class, "non-2xx");
  assert.equal(found["PATCH iam.example/s"].class, "non-2xx");
  assert.equal(found["PUT iam.example/t"].class, "ok");
  assert.equal(found["PUT iam.example/u"].class, "retried");
  assert.equal(
    found["PUT iam.example/v"].class,
    "retried",
    "two requests are a retry or a repeat whatever the answers",
  );
  assert.deepEqual(found["PUT iam.example/u"].statuses, [503, 200]);
  assert.deepEqual(cliWritesFromOutput(""), []);
  assert.equal(
    cliWritesFromOutput(
      REQ("POST", "x.example/a") +
        "\n" +
        REQ("POST", "x.example/a") +
        "\n" +
        STAT("POST", "x.example/a", 200),
    )[0].class,
    "retried",
  );
});

test("redactCliText takes signed upload URLs and API key values out and nothing else", () => {
  const text =
    'url https://storage.googleapis.com/b/o.zip?X-Goog-Signature=SIGNED&GoogleAccessId=x end\n{"client":{"apiKey" : "SECRET"}}\nkeep https://example.com/a?b=c';
  const out = redactCliText(text);
  assert.ok(!/SIGNED|SECRET/.test(out));
  assert.ok(out.includes("[REDACTED UPLOAD URL]") && out.includes('"apiKey":"[REDACTED]"'));
  assert.ok(out.includes("keep https://example.com/a?b=c"));
  assert.equal(redactCliText(5), "5");
});

test("inventoryDifferences compares by identity and allows only the build's copy and what the run enabled", () => {
  const before = {
    triggers: ["t1"],
    subscriptions: ["s1", "s2"],
    topics: ["p1"],
    packages: ["k1"],
    services: ["a", "b"],
    sourceObjects: { uploads: ["u1"], sources: ["pcblock/function-source.zip"] },
  };
  const kinds = ["triggers", "subscriptions", "topics", "packages"];
  const same = structuredClone(before);
  assert.deepEqual(inventoryDifferences({ before, after: same, kinds }), {
    complete: true,
    missing: [],
    differences: [],
  });
  assert.deepEqual(
    inventoryDifferences({ before, after: { ...same, subscriptions: ["s1", "s3"] }, kinds })
      .differences,
    [{ kind: "subscriptions", added: ["s3"], removed: ["s2"] }],
  );
  assert.equal(
    inventoryDifferences({ before, after: { ...same, services: ["a", "b", "c"] }, kinds })
      .differences.length,
    1,
  );
  assert.deepEqual(
    inventoryDifferences({
      before,
      after: { ...same, services: ["a", "b", "c"] },
      kinds,
      enabled: ["c"],
    }).differences,
    [],
  );
  assert.equal(
    inventoryDifferences({ before, after: { ...same, services: ["a"] }, kinds, enabled: ["a"] })
      .differences.length,
    1,
  );
  const copies = {
    ...same,
    sourceObjects: {
      uploads: ["u1"],
      sources: [
        "pcblock/function-source.zip",
        "pcblock/function-source.zip".replace("pcblock", "pcblock"),
      ],
    },
  };
  assert.deepEqual(inventoryDifferences({ before, after: copies, kinds }).differences, []);
  const odd = {
    ...same,
    sourceObjects: {
      uploads: ["u1"],
      sources: ["pcblock/function-source.zip", "other/function-source.zip", "pcblock/x.zip"],
    },
  };
  assert.deepEqual(inventoryDifferences({ before, after: odd, kinds }).differences, [
    { kind: "sourceObjects", added: ["other/function-source.zip", "pcblock/x.zip"], removed: [] },
  ]);
  assert.deepEqual(
    inventoryDifferences({
      before,
      after: {
        ...same,
        sourceObjects: { uploads: ["u1", "u2"], sources: ["pcblock/function-source.zip"] },
      },
      kinds,
    }).differences,
    [{ kind: "uploadObjects", added: ["u2"], removed: [] }],
  );
  assert.equal(
    inventoryDifferences({
      before,
      after: { ...same, sourceObjects: { uploads: [], sources: [] } },
      kinds,
    }).differences.length,
    2,
  );
  for (const key of kinds) {
    assert.deepEqual(
      inventoryDifferences({ before, after: { ...same, [key]: null }, kinds }).missing,
      [key],
      key,
    );
    assert.equal(
      inventoryDifferences({ before: { ...before, [key]: undefined }, after: same, kinds })
        .complete,
      false,
      key,
    );
  }
  assert.deepEqual(
    inventoryDifferences({
      before,
      after: { ...same, sourceObjects: { uploads: null, sources: null } },
      kinds,
    }).missing,
    ["uploadObjects", "sourceObjects"],
  );
  assert.equal(inventoryDifferences({ before: null, after: null, kinds }).complete, false);
  assert.deepEqual(INVENTORY_KINDS, [
    "channels",
    "triggers",
    "subscriptions",
    "topics",
    "packages",
  ]);
});

test("iamUnexpected lets service accounts in and nothing else", () => {
  assert.deepEqual(iamUnexpected(null), { complete: false, unexpected: [] });
  assert.deepEqual(iamUnexpected({ added: [], removed: [] }), { complete: true, unexpected: [] });
  assert.deepEqual(
    iamUnexpected({ added: ["roles/x|serviceAccount:a@b"], removed: [] }).unexpected,
    [],
  );
  assert.deepEqual(
    iamUnexpected({
      added: ["roles/x|user:a@b", "roles/y|allUsers"],
      removed: ["roles/z|user:c@d"],
    }).unexpected,
    ["removed roles/z|user:c@d", "added roles/x|user:a@b", "added roles/y|allUsers"],
  );
  assert.deepEqual(iamUnexpected({ added: ["roles/x"], removed: [] }).unexpected, [
    "added roles/x",
  ]);
});

test("the CLI write rows are numbered per action, an unreadable log is named after its action, and the inventory records what it could not read", async () => {
  const ok = { method: "POST", url: "x.example/a", requests: 1, statuses: [200], class: "ok" };
  const { journal, result } = await go({ cliWrites: [ok, { ...ok, url: "x.example/b" }] });
  assert.deepEqual(
    journal.filter((r) => r.state === "cli-write").map((r) => r.id),
    [
      "cli-dry-run-write-1",
      "cli-dry-run-write-2",
      "cli-deploy-write-1",
      "cli-deploy-write-2",
      "cli-delete-write-1",
      "cli-delete-write-2",
    ],
  );
  assert.deepEqual(result.inventory.missing, []);
  const bad = await go(
    {},
    (send) => send,
    (cli) => async (args) => ({ ...(await cli(args)), cliWrites: null }),
  );
  assert.deepEqual(
    bad.result.unknownMutationList.map((m) => m.id),
    ["cli-deploy", "cli-delete"],
  );
  const unknown = await go({ cliWrites: [{ ...ok, class: "unanswered", statuses: [] }] });
  const row = unknown.result.unknownMutationList.find((m) => m.id === "cli-deploy-write-1");
  assert.equal(row.request, "POST x.example/a");
  assert.equal(row.class, "cli-write-unanswered");
});

test("the read-back names its inventory reads and prints exactly what a missing baseline means", async () => {
  const { world, result } = await go();
  const ids = [];
  await a2(world, result, {
    save: async (row) => void (row.state === "before-send" && ids.push(row.id)),
  });
  for (const id of [
    "list-uploads",
    "list-sources",
    "list-triggers",
    "list-subscriptions",
    "list-topics",
    "list-services",
  ])
    assert.ok(ids.includes(id), id + " " + ids.join());
  const none = await a2(world, result, { baseline: null });
  assert.deepEqual(none.inventory, {
    baseline: false,
    complete: false,
    missing: ["baseline"],
    differences: [],
  });
});

test("writeAll passes the rest of the text and no more to each write", () => {
  const asked = [];
  writeAll(1, "abcdefgh", (fd, b, offset, length) => {
    asked.push([offset, length]);
    return Math.min(length, 5);
  });
  assert.deepEqual(asked, [
    [0, 8],
    [5, 3],
  ]);
});

test("more than one request to the same method and address is retried whatever the answers", () => {
  for (const code of [300, 299, 200]) {
    const found = cliWritesFromOutput(
      [
        REQ("POST", "x.example/a"),
        REQ("POST", "x.example/a"),
        STAT("POST", "x.example/a", code),
        STAT("POST", "x.example/a", 200),
      ].join("\n"),
    );
    assert.equal(found[0].class, "retried", String(code));
    assert.equal(found[0].requests, 2);
  }
  const one = cliWritesFromOutput(
    [REQ("POST", "x.example/a"), STAT("POST", "x.example/a", 299)].join("\n"),
  );
  assert.equal(one[0].class, "ok");
  const three = cliWritesFromOutput(
    [REQ("POST", "x.example/a"), STAT("POST", "x.example/a", 300)].join("\n"),
  );
  assert.equal(three[0].class, "non-2xx");
});
