// The Secure Token body session against the in-process world: the whole recording, what it sends,
// what it records, and what its cleanup does when a delete, a create or a switch answers badly.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { mock, test } from "node:test";

import { ROWS } from "./securetoken-body/corpus.mjs";
import {
  buildReport,
  classifyAnswer,
  mergeRecordings,
  readRow,
} from "./securetoken-body/judge.mjs";
import { createContext, SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { CONFORMANCE_DIR } from "./config.mjs";
import { tenancyIs } from "./securetoken-body/session.mjs";
import { fakeSession, NUMBER } from "./securetoken-body/test-support.mjs";

const rowSpec = (id) => ROWS.find((r) => r.id === id);
const reading = (recording, id) => readRow(rowSpec(id), mergeRecordings([recording.rows[id]]));

test("a clean recording answers every row, deletes everything it made and restores tenancy", async () => {
  const { session, world, journal } = fakeSession({ world: { tenancy: false } });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(Object.keys(recording.rows).length, ROWS.length);
  assert.equal(recording.closureReady, true);
  assert.deepEqual(recording.cleanupErrors, []);
  assert.equal(recording.tenancy.before, false);
  assert.equal(recording.tenancy.switchedOn, true);
  assert.equal(recording.tenancy.restored, true);
  assert.equal(world.tenancy, false);
  assert.equal(world.accounts.size, 0);
  assert.equal(world.tenants.size, 0);
  assert.equal(recording.requests, ROWS.length);
  assert.equal(journal.filter((e) => e.id === "refresh").length, ROWS.length);
  assert.equal(recording.ownership.owned.length, 0);
  assert.equal(recording.ownership.unknownAnswers.length, 0);
});

test("tenancy already on stays on and is not written", async () => {
  const { session, world, journal } = fakeSession({ world: { tenancy: true } });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, true);
  assert.equal(recording.tenancy.switchedOn, false);
  assert.equal(world.tenancy, true);
  assert.equal(journal.filter((e) => e.id === "write-tenancy").length, 0);
});

test("the request count is stable: rows plus a fixed harness budget", async () => {
  const off = fakeSession({ world: { tenancy: false } });
  const on = fakeSession({ world: { tenancy: true } });
  const a = await off.session.runRecording();
  const b = await on.session.runRecording();
  assert.equal(a.requests, 24);
  // tenancy on: config read, tenant list, tenant create, 3x (create, sign-in), 3x (delete, lookup),
  // tenant delete and read-back, tenant audit, account count; off adds the switch and its
  // read-back at both ends.
  assert.equal(b.harnessRequests, 19);
  assert.equal(a.harnessRequests, 23);
  assert.equal(b.requests, 24);
});

test("the rows send what the assignment asks: shapes, content types, only the API key", async () => {
  const { session, world } = fakeSession();
  await session.runRecording();
  const refreshes = world.log.filter((e) => e.path === "v1/token");
  assert.equal(refreshes.length, ROWS.length);
  const camel = refreshes[ROWS.findIndex((r) => r.id === "json-camel")];
  assert.equal(camel.contentType, "application/json");
  assert.deepEqual(Object.keys(JSON.parse(camel.body)), ["grantType", "refreshToken"]);
  const form = refreshes[ROWS.findIndex((r) => r.id === "form-snake")];
  assert.equal(form.contentType, "application/x-www-form-urlencoded");
  assert.match(form.body, /^grant_type=refresh_token&refresh_token=/);
  // The tenant user's sign-in names the tenant; its refresh rows do not.
  const signIns = world.log.filter((e) => e.path === "v1/accounts:signInWithPassword");
  assert.equal(signIns.filter((e) => JSON.parse(e.body).tenantId).length, 1);
  const tenantRow = refreshes[ROWS.findIndex((r) => r.id === "tenant-json-camel")];
  assert.ok(!/tenant/i.test(tenantRow.body));
});

test("a recorded row carries no token: its request is names and bytes, its answer lengths", async () => {
  const { session, world } = fakeSession();
  const { secrets, ...recording } = await session.runRecording();
  const text = JSON.stringify(recording);
  assert.ok(secrets.length >= 6);
  for (const secret of secrets) assert.ok(!text.includes(secret), "a token reached the record");
  for (const token of world.tokens.keys()) assert.ok(!text.includes(token));
  assert.ok(!text.includes("fireemu-stb-Password-1"));
  assert.ok(!/eyJ[A-Za-z0-9_-]{5,}/.test(text));
  const row = recording.rows["json-camel"];
  assert.deepEqual(row.request.fields, ["grantType", "refreshToken"]);
  assert.equal(row.request.contentType, "json");
  assert.ok(row.request.bodyBytes > 40);
  assert.ok(row.facts.tokens.refresh_token.length > 10);
  assert.equal(row.facts.refreshTokenReturned, "a");
  // The tenant id is masked inside the tenant account's tokens.
  const tenantRow = JSON.stringify(recording.rows["tenant-json-snake"]);
  assert.ok(tenantRow.includes('"tenant":"<tenant>"'));
  assert.ok(![...world.tenants.keys()].some((id) => text.includes(id)));
});

test("the policies of production the recorder is meant to tell apart read differently", async () => {
  const run = async (world) => await fakeSession({ world }).session.runRecording();
  const snake = await run({ precedence: "snake", camelJson: true, camelForm: false });
  assert.equal(reading(snake, "json-camel"), "accepted as a");
  assert.equal(reading(snake, "form-camel"), "refused MISSING_GRANT_TYPE");
  assert.equal(
    reading(snake, "json-both-tokens-camel-first"),
    "accepted; the snake_case token was used",
  );
  const camel = await run({ precedence: "camel", camelForm: true });
  assert.equal(
    reading(camel, "json-both-tokens-snake-first"),
    "accepted; the camelCase token was used",
  );
  assert.equal(reading(camel, "form-camel"), "accepted as a");
  const last = await run({ precedence: "last" });
  assert.equal(
    reading(last, "json-both-tokens-snake-first"),
    "accepted; the camelCase token was used",
  );
  assert.equal(
    reading(last, "json-both-tokens-camel-first"),
    "accepted; the snake_case token was used",
  );
  const refuse = await run({ precedence: "refuse" });
  assert.match(
    reading(refuse, "json-both-tokens-snake-first"),
    /^unknown: 400 with a message no recording shows/,
  );
  const noCamel = await run({ camelJson: false });
  assert.equal(reading(noCamel, "json-camel"), "refused MISSING_GRANT_TYPE");
  assert.equal(reading(noCamel, "tenant-json-camel"), "refused MISSING_GRANT_TYPE");
  // The controls read the same under every policy.
  for (const r of [snake, camel, last, refuse, noCamel]) {
    assert.equal(reading(r, "form-snake"), "accepted as a");
    assert.equal(reading(r, "tenant-form-snake"), "accepted as t");
    assert.equal(reading(r, "json-snake-after"), "accepted as a");
    assert.equal(reading(r, "json-snake-invalid-token"), "refused INVALID_REFRESH_TOKEN");
  }
  const report = buildReport({ productionRecordings: [snake], localRecordings: [camel] });
  assert.equal(report.find((r) => r.row === "json-both-tokens-snake-first").status, "differs");
  assert.equal(report.find((r) => r.row === "form-snake").status, "agrees");
});

test("a transport failure in a row is recorded as such and the recording goes on", async () => {
  let n = 0;
  const { session } = fakeSession({
    world: { faults: [(req) => (req.path === "v1/token" && (n += 1) === 3 ? "throw" : undefined)] },
  });
  const recording = await session.runRecording();
  assert.equal(recording.rows["json-camel"].status, 0);
  assert.equal(recording.rows["json-camel"].transport, "ECONNRESET");
  assert.equal(classifyAnswer(recording.rows["json-camel"]).kind, "unknown");
  assert.equal(Object.keys(recording.rows).length, ROWS.length);
  assert.equal(recording.closureReady, true);
});

// ---- cleanup ------------------------------------------------------------------------------

test("an unknown answer to an account delete is never re-sent and keeps the recording open", async () => {
  const { session, world, journal } = fakeSession({
    world: {
      lateFaults: [
        (req, res) =>
          req.path.endsWith("accounts:delete") &&
          res.status === 200 &&
          JSON.parse(req.body).localId.endsWith("-b")
            ? { status: 503, json: {} }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, false);
  assert.equal(world.accounts.size, 0); // the delete was applied; its answer was not seen
  assert.equal(journal.filter((e) => e.id === "delete-account").length, 3);
  assert.ok(recording.unknowns.some((u) => u.call.startsWith("delete account:stb-")));
  assert.ok(recording.ownership.reasons.some((r) => r.startsWith("unknown-delete-answers")));
  // Multi-tenancy is not switched back while a name of the run is open.
  assert.equal(recording.tenancy.restored, false);
  assert.equal(world.tenancy, true);
  assert.ok(recording.cleanupErrors.some((e) => e.includes("left on")));
});

test("an account delete that does not take effect reads back as present and stays open", async () => {
  const { session, world, journal } = fakeSession({
    world: {
      faults: [
        (req) =>
          req.path.endsWith("v1/projects/%P/accounts:delete") &&
          JSON.parse(req.body).localId.endsWith("-a")
            ? { status: 200, json: { kind: "identitytoolkit#DeleteAccountResponse" } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, false);
  assert.ok(recording.ownership.reasons.some((r) => r.startsWith("deleted-but-present:account:")));
  assert.equal(world.accounts.size, 1);
  assert.ok(recording.cleanupErrors.some((e) => e.includes("account audit")));
  assert.equal(journal.filter((e) => e.id === "delete-account").length, 3);
});

test("an account create whose answer was lost but took effect is settled by a lookup and deleted", async () => {
  let lost = false;
  const { session, world } = fakeSession({
    world: {
      lateFaults: [
        (req, res) => {
          if (
            lost ||
            res.status !== 200 ||
            !req.path.endsWith("accounts") ||
            req.path.includes("tenants")
          )
            return undefined;
          lost = true;
          return { status: 503, json: {} };
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.equal(world.accounts.size, 0);
  assert.equal(recording.ownership.a2Required, true);
  assert.equal(recording.ownership.unknownAnswers[0].settledBy, "present");
  assert.equal(recording.ownership.unknownAnswers[0].settled, true);
});

test("an account create with an unknown answer and nothing found stops the recording, open", async () => {
  const { session, world } = fakeSession({
    world: {
      faults: [
        (req) =>
          req.path.endsWith("projects/%P/accounts") ? { status: 503, json: {} } : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.fatal, true);
  assert.match(recording.failure, /create answer is unknown/);
  assert.equal(recording.closureReady, false);
  assert.ok(recording.ownership.absentUnconfirmed.length >= 1);
  assert.equal(Object.keys(recording.rows).length, 0);
  assert.equal(world.tenants.size, 0); // the tenant of the run was still deleted
  assert.equal(world.tenancy, true); // and the switch is left for the recovery
});

test("a tenant create whose answer was lost is found by its display name and deleted", async () => {
  let lost = false;
  const { session, world } = fakeSession({
    world: {
      lateFaults: [
        (req, res) => {
          if (lost || req.method !== "POST" || !req.path.endsWith("tenants") || res.status !== 200)
            return undefined;
          lost = true;
          return "throw";
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.equal(world.tenants.size, 0);
  assert.equal(world.tenancy, false);
});

test("a 200 tenant create that names no tenant is unknown, not an owned tenant", async () => {
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req) =>
          req.method === "POST" && req.path.endsWith("tenants")
            ? { status: 200, json: { name: "garbled" } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  // The tenant exists in the world, so the lookup by display name finds and settles it.
  assert.equal(recording.failure, undefined);
  assert.equal(recording.ownership.unknownAnswers.length, 1);
  assert.equal(recording.closureReady, true);
});

test("existing tenants stop the recording before anything is created", async () => {
  const { session, world, journal } = fakeSession({ world: { tenancy: true } });
  world.tenants.set("old", { id: "old", name: "projects/1/tenants/old", displayName: "old-one" });
  const recording = await session.runRecording();
  assert.match(recording.failure, /1 tenant\(s\) exist/);
  assert.equal(
    journal.filter((e) => e.id === "create-tenant" || e.id === "create-account").length,
    0,
  );
  assert.equal(world.tenants.size, 1);
});

test("a failed sign-in stops the rows and still deletes what was created", async () => {
  const { session, world } = fakeSession({
    world: {
      faults: [
        (req) =>
          req.path === "v1/accounts:signInWithPassword" && JSON.parse(req.body).tenantId
            ? { status: 400, json: { error: { code: 400, message: "X" } } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /sign-in of account t/);
  assert.equal(Object.keys(recording.rows).length, 0);
  assert.equal(world.accounts.size, 0);
  assert.equal(world.tenants.size, 0);
  assert.equal(recording.closureReady, true);
});

test("a stop request ends the rows at the next row and cleans up", async () => {
  let stop = false;
  const { session, world } = fakeSession({
    session: { shouldStop: () => stop, log: (l) => (stop ||= l.startsWith("json-camel ")) },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /stopped by a signal/);
  assert.ok(Object.keys(recording.rows).length < ROWS.length);
  assert.equal(world.accounts.size, 0);
  assert.equal(recording.closureReady, true);
});

test("the request ceiling stops the rows; cleanup has its own budget", async () => {
  const { session, world } = fakeSession({ session: { maxRequests: 5 } });
  const recording = await session.runRecording();
  assert.match(recording.failure, /request ceiling 5 reached/);
  assert.equal(recording.requests, 5);
  assert.equal(world.accounts.size, 0);
  assert.equal(recording.closureReady, true);
});

test("a switch that does not read back stops the recording before any write beyond it", async () => {
  const { session, world, journal } = fakeSession({
    world: { faults: [(req) => (req.method === "PATCH" ? { status: 200, json: {} } : undefined)] },
    session: { pollLimit: 3 },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /did not read back/);
  assert.equal(journal.filter((e) => e.id === "create-tenant").length, 0);
  assert.equal(world.tenants.size, 0);
  // The restore is attempted too (the world never changed, so it reads back at once).
  assert.equal(recording.tenancy.switchedOn, true);
  assert.equal(recording.tenancy.restored, true);
});

test("a restore that fails is a cleanup error and not closure-ready", async () => {
  let patches = 0;
  const { session, world } = fakeSession({
    world: {
      faults: [
        (req) =>
          req.method === "PATCH" && (patches += 1) === 2 ? { status: 500, json: {} } : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, false);
  assert.ok(recording.cleanupErrors.some((e) => e.startsWith("restore multi-tenancy")));
  assert.equal(world.tenancy, true);
});

test("a tenant that is still listed after its delete is a cleanup error", async () => {
  const { session } = fakeSession({
    world: { faults: [(req) => (req.method === "DELETE" ? { status: 200, json: {} } : undefined)] },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, false);
  assert.ok(recording.cleanupErrors.some((e) => e.startsWith("tenant audit")));
  assert.ok(recording.ownership.reasons.some((r) => r.startsWith("deleted-but-present:tenant:")));
});

test("the journal holds metadata only", async () => {
  const { session, journal } = fakeSession();
  await session.runRecording();
  for (const entry of journal) {
    assert.deepEqual(
      Object.keys(entry).toSorted(),
      ["at", "bodyBytes", "harness", "id", "method", "path", "seq", "status"].toSorted(),
    );
    assert.ok(!entry.path.includes("key="));
  }
  assert.deepEqual(
    journal.map((e) => e.seq),
    journal.map((_, i) => i + 1),
  );
});

test("a refused tenant create stops the recording without looking for a tenant", async () => {
  const { session, journal } = fakeSession({
    world: {
      tenancy: true,
      faults: [
        (req) =>
          req.method === "POST" && req.path.endsWith("tenants")
            ? { status: 400, json: { error: { code: 400, message: "MULTI_TENANCY_REQUIRED" } } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /tenant create was refused \(HTTP 400\)/);
  assert.equal(journal.filter((e) => e.id === "create-account").length, 0);
  assert.equal(journal.filter((e) => e.id === "get-tenant").length, 0);
  assert.equal(recording.closureReady, true);
  assert.equal(recording.ownership.unknownAnswers.length, 0);
});

test("a configuration change is settled after its read-back, in production only", async () => {
  const waits = [];
  const sleep = async (ms) => waits.push(ms);
  const prod = fakeSession({
    world: { tenancy: false },
    session: { sleep, settleMs: 5000, pollMs: 2000 },
  });
  await prod.session.runRecording();
  // One settle after the switch on and one after the switch off; the first read-back already shows it.
  assert.deepEqual(waits, [5000, 5000]);
  waits.length = 0;
  const local = fakeSession({ world: { tenancy: false }, session: { sleep } });
  await local.session.runRecording();
  assert.deepEqual(waits, []);
});

test("a read-back that lags is polled at the poll interval before the settle", async () => {
  const waits = [];
  let lag = 2;
  const { session } = fakeSession({
    world: {
      tenancy: false,
      lateFaults: [
        (req, res) => {
          if (
            req.method === "GET" &&
            req.path.startsWith("admin/v2") &&
            res.json?.multiTenant?.allowTenants === true &&
            lag > 0
          ) {
            lag -= 1;
            return { status: 200, json: { multiTenant: {} } };
          }
          return undefined;
        },
      ],
    },
    session: { sleep: async (ms) => waits.push(ms), settleMs: 5000, pollMs: 2000 },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, true);
  assert.deepEqual(waits.slice(0, 3), [2000, 2000, 5000]);
});

test("an unreadable 200 from the owner API stops the recording instead of reading as empty", async () => {
  const { session } = fakeSession({
    world: {
      tenancy: true,
      lateFaults: [
        (req) =>
          req.method === "GET" && req.path.startsWith("admin/v2")
            ? { status: 200, text: "not json" }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /unreadable body/);
  assert.equal(recording.fatal, true);
});

test("tenancyIs reads production's omitted false as off and only a true as on", () => {
  for (const off of [
    {},
    { multiTenant: {} },
    { multiTenant: { allowTenants: false } },
    null,
    undefined,
  ]) {
    assert.equal(tenancyIs(off, false), true);
    assert.equal(tenancyIs(off, true), false);
  }
  const on = { multiTenant: { allowTenants: true } };
  assert.equal(tenancyIs(on, true), true);
  assert.equal(tenancyIs(on, false), false);
  assert.equal(tenancyIs({ multiTenant: { allowTenants: "true" } }, true), false);
});

test("the defaults: a minute per request, 30 polls of 2 s before giving up", async () => {
  const waits = [];
  const timeouts = mock.method(AbortSignal, "timeout", AbortSignal.timeout);
  try {
    const { session, journal } = fakeSession({
      world: {
        tenancy: false,
        lateFaults: [
          (req) =>
            req.method === "GET" && req.path.startsWith("admin/v2")
              ? { status: 200, json: { multiTenant: {} } }
              : undefined,
        ],
      },
      // `undefined` leaves the session's own defaults in place.
      session: { pollMs: undefined, pollLimit: undefined, sleep: async (ms) => waits.push(ms) },
    });
    const recording = await session.runRecording();
    assert.match(recording.failure, /did not read back/);
    // One read for the state, then 30 polls of the switch on; the restore is attempted and polls too.
    // One read for the state, 30 polls that never show it, then the restore reads back at once.
    assert.equal(journal.filter((e) => e.id === "read-config").length, 32);
    assert.equal(waits.filter((ms) => ms === 2000).length, 30);
    assert.ok(timeouts.mock.calls.length > 0);
    assert.ok(timeouts.mock.calls.every((c) => c.arguments[0] === 60_000));
  } finally {
    timeouts.mock.restore();
  }
});

test("in production the settle after a configuration change defaults to 5 s, locally to none", async () => {
  const ctx = createContext({
    run: "1794000000",
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: "AIza-test-key",
      adminToken: "ya29.test",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: NUMBER,
    },
  });
  const { createWorld } = await import("./securetoken-body/test-world.mjs");
  const { openOwnership } = await import("./shared/ownership.mjs");
  const { createSession } = await import("./securetoken-body/session.mjs");
  const { tempDir } = await import("./test-tmpdir.mjs");
  const fake = createWorld({
    project: SANDBOX_PROJECT,
    number: NUMBER,
    tenancy: false,
    apiKey: "AIza-test-key",
  });
  const waits = [];
  const hosts = [];
  const transport = (url, init) => {
    const parsed = new URL(url);
    hosts.push(parsed.origin);
    return fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
  };
  const ownership = openOwnership({
    path: `${tempDir("stb-")}/issued.jsonl`,
    runId: "stb-1794000000",
  });
  const session = createSession(ctx, { transport, ownership, sleep: async (ms) => waits.push(ms) });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.equal(Object.keys(recording.rows).length, ROWS.length);
  assert.deepEqual(waits, [5000, 5000]);
  assert.deepEqual([...new Set(hosts)].toSorted(), [
    "https://identitytoolkit.googleapis.com",
    "https://securetoken.googleapis.com",
  ]);
});

test("a session without an ownership ledger is refused", async () => {
  const { createSession } = await import("./securetoken-body/session.mjs");
  assert.throws(
    () =>
      createSession(
        createContext({
          run: "1",
          project: SANDBOX_PROJECT,
          target: { kind: "local", origin: "http://127.0.0.1:1", projectNumber: NUMBER },
        }),
        {},
      ),
    /needs an ownership ledger/,
  );
});

test("the secrets a session holds are distinct and never empty", async () => {
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req, res) => {
          if (req.path !== "v1/accounts:signInWithPassword" || res.status !== 200) return undefined;
          return { status: 200, json: { ...res.json, idToken: "" } };
        },
      ],
    },
  });
  const { secrets } = await session.runRecording();
  assert.ok(secrets.length >= 3);
  assert.ok(secrets.every((secret) => typeof secret === "string" && secret.length > 0));
  assert.equal(new Set(secrets).size, secrets.length);
});

test("the guard runs on every request of a session: a tenant it did not create is refused", async () => {
  let armed = true;
  const tampering = fakeSession({
    world: {
      faults: [
        (req) => {
          // After the first account is created, the context forgets which tenant is the run's own.
          if (armed && req.path.endsWith("v1/projects/%P/accounts")) {
            armed = false;
            tampering.ctx.tenantId = "somebody-elses";
          }
          return undefined;
        },
      ],
    },
  });
  const recording = await tampering.session.runRecording();
  assert.match(recording.failure, /names a tenant this run did not create/);
  assert.equal(Object.keys(recording.rows).length, 0);
});

test("the harness ceiling is its own: reaching it stops the recording and cleanup cannot exceed it", async () => {
  const { session } = fakeSession({ session: { maxHarnessRequests: 4 } });
  const recording = await session.runRecording();
  assert.equal(recording.harnessRequests, 4);
  assert.equal(recording.fatal, true);
  assert.match(recording.failure, /harness request ceiling 4 reached/);
  assert.equal(recording.requests, 0);
  assert.equal(session.counts().harnessRequests, 4);
});

test("in production every management call renews the owner credential first, a row never does", async () => {
  const { createWorld } = await import("./securetoken-body/test-world.mjs");
  const { openOwnership } = await import("./shared/ownership.mjs");
  const { createSession } = await import("./securetoken-body/session.mjs");
  const { tempDir } = await import("./test-tmpdir.mjs");
  const target = {
    kind: "production",
    apiKey: "AIza-test-key",
    adminToken: "ya29.first",
    quotaProject: SANDBOX_PROJECT,
    projectNumber: NUMBER,
    refreshes: 0,
    async refresh() {
      this.refreshes += 1;
      this.adminToken = `ya29.renewed-${this.refreshes}`;
    },
  };
  const ctx = createContext({ run: "1794000000", project: SANDBOX_PROJECT, target });
  const fake = createWorld({
    project: SANDBOX_PROJECT,
    number: NUMBER,
    apiKey: "AIza-test-key",
    tenancy: true,
  });
  const bearers = [];
  const signInHeaders = [];
  const transport = (url, init) => {
    const parsed = new URL(url);
    if (init.headers.authorization) bearers.push(init.headers.authorization);
    if (parsed.pathname.endsWith("signInWithPassword"))
      signInHeaders.push(init.headers.authorization);
    return fake.fetch(`http://127.0.0.1:1${parsed.pathname}${parsed.search}`, init);
  };
  const ownership = openOwnership({
    path: `${tempDir("stb-")}/issued.jsonl`,
    runId: "stb-1794000000",
  });
  const recording = await createSession(ctx, {
    transport,
    ownership,
    sleep: async () => {},
  }).runRecording();
  assert.equal(recording.failure, undefined);
  // 16 management calls (tenancy on); the 3 sign-ins are harness calls that carry the key alone.
  assert.equal(recording.harnessRequests, 19);
  assert.equal(bearers.length, 16);
  assert.equal(target.refreshes, 16);
  assert.ok(bearers.every((b) => b.startsWith("Bearer ya29.renewed-")));
  assert.equal(new Set(bearers).size, 16);
  assert.deepEqual(signInHeaders, [undefined, undefined, undefined]);
});

test("a credential that cannot be renewed stops the recording as fatal", async () => {
  const { createWorld } = await import("./securetoken-body/test-world.mjs");
  const { openOwnership } = await import("./shared/ownership.mjs");
  const { createSession } = await import("./securetoken-body/session.mjs");
  const { tempDir } = await import("./test-tmpdir.mjs");
  const target = {
    kind: "production",
    apiKey: "AIza-test-key",
    adminToken: "ya29.first",
    quotaProject: SANDBOX_PROJECT,
    projectNumber: NUMBER,
    async refresh() {
      throw new Error("gcloud is gone");
    },
  };
  const ctx = createContext({ run: "1794000000", project: SANDBOX_PROJECT, target });
  const fake = createWorld({ project: SANDBOX_PROJECT, number: NUMBER, apiKey: "AIza-test-key" });
  const ownership = openOwnership({
    path: `${tempDir("stb-")}/issued.jsonl`,
    runId: "stb-1794000000",
  });
  const recording = await createSession(ctx, {
    transport: fake.fetch,
    ownership,
    sleep: async () => {},
  }).runRecording();
  assert.equal(recording.fatal, true);
  assert.match(recording.failure, /owner credential refresh failed: gcloud is gone/);
});

// ---- replay: the management answers production was recorded giving -----------------------

const recorded = (file, program, step) =>
  JSON.parse(readFileSync(join(CONFORMANCE_DIR, file), "utf8")).programs[program].steps[step];
const atb = (program, step) => recorded("auth-tenant-blocking-production.json", program, step);

test("replay: the recorded tenant, lookup, delete and read-back answers drive the session to a clean close", async () => {
  const createOpen = atb("atb/tenant/manage", "create-open").body;
  const deleted = atb("atb/tenant/manage", "get-deleted");
  const deleteTenant = atb("atb/tenant/manage", "delete-minimal");
  const missing = atb("atb/tenant/selection", "admin-lookup-a1-in-b");
  const present = atb("atb/tenant/selection", "admin-lookup-a1-email-in-b").body;
  const deleteAccount = recorded(
    "auth-account-production.json",
    "auth-account/admin/delete",
    "delete",
  );
  const { session, world } = fakeSession({
    world: {
      tenancy: true,
      lateFaults: [
        (req, res) => {
          if (req.method === "POST" && req.path.endsWith("tenants") && res.status === 200) {
            // The recorded create answer, carrying this run's own name and display name.
            return {
              status: 200,
              json: { ...createOpen, name: res.json.name, displayName: res.json.displayName },
            };
          }
          if (req.method === "DELETE")
            return { status: deleteTenant.status, json: deleteTenant.body };
          if (req.method === "GET" && /tenants\/[^/]+$/.test(req.path) && res.status === 404)
            return { status: deleted.status, json: deleted.body };
          if (req.path.endsWith("accounts:lookup")) {
            if (Object.keys(res.json).includes("users")) {
              const user = { ...present.users[0], localId: res.json.users[0].localId };
              return { status: 200, json: { ...present, users: [user] } };
            }
            return { status: missing.status, json: missing.body };
          }
          if (req.path.endsWith("accounts:delete") && res.status === 200)
            return { status: deleteAccount.status, json: deleteAccount.body };
          return undefined;
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.equal(world.accounts.size + world.tenants.size, 0);
  assert.equal(recording.ownership.owned.length, 0);
  assert.equal(recording.ownership.deletedUnverified.length, 0);
});

test("replay: a recorded 200 lookup that still lists the account reads as present, not as deleted", async () => {
  const present = atb("atb/tenant/selection", "admin-lookup-a1-email-in-b").body;
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req) => {
          if (
            !req.path.endsWith("accounts:lookup") ||
            !req.path.includes("%P/accounts") ||
            req.path.includes("tenants")
          )
            return undefined;
          if (!JSON.parse(req.body).localId[0].endsWith("-a")) return undefined;
          // The recorded answer for an account that exists, for every lookup of account a.
          return {
            status: 200,
            json: {
              ...present,
              users: [{ ...present.users[0], localId: JSON.parse(req.body).localId[0] }],
            },
          };
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.closureReady, false);
  assert.ok(
    recording.ownership.reasons.some((r) => r.startsWith("deleted-but-present:account:stb-")),
  );
});

test("a refresh answer's three tokens are kept as secrets and as lengths, each its own", async () => {
  const { session, world } = fakeSession();
  const { secrets, rows } = await session.runRecording();
  const facts = rows["json-camel"].facts.tokens;
  assert.deepEqual(Object.keys(facts).toSorted(), ["access_token", "id_token", "refresh_token"]);
  for (const f of Object.values(facts)) assert.ok(f.length > 20);
  // The world signs every token separately; every one it issued, sign-in or refresh, is held.
  assert.ok(world.jwts.size > 20);
  for (const jwt of world.jwts) assert.ok(secrets.includes(jwt));
  for (const token of world.tokens.keys()) assert.ok(secrets.includes(token));
});

// ---- failures of the transport and of the owner API, in their own words -----------------------

test("a transport failure is journaled with its code, its name, or a plain 'error'", async () => {
  let n = 0;
  const kinds = ["throw", "throw-plain"];
  const { session, journal } = fakeSession({
    world: { faults: [(req) => (req.path === "v1/token" && n < 2 ? kinds[n++] : undefined)] },
  });
  const recording = await session.runRecording();
  const failed = journal.filter((e) => e.status === 0);
  assert.deepEqual(
    failed.map((e) => [e.id, e.transport]),
    [
      ["refresh", "ECONNRESET"],
      ["refresh", "error"],
    ],
  );
  assert.equal(recording.rows["form-snake"].transport, "ECONNRESET");
  assert.equal(recording.rows["json-snake"].transport, "error");
  for (const entry of failed) assert.equal("bodyBytes" in entry, false);
});

test("an owner call that fails says which call and how, with the placeholder not the project", async () => {
  const http = fakeSession({
    world: {
      tenancy: true,
      faults: [
        (req) =>
          req.method === "GET" && req.path.startsWith("admin/v2")
            ? { status: 500, json: {} }
            : undefined,
      ],
    },
  });
  const a = await http.session.runRecording();
  assert.equal(a.failure, "harness GET admin/v2/projects/{project}/config: HTTP 500");
  const reset = fakeSession({
    world: {
      tenancy: true,
      faults: [
        (req) => (req.method === "GET" && req.path.startsWith("admin/v2") ? "throw" : undefined),
      ],
    },
  });
  const b = await reset.session.runRecording();
  assert.equal(b.failure, "harness GET admin/v2/projects/{project}/config: ECONNRESET");
  assert.equal(a.fatal && b.fatal, true);
});

test("a lost tenant create names its transport error in the ownership record", async () => {
  let lost = false;
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req, res) => {
          if (lost || req.method !== "POST" || !req.path.endsWith("tenants") || res.status !== 200)
            return undefined;
          lost = true;
          return "throw";
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.ownership.unknownAnswers[0].reason, "transport-error");
  assert.equal(recording.unknowns[0].answer, "transport-error");
  assert.equal(recording.unknowns[0].call, "create tenant:stb-1794000000");
});

test("a poll waits for its sleep before it reads again", async () => {
  const events = [];
  let lag = 2;
  const { session } = fakeSession({
    world: {
      tenancy: false,
      lateFaults: [
        (req, res) => {
          if (req.method === "GET" && req.path.startsWith("admin/v2")) {
            events.push("read");
            if (res.json?.multiTenant?.allowTenants === true && lag > 0) {
              lag -= 1;
              return { status: 200, json: { multiTenant: {} } };
            }
          }
          return undefined;
        },
      ],
    },
    session: {
      settleMs: 5000,
      pollMs: 2000,
      sleep: async (ms) => {
        events.push(`sleep:${ms}`);
        await new Promise((resolve) => setImmediate(resolve));
        events.push(`woke:${ms}`);
      },
    },
  });
  await session.runRecording();
  // read (state), read (lag), sleep, read (lag), sleep, read (on), settle, ... each sleep ends before the next read.
  const head = events.slice(0, 11);
  assert.deepEqual(head, [
    "read",
    "read",
    "sleep:2000",
    "woke:2000",
    "read",
    "sleep:2000",
    "woke:2000",
    "read",
    "sleep:5000",
    "woke:5000",
    "read",
  ]);
});

test("a switch that never reads back is bounded by the poll limit, not by the clock", async () => {
  let sleeps = 0;
  const { session } = fakeSession({
    world: {
      tenancy: false,
      faults: [(req) => (req.method === "PATCH" ? { status: 200, json: {} } : undefined)],
    },
    session: {
      pollLimit: 3,
      sleep: async () => {
        sleeps += 1;
        if (sleeps > 20) throw new Error("the poll loop does not end");
      },
    },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /multi-tenancy did not read back as true/);
  assert.equal(sleeps, 3);
});

test("a one-character secret is still a secret", async () => {
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req, res) =>
          req.path === "v1/accounts:signInWithPassword" && res.status === 200
            ? { status: 200, json: { ...res.json, refreshToken: "x" } }
            : undefined,
      ],
    },
  });
  const { secrets } = await session.runRecording();
  assert.ok(secrets.includes("x"));
});

// ---- the tenant list and the tenant create, edge by edge -------------------------------------

test("the tenant list is read page by page, up to twenty pages", async () => {
  const page = (n) => `page-${n}`;
  const lister = (pages) => {
    const asked = [];
    const fault = (req) => {
      if (req.method !== "GET" || !req.path.endsWith("tenants")) return undefined;
      asked.push(req.query.pageToken);
      const n = req.query.pageToken ? Number(req.query.pageToken.slice(5)) : 1;
      if (n < pages) return { status: 200, json: { nextPageToken: page(n + 1) } };
      return { status: 200, json: {} };
    };
    return { asked, fault };
  };
  // Twenty pages, the last one without a token: read to the end and carry on.
  const twenty = lister(20);
  const ok = fakeSession({ world: { tenancy: true, faults: [twenty.fault] } });
  const good = await ok.session.runRecording();
  assert.equal(good.failure, undefined);
  assert.equal(twenty.asked.slice(0, 20).filter(Boolean).length, 19);
  assert.equal(twenty.asked[0], undefined);
  assert.equal(twenty.asked[1], "page-2");
  assert.equal(twenty.asked[19], "page-20");
  // A twenty-first page is one too many.
  const many = lister(21);
  const bad = fakeSession({ world: { tenancy: true, faults: [many.fault] } });
  const failed = await bad.session.runRecording();
  assert.equal(failed.failure, "the tenant list has more than 20 pages");
  // The listing stops at twenty pages; no tenant was asked for, so there is no audit after it.
  assert.equal(many.asked.length, 20);
});

test("a tenant on a later page of the list stops the recording", async () => {
  const { session, journal } = fakeSession({
    world: {
      tenancy: true,
      faults: [
        (req) => {
          if (req.method !== "GET" || !req.path.endsWith("tenants")) return undefined;
          return req.query.pageToken === "p2"
            ? {
                status: 200,
                json: { tenants: [{ name: "projects/1/tenants/old", displayName: "old-one" }] },
              }
            : { status: 200, json: { nextPageToken: "p2" } };
        },
      ],
    },
  });
  const recording = await session.runRecording();
  assert.match(recording.failure, /1 tenant\(s\) exist; nothing is created/);
  assert.equal(journal.filter((e) => e.id === "create-tenant").length, 0);
});

test("a tenant create answered with a status that may be a lost answer is looked for, any other 4xx is a refusal", async () => {
  const answered = async (status) => {
    const { session, journal } = fakeSession({
      world: {
        tenancy: true,
        faults: [
          (req) =>
            req.method === "POST" && req.path.endsWith("tenants")
              ? { status, json: {} }
              : undefined,
        ],
      },
    });
    const recording = await session.runRecording();
    return {
      failure: recording.failure,
      listed: journal.filter((e) => e.id === "list-tenants").length,
      unknowns: recording.unknowns.length,
    };
  };
  for (const status of [400, 403, 409, 429]) {
    const r = await answered(status);
    assert.equal(r.failure, `the tenant create was refused (HTTP ${status})`, String(status));
    assert.equal(r.unknowns, 0, String(status));
    assert.equal(r.listed, 2, String(status)); // before the create, and the audit after
  }
  for (const status of [408, 499, 500, 502, 503]) {
    const r = await answered(status);
    assert.match(
      r.failure,
      /the answer to the tenant create is unknown and no read shows it/,
      String(status),
    );
    assert.equal(r.unknowns, 1, String(status));
    assert.equal(r.listed, 3, String(status)); // before, the search for the lost create, the audit
  }
});

test("a 200 that names no tenant is recorded as an unreadable answer", async () => {
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req) =>
          req.method === "POST" && req.path.endsWith("tenants")
            ? { status: 200, json: { name: "garbled" } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.ownership.unknownAnswers[0].reason, "unreadable-body");
  assert.equal(recording.ownership.unknownAnswers[0].status, undefined);
});

test("a run that never asked for a tenant does not audit for one", async () => {
  // The first configuration read fails: nothing was done, and a tenant list with tenancy off is refused.
  const { session, journal } = fakeSession({
    world: {
      tenancy: false,
      faults: [
        (req) =>
          req.method === "GET" && req.path.startsWith("admin/v2")
            ? { status: 500, json: {} }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, "harness GET admin/v2/projects/{project}/config: HTTP 500");
  assert.equal(journal.filter((e) => e.id === "list-tenants").length, 0);
  assert.deepEqual(recording.cleanupErrors, []);
  assert.equal(recording.closureReady, true);
});
