// The Secure Token body session against the in-process world: the whole recording, what it sends,
// what it records, and what its cleanup does when a delete, a create or a switch answers badly.

import assert from "node:assert/strict";
import { createServer } from "node:http";
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
  // The lookup that settled the create is a harness request, not a counted row.
  assert.equal(recording.requests, 24);
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
    session: { pollLimit: 3, sleep: boundedSleep() },
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
      session: { pollMs: undefined, pollLimit: undefined, sleep: boundedSleep(waits) },
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
      reason: recording.unknowns[0]?.answer,
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
    const reasons = {
      408: "request-timeout",
      499: "cancelled",
      500: "server-error",
      502: "server-error",
      503: "server-error",
    };
    assert.equal(r.reason, reasons[status], String(status));
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

// ---- finding a tenant whose create answer was lost --------------------------------------------

/** A sleep that records its waits and fails loudly instead of letting a poll loop run for ever. */
function boundedSleep(waits = []) {
  return async (ms) => {
    waits.push(ms);
    if (waits.length > 200) throw new Error("the poll loop does not end");
  };
}

const ledgerRows = (path) =>
  readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));

/** A world whose first tenant create is applied but answered `lost`; `edit` may change what lists and reads say. */
function lostTenantCreate({ lost = "throw", edit = () => undefined } = {}) {
  let first = true;
  return fakeSession({
    world: {
      lateFaults: [
        (req, res) => {
          if (
            first &&
            req.method === "POST" &&
            req.path.endsWith("tenants") &&
            res.status === 200
          ) {
            first = false;
            return lost;
          }
          return edit(req, res);
        },
      ],
    },
  });
}

test("a lost tenant create is found with one list and one read, counted as harness requests", async () => {
  const { session, journal, ledgerPath } = lostTenantCreate();
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.equal(
    journal.filter((e) => e.id === "get-tenant" && e.method === "GET").length >= 1,
    true,
  );
  // The reads of the search are harness requests: the rows are the only counted ones.
  assert.equal(recording.requests, 24);
  const rows = ledgerRows(ledgerPath).filter((r) => r.name === "tenant:stb-1794000000");
  const answer = rows.find((r) => r.phase === "answer" && r.action === "create");
  assert.equal(answer.class, "unknown");
  assert.equal(answer.reason, "transport-error");
  const read = rows.find((r) => r.phase === "read");
  assert.equal(read.observed, "present");
  assert.equal(read.status, 200);
});

test("a tenant with the right name but another display name is read, and is not taken as the run's own", async () => {
  const { session, journal } = fakeSession({
    world: {
      lateFaults: [
        (req, res) =>
          req.method === "POST" && req.path.endsWith("tenants") && res.status === 200
            ? { status: 200, json: { ...res.json, displayName: "someone-else" } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  // The answer named another display name, so the tenant is looked up by its real display name and read.
  assert.equal(journal.filter((e) => e.id === "get-tenant").length >= 1, true);
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
});

test("a candidate whose name has no tenant id is skipped, the next one is read", async () => {
  const run = "1794000000";
  const { session, journal } = lostTenantCreate({
    edit: (req, res) =>
      req.method === "GET" && req.path.endsWith("tenants") && res.json?.tenants
        ? {
            status: 200,
            json: {
              tenants: [
                { name: "projects/1/garbled", displayName: `stb-${run}` },
                ...res.json.tenants,
              ],
            },
          }
        : undefined,
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  assert.ok(journal.every((e) => !e.path.endsWith("/tenants/undefined")));
});

test("a read that shows another display name, or no tenant, does not settle a lost create", async () => {
  for (const reply of [
    { status: 200, json: { name: "projects/1/tenants/x", displayName: "someone-else" } },
    {
      status: 404,
      json: { error: { code: 404, message: "TENANT_NOT_FOUND", status: "NOT_FOUND" } },
    },
    { status: 200, json: {} },
  ]) {
    const { session, ctx, ledgerPath } = lostTenantCreate({
      edit: (req) => (req.method === "GET" && /tenants\/[^/]+$/.test(req.path) ? reply : undefined),
    });
    const recording = await session.runRecording();
    assert.match(
      recording.failure,
      /the answer to the tenant create is unknown and no read shows it/,
    );
    assert.equal(recording.closureReady, false);
    assert.equal(ctx.tenantId, undefined);
    const reads = ledgerRows(ledgerPath).filter((r) => r.phase === "read");
    assert.ok(reads.every((r) => r.observed !== "present"));
    assert.ok(recording.ownership.reasons.some((r) => r.startsWith("unsettled-create:tenant:")));
  }
});

// ---- the read-back of a deleted account, answer by answer ------------------------------------

/** Every lookup of account b (only the cleanup makes one) is answered `reply`; the delete itself works. */
function readBackAs(reply) {
  return fakeSession({
    world: {
      faults: [
        (req) =>
          req.path.endsWith("accounts:lookup") && JSON.parse(req.body).localId[0].endsWith("-b")
            ? reply
            : undefined,
      ],
    },
  });
}

test("a read-back that is not a clean 'no such account' leaves the delete unverified", async () => {
  const cases = [
    ["a server error", { status: 500, json: {} }, "unknown", "server-error"],
    ["a refusal", { status: 403, json: { error: { code: 403 } } }, "unknown", null],
    ["a garbled 200", { status: 200, text: "not json" }, "unknown", null],
    ["a lost answer", "throw", "unknown", "transport-error"],
    [
      "another account",
      { status: 200, json: { users: [{ localId: "someone-else" }] } },
      "unknown",
      null,
    ],
    ["users that is not a list", { status: 200, json: { users: "x" } }, "unknown", null],
  ];
  for (const [name, reply, observed, reason] of cases) {
    const { session, ledgerPath } = readBackAs(reply);
    const recording = await session.runRecording();
    assert.equal(recording.closureReady, false, name);
    assert.ok(
      recording.ownership.reasons.some((r) => r === "deleted-unverified:account:stb-1794000000-b"),
      name,
    );
    const read = ledgerRows(ledgerPath).find(
      (r) => r.phase === "read" && r.name === "account:stb-1794000000-b",
    );
    assert.equal(read.observed, observed, name);
    if (reason) assert.equal(read.reason, reason, name);
  }
});

test("a read-back that lists the account itself says present, a clean empty one says gone", async () => {
  const present = readBackAs({ status: 200, json: { users: [{ localId: "stb-1794000000-b" }] } });
  const a = await present.session.runRecording();
  assert.ok(a.ownership.reasons.includes("deleted-but-present:account:stb-1794000000-b"));
  const read = ledgerRows(present.ledgerPath).find(
    (r) => r.phase === "read" && r.name === "account:stb-1794000000-b",
  );
  assert.equal(read.observed, "present");
  assert.equal(read.status, 200);
  for (const gone of [
    { status: 200, json: {} },
    { status: 200, json: { users: [] } },
  ]) {
    const { session, ledgerPath } = readBackAs(gone);
    const recording = await session.runRecording();
    assert.equal(recording.closureReady, true);
    const row = ledgerRows(ledgerPath).find(
      (r) => r.phase === "read" && r.name === "account:stb-1794000000-b",
    );
    assert.equal(row.observed, "absent");
    assert.equal(row.status, 404);
  }
});

// ---- account creation and sign-in, answer by answer -------------------------------------------

test("a refused account create stops the recording: nothing owned, nothing looked up, nothing to delete", async () => {
  const { session, world, journal } = fakeSession({
    world: {
      faults: [
        (req) =>
          req.path.endsWith("v1/projects/%P/accounts") && req.method === "POST"
            ? { status: 400, json: { error: { code: 400, message: "DUPLICATE_LOCAL_ID" } } }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, "account a was not created (HTTP 400)");
  assert.equal(journal.filter((e) => e.id === "lookup-account").length, 0);
  assert.equal(journal.filter((e) => e.id === "delete-account").length, 0);
  assert.deepEqual(recording.ownership.owned, []);
  assert.equal(world.accounts.size, 0);
});

test("a sign-in that does not hand back a refresh token stops the recording, whatever else it says", async () => {
  const bad = [
    [
      "no token",
      (res) => ({ status: 200, json: { ...res.json, refreshToken: undefined } }),
      /answered 200/,
    ],
    [
      "an empty token",
      (res) => ({ status: 200, json: { ...res.json, refreshToken: "" } }),
      /answered 200/,
    ],
    [
      "a number",
      (res) => ({ status: 200, json: { ...res.json, refreshToken: 7 } }),
      /answered 200/,
    ],
    [
      "a refusal that still carries one",
      (res) => ({ status: 400, json: res.json }),
      /answered 400/,
    ],
    ["a lost answer", () => "throw", /answered ETIMEDOUT/],
  ];
  for (const [name, change, pattern] of bad) {
    const { session, world } = fakeSession({
      world: {
        lateFaults: [
          (req, res) =>
            req.path === "v1/accounts:signInWithPassword" && res.status === 200
              ? change(res)
              : undefined,
        ],
      },
    });
    const recording = await session.runRecording();
    assert.match(recording.failure, pattern, name);
    assert.match(recording.failure, /^sign-in of account a /, name);
    assert.equal(Object.keys(recording.rows).length, 0, name);
    assert.equal(world.accounts.size, 0, name);
    assert.equal(recording.closureReady, true, name);
  }
});

// ---- what a row keeps of an answer --------------------------------------------------------------

test("a row keeps only what is safe whatever the answer looks like", async () => {
  const answers = {
    "json-camel": { status: 200, text: "<html>not json</html>" },
    "form-camel": { status: 200, text: "null" },
    "json-snake": { status: 200, text: "[1,2]" },
    "form-snake": {
      status: 200,
      json: { id_token: 7, access_token: "short", refresh_token: "rotated-token" },
    },
  };
  let n = 0;
  const order = ROWS.map((r) => r.id);
  const { session } = fakeSession({
    world: {
      lateFaults: [
        (req) => {
          if (req.path !== "v1/token") return undefined;
          return answers[order[n++]];
        },
      ],
    },
  });
  const { rows, secrets } = await session.runRecording();
  // Not JSON and `null`: no token facts; a list has none to count. None of them crashes the row.
  assert.deepEqual(rows["json-camel"].facts, {});
  assert.equal(rows["json-camel"].nonJson, true);
  assert.deepEqual(rows["form-camel"].facts, {});
  assert.deepEqual(rows["json-snake"].facts, { tokens: {} });
  assert.equal(rows["json-camel"].request.contentType, "json");
  // Only the string tokens have a length; a refresh token the run never issued is `new`.
  assert.deepEqual(rows["form-snake"].facts, {
    tokens: { access_token: { length: 5 }, refresh_token: { length: 13 } },
    refreshTokenReturned: "new",
  });
  assert.ok(secrets.includes("rotated-token") && secrets.includes("short"));
  // An answer with no refresh token claims none.
  assert.equal("refreshTokenReturned" in rows["json-camel-no-grant"].facts, false);
});

test("an answer that returns the token of another account says whose it is", async () => {
  const { session } = fakeSession({ world: { precedence: "snake" } });
  const { rows } = await session.runRecording();
  assert.equal(rows["json-camel"].facts.refreshTokenReturned, "a");
  assert.equal(rows["tenant-json-camel"].facts.refreshTokenReturned, "t");
  assert.equal(rows["json-both-tokens-camel-first"].facts.refreshTokenReturned, "a");
});

// ---- masks and cleanup messages ------------------------------------------------------------------

test("the tenant id is masked whether or not it contains the run id", async () => {
  for (const tenantIdOf of [(name) => `${name}-abcde`, () => "ZGlmZmVyZW50"]) {
    const { session, world } = fakeSession({ world: { tenantIdOf } });
    const recording = await session.runRecording();
    assert.equal(recording.closureReady, true);
    const text = JSON.stringify(recording.rows);
    assert.ok(text.includes('"tenant":"<tenant>"'));
    assert.ok(!text.includes("abcde") && !text.includes("ZGlmZmVyZW50"));
    assert.equal(world.tenants.size, 0);
  }
});

test("a failed restore is reported as not restored, with the thrown text as it is", async () => {
  let patches = 0;
  let lag = false;
  const { session, world } = fakeSession({
    world: {
      tenancy: false,
      lateFaults: [
        (req, res) => {
          if (req.method === "PATCH" && ++patches === 2) lag = true;
          // After the restore PATCH the switch keeps reading back as on.
          if (lag && req.method === "GET" && req.path.startsWith("admin/v2"))
            return { status: 200, json: { ...res.json, multiTenant: { allowTenants: true } } };
          return undefined;
        },
      ],
    },
    session: {
      pollLimit: 2,
      sleep: async () => {
        throw "the sleep broke";
      },
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.tenancy.restored, false);
  assert.equal(recording.closureReady, false);
  assert.ok(
    recording.cleanupErrors.includes("restore multi-tenancy: the sleep broke"),
    JSON.stringify(recording.cleanupErrors),
  );
  assert.equal(world.tenancy, false);
});

// ---- cleanup that cannot finish, and a tenant read-back, answer by answer --------------------------

test("when the harness budget ends inside cleanup, each step that could not run says so by name", async () => {
  // Tenancy already on: 9 setup requests, then t, b, a (delete + lookup each), the tenant, the audits.
  const run = async (maxHarnessRequests) => {
    const { session } = fakeSession({ world: { tenancy: true }, session: { maxHarnessRequests } });
    return session.runRecording();
  };
  const early = await run(11);
  assert.deepEqual(
    early.cleanupErrors.map((e) => e.split(":")[0]),
    ["account b", "account a", "tenant", "tenant audit", "account audit"],
  );
  assert.ok(early.cleanupErrors.every((e) => e.endsWith("harness request ceiling 11 reached")));
  const late = await run(15);
  assert.deepEqual(
    late.cleanupErrors.map((e) => e.split(":")[0]),
    ["tenant", "tenant audit", "account audit"],
  );
  assert.equal(early.closureReady || late.closureReady, false);
});

test("a tenant read-back shows present only for the run's own display name", async () => {
  const afterDelete = (reply) =>
    fakeSession({
      world: {
        faults: [
          (req) => (req.method === "GET" && /tenants\/[^/]+$/.test(req.path) ? reply : undefined),
        ],
      },
    });
  // The tenant reads as itself after its delete: present, and the delete is not verified.
  const own = afterDelete({
    status: 200,
    json: { name: "projects/1/tenants/x", displayName: "stb-1794000000" },
  });
  const a = await own.session.runRecording();
  assert.ok(a.ownership.reasons.includes("deleted-but-present:tenant:stb-1794000000"));
  const row = ledgerRows(own.ledgerPath).find(
    (r) => r.phase === "read" && r.name === "tenant:stb-1794000000",
  );
  assert.equal(row.observed, "present");
  assert.equal(row.status, 200);
  // Another display name proves nothing about this tenant: the delete stays unverified.
  const other = afterDelete({
    status: 200,
    json: { name: "projects/1/tenants/x", displayName: "someone-else" },
  });
  const b = await other.session.runRecording();
  assert.ok(b.ownership.reasons.includes("deleted-unverified:tenant:stb-1794000000"));
  const read = ledgerRows(other.ledgerPath).find(
    (r) => r.phase === "read" && r.name === "tenant:stb-1794000000",
  );
  assert.equal(read.observed, "unknown");
});

// ---- the account audit, the accounts a corpus needs, and the project name in messages ----------------

test("an account count that is missing or not zero is an audit error", async () => {
  const count = (reply) =>
    fakeSession({
      world: { faults: [(req) => (req.path.endsWith("accounts:query") ? reply : undefined)] },
    });
  for (const [reply, text] of [
    [{ status: 200, json: {} }, "undefined project-level account(s) remain"],
    [{ status: 200, json: { recordsCount: "2" } }, "2 project-level account(s) remain"],
    [{ status: 200, json: { recordsCount: 1 } }, "1 project-level account(s) remain"],
  ]) {
    const recording = await count(reply).session.runRecording();
    assert.ok(
      recording.cleanupErrors.includes(`account audit: ${text}`),
      JSON.stringify(recording.cleanupErrors),
    );
    assert.equal(recording.closureReady, false);
  }
  const zero = await count({ status: 200, json: { recordsCount: "0" } }).session.runRecording();
  assert.deepEqual(zero.cleanupErrors, []);
});

test("a session creates only the accounts its rows name", async () => {
  const only = ROWS.filter((r) => r.id === "json-camel");
  const { session, journal, world } = fakeSession({ session: { rows: only } });
  const recording = await session.runRecording();
  assert.equal(journal.filter((e) => e.id === "create-account").length, 1);
  assert.equal(journal.filter((e) => e.id === "sign-in").length, 1);
  assert.equal(Object.keys(recording.rows).length, 1);
  assert.equal(recording.closureReady, true);
  assert.equal(world.accounts.size, 0);
});

test("the project id never appears in a message the record keeps", async () => {
  const { session } = fakeSession({
    world: {
      tenancy: false,
      faults: [(req) => (req.method === "PATCH" ? { status: 200, json: {} } : undefined)],
    },
    session: {
      pollLimit: 2,
      sleep: async () => {
        throw new Error(`broke while talking to ${SANDBOX_PROJECT}`);
      },
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, "broke while talking to <project>");
  assert.ok(!JSON.stringify(recording).includes(SANDBOX_PROJECT));
});

// ---- a tenant create that answers wrongly in ways that look like success --------------------------

test("a failed status carrying a tenant's name is still a lost answer: the tenant is found by a read", async () => {
  const { session, ledgerPath, journal } = fakeSession({
    world: {
      lateFaults: [
        (req, res) =>
          req.method === "POST" && req.path.endsWith("tenants") && res.status === 200
            ? { status: 503, json: res.json }
            : undefined,
      ],
    },
  });
  const recording = await session.runRecording();
  assert.equal(recording.failure, undefined);
  assert.equal(recording.closureReady, true);
  const rows = ledgerRows(ledgerPath).filter((r) => r.name === "tenant:stb-1794000000");
  const answer = rows.find((r) => r.phase === "answer" && r.action === "create");
  assert.equal(answer.class, "unknown");
  assert.equal(answer.status, 503);
  assert.equal(answer.reason, "server-error");
  // Settled by a read (the search), then read back once more after its own delete.
  assert.equal(rows.filter((r) => r.phase === "read").length, 2);
  assert.equal(recording.ownership.unknownAnswers[0].settled, true);
  assert.ok(journal.filter((e) => e.id === "get-tenant").length >= 2);
});

test("a 200 that names the wrong display name, or no tenant, is read back before it is trusted", async () => {
  for (const [name, change] of [
    ["another display name", (json) => ({ ...json, displayName: "someone-else" })],
    ["no name", (json) => ({ displayName: json.displayName })],
  ]) {
    const { session, ledgerPath } = fakeSession({
      world: {
        lateFaults: [
          (req, res) =>
            req.method === "POST" && req.path.endsWith("tenants") && res.status === 200
              ? { status: 200, json: change(res.json) }
              : undefined,
        ],
      },
    });
    const recording = await session.runRecording();
    assert.equal(recording.closureReady, true, name);
    const rows = ledgerRows(ledgerPath).filter((r) => r.name === "tenant:stb-1794000000");
    const answer = rows.find((r) => r.phase === "answer" && r.action === "create");
    // Another display name: the id was readable, so the answer is a create; no name: it is unreadable.
    assert.equal(answer.status, 200, name);
    assert.equal(answer.class, name === "no name" ? "unknown" : "ok", name);
    // Either way the tenant is looked up and read before the run goes on, and read back after its delete.
    assert.equal(rows.filter((r) => r.phase === "read").length, 2, name);
  }
});

test("the switch is written before it is read back", async () => {
  let inner;
  const ticks = async () => {
    for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setImmediate(resolve));
  };
  const slowPatch = async (url, init) => {
    if (init.method === "PATCH") await ticks();
    return inner(url, init);
  };
  const t = fakeSession({ world: { tenancy: false }, session: { transport: slowPatch } });
  inner = t.fetch;
  const recording = await t.session.runRecording();
  assert.equal(recording.closureReady, true);
  const ids = t.journal.map((e) => e.id);
  // Each write completes before the first read that could show it.
  assert.deepEqual(ids.slice(0, 4), [
    "read-config",
    "write-tenancy",
    "read-config",
    "list-tenants",
  ]);
  const last = ids.lastIndexOf("write-tenancy");
  assert.equal(ids[last + 1], "read-config");
  assert.equal(ids[last + 2], "count-accounts");
});

// ---- a redirect is never followed ----------------------------------------------------------------

test("every request tells fetch not to follow a redirect", async () => {
  const { session, world } = fakeSession({ world: { tenancy: false } });
  await session.runRecording();
  assert.ok(world.log.length > 40);
  assert.ok(world.log.every((e) => e.redirect === "error"));
});

test("a redirect met by a create, a delete or a row is an unknown answer, never an answer", async () => {
  const redirected = (match) =>
    fakeSession({ world: { faults: [(req) => (match(req) ? "throw-redirect" : undefined)] } });
  // A create: the name is unknown and, with nothing found, the recording stops open.
  const create = redirected(
    (req) => req.method === "POST" && req.path.endsWith("v1/projects/%P/accounts"),
  );
  const a = await create.session.runRecording();
  assert.match(a.failure, /account a: the create answer is unknown/);
  assert.equal(a.closureReady, false);
  assert.equal(a.ownership.unknownAnswers[0].reason, "transport-error");
  // The same for the tenant create, which is looked for by name before the recording stops.
  const tenant = redirected((req) => req.method === "POST" && req.path.endsWith("tenants"));
  const b = await tenant.session.runRecording();
  assert.equal(b.ownership.unknownAnswers[0].reason, "transport-error");
  // A delete: sticky, never sent again, the recording is not closure-ready.
  const del = redirected(
    (req) => req.path.endsWith("accounts:delete") && JSON.parse(req.body).localId.endsWith("-b"),
  );
  const c = await del.session.runRecording();
  assert.equal(c.closureReady, false);
  assert.ok(c.ownership.reasons.some((r) => r.startsWith("unknown-delete-answers")));
  assert.equal(del.journal.filter((e) => e.id === "delete-account").length, 3);
  // A row: recorded as a transport failure, which the judge reads as unknown.
  let refreshes = 0;
  const row = redirected((req) => req.path === "v1/token" && ++refreshes === 3);
  const d = await row.session.runRecording();
  assert.equal(d.rows["json-camel"].status, 0);
  assert.equal(d.rows["json-camel"].transport, "TypeError");
  assert.equal(classifyAnswer(d.rows["json-camel"]).why, "transport failure");
  assert.equal(d.closureReady, true);
});

/** A server that answers every request with a redirect and counts what it is asked. */
async function redirectingServer() {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(302, { location: "/elsewhere" });
    res.end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    seen,
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test("against a real server that redirects, the session sees a transport failure and follows nothing", async () => {
  const server = await redirectingServer();
  try {
    const ctx = createContext({
      run: "1794000000",
      project: SANDBOX_PROJECT,
      target: { kind: "local", origin: server.origin, projectNumber: NUMBER },
    });
    const { openOwnership } = await import("./shared/ownership.mjs");
    const { createSession } = await import("./securetoken-body/session.mjs");
    const { tempDir } = await import("./test-tmpdir.mjs");
    const ownership = openOwnership({
      path: `${tempDir("stb-")}/issued.jsonl`,
      runId: "stb-1794000000",
    });
    const recording = await createSession(ctx, { ownership, sleep: async () => {} }).runRecording();
    assert.match(
      recording.failure,
      /^harness GET admin\/v2\/projects\/\{project\}\/config: TypeError$/,
    );
    // The config read, then the one request cleanup still makes (the account count): no redirect is followed.
    assert.deepEqual(server.seen, [
      `/identitytoolkit.googleapis.com/admin/v2/projects/${SANDBOX_PROJECT}/config`,
      `/identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:query`,
    ]);
  } finally {
    await server.close();
  }
});
