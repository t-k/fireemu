// The Secure Token body session against the in-process world: the whole recording, what it sends,
// what it records, and what its cleanup does when a delete, a create or a switch answers badly.

import assert from "node:assert/strict";
import { test } from "node:test";

import { ROWS } from "./securetoken-body/corpus.mjs";
import {
  buildReport,
  classifyAnswer,
  mergeRecordings,
  readRow,
} from "./securetoken-body/judge.mjs";
import { fakeSession } from "./securetoken-body/test-support.mjs";

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
