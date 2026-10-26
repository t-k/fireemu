// The retirement of `entpipe1`: the guard, the judges against the recorded delete shape, and the
// three phases against a fake database service. Nothing here sends a request.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  DB,
  DATABASE,
  ORIGIN,
  PLAN,
  PROJECT,
  buildRequest,
  definite,
  guardRequest,
  judgeA2,
  judgeDelete,
  judgeOperation,
  judgeS0,
} from "./fs-ent-pipeline/retire.mjs";
import { PHASES, READ_BACK_AFTER_MS } from "./fs-ent-pipeline/retire-entpipe1.mjs";
import { between, forAll, pick } from "./fs-ent-pipeline/test-support.mjs";

const OTHER = `projects/${PROJECT}/databases/(default)`;
const OPERATION = `${DB}/operations/AbCd-1_2.3`;
const ok = (body) => ({ status: 200, body });

/** A clean S0: the database, listed with `(default)`, nothing configured or running. */
const s0Answers = (overrides = {}) => ({
  "s0-databases": ok({ databases: [{ name: OTHER }, { name: DB }] }),
  "s0-describe": ok({
    name: DB,
    uid: "uid-1",
    type: "FIRESTORE_NATIVE",
    databaseEdition: "ENTERPRISE",
    deleteProtectionState: "DELETE_PROTECTION_DISABLED",
  }),
  "s0-indexes": ok({}),
  "s0-operations": ok({ operations: [{ name: `${DB}/operations/old`, done: true }] }),
  "s0-collection-ids": ok({}),
  ...overrides,
});

/** The delete answer of FS-CONFIG-LIFECYCLE's recording, as it reads for this database. */
const recordedDelete = () => {
  const fixture = JSON.parse(
    readFileSync(new URL("../fs-config-lifecycle-production.json", import.meta.url), "utf8"),
  );
  const body = structuredClone(
    fixture.programs["fs-config/database/delete/basic"].steps.delete.body,
  );
  body.name = OPERATION;
  body.response.databaseEdition = "ENTERPRISE";
  body.response.previousId = DATABASE;
  body.response.deleteTime = "2026-10-28T00:00:00Z";
  return ok(body);
};

test("the constants are the literal names, and the read-back waits ten minutes", () => {
  assert.equal(PROJECT, "fireemu-oracle-query");
  assert.equal(DATABASE, "entpipe1");
  assert.equal(DB, "projects/fireemu-oracle-query/databases/entpipe1");
  assert.equal(ORIGIN, "https://firestore.googleapis.com/v1");
  assert.equal(READ_BACK_AFTER_MS, 600_000);
});

test("the plan builds nine planned requests, each to this database only", () => {
  assert.equal(PLAN.length, 9);
  for (const step of PLAN) {
    const request = buildRequest(step);
    assert.ok(request.url.startsWith(`${ORIGIN}/projects/${PROJECT}/databases`), request.url);
    assert.doesNotMatch(request.url, /[?#]/);
  }
  assert.equal(
    buildRequest({ id: "s4-operation-1", method: "GET" }, OPERATION).url,
    `${ORIGIN}/${OPERATION}`,
  );
  assert.deepEqual(
    PLAN.filter((s) => s.method === "DELETE").map((s) => s.id),
    ["s4-delete"],
  );
});

test("the guard refuses everything that is not a planned request for this database", () => {
  const refused = [
    ["DELETE", `${ORIGIN}/${OTHER}`],
    ["DELETE", `${ORIGIN}/projects/${PROJECT}/databases/cfgabc-a`],
    ["DELETE", `${ORIGIN}/projects/${PROJECT}/databases`],
    ["DELETE", `${ORIGIN}/${DB}/collectionGroups/-/indexes`],
    ["DELETE", `${ORIGIN}/${DB}/operations/x`],
    ["DELETE", `${ORIGIN}/projects/other-project/databases/${DATABASE}`],
    ["DELETE", `${ORIGIN}/${DB}?force=true`],
    ["DELETE", `${ORIGIN}/${DB}/`],
    ["DELETE", `https://example.test/v1/${DB}`],
    ["DELETE", `${ORIGIN}/${DB}2`],
    ["PATCH", `${ORIGIN}/${DB}`],
    ["POST", `${ORIGIN}/${DB}`],
    ["GET", `${ORIGIN}/${DB}/operations/../../${DATABASE}x`],
    ["GET", `${ORIGIN}/projects/${PROJECT}/databases/${DATABASE}x/operations/a`],
    ["GET", `${ORIGIN}/${OTHER}/operations/a`],
    ["GET", `${ORIGIN}/${DB}/documents/x/y`],
    ["GET", `x${ORIGIN}/${DB}/operations`],
    ["GET", `x${ORIGIN}/${DB}/operations/a`],
    ["GET", `x${ORIGIN}/${DB}`],
    ["GET", `x${ORIGIN}/${DB}/collectionGroups/-/indexes`],
    ["GET", `x${ORIGIN}/projects/${PROJECT}/databases`],
    ["POST", `x${ORIGIN}/${DB}/documents:listCollectionIds`],
    ["DELETE", `x${ORIGIN}/${DB}`],
  ];
  for (const [method, url] of refused)
    assert.throws(() => guardRequest({ method, url }), /not a planned request/, `${method} ${url}`);
  assert.throws(() => guardRequest({ method: "GET", url: `${ORIGIN}/${DB}`, body: {} }), /no body/);
  assert.throws(
    () =>
      guardRequest({
        method: "POST",
        url: `${ORIGIN}/${DB}/documents:listCollectionIds`,
        body: { pageSize: 1 },
      }),
    /empty one/,
  );
});

test("property: no change to the database name, the project or the method passes the guard", () => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_()./";
  forAll(
    300,
    (random) => {
      const mutate = pick(random, ["database", "project", "method"]);
      const length = between(random, 0, 12);
      let junk = "";
      for (let i = 0; i < length; i += 1) junk += pick(random, [...alphabet]);
      return { mutate, junk };
    },
    ({ mutate, junk }) => {
      const database = mutate === "database" ? junk : DATABASE;
      const project = mutate === "project" ? junk : PROJECT;
      const method = mutate === "method" ? junk.toUpperCase() : "DELETE";
      const unchanged = database === DATABASE && project === PROJECT && method === "DELETE";
      const url = `${ORIGIN}/projects/${project}/databases/${database}`;
      if (unchanged) assert.doesNotThrow(() => guardRequest({ method, url }));
      else assert.throws(() => guardRequest({ method, url }), `${method} ${url}`);
    },
  );
});

test("definite answers: a 2xx, or a 4xx other than 408, 429 and 499", () => {
  for (const status of [200, 201, 204, 400, 403, 404, 409, 412])
    assert.ok(definite(status), status);
  for (const status of [0, -1, 100, 199, 300, 302, 408, 429, 499, 500, 503, 504, undefined, "200"])
    assert.ok(!definite(status), String(status));
});

test("S0 passes only on exactly the expected database, and says why when it does not", () => {
  const good = judgeS0(s0Answers());
  assert.equal(good.ok, true);
  assert.deepEqual(good.snapshot, { uid: "uid-1", others: [OTHER] });
  const describe = (patch) => ok({ ...s0Answers()["s0-describe"].body, ...patch });
  const cases = [
    [
      { "s0-describe": describe({ deleteProtectionState: "DELETE_PROTECTION_ENABLED" }) },
      /delete protection/,
    ],
    [{ "s0-describe": describe({ deleteProtectionState: undefined }) }, /delete protection/],
    [{ "s0-describe": describe({ databaseEdition: "STANDARD" }) }, /edition/],
    [{ "s0-describe": describe({ type: "DATASTORE_MODE" }) }, /type/],
    [{ "s0-describe": describe({ uid: "" }) }, /uid/],
    [{ "s0-describe": describe({ name: OTHER }) }, /describe names/],
    [{ "s0-databases": ok({ databases: [{ name: OTHER }] }) }, /not in the list/],
    [{ "s0-indexes": ok({ indexes: [{ name: "i" }] }) }, /index/],
    [{ "s0-operations": ok({ operations: [{ name: "o", done: false }] }) }, /operation/],
    [{ "s0-operations": ok({ operations: [{ name: "o" }] }) }, /operation/],
    [{ "s0-collection-ids": ok({ collectionIds: ["x"] }) }, /collection holds documents/],
    [{ "s0-collection-ids": { status: 500, body: {} } }, /not a complete 200/],
    [{ "s0-indexes": { status: 200, body: null } }, /not a complete 200/],
  ];
  for (const [overrides, pattern] of cases) {
    const verdict = judgeS0(s0Answers(overrides));
    assert.equal(verdict.ok, false, JSON.stringify(overrides));
    assert.match(verdict.reasons.join(";"), pattern);
  }
  // A missing answer (the run stopped earlier) is not a pass.
  const stopped = s0Answers();
  delete stopped["s0-operations"];
  assert.equal(judgeS0(stopped).ok, false);
});

test("the delete answer: the recorded shape is accepted, every other shape is unknown, a refusal is refused", () => {
  const accepted = judgeDelete(recordedDelete());
  assert.deepEqual(accepted, { verdict: "accepted", operation: OPERATION });
  const mutate = (change) => {
    const answer = recordedDelete();
    change(answer.body);
    return judgeDelete(answer).verdict;
  };
  assert.equal(
    mutate((b) => (b.name = `projects/${PROJECT}/databases/(default)/operations/x`)),
    "unknown",
  );
  assert.equal(
    mutate((b) => (b.name = `${DB}/operations/`)),
    "unknown",
  );
  assert.equal(
    mutate((b) => (b.name = `${DB}/operations/a/b`)),
    "unknown",
  );
  assert.equal(
    mutate(
      (b) =>
        (b.metadata["@type"] =
          "type.googleapis.com/google.firestore.admin.v1.CreateDatabaseMetadata"),
    ),
    "unknown",
  );
  assert.equal(
    mutate((b) => (b.response.databaseEdition = "STANDARD")),
    "unknown",
  );
  assert.equal(
    mutate((b) => (b.response.previousId = "other")),
    "unknown",
  );
  assert.equal(
    mutate((b) => delete b.response.deleteTime),
    "unknown",
  );
  assert.equal(
    mutate((b) => delete b.response),
    "unknown",
  );
  assert.equal(
    mutate((b) => (b.error = { code: 9 })),
    "unknown",
  );
  for (const status of [0, 302, 408, 429, 499, 500, 502, 503, 504])
    assert.equal(judgeDelete({ status, body: {} }).verdict, "unknown", String(status));
  for (const status of [400, 403, 404, 409, 412])
    assert.equal(judgeDelete({ status, body: {} }).verdict, "refused", String(status));
  assert.equal(judgeDelete(ok({})).verdict, "unknown");
  assert.equal(judgeDelete(undefined).verdict, "unknown");
});

test("an operation read: done, pending (the recorded behaviour), failed or unknown", () => {
  const read = (body) => judgeOperation(ok({ name: OPERATION, ...body }), OPERATION).verdict;
  assert.equal(read({}), "pending");
  assert.equal(read({ done: false }), "pending");
  assert.equal(read({ done: true }), "done");
  assert.equal(read({ error: { code: 13 } }), "failed");
  assert.equal(
    judgeOperation(ok({ name: `${DB}/operations/other` }), OPERATION).verdict,
    "unknown",
  );
  assert.equal(judgeOperation({ status: 503, body: {} }, OPERATION).verdict, "unknown");
});

test("the read-back closes only on the list without this database and the recorded 404", () => {
  const snapshot = { uid: "uid-1", others: [OTHER] };
  const notFound = {
    status: 404,
    body: {
      error: { code: 404, message: "Requested database was not found.", status: "NOT_FOUND" },
    },
  };
  const answers = (list, describe) => ({ "a2-databases": list, "a2-describe": describe });
  const listed = (...names) => ok({ databases: names.map((name) => ({ name })) });
  assert.equal(judgeA2(answers(listed(OTHER), notFound), snapshot).verdict, "deleted");
  assert.equal(judgeA2(answers(listed(OTHER, DB), ok({ name: DB })), snapshot).verdict, "present");
  assert.equal(judgeA2(answers(listed(OTHER), ok({ name: DB })), snapshot).verdict, "present");
  // Not settled: another message or status, a failing list, a list that lost or gained a database.
  const otherNotFound = {
    ...notFound,
    body: { error: { ...notFound.body.error, message: "nope" } },
  };
  assert.equal(judgeA2(answers(listed(OTHER), otherNotFound), snapshot).verdict, "unknown");
  assert.equal(
    judgeA2(answers(listed(OTHER), { status: 503, body: {} }), snapshot).verdict,
    "unknown",
  );
  assert.equal(judgeA2(answers({ status: 500, body: {} }, notFound), snapshot).verdict, "unknown");
  assert.equal(judgeA2(answers(listed(), notFound), snapshot).verdict, "unknown");
  assert.equal(
    judgeA2(answers(listed(OTHER, `projects/${PROJECT}/databases/extra`), notFound), snapshot)
      .verdict,
    "unknown",
  );
});

// --- the phases, against a fake database service ---

/** A fake of the three endpoints the plan uses. `deleteStatus` fails the delete; `deletes` counts them. */
function fakeService({
  deleteStatus = 200,
  describeAfterDelete = 404,
  protection = "DELETE_PROTECTION_DISABLED",
  failDescribe = false,
} = {}) {
  const state = { exists: true, deleted: false, deletes: 0, requests: [], deleteAnswered: false };
  const respond = (status, body) => ({ status, text: async () => JSON.stringify(body) });
  const fetch = async (url, init) => {
    state.requests.push(`${init.method} ${url.slice(ORIGIN.length + 1)}`);
    assert.equal(init.redirect, "error");
    assert.equal(init.headers["x-goog-user-project"], PROJECT);
    const path = url.slice(ORIGIN.length + 1);
    if (init.method === "DELETE") {
      state.deletes += 1;
      if (deleteStatus !== 200) return respond(deleteStatus, {});
      state.deleted = true;
      const body = structuredClone(recordedDelete().body);
      return respond(200, body);
    }
    if (path === `projects/${PROJECT}/databases`)
      return respond(200, {
        databases: [
          { name: OTHER },
          ...(state.deleted && describeAfterDelete === 404 ? [] : [{ name: DB }]),
        ],
      });
    if (path === DB) {
      if (failDescribe) return respond(503, {});
      if (state.deleted && describeAfterDelete === 404)
        return respond(404, {
          error: { code: 404, message: "Requested database was not found.", status: "NOT_FOUND" },
        });
      return respond(200, {
        ...s0Answers()["s0-describe"].body,
        deleteProtectionState: protection,
      });
    }
    if (path.endsWith("/indexes")) return respond(200, {});
    if (path.endsWith("/operations")) return respond(200, { operations: [] });
    if (path.endsWith(":listCollectionIds")) return respond(200, {});
    if (path.startsWith(`${DB}/operations/`)) return respond(200, { name: path });
    return respond(500, {});
  };
  return { fetch, state };
}

const ctxFor = (service, dirs, clock) => ({
  token: "TOKEN-SHOULD-NEVER-BE-WRITTEN",
  fetch: service.fetch,
  now: () => new Date(clock.now),
  sleep: async (ms) => {
    clock.now += ms;
  },
  ...dirs,
});
const scratch = () => mkdtempSync(join(tmpdir(), "retire-"));
const filesOf = (dir) => readdirSync(dir).toSorted();

test("S0 sends the five reads, journals each twice, writes a verdict and no token", async () => {
  const service = fakeService();
  const clock = { now: Date.parse("2026-10-28T00:00:00Z") };
  const out = join(scratch(), "s0");
  const { code, verdict } = await PHASES.s0(ctxFor(service, { out }, clock));
  assert.equal(code, 0);
  assert.equal(verdict.ok, true);
  assert.equal(service.state.requests.length, 5);
  assert.equal(service.state.deletes, 0);
  const journal = readFileSync(join(out, "journal.jsonl"), "utf8").trim().split("\n");
  assert.equal(journal.length, 10);
  for (const file of filesOf(out))
    assert.doesNotMatch(readFileSync(join(out, file), "utf8"), /TOKEN-SHOULD/);
});

test("S0 stops at the first answer that is not a complete 200, and an S4 after it sends nothing", async () => {
  const service = fakeService({ protection: "DELETE_PROTECTION_ENABLED" });
  const clock = { now: 0 };
  const dirs = scratch();
  const s0 = join(dirs, "s0");
  const first = await PHASES.s0(ctxFor(service, { out: s0 }, clock));
  assert.equal(first.code, 1);
  assert.match(first.verdict.reasons.join(), /delete protection/);
  const second = await PHASES.s4(ctxFor(service, { out: join(dirs, "s4"), s0 }, clock));
  assert.equal(second.code, 1);
  assert.equal(service.state.deletes, 0);
  assert.ok(!existsSync(join(s0, "s4-sent")));
});

test("S0 stops at the first read that fails: nothing after it is sent", async () => {
  const service = fakeService({ failDescribe: true });
  const { code, verdict } = await PHASES.s0(
    ctxFor(service, { out: join(scratch(), "s0") }, { now: 0 }),
  );
  assert.equal(code, 1);
  assert.equal(verdict.ok, false);
  assert.deepEqual(service.state.requests, [`GET projects/${PROJECT}/databases`, `GET ${DB}`]);
});

test("S4 sends one delete, then reads the operation and the database; a second S4 sends nothing", async () => {
  const service = fakeService();
  const clock = { now: Date.parse("2026-10-28T00:00:00Z") };
  const dirs = scratch();
  const s0 = join(dirs, "s0");
  await PHASES.s0(ctxFor(service, { out: s0 }, clock));
  const out = join(dirs, "s4");
  const run = await PHASES.s4(ctxFor(service, { out, s0 }, clock));
  assert.equal(run.code, 0);
  assert.equal(run.verdict.delete.verdict, "accepted");
  assert.deepEqual(run.verdict.operations, ["pending", "pending", "pending"]);
  assert.equal(run.verdict.describeAfter, 404);
  assert.equal(service.state.deletes, 1);
  assert.ok(existsSync(join(s0, "s4-sent")));
  await assert.rejects(PHASES.s4(ctxFor(service, { out: join(dirs, "s4b"), s0 }, clock)), /EEXIST/);
  assert.equal(service.state.deletes, 1);
  for (const file of filesOf(out))
    assert.doesNotMatch(readFileSync(join(out, file), "utf8"), /TOKEN-SHOULD/);
});

test("an unknown delete (a server error) is not retried and reads nothing further", async () => {
  for (const deleteStatus of [500, 503, 0, 302]) {
    const service = fakeService({ deleteStatus });
    const clock = { now: Date.parse("2026-10-28T00:00:00Z") };
    const dirs = scratch();
    const s0 = join(dirs, "s0");
    await PHASES.s0(ctxFor(service, { out: s0 }, clock));
    const before = service.state.requests.length;
    const run = await PHASES.s4(ctxFor(service, { out: join(dirs, "s4"), s0 }, clock));
    assert.equal(run.code, 2, String(deleteStatus));
    assert.equal(run.verdict.delete.verdict, "unknown");
    assert.equal(service.state.requests.length, before + 1, "only the delete was sent");
    assert.equal(service.state.deletes, 1);
  }
});

test("A2 waits ten minutes after the delete, then closes on the list and the 404, and never on a 200", async () => {
  const service = fakeService();
  const clock = { now: Date.parse("2026-10-28T00:00:00Z") };
  const dirs = scratch();
  const [s0, s4] = [join(dirs, "s0"), join(dirs, "s4")];
  await PHASES.s0(ctxFor(service, { out: s0 }, clock));
  await PHASES.s4(ctxFor(service, { out: s4, s0 }, clock));
  const sentAt = Date.parse(JSON.parse(readFileSync(join(s4, "s4-verdict.json"), "utf8")).sentAt);
  clock.now = sentAt + READ_BACK_AFTER_MS - 1;
  const early = await PHASES.a2(ctxFor(service, { out: join(dirs, "a2-early"), s0, s4 }, clock));
  assert.equal(early.code, 1);
  assert.match(early.verdict.stopped, /ten minutes/);
  clock.now = sentAt + READ_BACK_AFTER_MS;
  const late = await PHASES.a2(ctxFor(service, { out: join(dirs, "a2"), s0, s4 }, clock));
  assert.equal(late.code, 0);
  assert.deepEqual(late.verdict, { verdict: "deleted" });
  // A database that is still there is not closed, however the delete was answered.
  const alive = fakeService({ describeAfterDelete: 200 });
  const dirs2 = scratch();
  const [t0, t4] = [join(dirs2, "s0"), join(dirs2, "s4")];
  const clock2 = { now: Date.parse("2026-10-28T00:00:00Z") };
  await PHASES.s0(ctxFor(alive, { out: t0 }, clock2));
  await PHASES.s4(ctxFor(alive, { out: t4, s0: t0 }, clock2));
  clock2.now += 2 * READ_BACK_AFTER_MS;
  const present = await PHASES.a2(
    ctxFor(alive, { out: join(dirs2, "a2"), s0: t0, s4: t4 }, clock2),
  );
  assert.equal(present.code, 1);
  assert.equal(present.verdict.verdict, "present");
});

test("an output directory that is not empty is refused", async () => {
  const dir = scratch();
  writeFileSync(join(dir, "something"), "x");
  await assert.rejects(PHASES.s0(ctxFor(fakeService(), { out: dir }, { now: 0 })), /not empty/);
});
