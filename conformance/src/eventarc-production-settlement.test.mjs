// What settles a creation or a deletion of the recorder, and what never does (v3 of the stage A recorder).
// The binding rule:
// - An unknown CREATE is settled only by its own operation read as done, or by an exact own 2xx read that
//   shows the channel (which is then cleaned up). A 404, inside the run or in the later run, never settles
//   it: the name stays unsettled as `unknown-create-absent-unconfirmed`.
// - An unknown DELETE, or a DELETE whose operation was never read as done, stays unsettled inside the
//   recording; only the later run's own read-back, at least ten minutes on, closes it.
// - A later request for the same name (the deliberate duplicate creation) settles nothing of an earlier one.

import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";
import { createLedger } from "./pubsub-production/ledger.mjs";
import {
  OPERATION_READS,
  cleanup,
  ledgerFacts,
  pendingCreateOperations,
} from "./eventarc-production/cleanup.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { CLEANUP_BUDGET } from "./eventarc-production/record.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";
const OP1 = `projects/${PROJECT}/locations/us-central1/operations/op-1`;
const OP2 = `projects/${PROJECT}/locations/us-central1/operations/op-2`;
const OPD = `projects/${PROJECT}/locations/us-central1/operations/op-delete`;
const NOT_FOUND = { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
const ALREADY_EXISTS = { code: 6, status: "ALREADY_EXISTS" };

let own;
let ledger;
beforeEach(() => {
  own = createOwnership({ project: PROJECT, runId: RUN });
  ledger = createLedger();
  own.channel("us-central1", "seed");
});
const mine = (key) => own.channel("us-central1", key);
const issue = (name, kind, action = "create") => {
  ledger.sent({ name, action, transport: "rest" });
  ledger.answered({ name, action, transport: "rest", kind });
};

/**
 * A channel service. `operations` maps an operation name to its reply (default: not done). `hidden` are
 * channels a list omits; `goneAfter` makes a channel read 200 that many times and then 404.
 */
function fakeService({
  channels = [],
  hidden = new Set(),
  operations = {},
  goneAfter = new Map(),
  readBody = (name) => ({ name }),
  stay = false,
} = {}) {
  const live = new Set(channels);
  const calls = [];
  const reads = new Map();
  const reply = {
    name: "rest",
    async request({ method, path }) {
      calls.push(`${method} ${path}`);
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      if (method === "GET" && bare.includes("/operations/")) {
        reads.set(bare, (reads.get(bare) ?? 0) + 1);
        return (
          operations[bare] ?? { status: 200, body: { name: bare, done: false }, unknown: false }
        );
      }
      if (method === "GET" && bare.endsWith("/channels"))
        return {
          status: 200,
          body: {
            channels: [...live].filter((name) => !hidden.has(name)).map((name) => ({ name })),
          },
          unknown: false,
        };
      if (method === "GET") {
        if (!live.has(bare)) return NOT_FOUND;
        const seen = (reads.get(bare) ?? 0) + 1;
        reads.set(bare, seen);
        if (goneAfter.has(bare) && seen > goneAfter.get(bare)) {
          live.delete(bare);
          return NOT_FOUND;
        }
        return { status: 200, body: readBody(bare), unknown: false };
      }
      if (method === "DELETE") {
        if (!live.has(bare)) return NOT_FOUND;
        if (!stay) live.delete(bare);
        return { status: 200, body: { name: OPD, done: !stay }, unknown: false };
      }
      throw new Error(`unexpected ${method} ${path}`);
    },
  };
  return {
    live,
    calls,
    reads,
    client: createClient({
      transports: { eventarc: reply },
      ownership: own,
      caseId: "cleanup",
      usageProject: "p",
      ledger,
    }),
  };
}
const run = (service, extra = {}) =>
  cleanup({
    client: service.client,
    ownership: own,
    project: PROJECT,
    ledger,
    sleep: async () => {},
    ...extra,
  });
const deletesOf = (service) => service.calls.filter((call) => call.startsWith("DELETE"));
const done = (extra = {}) => ({
  status: 200,
  body: { name: OP1, done: true, ...extra },
  unknown: false,
});

test("V2-M1(a): a duplicate creation answered 409 does not settle the first creation, whose operation was never read as done", async () => {
  const c1 = mine("cl-c1");
  issue(c1, `unknown@${OP1}`);
  issue(c1, `unknown@${OP1}`);
  issue(c1, "conflict");
  assert.deepEqual(ledgerFacts(ledger.state().get(c1)), {
    mayExist: true,
    createPending: true,
    deleteSent: false,
    deletePending: false,
  });
  // The channel exists but the list does not show it yet: it is read by name, confirmed by that 2xx
  // read and then deleted.
  const present = fakeService({ channels: [c1], hidden: new Set([c1]) });
  const report = await run(present);
  assert.equal(deletesOf(present).length, 1);
  assert.deepEqual(report.settled, [{ name: c1, how: "deleted" }]);
  assert.deepEqual([report.unsettled, report.unconfirmed], [[], []]);
  assert.ok(ledger.state().get(c1).creates.includes("confirmed"), "the read is written down");
});

test("V2-M1(a): the same channel, absent when read, stays unsettled as unconfirmed and the run is not closable", async () => {
  const c1 = mine("cl-c1");
  issue(c1, `unknown@${OP1}`);
  issue(c1, `unknown@${OP1}`);
  issue(c1, "conflict");
  const absent = fakeService({ channels: [] });
  const report = await run(absent);
  assert.deepEqual(report.settled, []);
  assert.deepEqual(report.unsettled, [c1]);
  assert.deepEqual(report.unconfirmed, [c1]);
  assert.deepEqual(report.alreadyGone, [c1]);
  assert.equal(deletesOf(absent).length, 0);
});

test("V2-M1(a): a duplicate creation whose own operation ends with ALREADY_EXISTS settles only itself", async () => {
  const c1 = mine("cl-c1");
  issue(c1, `unknown@${OP1}`);
  issue(c1, `unknown@${OP2}`);
  issue(c1, `conflict@${OP2}`);
  const facts = ledgerFacts(ledger.state().get(c1));
  assert.equal(facts.createPending, true);
  assert.deepEqual(pendingCreateOperations(ledger.state().get(c1)), [OP1]);
  const report = await run(fakeService({ channels: [] }));
  assert.deepEqual([report.unsettled, report.unconfirmed], [[c1], [c1]]);
});

test("a pending creation is settled by its own operation read as done: ok confirms it, an error means nothing was created", async () => {
  // Done without an error: the creation is confirmed, the channel is deleted and the 404 settles it.
  const made = mine("made");
  issue(made, `unknown@${OP1}`);
  const confirmed = fakeService({
    channels: [made],
    hidden: new Set([made]),
    operations: { [OP1]: done() },
  });
  const first = await run(confirmed);
  assert.deepEqual(first.settled, [{ name: made, how: "deleted" }]);
  assert.deepEqual(ledger.state().get(made).creates, [`unknown@${OP1}`, `ok@${OP1}`]);
  // Done without an error, and the channel is gone: the creation is confirmed, so absence settles.
  ledger = createLedger();
  const gone = mine("gone");
  issue(gone, `unknown@${OP1}`);
  const absent = await run(fakeService({ channels: [], operations: { [OP1]: done() } }));
  assert.deepEqual(absent.settled, [{ name: gone, how: "absent" }]);
  assert.deepEqual([absent.unsettled, absent.unconfirmed], [[], []]);
  // Done with ALREADY_EXISTS or another error: nothing was created by this run. The channel is not read,
  // not deleted, and it settles by the operation.
  for (const error of [ALREADY_EXISTS, { code: 13, status: "INTERNAL" }]) {
    ledger = createLedger();
    const taken = own.registerProbe(
      `projects/${PROJECT}/locations/us-central1/channels/taken-${error.code}`,
    );
    issue(taken, `unknown@${OP1}`);
    const service = fakeService({ channels: [taken], operations: { [OP1]: done({ error }) } });
    const report = await run(service);
    assert.deepEqual(report.settled, [{ name: taken, how: "operation" }]);
    assert.deepEqual([report.unsettled, report.unconfirmed, report.deleted], [[], [], []]);
    assert.equal(deletesOf(service).length, 0, "a channel the run did not create is never deleted");
    assert.equal(
      service.calls.some((call) => call.endsWith(`/channels/taken-${error.code}`)),
      false,
    );
  }
});

test("an operation that is not done or cannot be read leaves the creation pending: a 404 does not settle it, in the recording or in the later run", async () => {
  for (const operations of [
    {},
    { [OP1]: { status: 503, body: {}, unknown: true } },
    { [OP1]: { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false } },
    { [OP1]: { status: 200, body: { raw: "<html>" }, unknown: true } },
  ])
    for (const mode of ["recording", "later"]) {
      ledger = createLedger();
      const name = mine("pending");
      issue(name, `unknown@${OP1}`);
      const report = await run(fakeService({ channels: [], operations }), { mode });
      assert.deepEqual(report.settled, [], mode);
      assert.deepEqual([report.unsettled, report.unconfirmed], [[name], [name]], mode);
      assert.equal(ledgerFacts(ledger.state().get(name)).createPending, true);
    }
});

test("a creation with no operation to read (an answer that was unknown) is never settled by a 404, in either run", async () => {
  for (const mode of ["recording", "later"]) {
    ledger = createLedger();
    const name = mine("plain");
    issue(name, "unknown");
    const service = fakeService({ channels: [] });
    const report = await run(service, { mode });
    assert.deepEqual([report.settled, report.unsettled, report.unconfirmed], [[], [name], [name]]);
    assert.equal(
      service.calls.some((call) => call.includes("/operations/")),
      false,
      "there is no operation to read",
    );
  }
  // A creation that never got its answer is the same.
  ledger = createLedger();
  const sent = mine("sent-only");
  ledger.sent({ name: sent, action: "create", transport: "rest" });
  const report = await run(fakeService({ channels: [] }), { mode: "later" });
  assert.deepEqual(report.unconfirmed, [sent]);
});

test("an exact own 2xx read of a pending creation confirms it and it is cleaned up in the later run too", async () => {
  const name = mine("plain");
  issue(name, "unknown");
  const service = fakeService({ channels: [name], hidden: new Set([name]) });
  const report = await run(service, { mode: "later" });
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
  assert.deepEqual(report.unconfirmed, []);
  assert.deepEqual(ledger.state().get(name).creates, ["unknown", "confirmed"]);
  // The confirmation is in the ledger, so a second later run, finding the channel gone, settles it.
  const again = await run(fakeService({ channels: [] }), { mode: "later" });
  assert.deepEqual(again.settled, [{ name, how: "absent" }]);
  assert.deepEqual([again.unsettled, again.unconfirmed], [[], []]);
});

test("a channel a fresh list shows confirms its pending creation too", async () => {
  const name = mine("listed");
  issue(name, `unknown@${OP1}`);
  const service = fakeService({ channels: [name] });
  const report = await run(service);
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
  assert.ok(ledger.state().get(name).creates.includes("confirmed"));
  assert.equal(
    service.calls.filter((call) => call === `GET /v1/${name}`).length,
    1,
    "only the read-back: the list is the confirming read",
  );
});

test("a read that is 2xx but does not show the channel confirms nothing: it is an error and nothing is deleted", async () => {
  for (const readBody of [() => ({}), () => ({ name: mine("other") }), () => ({ raw: "<html>" })]) {
    ledger = createLedger();
    const name = mine("plain");
    issue(name, "unknown");
    const service = fakeService({ channels: [name], hidden: new Set([name]), readBody });
    const report = await run(service);
    assert.deepEqual(report.errors, [
      `getChannel ${name}: a 2xx read that does not show the channel`,
    ]);
    assert.deepEqual([report.settled, report.unsettled], [[], [name]]);
    assert.equal(deletesOf(service).length, 0);
    assert.equal(ledgerFacts(ledger.state().get(name)).createPending, true);
  }
});

test("the name in a confirming read may carry the project number instead of the ID, as long as the channel is the same", async () => {
  const name = mine("plain");
  issue(name, "unknown");
  const service = fakeService({
    channels: [name],
    hidden: new Set([name]),
    readBody: (bare) => ({ name: bare.replace(`projects/${PROJECT}/`, "projects/123456789/") }),
  });
  const report = await run(service);
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
});

test("a pending creation's operation is read before anything else, at most four times, two seconds apart", async () => {
  const name = mine("pending");
  issue(name, `unknown@${OP1}`);
  const sleeps = [];
  const service = fakeService({ channels: [] });
  await run(service, { sleep: async (ms) => sleeps.push(ms) });
  assert.equal(OPERATION_READS, 4);
  assert.match(
    service.calls[0],
    /^GET \/v1\/projects\/demo-project\/locations\/us-central1\/operations\/op-1$/,
  );
  assert.equal(service.reads.get(OP1), OPERATION_READS);
  assert.deepEqual(sleeps, [2000, 2000, 2000]);
  const listedAt = service.calls.findIndex((call) => /\/channels(\?|$)/.test(call));
  assert.ok(listedAt > OPERATION_READS - 1, "the lists come after the operation reads");
  // An operation already read as done is not read again.
  ledger = createLedger();
  issue(name, `unknown@${OP1}`);
  issue(name, `ok@${OP1}`);
  const second = fakeService({ channels: [] });
  await run(second);
  assert.equal(second.reads.get(OP1), undefined);
});

test("V2-M1(b): a deletion whose operation was never read as done is not settled by a 404 inside the recording, only by the later run", async () => {
  const name = mine("deleting");
  issue(name, "ok");
  issue(name, `unknown@${OPD}`, "delete");
  issue(name, `unknown@${OPD}`, "delete");
  const inRecording = await run(fakeService({ channels: [] }));
  assert.deepEqual(inRecording.settled, []);
  assert.deepEqual(inRecording.unsettled, [name]);
  assert.deepEqual(inRecording.alreadyGone, [name]);
  assert.deepEqual(
    inRecording.unconfirmed,
    [],
    "it is the deletion that is open, not the creation",
  );
  const afterwards = await run(fakeService({ channels: [] }), { mode: "later" });
  assert.deepEqual(afterwards.settled, [{ name, how: "absent" }]);
  assert.deepEqual(afterwards.unsettled, []);
});

test("V2-M1(b): a read-back that finds the channel gone after an unfinished deletion does not settle it inside the recording either", async () => {
  const name = mine("deleting");
  issue(name, "ok");
  issue(name, `unknown@${OPD}`, "delete");
  const service = fakeService({
    channels: [name],
    hidden: new Set([name]),
    goneAfter: new Map([[name, 1]]),
  });
  const inRecording = await run(service);
  assert.equal(deletesOf(service).length, 0, "no deletion is sent again");
  assert.deepEqual(
    [inRecording.settled, inRecording.leftover, inRecording.unsettled],
    [[], [], [name]],
  );
  // The later run: one deletion after its own 2xx read, then the 404.
  const later = fakeService({ channels: [name], hidden: new Set([name]) });
  const closing = await run(later, { mode: "later" });
  assert.equal(deletesOf(later).length, 1);
  assert.deepEqual(closing.settled, [{ name, how: "deleted" }]);
});

test("a deletion that was answered ok with its operation done is settled by the 404 inside the recording", async () => {
  const name = mine("deleted");
  issue(name, "ok");
  issue(name, `unknown@${OPD}`, "delete");
  issue(name, `ok@${OPD}`, "delete");
  const report = await run(fakeService({ channels: [] }));
  assert.deepEqual(report.settled, [{ name, how: "absent" }]);
  assert.deepEqual(report.unsettled, []);
});

// A differential test of what the ledger says of a channel, against a plain specification of the rule.
function specification(creates, deletes) {
  const parse = (kind) => {
    const at = kind.indexOf("@");
    return at < 0 ? [kind, null] : [kind.slice(0, at), kind.slice(at + 1)];
  };
  const parsed = creates.map(parse);
  const confirmed = parsed.some(([base]) => base === "confirmed");
  const resolvedOperations = new Set(
    parsed
      .filter(([base, op]) => op !== null && ["ok", "conflict", "error"].includes(base))
      .map(([, op]) => op),
  );
  const open = parsed.some(
    ([base, op]) => base === "unknown" && (op === null || !resolvedOperations.has(op)),
  );
  const createdOk = parsed.some(([base]) => base === "ok" || base === "confirmed");
  const bases = deletes.map((kind) => parse(kind)[0]);
  const last = (kind) => bases.lastIndexOf(kind);
  return {
    mayExist: createdOk || (!confirmed && open),
    createPending: !confirmed && open,
    deleteSent: deletes.length > 0,
    deletePending: last("unknown") > Math.max(last("ok"), last("error")),
  };
}

test("ledgerFacts agrees with the specification on random ledgers, and a duplicate never resolves an earlier creation", () => {
  let seed = 20261005;
  const next = (bound) => {
    seed = (seed * 1664525 + 1013904223) % 4294967296;
    return Math.floor((seed / 4294967296) * bound);
  };
  const kinds = [
    "ok",
    "unknown",
    "conflict",
    "error",
    "confirmed",
    `unknown@${OP1}`,
    `unknown@${OP2}`,
    `ok@${OP1}`,
    `ok@${OP2}`,
    `conflict@${OP1}`,
    `conflict@${OP2}`,
    `error@${OP1}`,
    `error@${OP2}`,
  ];
  for (let round = 0; round < 3000; round += 1) {
    const draw = () => Array.from({ length: next(6) }, () => kinds[next(kinds.length)]);
    const creates = draw();
    const deletes = draw();
    const open = Array.from({ length: next(2) }, () => (next(2) === 0 ? "create" : "delete"));
    const item = { creates: [...creates], deletes: [...deletes], open };
    const expected = specification(
      [...creates, ...open.filter((a) => a === "create").map(() => "unknown")],
      [...deletes, ...open.filter((a) => a === "delete").map(() => "unknown")],
    );
    assert.deepEqual(ledgerFacts(item), expected, JSON.stringify(item));
    // Appending a plain conflict or error (a refused duplicate) never makes a pending creation settled.
    for (const extra of ["conflict", "error"]) {
      const more = ledgerFacts({ ...item, creates: [...creates, extra] });
      assert.equal(more.createPending, expected.createPending, JSON.stringify(item));
    }
  }
});

test("the operations still to read are those a creation named and nothing resolved, once each, in order", () => {
  const item = {
    creates: [`unknown@${OP2}`, `unknown@${OP1}`, `unknown@${OP2}`, `ok@${OP1}`, "unknown"],
    deletes: [`unknown@${OPD}`],
    open: [],
  };
  assert.deepEqual(pendingCreateOperations(item), [OP2]);
  assert.deepEqual(pendingCreateOperations(undefined), []);
  assert.deepEqual(
    pendingCreateOperations({ creates: ["confirmed", `unknown@${OP1}`], deletes: [], open: [] }),
    [],
  );
});

test("the most a cleanup sends for twelve pending creations that all exist and never finish stays inside the cleanup budget", async () => {
  const names = Array.from({ length: 12 }, (_, index) => mine(`pending-${index}`));
  names.forEach((name, index) =>
    issue(name, `unknown@projects/${PROJECT}/locations/us-central1/operations/op-${index}`),
  );
  const service = fakeService({ channels: names, hidden: new Set(names), stay: true });
  const report = await run(service);
  assert.equal(report.budgetSpent, false);
  assert.deepEqual(report.leftover.toSorted(), names.toSorted());
  assert.ok(service.calls.length <= CLEANUP_BUDGET, `${service.calls.length} requests`);
  // 12 x (4 operation reads, 1 read, 1 deletion, 15 polls, 3 read-backs) and one list.
  assert.equal(service.calls.length, 12 * (OPERATION_READS + 1 + 1 + 15 + 3) + 1);
});
