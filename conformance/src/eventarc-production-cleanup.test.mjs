import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { beforeEach } from "node:test";
import { BudgetExceeded, createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createRest } from "./pubsub-production/rest.mjs";
import { PAGE_LIMIT, cleanup } from "./eventarc-production/cleanup.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";

const RUN = "0123456789ab";
let own;
let ledger;
beforeEach(() => {
  own = createOwnership({ project: "demo-project", runId: RUN });
  ledger = createLedger();
});
const mine = (key, location = "us-central1") => own.channel(location, key);
const sleep = async () => {};
const NOT_FOUND = { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
const issue = (name, kind, action = "create") => {
  ledger.sent({ name, action, transport: "rest" });
  ledger.answered({ name, action, transport: "rest", kind });
};

/** A service of channels with pages and long-running deletions, with optional faults. */
function fakeService({
  channels,
  pageSize = 2,
  hidden = new Set(),
  listFault = {},
  deleteFault,
  doneAfter = 2,
  stay = new Set(),
  endless = false,
  textNotFound = false,
}) {
  const live = new Set(channels);
  const calls = [];
  const operations = new Map();
  const eventarc = {
    name: "rest",
    async request({ method, path }) {
      calls.push(`${method} ${path}`);
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      const list = /^projects\/[^/]+\/locations\/([^/]+)\/channels$/.exec(bare);
      if (method === "GET" && list) {
        if (listFault[list[1]]) return listFault[list[1]];
        if (endless) return { status: 200, body: { nextPageToken: "more" }, unknown: false };
        const items = [...live]
          .filter((name) => name.split("/")[3] === list[1] && !hidden.has(name))
          .toSorted();
        const offset = Number(new URL(`http://x${path}`).searchParams.get("pageToken") ?? 0);
        const next = offset + pageSize < items.length ? String(offset + pageSize) : undefined;
        return {
          status: 200,
          body: {
            channels: items.slice(offset, offset + pageSize).map((name) => ({ name })),
            ...(next ? { nextPageToken: next } : {}),
          },
          unknown: false,
        };
      }
      if (method === "GET" && bare.includes("/operations/")) {
        const state = operations.get(bare);
        state.reads += 1;
        return {
          status: 200,
          body: { name: bare, done: state.reads >= doneAfter },
          unknown: false,
        };
      }
      if (method === "GET")
        return live.has(bare)
          ? { status: 200, body: { name: bare }, unknown: false }
          : textNotFound
            ? { status: 404, body: { raw: "Not Found" }, unknown: false }
            : NOT_FOUND;
      if (method === "DELETE") {
        const fault = deleteFault?.(bare);
        if (fault) return fault;
        if (!live.has(bare)) return NOT_FOUND;
        if (!stay.has(bare)) live.delete(bare);
        const name = `projects/demo-project/locations/us-central1/operations/op-${operations.size}`;
        operations.set(name, { reads: 0 });
        return { status: 200, body: { name, done: false }, unknown: false };
      }
      throw new Error(`unexpected ${method} ${path}`);
    },
  };
  return {
    live,
    calls,
    operations,
    client: createClient({
      transports: { eventarc },
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
    project: "demo-project",
    ledger,
    sleep,
    ...extra,
  });
const deletes = (service) => service.calls.filter((call) => call.startsWith("DELETE"));

test("what a fresh list shows under the run's prefix is deleted across pages and locations, each operation polled to done and read back", async () => {
  const resources = [
    mine("a"),
    mine("b"),
    mine("c"),
    mine("d", "europe-west1"),
    "projects/demo-project/locations/us-central1/channels/someone-else",
    "projects/demo-project/locations/us-central1/channels/fe999999999999-x",
  ];
  own.channel("us-central1", "seed");
  own.channel("europe-west1", "seed");
  const service = fakeService({ channels: resources });
  const report = await run(service);
  assert.deepEqual([report.leftover, report.errors, report.unsettled], [[], [], []]);
  assert.deepEqual(report.deleted, [mine("d", "europe-west1"), mine("a"), mine("b"), mine("c")]);
  assert.deepEqual(report.listed, ["europe-west1", "us-central1"]);
  assert.equal(service.live.size, 2);
  assert.equal(
    [...service.operations.values()].every((state) => state.reads === 2),
    true,
    "polled until done",
  );
});

test("a channel the run created with a 2xx is deleted even when the list omits it, after being read by name", async () => {
  const name = mine("hidden");
  issue(name, "ok");
  const service = fakeService({ channels: [name], hidden: new Set([name]) });
  const report = await run(service);
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
  const sequence = service.calls.filter(
    (call) => call.includes("fe0123456789ab-hidden") && !call.includes("operations"),
  );
  assert.deepEqual(
    sequence.map((call) => call.split(" ")[0]),
    ["GET", "DELETE", "GET"],
    "read first, deleted, read back",
  );
});

test("a probe is touched only when the run's own creation of it answered 2xx or unknown, whatever a list shows", async () => {
  const conflict = own.registerProbe("projects/demo-project/locations/us-central1/channels/taken");
  const created = own.registerProbe("projects/demo-project/locations/us-central1/channels/created");
  const unknownPresent = own.registerProbe(
    "projects/demo-project/locations/us-central1/channels/unk-present",
  );
  const unknownAbsent = own.registerProbe(
    "projects/demo-project/locations/us-central1/channels/unk-absent",
  );
  const never = own.registerProbe(
    "projects/demo-project/locations/us-central1/channels/never-issued",
  );
  issue(conflict, "conflict");
  issue(created, "ok");
  issue(unknownPresent, "unknown");
  issue(unknownAbsent, "unknown");
  const service = fakeService({ channels: [conflict, created, unknownPresent, never] });
  const report = await run(service);
  assert.deepEqual(report.deleted.toSorted(), [created, unknownPresent].toSorted());
  assert.deepEqual(report.alreadyGone, [unknownAbsent]);
  const touched = (name) =>
    service.calls.some((call) => call.endsWith(`/${name.split("/").at(-1)}`));
  assert.equal(
    touched(conflict),
    false,
    "a probe that answered 409 is not ours, even though it is listed",
  );
  assert.equal(touched(never), false);
  assert.equal(service.live.has(conflict), true);
  assert.deepEqual(
    report.unsettled,
    [unknownAbsent],
    "a creation that is still unknown is not settled by absence",
  );
});

test("a creation sent and never answered is unknown and read by name, and a location the ledger names is listed too", async () => {
  const name = mine("sent-only", "europe-west1");
  ledger.sent({ name, action: "create", transport: "rest" });
  own.registerProbe(name);
  const service = fakeService({ channels: [name] });
  const report = await run(service);
  assert.deepEqual(report.deleted, [name]);
  assert.deepEqual(report.listed, ["europe-west1"]);
});

test("a location whose list cannot be read is an error, a late list does not settle, and the ledger still finds the channel", async () => {
  const name = mine("a");
  issue(name, "ok");
  const service = fakeService({
    channels: [name],
    listFault: { "us-central1": { status: 503, body: {}, unknown: true } },
  });
  const report = await run(service);
  assert.deepEqual(report.errors, ["listChannels us-central1: unknown answer"]);
  assert.deepEqual([report.listed, report.deleted], [[], [name]]);
  ledger = createLedger();
  const nothing = fakeService({
    channels: [mine("b")],
    listFault: {
      "us-central1": {
        status: 403,
        body: { error: { status: "PERMISSION_DENIED" } },
        unknown: false,
      },
    },
  });
  own.channel("us-central1", "seed");
  const refused = await run(nothing);
  assert.deepEqual(
    [refused.errors, refused.deleted],
    [["listChannels us-central1: PERMISSION_DENIED"], []],
  );
  assert.equal(deletes(nothing).length, 0, "nothing is deleted on the strength of a failed list");
});

test("an unreadable list and a list that never ends are errors, not empty lists", async () => {
  own.channel("us-central1", "seed");
  const unreadable = fakeService({
    channels: [],
    listFault: { "us-central1": { status: 200, body: { raw: "<html>" }, unknown: true } },
  });
  assert.deepEqual((await run(unreadable)).errors, ["listChannels us-central1: unknown answer"]);
  const endless = fakeService({ channels: [], endless: true });
  const stuck = await run(endless);
  assert.equal(PAGE_LIMIT, 20);
  assert.equal(endless.calls.length, 20);
  assert.ok(
    endless.calls[0].includes("pageSize=100") && endless.calls[1].includes("pageToken=more"),
  );
  assert.deepEqual(stuck.errors, [`listChannels us-central1: more than ${PAGE_LIMIT} pages`]);
  assert.deepEqual(stuck.listed, []);
});

test("an unknown deletion is not sent again and is settled only by the read-back; a refusal is an error; an unfinished operation is reported", async () => {
  const flaky = mine("flaky");
  const denied = mine("denied");
  const slow = mine("slow");
  let service;
  service = fakeService({
    channels: [flaky, denied, slow],
    doneAfter: 99,
    deleteFault: (name) =>
      name.endsWith("-flaky")
        ? (service.live.delete(name), { status: 503, body: {}, unknown: true })
        : name.endsWith("-denied")
          ? { status: 403, body: { error: { status: "PERMISSION_DENIED" } }, unknown: false }
          : undefined,
  });
  own.channel("us-central1", "seed");
  const report = await run(service, { pollAttempts: 3 });
  assert.equal(deletes(service).filter((call) => call.endsWith("-flaky")).length, 1);
  assert.ok(report.errors.includes(`deleteChannel ${denied}: PERMISSION_DENIED`));
  assert.ok(report.errors.some((error) => /^operation .*: not done$/.test(error)));
  assert.deepEqual(report.settled.map((item) => item.name).toSorted(), [flaky, slow].toSorted());
  assert.deepEqual(report.unsettled, [denied]);
});

test("a stuck channel is left over with two seconds between the three reads, and a channel already gone is not an error", async () => {
  const name = mine("stubborn");
  const service = fakeService({ channels: [name], stay: new Set([name]), doneAfter: 1 });
  const sleeps = [];
  const report = await run(service, { sleep: async (ms) => sleeps.push(ms) });
  assert.deepEqual([report.leftover, sleeps.filter((ms) => ms === 2000).length], [[name], 2]);
  assert.equal(service.calls.filter((call) => call === `GET /v1/${name}`).length, 3);
  ledger = createLedger();
  const gone = mine("gone");
  let other;
  other = fakeService({ channels: [gone], deleteFault: (n) => (other.live.delete(n), NOT_FOUND) });
  own.channel("us-central1", "seed");
  const second = await run(other);
  assert.deepEqual([second.alreadyGone, second.errors, second.leftover], [[gone], [], []]);
});

test("a name of the ledger that the list did not show and whose read is not a clean answer is an error and nothing is deleted for it", async () => {
  const name = mine("unreadable");
  issue(name, "ok");
  const calls = [];
  const transport = {
    name: "rest",
    request: async ({ method, path }) => {
      calls.push(`${method} ${path}`);
      return path.includes("/channels?")
        ? { status: 200, body: {}, unknown: false }
        : { status: 503, body: {}, unknown: true };
    },
  };
  const client = createClient({
    transports: { eventarc: transport },
    ownership: own,
    caseId: "cleanup",
    usageProject: "p",
    ledger,
  });
  const report = await cleanup({ client, ownership: own, project: "demo-project", ledger, sleep });
  assert.deepEqual(report.errors, [`getChannel ${name}: unknown answer`]);
  assert.equal(
    calls.some((call) => call.startsWith("DELETE")),
    false,
  );
  assert.deepEqual([report.unsettled, report.budgetSpent, report.deleted], [[name], false, []]);
});

test("running out of the cleanup budget is reported, not thrown, and leaves the rest unsettled", async () => {
  const names = [mine("a"), mine("b")];
  for (const name of names) issue(name, "ok");
  const client = createClient({
    transports: {
      eventarc: createRest({
        base: "http://127.0.0.1:1",
        budget: createBudget(3),
        capture: createCapture({ journal: { write() {} } }),
        fetchImpl: async () => ({ status: 200, text: async () => "{}" }),
      }),
    },
    ownership: own,
    caseId: "cleanup",
    usageProject: "p",
    ledger,
  });
  const report = await cleanup({ client, ownership: own, project: "demo-project", ledger, sleep });
  assert.equal(report.budgetSpent, true);
  assert.match(report.errors.at(-1), /the cleanup budget is spent/);
  assert.equal(report.unsettled.length, 2);
  assert.ok(new BudgetExceeded(1) instanceof Error);
});

test("replay on the recorded answers: the empty channel list and the 404 of channels/firebase", async () => {
  const fixture = (name) =>
    JSON.parse(
      readFileSync(
        new URL(`./eventarc-production/fixtures/preflight-002/${name}`, import.meta.url),
        "utf8",
      ),
    );
  const list = fixture("channels-list.json");
  const missing = fixture("channel-firebase-404.json");
  assert.equal(list.url.endsWith("/locations/us-central1/channels?pageSize=100"), true);
  assert.equal(
    Buffer.byteLength(missing.body, "utf8"),
    373,
    "the recorded layout is the recorded length",
  );
  const eventarc = {
    name: "rest",
    request: async ({ path }) => {
      const recorded = path.includes("?") ? list : missing;
      return { status: recorded.status, body: JSON.parse(recorded.body), unknown: false };
    },
  };
  const ownership = createOwnership({ project: "fireemu-oracle-idp", runId: RUN });
  ownership.channel("us-central1", "x");
  const client = createClient({
    transports: { eventarc },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
  });
  const report = await cleanup({ client, ownership, project: "fireemu-oracle-idp", sleep });
  assert.deepEqual(
    [report.deleted, report.errors, report.unsettled, report.listed],
    [[], [], [], ["us-central1"]],
  );
  const answer = await client.getChannel(
    "projects/fireemu-oracle-idp/locations/us-central1/channels/firebase",
  );
  assert.deepEqual([answer.ok, answer.code, answer.status], [false, "NOT_FOUND", 404]);
});

test("a channel that is absent when read by name is settled as absent, and a refused deletion is not read back", async () => {
  const gone = mine("absent");
  issue(gone, "ok");
  const denied = mine("denied-readback");
  issue(denied, "ok");
  const service = fakeService({
    channels: [denied],
    deleteFault: () => ({
      status: 403,
      body: { error: { status: "PERMISSION_DENIED" } },
      unknown: false,
    }),
  });
  const report = await run(service);
  assert.deepEqual(report.settled, [{ name: gone, how: "absent" }]);
  assert.deepEqual(report.alreadyGone, [gone]);
  const after = service.calls.slice(
    service.calls.findIndex((call) => call.startsWith("DELETE")) + 1,
  );
  assert.equal(
    after.some((call) => call.includes("denied-readback")),
    false,
    "no read-back after a refusal",
  );
  assert.deepEqual(report.unsettled, [denied]);
});

test("an operation that never finishes is read fifteen times by default with two seconds between, and as often as it is asked for", async () => {
  const name = mine("never-done");
  const defaultReads = fakeService({ channels: [name], doneAfter: 99 });
  own.channel("us-central1", "seed");
  const sleeps = [];
  const report = await run(defaultReads, { sleep: async (ms) => sleeps.push(ms) });
  assert.equal([...defaultReads.operations.values()][0].reads, 15);
  assert.deepEqual(sleeps.slice(0, 14), Array(14).fill(2000));
  assert.ok(report.errors.some((error) => error.endsWith("not done")));
  ledger = createLedger();
  const three = fakeService({ channels: [mine("three")], doneAfter: 99 });
  await run(three, { pollAttempts: 3 });
  assert.equal([...three.operations.values()][0].reads, 3);
  ledger = createLedger();
  const one = fakeService({ channels: [mine("one")], doneAfter: 99 });
  await run(one, { pollAttempts: 1 });
  assert.equal([...one.operations.values()][0].reads, 1);
});

const later = { mode: "later" };

test("a creation that is still unknown is not settled by a 404 inside the recording, but by the later run's own 404", async () => {
  // The POST answered 2xx and the operation was never read as done: `unknown`, not `ok`.
  const pending = mine("pending");
  issue(pending, "unknown");
  const absent = fakeService({ channels: [] });
  own.channel("us-central1", "seed");
  const inRecording = await run(absent);
  assert.deepEqual(inRecording.unsettled, [pending]);
  assert.deepEqual(inRecording.settled, []);
  assert.deepEqual(inRecording.alreadyGone, [pending]);
  const afterwards = await run(fakeService({ channels: [] }), later);
  assert.deepEqual(afterwards.unsettled, []);
  assert.deepEqual(afterwards.settled, [{ name: pending, how: "absent" }]);
  // Once the operation is read as done and the channel is ours, a 404 settles it.
  ledger = createLedger();
  const proven = mine("proven");
  issue(proven, "unknown");
  issue(proven, "ok");
  const second = await run(fakeService({ channels: [] }));
  assert.deepEqual(second.settled, [{ name: proven, how: "absent" }]);
});

test("a creation whose operation ended with ALREADY_EXISTS is a conflict and the channel is never deleted", async () => {
  const taken = own.registerProbe("projects/demo-project/locations/us-central1/channels/taken");
  issue(taken, "unknown");
  issue(taken, "conflict");
  const service = fakeService({ channels: [taken] });
  const report = await run(service);
  assert.equal(service.calls.length > 0, true);
  assert.equal(
    service.calls.some((call) => call.startsWith("DELETE")),
    false,
  );
  assert.equal(service.live.has(taken), true);
  assert.deepEqual([report.deleted, report.unsettled], [[], []]);
});

test("after an unknown deletion nothing is sent again inside the recording; the later run sends one after its own 2xx read, unless an earlier later run did", async () => {
  const name = mine("flaky");
  issue(name, "ok");
  issue(name, "unknown", "delete");
  const inRecording = fakeService({ channels: [name] });
  const recorded = await run(inRecording);
  assert.equal(deletes(inRecording).length, 0, "read-backs only");
  assert.deepEqual(recorded.leftover, [name]);
  assert.deepEqual(recorded.unsettled, [name]);
  // The deletion was applied after all: a read-back settles it.
  let applied;
  applied = fakeService({ channels: [name] });
  applied.live.delete(name);
  const settledBack = await run(applied);
  assert.deepEqual(settledBack.settled, [{ name, how: "absent" }]);
  assert.equal(deletes(applied).length, 0);
  // The later run: one DELETE after its own read.
  const afterwards = fakeService({ channels: [name] });
  const one = await run(afterwards, later);
  assert.equal(deletes(afterwards).length, 1);
  assert.deepEqual(one.settled, [{ name, how: "deleted" }]);
  // Not again when an earlier later run sent one.
  const again = fakeService({ channels: [name], stay: new Set([name]) });
  const blocked = await run(again, { ...later, noDelete: new Set([name]) });
  assert.equal(deletes(again).length, 0);
  assert.deepEqual(blocked.leftover, [name]);
});

test("a deletion answered 2xx whose operation did not finish is written into the ledger as unknown and is not sent again", async () => {
  const name = mine("slow-delete");
  issue(name, "ok");
  const service = fakeService({ channels: [name], doneAfter: 99, stay: new Set([name]) });
  const first = await run(service, { pollAttempts: 2 });
  assert.equal(deletes(service).length, 1);
  assert.ok(first.errors.some((error) => error.endsWith("not done")));
  assert.deepEqual(first.leftover, [name]);
  const facts = ledger.state().get(name);
  assert.deepEqual(
    facts.deletes,
    ["unknown", "unknown"],
    "the 2xx, then the operation that was not done",
  );
  // A second cleanup of the same run sends nothing more.
  const second = await run(service, { pollAttempts: 2 });
  assert.equal(deletes(service).length, 1);
  assert.deepEqual(second.unsettled, [name]);
});

test("only the recorded JSON 404 settles anything: a 404 with a text body is an error", async () => {
  const name = mine("text-404");
  issue(name, "ok");
  const service = fakeService({ channels: [], textNotFound: true });
  own.channel("us-central1", "seed");
  const report = await run(service);
  assert.deepEqual(report.settled, []);
  assert.deepEqual(report.alreadyGone, []);
  assert.deepEqual(report.errors, [
    `getChannel ${name}: NOT_FOUND (a 404 that is not the recorded shape)`,
  ]);
  assert.deepEqual(report.unsettled, [name]);
  // And a read-back that answers a text 404 is not a settlement.
  ledger = createLedger();
  const stuck = fakeService({ channels: [mine("gone-by-text")], textNotFound: true });
  const back = await run(stuck);
  assert.deepEqual(back.leftover.length + back.settled.length, 1);
  assert.equal(back.settled.length, 0, "the text 404 did not settle the read-back");
});

test("a target in a location that cannot exist is read by name and its location is never listed", async () => {
  const nowhere = own.registerProbe(
    "projects/demo-project/locations/no-such-location1/channels/nowhere",
    { listable: false },
  );
  issue(nowhere, "unknown");
  const service = fakeService({ channels: [] });
  const report = await run(service, later);
  assert.equal(
    service.calls.some((call) => call.includes("locations/no-such-location1/channels?")),
    false,
  );
  assert.deepEqual(report.listed, []);
  assert.deepEqual(report.settled, [{ name: nowhere, how: "absent" }]);
  assert.deepEqual(report.errors, []);
});
