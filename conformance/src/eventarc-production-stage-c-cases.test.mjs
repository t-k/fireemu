// Stage C: the cases the second recording adds (channel-order, channel-busy, channel-ids, locations,
// publish-boundaries), each run through the real runner against the model of the service. The model is a
// flow model: what a test asserts is what the recorder sends, in what order, to which names, and what it
// leaves behind, never what production answers.

import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { channelBusy } from "./eventarc-production/cases/busy.mjs";
import { channelIds } from "./eventarc-production/cases/ids.mjs";
import { locations } from "./eventarc-production/cases/locations.mjs";
import { channelOrder } from "./eventarc-production/cases/order.mjs";
import { publishBoundaries } from "./eventarc-production/cases/boundaries.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { exitCodeOf, runCases } from "./eventarc-production/runner.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";
const PREFIX = `fe${RUN}-`;
const PARENT = `projects/${PROJECT}/locations/us-central1`;

/** One case through the real runner against the model, with its ceiling lifted. */
async function runOne(item, worldOptions = {}, { wrap = (request) => request } = {}) {
  const world = createWorld({ project: PROJECT, ...worldOptions });
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const notes = [];
  const capture = createCapture({ journal: { write: (line) => notes.push(line) } });
  const transport = { name: "rest", request: wrap((call) => world.request(call), world) };
  const cleanupClient = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: PROJECT,
    ledger,
  });
  const summary = await runCases({
    cases: [{ ...item, requests: Infinity }],
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient,
    ownership,
    capture,
    options: {
      production: false,
      location: "us-central1",
      usageProject: PROJECT,
      publishPrefix: "/v1",
    },
    sleep: async () => {},
    ledger,
  });
  const inCase = world.calls.filter((call) => call.caseId === item.id);
  return { world, summary, ledger, notes, inCase, ownership };
}

const idOf = (path) =>
  decodeURIComponent(path.split("?")[0])
    .split("/")
    .at(-1)
    .replace(/:publishEvents$/, "");
const created = (calls) =>
  calls
    .filter((call) => call.op === "createChannel")
    .map((call) => new URL(`http://w${call.path}`).searchParams.get("channelId"));

test("channel-order: six own channels are created in an order that differs from their name order, then listed in every way the recording needs", async () => {
  const { summary, inCase, world } = await runOne(channelOrder);
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed"],
  );
  const ids = created(inCase);
  assert.equal(ids.length, 6);
  assert.ok(ids.every((id) => id.startsWith(`${PREFIX}co-`)));
  assert.notDeepEqual(ids, ids.toSorted(), "the creation order is not the name order");
  assert.equal(new Set(ids).size, 6);
  const lists = inCase
    .filter((call) => call.op === "listChannels")
    .map((call) => decodeURIComponent(call.path));
  // The whole list twice (is the order stable?), the pages of one, two and three, the page sizes the
  // service may refuse, and the tokens carried to another location, project and the aggregated location.
  const plain = lists.filter((path) => path === `/v1/${PARENT}/channels`);
  assert.ok(plain.length >= 2);
  for (const size of [1, 2, 3])
    assert.ok(
      lists.some((path) => path.includes(`pageSize=${size}`)),
      `pageSize=${size}`,
    );
  for (const size of ["0", "-1", "1001", "100000"])
    assert.equal(
      lists.filter((path) => path.endsWith(`?pageSize=${size}`)).length,
      1,
      `pageSize=${size} once`,
    );
  const withToken = (location) =>
    lists.filter(
      (path) => path.includes(`/locations/${location}/channels?`) && path.includes("pageToken="),
    );
  assert.ok(withToken("europe-west1").length >= 1, "a token of another location");
  assert.ok(withToken("-").length >= 1, "a token for the aggregated location");
  assert.ok(
    lists.some(
      (path) =>
        path.startsWith("/v1/projects/fireemu-no-such-project-0/") && path.includes("pageToken="),
    ),
    "a token of another project",
  );
  // Nothing else changes anything, and every creation is settled.
  assert.deepEqual(
    inCase.filter((call) => ["deleteChannel", "publishEvents"].includes(call.op)),
    [],
  );
  assert.deepEqual(world.refusals, []);
});

test("channel-order: a creation that is not confirmed stops the case before any list", async () => {
  const { summary, inCase } = await runOne(channelOrder, { createAnswer: "unknown-absent" });
  assert.equal(summary.cases[0].outcome, "aborted");
  assert.equal(inCase.filter((call) => call.op === "listChannels").length, 0);
  assert.equal(
    created(inCase).length,
    1,
    "nothing is created after the first one that is not confirmed",
  );
});

test("channel-busy: a second creation, a read, a list, a publish and a deletion are sent while a creation runs, and the same while a deletion runs", async () => {
  for (const busy of ["reject", "accept"]) {
    const { summary, inCase, world } = await runOne(channelBusy, {
      busy,
      duplicate: "409",
      doneAfter: 4,
    });
    assert.deepEqual(
      summary.cases.map((entry) => entry.outcome),
      ["completed"],
      busy,
    );
    const ops = inCase.map((call) => call.op);
    // The first creation is directly followed by the five requests that need it to be running.
    const first = ops.indexOf("createChannel");
    assert.deepEqual(
      ops.slice(first, first + 6),
      [
        "createChannel",
        "getChannel",
        "listChannels",
        "publishEvents",
        "createChannel",
        "deleteChannel",
      ],
      busy,
    );
    // The same name in all six, and it is the case's own.
    const names = new Set(
      inCase
        .slice(first, first + 6)
        .map((call) =>
          call.op === "listChannels" ? null : idOf(call.path.replace(/\?channelId=/, "/")),
        ),
    );
    names.delete(null);
    assert.ok(
      [...names].every((id) => id.startsWith(`${PREFIX}bz-`)),
      busy,
    );
    // A second deletion only after the first answered 2xx and named its operation, and then directly.
    const deletes = ops
      .map((op, index) => (op === "deleteChannel" ? index : -1))
      .filter((index) => index >= 0);
    assert.equal(deletes.length, 3, "one while the creation runs, two while the deletion runs");
    const between = ops.slice(deletes[1] + 1, deletes[2]);
    assert.deepEqual(between, ["getChannel", "listChannels", "publishEvents"], busy);
    // Every operation a request started was read to its end: nothing is left unknown in the ledger.
    assert.ok(world.operations.size >= 4, busy);
    for (const [operation, state] of world.operations)
      assert.ok(
        state.reads >= 4,
        `${busy}: ${operation} was read ${state.reads} times, it is done at 4`,
      );
    assert.deepEqual(world.refusals, [], busy);
  }
});

test("channel-busy: after an unknown first deletion no second deletion is sent", async () => {
  const { summary, inCase } = await runOne(channelBusy, {
    busy: "reject",
    deleteAnswer: "unknown-noeffect",
    duplicate: "409",
  });
  assert.notEqual(summary.cases[0].outcome, "error");
  const deletes = inCase.filter((call) => call.op === "deleteChannel");
  // One deletion while the creation runs, one that answered unknown; never re-sent.
  assert.equal(deletes.length, 2);
});

test("channel-ids: the one-character ID, the final hyphen, a leading hyphen and exactly 63 characters are created or refused and read back; the two variants are sent once each", async () => {
  const { summary, inCase, world } = await runOne(channelIds, { acceptAnyId: true });
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed"],
  );
  const ids = created(inCase).filter((id) => id !== null);
  assert.ok(ids.includes("a"), "one character");
  assert.ok(
    ids.some((id) => id.startsWith(PREFIX) && id.endsWith("-")),
    "a final hyphen",
  );
  assert.ok(
    ids.some((id) => id.startsWith("-")),
    "a leading hyphen",
  );
  assert.ok(
    ids.some((id) => id.length === 63 && id.startsWith(PREFIX)),
    "exactly 63 characters",
  );
  // A name that is not the run's is read before it is created.
  const calls = inCase.map((call) => `${call.op} ${idOf(call.path.replace(/\?channelId=/, "/"))}`);
  assert.ok(
    calls.indexOf("getChannel a") >= 0 &&
      calls.indexOf("getChannel a") < calls.indexOf("createChannel a"),
  );
  // The two variants, once each, refused by the model as the mismatches they are.
  assert.deepEqual(
    world.refusals.map((refusal) => refusal.kind),
    ["create-name-mismatch", "create-name-mismatch"],
  );
});

test("channel-ids: a channel that appears from the creation without a channelId is reported as foreign, never touched, and fails the exit code", async () => {
  const wrap = (request, world) => async (call) => {
    const reply = await request(call);
    if (call.op === "createChannel" && !call.path.includes("channelId="))
      world.channels.set(`${PARENT}/channels/auto-generated-1`, {
        createTime: "2026-10-05T00:00:00Z",
      });
    return reply;
  };
  const { summary, world, notes } = await runOne(channelIds, { acceptAnyId: true }, { wrap });
  assert.deepEqual(summary.foreign, [`${PARENT}/channels/auto-generated-1`]);
  assert.ok(
    world.channels.has(`${PARENT}/channels/auto-generated-1`),
    "it is not deleted: it is not the run's",
  );
  assert.ok(notes.some((line) => JSON.stringify(line).includes("foreign-channel-appeared")));
  assert.equal(exitCodeOf(summary), 1);
});

test("locations: only reads are sent, to real and invented locations, and the operations that were never issued", async () => {
  const { summary, inCase } = await runOne(locations);
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed"],
  );
  assert.deepEqual([...new Set(inCase.map((call) => call.op))].toSorted(), [
    "getChannel",
    "getOperation",
    "listChannels",
  ]);
  assert.ok(inCase.every((call) => call.method === "GET"));
  const lists = inCase
    .filter((call) => call.op === "listChannels")
    .map((call) => call.path.split("/")[5]);
  for (const location of [
    "asia-northeast1",
    "us-east1",
    "us-west1",
    "europe-west4",
    "us-east99",
    "us-central9",
    "europe-north99",
    "asia-south9",
    "global",
    "US-CENTRAL1",
  ])
    assert.ok(lists.includes(location), location);
  const operations = inCase.filter((call) => call.op === "getOperation").map((call) => call.path);
  assert.ok(
    operations.some((path) => path.includes("/locations/us-central1/operations/operation-0-0-0-0")),
  );
  assert.ok(
    operations.some((path) =>
      path.includes("/locations/europe-west1/operations/operation-0-0-0-0"),
    ),
  );
});

test("publish-boundaries: each limit is searched between its recorded bracket and the boundary is noted", async () => {
  const { summary, notes } = await runOne(publishBoundaries, {
    textLimit: 524_500,
    attributeLimit: 100,
    keyLimit: 256,
    doneAfter: 2,
  });
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed"],
  );
  const boundary = (name) =>
    notes
      .map((line) => JSON.parse(JSON.stringify(line)))
      .find(
        (line) =>
          JSON.stringify(line).includes("limit-boundary") && JSON.stringify(line).includes(name),
      );
  assert.ok(boundary("event-text-length"));
  const text = JSON.stringify(boundary("event-text-length"));
  assert.match(text, /"accepted":524500/);
  assert.match(text, /"refused":524501/);
  assert.match(
    JSON.stringify(boundary("extra-attributes")),
    /"accepted":94.*"refused":95|"refused":95.*"accepted":94/,
  );
  assert.match(
    JSON.stringify(boundary("attribute-name-length")),
    /"accepted":253.*"refused":254|"refused":254.*"accepted":253/,
  );
});

test("publish-boundaries: a bracket that moved ends only its own search, and the case goes on", async () => {
  const { summary, notes, inCase } = await runOne(publishBoundaries, {
    textLimit: 100_000,
    attributeLimit: 100,
    keyLimit: 256,
  });
  assert.deepEqual(
    summary.cases.map((entry) => entry.outcome),
    ["completed"],
  );
  assert.ok(
    notes.some(
      (line) =>
        JSON.stringify(line).includes("bracket-moved") &&
        JSON.stringify(line).includes("event-text-length"),
    ),
  );
  assert.ok(
    inCase.filter((call) => call.op === "publishEvents").length > 20,
    "the other searches and the order pairs still ran",
  );
});

test("publish-boundaries: the order-of-checks pairs each carry exactly the two named defects", async () => {
  const { inCase } = await runOne(publishBoundaries, {
    attributeLimit: 100,
    keyLimit: 256,
    textLimit: 524_500,
  });
  const bodies = inCase.filter((call) => call.op === "publishEvents").map((call) => call.body);
  const defects = (event) => {
    const found = [];
    for (const name of ["id", "source", "type", "specVersion"])
      if (event[name] === undefined) found.push(`no ${name}`);
    if (event.attributes?.datacontenttype === undefined) found.push("no datacontenttype");
    if (event.attributes?.time?.ceString !== undefined) found.push("time is a string");
    if (event.attributes?.datacontenttype?.ceString === "application/xml") found.push("xml");
    return found;
  };
  const single = bodies
    .filter((body) => body.events?.length === 1)
    .map((body) => defects(body.events[0]).toSorted().join(" + "));
  for (const pair of [
    "no datacontenttype + no id",
    "no source + time is a string",
    "time is a string + xml",
  ])
    assert.ok(single.includes(pair), pair);
});
