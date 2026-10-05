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
async function runOne(item, worldOptions = {}, { wrap = (request) => request, log = [] } = {}) {
  const sleeps = [];
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
    sleep: async (ms) => {
      sleeps.push(ms);
      log.push(`sleep:${ms}`);
    },
    ledger,
  });
  const inCase = world.calls.filter((call) => call.caseId === item.id);
  return { world, summary, ledger, notes, inCase, ownership, sleeps };
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

const noteOf = (notes, kind, name) =>
  notes.find((line) => line.note === kind && line.name === name);

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
  const found = (name) => {
    const note = noteOf(notes, "limit-boundary", name);
    assert.ok(note, name);
    return [note.accepted, note.refused, note.unknown];
  };
  assert.deepEqual(found("event-text-length"), [524_500, 524_501, false]);
  assert.deepEqual(found("extra-attributes"), [94, 95, false]);
  assert.deepEqual(found("attribute-name-length"), [253, 254, false]);
});

// Model-based: for any limit inside the recorded bracket the search finds it exactly, in at most the steps
// its interval needs, and the case stays inside its ceiling.
test("property: for any limits inside the recorded brackets every search pins its boundary exactly and the case fits its ceiling", async () => {
  let seed = 424242;
  const next = (low, high) => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return low + (seed % (high - low + 1));
  };
  for (let round = 0; round < 25; round += 1) {
    const textLimit = next(524_032, 524_799);
    const attributeLimit = next(6, 105);
    const keyLimit = next(4, 258);
    const { summary, notes, inCase } = await runOne(publishBoundaries, {
      textLimit,
      attributeLimit,
      keyLimit,
      doneAfter: 3,
    });
    const label = JSON.stringify({ textLimit, attributeLimit, keyLimit });
    assert.equal(summary.cases[0].outcome, "completed", label);
    assert.ok(inCase.length <= publishBoundaries.requests, `${label}: ${inCase.length}`);
    for (const [name, accepted] of [
      ["event-text-length", textLimit],
      ["extra-attributes", attributeLimit - 6],
      ["attribute-name-length", keyLimit - 3],
    ]) {
      const note = noteOf(notes, "limit-boundary", name);
      assert.deepEqual(
        [note?.accepted, note?.refused],
        [accepted, accepted + 1],
        `${name} ${label}`,
      );
    }
  }
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
  assert.ok(noteOf(notes, "bracket-moved", "event-text-length"));
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

// Model-based: whatever the service does while an operation runs (nothing, a refusal, a second operation),
// the case completes without touching a name that is not the run's, and when every deletion answers, the
// cleanup leaves none of the run's channels behind.
test("property: channel-busy and channel-order complete in every mode of the model and leave nothing of the run behind when deletions answer", async () => {
  for (const busy of ["off", "reject", "accept"])
    for (const doneAfter of [1, 2, 3, 5, 10])
      for (const item of [channelBusy, channelOrder, channelIds]) {
        const label = `${item.id} busy=${busy} doneAfter=${doneAfter}`;
        const { summary, world } = await runOne(item, {
          busy,
          doneAfter,
          duplicate: "409",
          acceptAnyId: true,
          acceptVariants: doneAfter % 2 === 0,
        });
        assert.equal(summary.cases[0].outcome, "completed", label);
        assert.deepEqual(summary.cleanup.errors, [], label);
        assert.deepEqual(summary.cleanup.leftover, [], label);
        assert.deepEqual(
          [...world.channels.keys()].filter((name) => name.includes(`/fe${RUN}-`)),
          [],
          label,
        );
      }
});

test("property: an unknown deletion is never re-sent, whatever else the service does", async () => {
  for (const deleteAnswer of ["unknown-effective", "unknown-noeffect"])
    for (const busy of ["off", "reject", "accept"]) {
      const { inCase, summary } = await runOne(channelBusy, {
        busy,
        deleteAnswer,
        duplicate: "409",
      });
      const label = `${deleteAnswer} ${busy}`;
      assert.equal(summary.cases[0].outcome, "completed", label);
      // Per name, one deletion in the case: the one that answered unknown is not sent again.
      const perName = new Map();
      for (const call of inCase.filter((c) => c.op === "deleteChannel"))
        perName.set(call.path, (perName.get(call.path) ?? 0) + 1);
      for (const [path, count] of perName) assert.equal(count, 1, `${label} ${path}`);
    }
});

// ---- Tests that kill the survivors of the first Node mutation pass (each named for what it pins) ----

/** The query of a list request, with the token replaced by `<token>`: the sequence a case sends. */
const listQueries = (calls, location = "us-central1") =>
  calls
    .filter(
      (call) =>
        call.op === "listChannels" &&
        call.path.startsWith(`/v1/projects/${PROJECT}/locations/${location}/`),
    )
    .map((call) => call.path.split("/channels")[1].replace(/pageToken=[^&]+/, "pageToken=<token>"));

test("channel-order: the exact list requests, for six channels", async () => {
  const { inCase } = await runOne(channelOrder);
  assert.deepEqual(listQueries(inCase), [
    "",
    "",
    // pages of one: six pages, the last has no token
    "?pageSize=1",
    ...Array.from({ length: 5 }, () => "?pageSize=1&pageToken=<token>"),
    "?pageSize=2",
    "?pageSize=2&pageToken=<token>",
    "?pageSize=2&pageToken=<token>",
    "?pageSize=3",
    "?pageSize=3&pageToken=<token>",
    "?pageSize=0",
    "?pageSize=-1",
    "?pageSize=1001",
    "?pageSize=100000",
    "?pageSize=2&pageToken=<token>",
  ]);
  const other = inCase.filter(
    (call) => call.op === "listChannels" && !call.path.startsWith(`/v1/${PARENT}/`),
  );
  assert.deepEqual(
    other.map((call) => call.path.replace(/pageToken=[^&]+/, "pageToken=<token>")),
    [
      "/v1/projects/demo-project/locations/-/channels?pageSize=100",
      "/v1/projects/demo-project/locations/europe-west1/channels?pageSize=1&pageToken=<token>",
      "/v1/projects/fireemu-no-such-project-0/locations/us-central1/channels?pageSize=1&pageToken=<token>",
      "/v1/projects/demo-project/locations/-/channels?pageSize=1&pageToken=<token>",
    ],
  );
});

test("channel-order: the pages are bounded (8 of one, 5 of two, 4 of three) in a location with many channels", async () => {
  const existing = Array.from({ length: 60 }, (_, i) => `${PARENT}/channels/other-${i}`);
  const { inCase } = await runOne(channelOrder, { existing });
  const queries = listQueries(inCase);
  const sized = (size) =>
    queries.filter(
      (query) => query === `?pageSize=${size}` || query.startsWith(`?pageSize=${size}&`),
    );
  assert.equal(sized(1).length, 8 + 0, "eight pages of one");
  assert.equal(
    sized(2).length,
    5 + 1,
    "five pages of two, and the token carried to the same location",
  );
  assert.equal(sized(3).length, 4, "four pages of three");
});

test("channel-order: a list that carries no token ends the case with a note, and sends no token", async () => {
  const wrap = (request) => async (call) => {
    const reply = await request(call);
    if (call.op === "listChannels" && reply.body?.nextPageToken !== undefined) {
      const rest = { ...reply.body };
      delete rest.nextPageToken;
      return { ...reply, body: rest };
    }
    return reply;
  };
  const { notes, inCase } = await runOne(channelOrder, {}, { wrap });
  assert.ok(notes.some((line) => line.note === "no-page-token" && line.pages === 0));
  assert.equal(inCase.filter((call) => call.path.includes("pageToken=")).length, 0);
});

test("channel-busy: a second deletion is sent only after a 2xx that names its operation, and the read-back is three reads two seconds apart", async () => {
  // A deletion answered 2xx with no operation (and no done) is not a running operation: nothing is sent again.
  const sent = [];
  const wrap = (request) => async (call) => {
    if (call.op !== "deleteChannel") return request(call);
    sent.push(call.path);
    return { status: 200, body: {}, unknown: false };
  };
  await runOne(channelBusy, { busy: "reject", duplicate: "409" }, { wrap });
  assert.equal(sent.length >= 2, true);
  assert.equal(new Set(sent).size, sent.length, "no name is deleted twice");
  // A channel that still reads as there: the read-back runs to its end, three reads two seconds apart.
  let seen = 0;
  const log = [];
  const stays = (request) => async (call) => {
    if (call.op !== "getChannel" || !call.path.endsWith("-bz-b")) return request(call);
    // Only the case's own reads: the cleanup after it reads the name too, from the same transport.
    if (call.label?.case === "channel-busy") {
      seen += 1;
      log.push("get");
    }
    return { status: 200, body: { name: call.path.replace(/^\/v1\//, "") }, unknown: false };
  };
  await runOne(channelBusy, { busy: "reject", duplicate: "409" }, { wrap: stays, log });
  assert.equal(seen, 1 + 3, "one read while the deletion runs, three in the read-back");
  assert.deepEqual(
    log.slice(0, log.lastIndexOf("get") + 1).slice(-5),
    ["get", "sleep:2000", "get", "sleep:2000", "get"],
    "three reads, two seconds between them, none before the first",
  );
});

test("channel-ids: a foreign channel needs to be neither listed before nor the run's; a failed list is reported unavailable", async () => {
  // Others existed before and the variants create channels of the run: nothing is foreign.
  const existing = Array.from({ length: 3 }, (_, i) => `${PARENT}/channels/other-${i}`);
  const clean = await runOne(channelIds, { acceptAnyId: true, acceptVariants: true, existing });
  assert.deepEqual(clean.summary.foreign, []);
  assert.equal(
    clean.notes.some((line) => line.note === "foreign-channel-appeared"),
    false,
  );
  assert.equal(
    clean.notes.some((line) => line.note === "foreign-check-unavailable"),
    false,
  );
  // A list that fails ends the check with a note that says which list: the first only, then the second only.
  for (const [failing, expected] of [
    [1, { before: false, after: true }],
    [2, { before: true, after: false }],
  ]) {
    let lists = 0;
    const wrap = (request) => async (call) => {
      if (call.op === "listChannels" && call.path.includes("pageSize=100")) {
        lists += 1;
        if (lists === failing) return { status: 503, body: {}, unknown: true };
      }
      return request(call);
    };
    const run = await runOne(channelIds, { acceptAnyId: true }, { wrap });
    const note = run.notes.find((line) => line.note === "foreign-check-unavailable");
    assert.ok(note, `list ${failing}`);
    assert.deepEqual({ before: note.before, after: note.after }, expected);
    assert.deepEqual(run.summary.foreign, []);
  }
});

test("channel-ids: a variant the service accepts is settled for both names by its own operation", async () => {
  const { ledger } = await runOne(channelIds, {
    acceptAnyId: true,
    acceptVariants: true,
    doneAfter: 2,
  });
  for (const key of ["mm-a", "mm-b"]) {
    const name = `${PARENT}/channels/${PREFIX}id-${key}`;
    const kinds = ledger.state().get(name)?.creates ?? [];
    assert.ok(
      kinds.some((kind) => kind.startsWith("ok@")),
      `${name}: ${kinds.join()}`,
    );
  }
});

/** The values a search asks for, by an independent bisection: the ends first, then the middle of what is left. */
function reference(low, high, limit, { askLow }) {
  const asked = askLow ? [low, high] : [high];
  let accepted = low;
  let refused = high;
  while (refused - accepted > 1) {
    const middle = accepted + Math.floor((refused - accepted) / 2);
    asked.push(middle);
    if (middle <= limit) accepted = middle;
    else refused = middle;
  }
  return asked;
}

test("publish-boundaries: the exact values every search asks for, in order, and the pairs' shapes", async () => {
  const limits = { textLimit: 524_500, attributeLimit: 100, keyLimit: 256 };
  const { inCase } = await runOne(publishBoundaries, limits);
  const bodies = inCase
    .filter((call) => call.op === "publishEvents")
    .map((call) => call.body.events);
  const sizeOf = (events) => events[0].textData?.length;
  const sent = bodies.filter(
    (events) => events.length === 1 && sizeOf(events) > 100_000 && events[0].id !== undefined,
  );
  // The ends of the text bracket, then the bisection between them.
  assert.deepEqual(
    sent.slice(0, reference(524_032, 524_800, 524_500, { askLow: true }).length).map(sizeOf),
    reference(524_032, 524_800, 524_500, { askLow: true }),
  );
  const extrasOf = (events) =>
    Object.keys(events[0].attributes ?? {}).filter((key) => key.startsWith("ext")).length;
  const extras = bodies.filter((events) => (events.length === 1 && extrasOf(events) > 0) || false);
  const wanted = reference(0, 100, 94, { askLow: false });
  assert.deepEqual(extras.slice(0, wanted.length).map(extrasOf), wanted);
  const nameLength = (events) =>
    Object.keys(events[0].attributes ?? {}).find(
      (key) => key.startsWith("n") && key.length > 3 && !key.startsWith("ext"),
    )?.length;
  const names = bodies.filter((events) => events.length === 1 && nameLength(events) !== undefined);
  const wantedNames = reference(1, 256, 253, { askLow: false });
  assert.deepEqual(names.slice(0, wantedNames.length).map(nameLength), wantedNames);
  // Nothing else is asked: the ends and the bisections, and the eight events with two defects. The low ends
  // of the two attribute brackets (no extra attribute, a name of one character) are not asked again.
  assert.equal(
    bodies.length,
    reference(524_032, 524_800, 524_500, { askLow: true }).length +
      wanted.length +
      wantedNames.length +
      8,
  );
  // 101 events, each without a type.
  const many = bodies.find((events) => events.length === 101);
  assert.ok(many && many.every((event) => event.type === undefined));
  assert.equal(bodies.filter((events) => events.length > 100).length, 1);
});

test("publish-boundaries: a high end answered with no verdict (a 503) ends that search with the note, and an accepted one too", async () => {
  for (const [answer, expected] of [
    [{ status: 503, body: {}, unknown: true }, null],
    [{ status: 200, body: {}, unknown: false }, true],
  ]) {
    const wrap = (request) => async (call) => {
      const size = call.body?.events?.[0]?.textData?.length;
      if (call.op === "publishEvents" && size === 524_800) return answer;
      return request(call);
    };
    const { notes } = await runOne(
      publishBoundaries,
      { textLimit: 524_500, attributeLimit: 100, keyLimit: 256 },
      { wrap },
    );
    const moved = notes.find(
      (line) => line.note === "bracket-moved" && line.name === "event-text-length",
    );
    assert.ok(moved, String(expected));
    assert.deepEqual([moved.lowAccepted, moved.highAccepted], [true, expected]);
    assert.equal(noteOf(notes, "limit-boundary", "event-text-length"), undefined);
  }
});
