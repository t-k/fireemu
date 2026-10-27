// Before and after the run, the CV14 recorder lists what a deploy of event-triggered functions can
// leave behind besides the functions (Cloud Run services, Eventarc triggers, Pub/Sub topics and
// subscriptions). A 2nd gen RTDB trigger makes an Eventarc trigger and a Pub/Sub topic whose names the
// platform chooses; they are normally removed with the function. Only the exact names the function
// record itself names are ever deleted; anything else new is reported, never removed.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import { resolveTarget } from "../../functions-http/harness.mjs";
import {
  CLASSES,
  INVENTORY_BOUNDS,
  newItems,
  ownedEventarcNames,
  removeLeftovers,
  takeInventory,
} from "./inventory.mjs";

const REGION = "us-central1";
const target = resolveTarget({
  functionName: "rtdbWrittenV2",
  region: REGION,
  codebase: "rtdb-functions-oracle",
  generation: "gcfv2",
});
const TRIGGER = `projects/${PROJECT}/locations/${REGION}/triggers/rtdbwrittenv2-494903`;
const TOPIC = `projects/${PROJECT}/topics/eventarc-${REGION}-rtdbwrittenv2-494903-679`;
const record = (over = {}) => ({
  name: `projects/${PROJECT}/locations/${REGION}/functions/rtdbWrittenV2`,
  eventTrigger: { trigger: TRIGGER, triggerRegion: REGION, pubsubTopic: TOPIC },
  ...over,
});

const URLS = {
  functions: `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/functions`,
  services: `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services`,
  triggers: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/triggers`,
  topics: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics`,
  subscriptions: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions`,
};
const KEYS = {
  functions: "functions",
  services: "services",
  triggers: "triggers",
  topics: "topics",
  subscriptions: "subscriptions",
};

/** A fake of the five lists, with paging, deletes and failures. */
function world(initial = {}, { pageSize = 100, brokenList = null, deleteFails = new Set() } = {}) {
  const sets = Object.fromEntries(CLASSES.map((c) => [c, new Set(initial[c] ?? [])]));
  const calls = [];
  const control = async (method, url, _body, kind, allowed = [200]) => {
    calls.push({ method, url, kind });
    let answer;
    const base = url.split("?")[0];
    const cls = CLASSES.find((c) => URLS[c] === base);
    if (method === "GET" && cls) {
      if (brokenList === cls) return { status: 200, value: { [KEYS[cls]]: "not a list" } };
      const names = [...sets[cls]].toSorted();
      const token = new URL(url).searchParams.get("pageToken");
      const start = token ? Number(token) : 0;
      const page = names.slice(start, start + pageSize);
      answer = {
        status: 200,
        value: {
          [KEYS[cls]]: page.map((name) => ({ name })),
          ...(start + pageSize < names.length ? { nextPageToken: String(start + pageSize) } : {}),
        },
      };
    } else if (method === "DELETE") {
      const name = base.replace(/^https:\/\/[^/]+\/v1\//, "");
      if (deleteFails.has(name)) throw new Error("socket hang up");
      for (const c of CLASSES) if (sets[c].delete(name)) break;
      answer = name.includes("/triggers/")
        ? {
            status: 200,
            value: { name: `projects/${PROJECT}/locations/${REGION}/operations/op-1`, done: false },
          }
        : { status: 200, value: {} };
    } else if (method === "GET" && base.includes("/operations/")) {
      answer = { status: 200, value: { name: base.split("/v1/")[1], done: true } };
    } else answer = { status: 404, value: {} };
    if (!allowed.includes(answer.status)) throw new Error(`status ${answer.status}`);
    return answer;
  };
  return { control, calls, sets };
}
const noSleep = async () => {};

test("the five lists are read page by page within a bound, and a list that is not complete says so", async () => {
  const names = Array.from(
    { length: 305 },
    (_, i) => `projects/p/topics/t-${String(i).padStart(3, "0")}`,
  );
  const w = world({ topics: names }, { pageSize: 100 });
  const taken = await takeInventory(w.control, "inventory");
  assert.equal(taken.complete, false, "305 entries are more than 3 pages of 100");
  assert.equal(INVENTORY_BOUNDS.pageSize, 100);
  assert.equal(INVENTORY_BOUNDS.maxPages, 3);
  assert.equal(w.calls.filter((c) => c.url.startsWith(URLS.topics)).length, 3);
  const small = world({ topics: names.slice(0, 150) });
  const ok = await takeInventory(small.control, "inventory");
  assert.equal(ok.complete, true);
  assert.equal(ok.items.topics.length, 150);
  assert.deepEqual(Object.keys(ok.items), CLASSES);
  assert.ok(small.calls.every((c) => c.kind === "inventory"));
  const broken = await takeInventory(world({}, { brokenList: "services" }).control, "inventory");
  assert.equal(broken.complete, false);
});

test("what is new after the run is the difference of the names, class by class", () => {
  const before = { complete: true, items: Object.fromEntries(CLASSES.map((c) => [c, ["a", "b"]])) };
  const after = {
    complete: true,
    items: {
      ...before.items,
      triggers: ["a", "b", "c"],
      topics: ["b"],
      functions: ["a", "b", "d", "e"],
    },
  };
  const fresh = newItems(before, after);
  assert.deepEqual(fresh.triggers, ["c"]);
  assert.deepEqual(fresh.functions, ["d", "e"]);
  assert.deepEqual(fresh.topics, []);
  assert.throws(() => newItems({ complete: false, items: before.items }, after), /incomplete/);
  assert.throws(() => newItems(before, { complete: false, items: after.items }), /incomplete/);
});

test("the trigger and the topic a 2nd gen record names are validated against the function's own name", () => {
  assert.deepEqual(ownedEventarcNames(record(), target), { trigger: TRIGGER, topic: TOPIC });
  assert.equal(ownedEventarcNames(record({ eventTrigger: undefined }), target), null);
  assert.equal(ownedEventarcNames({ name: "x" }, target), null);
  for (const eventTrigger of [
    { trigger: TRIGGER.replace("rtdbwrittenv2", "other"), pubsubTopic: TOPIC },
    { trigger: TRIGGER, pubsubTopic: TOPIC.replace(`eventarc-${REGION}`, "eventarc-europe-west1") },
    { trigger: `${TRIGGER}/../x`, pubsubTopic: TOPIC },
    { trigger: TRIGGER, pubsubTopic: `${TOPIC}-x` },
    { trigger: TRIGGER.replace(PROJECT, "someone-else"), pubsubTopic: TOPIC },
    { trigger: TRIGGER, pubsubTopic: undefined },
    { trigger: 5, pubsubTopic: TOPIC },
  ]) {
    assert.throws(
      () => ownedEventarcNames(record({ eventTrigger }), target),
      /unreviewed Eventarc/,
      JSON.stringify(eventTrigger),
    );
  }
});

test("a leftover trigger or topic the function record named is deleted by its exact name, nothing else is", async () => {
  const baseline = {
    triggers: ["projects/x/locations/l/triggers/old"],
    topics: ["projects/x/topics/old"],
  };
  const w = world(baseline);
  const before = await takeInventory(w.control, "inventory");
  for (const name of [TRIGGER, "projects/x/locations/l/triggers/stranger"])
    w.sets.triggers.add(name);
  for (const name of [TOPIC, "projects/x/topics/stranger"]) w.sets.topics.add(name);
  w.calls.length = 0;
  const result = await removeLeftovers(
    w.control,
    before,
    { trigger: TRIGGER, topic: TOPIC },
    { sleep: noSleep },
  );
  assert.deepEqual(
    w.calls.filter((c) => c.method === "DELETE").map((c) => c.url),
    [`https://eventarc.googleapis.com/v1/${TRIGGER}`, `https://pubsub.googleapis.com/v1/${TOPIC}`],
  );
  assert.deepEqual(result.deleted, [TRIGGER, TOPIC]);
  assert.equal(result.ok, false, "the strangers are still there");
  assert.deepEqual(result.residual.triggers, ["projects/x/locations/l/triggers/stranger"]);
  assert.deepEqual(result.residual.topics, ["projects/x/topics/stranger"]);
});

test("nothing new after the run is a clean inventory and sends no delete", async () => {
  const w = world({ functions: ["projects/x/f"], triggers: ["t"] });
  const before = await takeInventory(w.control, "inventory");
  w.calls.length = 0;
  const result = await removeLeftovers(w.control, before, null, { sleep: noSleep });
  assert.equal(result.ok, true);
  assert.deepEqual(result.deleted, []);
  assert.equal(w.calls.filter((c) => c.method !== "GET").length, 0);
  assert.equal(w.calls.length, CLASSES.length, "one read of each list");
});

test("a leftover function or service is reported, never deleted here", async () => {
  const w = world();
  const before = await takeInventory(w.control, "inventory");
  w.sets.functions.add("projects/x/locations/l/functions/leftover");
  w.sets.services.add("projects/x/locations/l/services/leftover");
  const result = await removeLeftovers(w.control, before, null, { sleep: noSleep });
  assert.equal(result.ok, false);
  assert.deepEqual(result.residual.functions, ["projects/x/locations/l/functions/leftover"]);
  assert.deepEqual(result.residual.services, ["projects/x/locations/l/services/leftover"]);
  assert.equal(w.calls.filter((c) => c.method === "DELETE").length, 0);
});

test("a delete that cannot be trusted is not repeated and leaves the inventory not ok", async () => {
  const w = world({}, { deleteFails: new Set([TRIGGER]) });
  const before = await takeInventory(w.control, "inventory");
  w.sets.triggers.add(TRIGGER);
  w.sets.topics.add(TOPIC);
  const result = await removeLeftovers(
    w.control,
    before,
    { trigger: TRIGGER, topic: TOPIC },
    { sleep: noSleep },
  );
  assert.equal(result.ok, false);
  assert.match(result.error, /socket hang up/);
  assert.equal(
    w.calls.filter((c) => c.method === "DELETE").length,
    1,
    "no retry, and the topic is left to the next review",
  );
});

test("an incomplete list after the run is not ok", async () => {
  const w = world();
  const before = await takeInventory(w.control, "inventory");
  const names = Array.from({ length: 400 }, (_, i) => `projects/p/topics/t-${i}`);
  for (const name of names) w.sets.topics.add(name);
  const result = await removeLeftovers(w.control, before, null, { sleep: noSleep });
  assert.equal(result.ok, false);
  assert.equal(result.incomplete, true);
});

test("several owned trigger and topic pairs are each deleted by exact name, once", async () => {
  const w = world();
  const before = await takeInventory(w.control, "inventory");
  const pairs = ["a", "b"].map((n) => ({
    trigger: `projects/${PROJECT}/locations/${REGION}/triggers/f${n}-1`,
    topic: `projects/${PROJECT}/topics/eventarc-${REGION}-f${n}-1-1`,
  }));
  for (const pair of pairs) {
    w.sets.triggers.add(pair.trigger);
    w.sets.topics.add(pair.topic);
  }
  const result = await removeLeftovers(w.control, before, pairs, { sleep: noSleep });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(
    result.deleted,
    pairs.flatMap((p) => [p.trigger, p.topic]),
  );
  assert.equal(w.calls.filter((c) => c.method === "DELETE").length, 4);
});
