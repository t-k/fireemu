import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import {
  FIXTURE_HANDLERS,
  FRAME_MARKER,
  GROUP_PATH,
  INSTANCE,
  ITEM_PATH,
  LOCATION,
  NAMED_CONTEXT_MEMBERS,
  NAMED_EVENT_MEMBERS,
} from "./kinds-frames.mjs";
import { reduceBig } from "./kinds-sequence.mjs";
const require = createRequire(import.meta.url);
const frames = require("./fixtures-kinds/frames.js");

const snap = (value) => ({ exists: () => value !== null, val: () => value, key: "a" });

function load() {
  const calls = [];
  const builder = (kind) => (handler) => (calls.push(kind), { kind, handler });
  const ref = {
    onCreate: builder("v1create"),
    onUpdate: builder("v1update"),
    onDelete: builder("v1delete"),
    onWrite: builder("v1write"),
  };
  const v1 = { runWith: [], instance: [], ref: [], region: [] };
  const registry = {
    "firebase-admin/app": { initializeApp() {}, getApps: () => [] },
    "firebase-functions/v1": {
      region: (name) => (
        v1.region.push(name),
        {
          runWith: (options) => (
            v1.runWith.push(options),
            {
              database: {
                instance: (name) => (
                  v1.instance.push(name),
                  { ref: (path) => (v1.ref.push(path), ref) }
                ),
              },
            }
          ),
        }
      ),
    },
    "firebase-functions/v2/database": Object.fromEntries(
      ["Created", "Updated", "Deleted", "Written"].map((kind) => [
        `onValue${kind}`,
        (options, handler) => ({ options, handler, kind }),
      ]),
    ),
    "./frames": frames,
  };
  const exports = {};
  new Function(
    "require",
    "exports",
    readFileSync(new URL("./fixtures-kinds/index.js", import.meta.url), "utf8"),
  )((name) => registry[name], exports);
  return { exports, v1 };
}

test("the fixture exports exactly the planned handlers, once each", () => {
  const { exports } = load();
  assert.deepEqual(Object.keys(exports).sort(), FIXTURE_HANDLERS.map((h) => h.name).sort());
});

test("each handler watches its pattern, kind and generation", () => {
  const { exports, v1 } = load();
  const kindOf = { create: "Created", update: "Updated", delete: "Deleted", write: "Written" };
  for (const handler of FIXTURE_HANDLERS.filter((h) => h.generation === 2)) {
    const exported = exports[handler.name];
    assert.equal(exported.kind, kindOf[handler.event], handler.name);
    assert.equal(exported.options.ref, handler.level === "group" ? GROUP_PATH : ITEM_PATH);
    assert.equal(exported.options.region, LOCATION);
    assert.equal(exported.options.retry, undefined);
    // the any-instance handler names no instance at all: the SDK then uses `*`
    assert.equal("instance" in exported.options, handler.name !== "k9AnyWrittenV2", handler.name);
    if ("instance" in exported.options) assert.equal(exported.options.instance, INSTANCE);
  }
  assert.equal(exports.k9CreatedV1.kind, "v1create");
  assert.equal(exports.k9UpdatedV1.kind, "v1update");
  assert.equal(exports.k9DeletedV1.kind, "v1delete");
  // one builder serves the three 1st gen handlers
  assert.deepEqual(v1.ref, [ITEM_PATH]);
  assert.deepEqual(v1.instance, [INSTANCE]);
  assert.ok(v1.region.every((region) => region === LOCATION));
  // no handler asks for redelivery: no failurePolicy on 1st gen, no retry on 2nd gen
  assert.ok(v1.runWith.every((options) => options.failurePolicy === undefined));
});

function capture() {
  const original = console.log;
  const lines = [];
  console.log = (line) => lines.push(line);
  return { lines, restore: () => (console.log = original) };
}
const frame = (lines) => JSON.parse(lines.at(-1).slice(FRAME_MARKER.length));

test("a v2 created event prints one typed frame with the data of the new node", () => {
  const { exports } = load();
  const out = capture();
  try {
    exports.k9CreatedV2.handler({
      id: "e1",
      time: new Date().toISOString(),
      type: "t",
      source: "s",
      params: { group: "ga", id: "a" },
      authType: "unknown",
      authId: null,
      data: snap({ value: 1, blob: "y".repeat(300), ".priority": 7 }),
    });
  } finally {
    out.restore();
  }
  const printed = frame(out.lines);
  assert.equal(printed.handler, "k9CreatedV2");
  assert.equal(printed.generation, 2);
  assert.deepEqual(printed.event.data, {
    exists: true,
    key: "a",
    value: { value: 1, blob: { type: "string", length: 300 }, ".priority": 7 },
  });
  assert.deepEqual(printed.event.params, { group: "ga", id: "a" });
  assert.equal("attempt" in printed, false);
});

test("a v1 update prints before and after; a v1 delete prints the old node", () => {
  const { exports } = load();
  const out = capture();
  const context = {
    eventId: "e",
    timestamp: new Date().toISOString(),
    eventType: "t",
    resource: { name: "n" },
    params: { group: "ga", id: "a" },
    authType: "ADMIN",
  };
  try {
    exports.k9UpdatedV1.handler({ before: snap({ value: 1 }), after: snap({ value: 2 }) }, context);
    const update = frame(out.lines);
    assert.deepEqual(update.event.data.before.value, { value: 1 });
    assert.deepEqual(update.event.data.after.value, { value: 2 });
    exports.k9DeletedV1.handler(snap({ value: 2 }), context);
    const deleted = frame(out.lines);
    assert.deepEqual(deleted.event.data, {
      exists: true,
      key: "a",
      value: { value: 2 },
    });
  } finally {
    out.restore();
  }
});

test("a v1 user write prints the uid, the token key names and the custom claim values", () => {
  const auth = frames.v1Context({
    auth: {
      uid: "user",
      token: {
        z: "sensitive",
        email: "person@example.test",
        k9role: "claims",
        k9n: 3,
        k9long: "q".repeat(300),
        firebase: { sign_in_provider: "password" },
        email_verified: true,
      },
    },
  }).auth;
  assert.deepEqual(auth, {
    uid: "user",
    tokenKeys: ["email", "email_verified", "firebase", "k9long", "k9n", "k9role", "z"],
    signInProvider: "password",
    emailVerified: true,
    claims: { k9long: { type: "string", length: 300 }, k9n: 3, k9role: "claims" },
  });
});

test("the fixture's reduction equals the model's reduction on the planned values", () => {
  for (const value of [
    "short",
    "x".repeat(256),
    "x".repeat(257),
    { a: ["y".repeat(1000), 3, null, { b: "z".repeat(300) }] },
    5,
    null,
    true,
  ])
    assert.deepEqual(frames.reduce(value), reduceBig(value));
});

test("the named members the fixture agrees on are the CV14 ones", () => {
  assert.deepEqual([...frames.CONTEXT_MEMBERS].sort(), [...NAMED_CONTEXT_MEMBERS].sort());
  assert.deepEqual([...frames.EVENT_MEMBERS].sort(), [...NAMED_EVENT_MEMBERS].sort());
  assert.equal(frames.MARKER, FRAME_MARKER);
});

test("members beyond the named ones are listed by name and type only", () => {
  const event = frames.v2Event({
    id: "e",
    time: "t",
    type: "ty",
    source: "s",
    params: {},
    traceparent: "00-aa",
    snapshot: { _data: 1, _path: "p", app: {}, instance: "i" },
    data: snap(null),
  });
  assert.deepEqual(event.extras.traceparent, "00-aa");
  assert.deepEqual(event.extras.snapshot, {
    type: "object",
    keys: ["_data", "_path", "app", "instance"],
  });
  assert.ok(event.eventKeys.includes("snapshot"));
});
