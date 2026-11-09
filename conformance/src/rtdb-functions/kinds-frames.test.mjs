import test from "node:test";
import assert from "node:assert/strict";
import { FIXTURE_HANDLERS, isRecordedMember } from "./kinds-frames.mjs";

const TRACE = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const obj = (...keys) => ({ type: "object", keys });
const CONTEXT = obj("eventId", "eventType", "params", "resource", "timestamp");
const USER_CONTEXT = obj(
  "auth",
  "authType",
  "eventId",
  "eventType",
  "params",
  "resource",
  "timestamp",
);
const SNAPSHOT = obj("_data", "_path", "app", "instance");
const CHANGE = obj("after", "before");

test("the handlers are the planned eight with their kind, level and requirement", () => {
  assert.deepEqual(
    FIXTURE_HANDLERS.map((h) => [h.name, h.generation, h.event, h.level, h.required]),
    [
      ["k9CreatedV2", 2, "create", "item", true],
      ["k9UpdatedV2", 2, "update", "item", true],
      ["k9DeletedV2", 2, "delete", "item", true],
      ["k9CreatedV1", 1, "create", "item", true],
      ["k9UpdatedV1", 1, "update", "item", true],
      ["k9DeletedV1", 1, "delete", "item", true],
      ["k9AnyWrittenV2", 2, "write", "item", false],
      ["k9GroupWrittenV2", 2, "write", "group", false],
    ],
  );
});

test("a member is recorded only for the event type and generation CV14 recorded it on", () => {
  for (const handler of FIXTURE_HANDLERS) {
    const { name, generation, event } = handler;
    const check = (member, value) => isRecordedMember(name, generation, member, value);
    assert.equal(check("domain", "firebaseio.com"), generation === 1, name);
    assert.equal(check("domain", "example.com"), false, name);
    assert.equal(check("context", CONTEXT), generation === 2, name);
    assert.equal(check("traceparent", TRACE), generation === 2, name);
    assert.equal(check("traceparent", "00-bad"), false, name);
    assert.equal(check("traceparent", 5), false, name);
    assert.equal(
      check("change", CHANGE),
      generation === 2 && (event === "update" || event === "write"),
      name,
    );
    assert.equal(
      check("snapshot", SNAPSHOT),
      generation === 2 && (event === "create" || event === "delete"),
      name,
    );
    assert.equal(check("unheard-of", CONTEXT), false, name);
  }
});

test("a recorded member in the wrong generation or under an unknown handler is refused", () => {
  assert.equal(isRecordedMember("k9CreatedV2", 1, "domain", "firebaseio.com"), false);
  assert.equal(isRecordedMember("k9CreatedV1", 2, "traceparent", TRACE), false);
  assert.equal(isRecordedMember("k9CreatedV1", 1, "domain", "firebaseio.com"), true);
  assert.equal(isRecordedMember("g9WrittenV2", 2, "traceparent", TRACE), false);
  assert.equal(isRecordedMember("nothing", 2, "context", CONTEXT), false);
});

test("shapes are exact: key sets and types", () => {
  assert.equal(isRecordedMember("k9UpdatedV2", 2, "change", obj("after")), false);
  assert.equal(isRecordedMember("k9UpdatedV2", 2, "change", obj("before", "after")), false);
  assert.equal(isRecordedMember("k9CreatedV2", 2, "snapshot", obj("_data", "_path", "app")), false);
  assert.equal(
    isRecordedMember("k9CreatedV2", 2, "context", { type: "array", keys: CONTEXT.keys }),
    false,
  );
  assert.equal(isRecordedMember("k9CreatedV2", 2, "context", null), false);
});

test("the user-write context is the recorded key set on 2nd gen handlers only", () => {
  for (const handler of FIXTURE_HANDLERS) {
    assert.equal(
      isRecordedMember(handler.name, handler.generation, "context", USER_CONTEXT),
      handler.generation === 2,
      handler.name,
    );
  }
});
