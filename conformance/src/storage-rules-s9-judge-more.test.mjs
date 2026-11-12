import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  classifyAnswer,
  compileRecord,
  mask,
  normalizeAnswer,
  parseCreated,
  parseObjectList,
  parseRelease,
  parseRulesetList,
  renderLoads,
  renderTable,
  rowRecord,
  rowsAgree,
  tableOf,
} from "./storage-rules-s9/judge.mjs";

const bytes = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
const meta = { op: "meta", program: "s9", id: "m", plan: "allow" };
const media = { op: "media", program: "s9", id: "d", plan: "allow" };
const list = { op: "list", program: "s9", id: "l", plan: "allow" };
const reply = (status, body, headers = {}) => ({ status, headers, body: bytes(body) });

describe("storage rules s9 judge details", () => {
  it("drops every field that differs between runs and keeps the others", () => {
    const resource = {
      kind: "storage#object",
      id: "i",
      selfLink: "s",
      mediaLink: "m",
      name: "n",
      bucket: "b",
      generation: "1",
      metageneration: "1",
      timeCreated: "t",
      updated: "t",
      timeStorageClassUpdated: "t",
      etag: "e",
      md5Hash: "h",
      crc32c: "c",
      downloadTokens: "d",
      contentType: "text/plain",
      size: "5",
      storageClass: "STANDARD",
      metadata: { k: "v" },
    };
    const out = normalizeAnswer(
      meta,
      reply(200, resource, { "content-type": "application/json" }),
      [],
    );
    assert.deepEqual(out.resource, {
      kind: "storage#object",
      name: "n",
      bucket: "b",
      contentType: "text/plain",
      size: "5",
      storageClass: "STANDARD",
      metadata: { k: "v" },
    });
    assert.equal(out.status, 200);
    assert.equal(out.contentType, "application/json");
    assert.equal(out.bodyBytes, bytes(resource).length);
    assert.equal(normalizeAnswer(meta, reply(200, {}), []).contentType, null);
  });

  it("keeps media bytes as text and short non-JSON bodies, and cuts a long one", () => {
    assert.equal(normalizeAnswer(media, reply(200, "payload"), []).text, "payload");
    assert.equal(
      normalizeAnswer(media, reply(200, '{"a":1}'), []).text,
      '{"a":1}',
      "media is never read as JSON",
    );
    assert.equal(normalizeAnswer(media, reply(200, ""), []).text, "");
    assert.equal(normalizeAnswer(media, reply(404, "No such object"), []).text, "No such object");
    assert.equal(normalizeAnswer(meta, reply(403, "denied text"), []).text, "denied text");
    assert.equal(
      "text" in normalizeAnswer(meta, reply(204, ""), []),
      false,
      "an empty body has no text",
    );
    assert.equal(normalizeAnswer(meta, reply(500, "x".repeat(450)), []).text, "x".repeat(400));
    assert.equal(normalizeAnswer(meta, reply(500, "x".repeat(400)), []).text.length, 400);
    assert.equal(normalizeAnswer(meta, reply(500, "x"), []).text, "x");
    assert.equal(
      normalizeAnswer(meta, reply(200, "abc"), [["b", "-"]]).text,
      "a-c",
      "masks apply to text",
    );
    assert.equal(normalizeAnswer(media, reply(200, "abc"), [["b", "-"]]).text, "a-c");
  });

  it("shapes lists, errors and other JSON by status and operation", () => {
    const page = {
      kind: "storage#objects",
      items: [{ name: "b" }, { name: "a" }],
      prefixes: ["q/", "p/"],
      nextPageToken: "T",
    };
    const listed = normalizeAnswer(list, reply(200, page), []);
    assert.deepEqual(listed.list, {
      kind: "storage#objects",
      items: ["a", "b"],
      prefixes: ["p/", "q/"],
      nextPageToken: "<token>",
    });
    const bare = normalizeAnswer(list, reply(200, {}), []);
    assert.deepEqual(bare.list, { kind: null, items: [], prefixes: [], nextPageToken: undefined });
    assert.equal("resource" in listed, false);
    assert.equal(
      "resource" in normalizeAnswer(meta, reply(403, { error: { code: 403, message: "m" } }), []),
      false,
    );
    assert.equal(
      "list" in normalizeAnswer(list, reply(403, { error: { code: 403, message: "m" } }), []),
      false,
    );
    assert.equal("list" in normalizeAnswer(meta, reply(200, { name: "x" }), []), false);
    assert.deepEqual(
      normalizeAnswer(
        meta,
        reply(403, { error: { code: 403, status: "S", message: "bucket b" } }),
        [["b", "<x>"]],
      ).error,
      { code: 403, status: "S", message: "<x>ucket <x>" },
    );
    assert.deepEqual(normalizeAnswer(meta, reply(400, { error: {} }), []).error, {
      code: null,
      status: null,
      message: "",
    });
    assert.deepEqual(normalizeAnswer(meta, reply(201, { zeta: 1, alpha: 2 }), []).json, [
      "alpha",
      "zeta",
    ]);
    assert.equal("json" in normalizeAnswer(meta, reply(403, { error: { code: 403 } }), []), false);
  });

  it("agrees only when the class and the answer agree", () => {
    const record = (response, row = meta) =>
      rowRecord({ recording: 1, row, request: {}, response, masks: [] });
    const deny = record(reply(403, { error: { code: 403, message: "Permission denied." } }));
    const same = { ...deny, answer: { ...deny.answer } };
    assert.equal(rowsAgree(deny, same), true);
    assert.equal(
      rowsAgree(deny, { ...same, class: "allow" }),
      false,
      "a different class never agrees, whatever the answer",
    );
    assert.equal(rowsAgree({ ...deny, class: "allow" }, { ...same, class: "allow" }), true);
    assert.equal(rowsAgree({ ...deny, class: "allow" }, { ...same, class: "deny" }), false);
    const other = { ...deny, answer: { ...deny.answer, status: 404 } };
    assert.equal(rowsAgree(deny, other), false);
  });

  it("tabulates rows", () => {
    const record = (id) =>
      rowRecord({
        recording: 1,
        row: { ...meta, id, plan: "deny" },
        request: {},
        response: reply(403, { error: { code: 403, message: "Permission denied." } }),
        masks: [],
      });
    assert.deepEqual(tableOf([record("a"), record("b")]), [
      { id: "a", plan: "deny", class: "deny", status: 403 },
      { id: "b", plan: "deny", class: "deny", status: 403 },
    ]);
    assert.deepEqual(tableOf([]), []);
  });

  it("records a compile answer by its status", () => {
    const masks = [];
    const made = (status, body) =>
      compileRecord({ recording: 2, id: "x", response: reply(status, body), masks });
    assert.deepEqual(made(200, { name: "projects/p/rulesets/r" }), {
      recording: 2,
      id: "x",
      compiled: true,
      status: 200,
    });
    assert.deepEqual(made(400, { error: { message: "bad" } }), {
      recording: 2,
      id: "x",
      compiled: false,
      status: 400,
      message: "bad",
    });
    assert.deepEqual(made(400, "plain text"), {
      recording: 2,
      id: "x",
      compiled: false,
      status: 400,
      message: "plain text",
    });
    assert.equal(made(400, "y".repeat(500)).message.length, 400);
    for (const status of [401, 403, 404, 429, 500]) {
      const unread = made(status, "no");
      assert.equal(unread.compiled, null, `${status}`);
      assert.equal(unread.status, status);
      assert.equal(unread.message, "no");
    }
    assert.equal(made(500, "z".repeat(500)).message.length, 400);
    assert.equal(made(200, { name: 5 }).compiled, null);
    assert.equal(made(200, "not json").compiled, null);
    assert.equal(made(200, []).compiled, null);
    assert.equal(made(200, "[]").compiled, null);
  });

  it("reads a ruleset list page only in its recorded shape, sorted by name", () => {
    const entry = (name, services) => ({ name, createTime: "t", metadata: { services } });
    const page = (rulesets, extra = {}) => reply(200, { rulesets, ...extra });
    const sorted = parseRulesetList(
      page([
        entry("b", ["firebase.storage"]),
        entry("a", ["x", "cloud.firestore"]),
        entry("c", ["z"]),
      ]),
    );
    assert.deepEqual(sorted, [
      { name: "a", services: ["cloud.firestore", "x"] },
      { name: "b", services: ["firebase.storage"] },
      { name: "c", services: ["z"] },
    ]);
    assert.deepEqual(
      parseRulesetList(page([entry("a", ["s"]), entry("b", ["s"])])).map((r) => r.name),
      ["a", "b"],
    );
    assert.deepEqual(
      parseRulesetList(page([entry("b", ["s"]), entry("a", ["s"])])).map((r) => r.name),
      ["a", "b"],
    );
    assert.deepEqual(parseRulesetList(page([entry("a", ["s"]), entry("a", ["s"])])).length, 2);
    assert.deepEqual(parseRulesetList(page([])), []);
    assert.deepEqual(parseRulesetList(reply(200, {})), []);
    assert.equal(parseRulesetList(page([], { nextPageToken: "t" })), null);
    assert.equal(parseRulesetList(reply(500, { rulesets: [] })), null);
    assert.equal(parseRulesetList(reply(404, { rulesets: [] })), null);
    assert.equal(parseRulesetList(reply(200, "not json")), null);
    assert.equal(parseRulesetList(reply(200, "[]")), null);
    assert.equal(parseRulesetList(reply(200, { rulesets: "x" })), null);
    assert.equal(parseRulesetList(reply(200, { rulesets: { length: 1 } })), null);
    assert.equal(parseRulesetList(page([{ name: 5, metadata: { services: [] } }])), null);
    assert.equal(parseRulesetList(page([{ name: "a", metadata: {} }])), null);
    assert.equal(parseRulesetList(page([{ name: "a", metadata: { services: "s" } }])), null);
    assert.equal(parseRulesetList(page([{ name: "a" }])), null);
    assert.equal(parseRulesetList(page([null])), null);
  });

  it("reads a created object and an object list page only in the recorded shape", () => {
    const object = { kind: "storage#object", name: "n", generation: 17, metadata: { k: "v" } };
    assert.deepEqual(parseCreated(reply(200, object)), {
      name: "n",
      generation: "17",
      metadata: { k: "v" },
    });
    assert.deepEqual(parseCreated(reply(200, { ...object, metadata: undefined })), {
      name: "n",
      generation: "17",
      metadata: null,
    });
    for (const bad of [
      reply(201, object),
      reply(412, object),
      reply(200, { ...object, kind: "storage#objects" }),
      reply(200, { ...object, name: 5 }),
      reply(200, { ...object, name: undefined }),
      reply(200, { ...object, generation: "0" }),
      reply(200, { ...object, generation: "abc" }),
      reply(200, { ...object, generation: "1".repeat(21) }),
      reply(200, { ...object, generation: undefined }),
      reply(200, "not json"),
      reply(200, "[]"),
    ])
      assert.equal(parseCreated(bad), null);
    assert.equal(
      parseCreated(reply(200, { ...object, generation: "1".repeat(20) })).generation,
      "1".repeat(20),
    );
    assert.equal(parseCreated(reply(200, { ...object, generation: "9" })).generation, "9");

    const page = (items, extra = {}) => reply(200, { kind: "storage#objects", items, ...extra });
    assert.deepEqual(
      parseObjectList(
        page([
          { name: "a", generation: "5" },
          { name: "b", generation: 6 },
        ]),
      ),
      [
        { name: "a", generation: "5" },
        { name: "b", generation: "6" },
      ],
    );
    assert.deepEqual(parseObjectList(reply(200, { kind: "storage#objects" })), []);
    for (const bad of [
      reply(500, { kind: "storage#objects" }),
      reply(404, { kind: "storage#objects" }),
      reply(200, { kind: "storage#bucket" }),
      reply(200, { items: [] }),
      reply(200, "not json"),
      page([], { nextPageToken: "t" }),
      reply(200, { kind: "storage#objects", items: "x" }),
      reply(200, { kind: "storage#objects", items: { length: 1 } }),
      page([{ name: 5, generation: "5" }]),
      page([{ generation: "5" }]),
      page([{ name: "a", generation: "0" }]),
      page([{ name: "a", generation: "x" }]),
      page([{ name: "a" }]),
      page([null]),
    ])
      assert.equal(parseObjectList(bad), null);
  });

  it("reads a release answer only in the recorded shape", () => {
    const name = "projects/p/releases/firebase.storage/b";
    assert.deepEqual(
      parseRelease(reply(404, { error: { code: 404, status: "NOT_FOUND" } }), name),
      { state: "absent" },
    );
    assert.equal(parseRelease(reply(404, { error: { code: 404, status: "OTHER" } }), name), null);
    assert.equal(
      parseRelease(reply(404, { error: { code: 400, status: "NOT_FOUND" } }), name),
      null,
    );
    assert.equal(parseRelease(reply(404, "not json"), name), null);
    assert.deepEqual(
      parseRelease(reply(200, { name, rulesetName: "projects/p/rulesets/r" }), name),
      { state: "present", rulesetName: "projects/p/rulesets/r" },
    );
    assert.equal(parseRelease(reply(200, { name, rulesetName: 5 }), name), null);
    assert.equal(parseRelease(reply(200, { name }), name), null);
    assert.equal(parseRelease(reply(200, { name: "other", rulesetName: "r" }), name), null);
    assert.equal(parseRelease(reply(201, { name, rulesetName: "r" }), name), null);
    assert.equal(parseRelease(reply(200, "not json"), name), null);
    assert.equal(parseRelease(reply(500, {}), name), null);
  });

  it("classifies a 200 by the operation and a refusal by its exact words", () => {
    assert.equal(classifyAnswer(media, reply(200, "")), "allow");
    assert.equal(classifyAnswer(meta, reply(200, "")), "other");
    assert.equal(classifyAnswer(list, reply(200, [])), "other");
    assert.equal(
      classifyAnswer(meta, reply(403, { error: { code: 403, message: "Permission denied." } })),
      "deny",
    );
    assert.equal(
      classifyAnswer(
        meta,
        reply(403, {
          error: { code: 403, message: "Permission denied. Could not perform this operation" },
        }),
      ),
      "deny",
    );
    assert.equal(
      classifyAnswer(meta, reply(403, { error: { code: 403, message: "permission denied" } })),
      "other",
    );
    assert.equal(classifyAnswer(meta, reply(403, { error: { code: 403, message: 5 } })), "other");
    assert.equal(classifyAnswer(meta, reply(403, {})), "other");
    assert.equal(
      classifyAnswer(
        meta,
        reply(400, {
          error: { message: "Your bucket has not been set up properly for Firebase Storage." },
        }),
      ),
      "no-release",
    );
    assert.equal(
      classifyAnswer(
        meta,
        reply(400, { error: { message: "Oh: Your bucket has not been set up properly" } }),
      ),
      "other",
    );
    assert.equal(classifyAnswer(meta, reply(400, {})), "other");
    assert.equal(classifyAnswer(meta, reply(404, "")), "not-found");
    assert.equal(classifyAnswer(meta, reply(412, {})), "other");
    assert.equal(classifyAnswer(meta, reply(199, {})), "unknown");
    assert.equal(classifyAnswer(meta, reply(300, {})), "unknown");
    assert.equal(classifyAnswer(meta, reply(399, {})), "unknown");
    assert.equal(classifyAnswer(meta, reply(500, {})), "unknown");
    assert.equal(classifyAnswer(meta, { status: 1.5, body: bytes("") }), "unknown");
    assert.equal(classifyAnswer(meta, { status: "200", body: bytes("{}") }), "unknown");
    assert.equal(classifyAnswer(meta, { status: 200 }), "other");
    assert.equal(mask("a.b", [["a.b", "x"]]), "x");
    assert.equal(mask("aaa", [["a", "bb"]]), "bbbbbb");
  });

  it("shows a row that was not evaluated with a dash for its status", () => {
    const skipped = {
      recording: 1,
      program: "s9",
      id: "z",
      op: "meta",
      plan: "allow",
      class: "not-evaluated",
      why: "x",
      answer: { status: null },
    };
    const table = renderTable([{ label: "run", rows: [skipped], loads: [] }]).split("\n");
    assert.equal(table[1], "z\tallow\tnot-evaluated/-");
  });

  it("renders missing cells and failed loads", () => {
    const row = (id, status, recording = 1) =>
      rowRecord({
        recording,
        row: { ...meta, id },
        request: {},
        response: reply(
          status,
          status === 403 ? { error: { code: 403, message: "Permission denied." } } : {},
        ),
        masks: [],
      });
    const left = {
      label: "left",
      rows: [row("a", 403)],
      loads: [
        { id: "l1", compiled: true, status: 200 },
        { id: "l2", compiled: false, status: 400 },
        { id: "l3", compiled: null, status: 503 },
      ],
    };
    const right = {
      label: "right",
      rows: [row("b", 200)],
      loads: [{ id: "l1", compiled: true, status: 200 }],
    };
    const table = renderTable([left, right]).split("\n");
    assert.deepEqual(table, [
      "row\tplan\tleft\tright",
      "a\tallow\tdeny/403\t-",
      "b\tallow\t-\tallow/200",
    ]);
    const same = renderTable([left, { label: "copy", rows: [row("a", 403)], loads: [] }]).split(
      "\n",
    );
    assert.equal(same[1], "a\tallow\tdeny/403\t=");
    const different = renderTable([
      left,
      { label: "other", rows: [row("a", 200)], loads: [] },
    ]).split("\n");
    assert.equal(different[1], "a\tallow\tdeny/403\tallow/200");
    const starred = renderTable([
      { label: "s", rows: [row("a", 403), row("a", 200, 2)], loads: [] },
      { label: "t", rows: [row("a", 403), row("a", 200, 2)], loads: [] },
    ]).split("\n");
    assert.equal(
      starred[1],
      "a\tallow\tdeny/403*\tdeny/403*",
      "a disagreeing recording is starred in every column",
    );
    const loads = renderLoads([left, right]).split("\n");
    assert.deepEqual(loads, [
      "load\tleft\tright",
      "l1\tloads/200\tloads/200",
      "l2\trefused/400\t-",
      "l3\t?/503\t-",
    ]);
    assert.deepEqual(
      renderLoads([
        {
          label: "x",
          rows: [],
          loads: [
            { id: "q", compiled: true, status: 200 },
            { id: "q", compiled: true, status: 200 },
          ],
        },
      ]).split("\n"),
      ["load\tx", "q\tloads/200"],
      "an id listed twice is one line",
    );
  });
});
