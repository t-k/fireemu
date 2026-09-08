import { describe, expect, it } from "vitest";
import {
  applyFieldDiff,
  defaultText,
  diffFields,
  FIELD_TYPES,
  isDocumentPath,
  lastSegment,
  parentPath,
  parseField,
  parseFields,
  relativePath,
  summarize,
  toEditable,
  toPlain,
  toText,
  typeOf,
  validFieldName,
  type EditableField,
  type FieldType,
  type FsValue,
} from "./firestoreValue";

const ROOT = "projects/demo-app/databases/(default)/documents";

// Every wire value type once: its editor type, its plain JSON, its list summary, its editor text.
const WIRE: { value: FsValue; type: FieldType; plain: unknown; summary: string; text: string }[] = [
  { value: { nullValue: null }, type: "null", plain: null, summary: "null", text: "" },
  {
    value: { booleanValue: false },
    type: "boolean",
    plain: false,
    summary: "false",
    text: "false",
  },
  { value: { integerValue: "-42" }, type: "number", plain: -42, summary: "-42", text: "-42" },
  { value: { doubleValue: 1.5 }, type: "number", plain: 1.5, summary: "1.5", text: "1.5" },
  { value: { doubleValue: "NaN" }, type: "number", plain: "NaN", summary: "NaN", text: "NaN" },
  {
    value: { stringValue: 'a"b' },
    type: "string",
    plain: 'a"b',
    summary: '"a\\"b"',
    text: 'a"b',
  },
  {
    value: { timestampValue: "2026-01-02T03:04:05Z" },
    type: "timestamp",
    plain: "2026-01-02T03:04:05Z",
    summary: "2026-01-02T03:04:05Z",
    text: "2026-01-02T03:04:05Z",
  },
  {
    value: { geoPointValue: { latitude: -1.5, longitude: 20 } },
    type: "geopoint",
    plain: { latitude: -1.5, longitude: 20 },
    summary: "[-1.5, 20]",
    text: "-1.5, 20",
  },
  {
    value: { referenceValue: `${ROOT}/users/alice` },
    type: "reference",
    plain: `${ROOT}/users/alice`,
    summary: "users/alice",
    text: `${ROOT}/users/alice`,
  },
  {
    value: { bytesValue: "aGVsbG8=" },
    type: "bytes",
    plain: "aGVsbG8=",
    summary: "bytes(8)",
    text: "aGVsbG8=",
  },
  {
    value: { arrayValue: { values: [{ integerValue: "1" }, { stringValue: "x" }] } },
    type: "array",
    plain: [1, "x"],
    summary: '[1,"x"]',
    text: JSON.stringify([{ integerValue: "1" }, { stringValue: "x" }], null, 2),
  },
  { value: { arrayValue: {} }, type: "array", plain: [], summary: "[]", text: "[]" },
  {
    value: { mapValue: { fields: { k: { booleanValue: true } } } },
    type: "map",
    plain: { k: true },
    summary: '{"k":true}',
    text: JSON.stringify({ k: { booleanValue: true } }, null, 2),
  },
  { value: { mapValue: {} }, type: "map", plain: {}, summary: "{}", text: "{}" },
];

describe("wire value readings", () => {
  it.each(WIRE)("reads $value", ({ value, type, plain, summary, text }) => {
    expect(typeOf(value)).toBe(type);
    expect(toPlain(value)).toEqual(plain);
    expect(summarize(value)).toBe(summary);
    expect(toText(value)).toBe(text);
  });

  it("keeps a reference outside the documents root whole in a summary", () => {
    expect(summarize({ referenceValue: "projects/p/databases/d/documents/a/b" })).toBe("a/b");
    expect(summarize({ referenceValue: "elsewhere/a/b" })).toBe("elsewhere/a/b");
  });

  it("records the number subtype of an editable field and nothing for other types", () => {
    expect(toEditable({ i: { integerValue: "1" } })[0]).toEqual({
      name: "i",
      type: "number",
      text: "1",
      original: { integerValue: "1" },
      dirty: false,
      numberKind: "integer",
    });
    expect(toEditable({ d: { doubleValue: 2 } })[0]?.numberKind).toBe("double");
    expect(toEditable({ s: { stringValue: "" } })[0]?.numberKind).toBeUndefined();
    expect(toEditable(undefined)).toEqual([]);
  });
});

type Case = { type: FieldType; text: string; kind?: "integer" | "double" } & (
  | { ok: FsValue }
  | { err: string }
);

const ARRAY_MSG = 'a JSON array of Firestore values, for example [{"stringValue": "a"}]';
const MAP_MSG = 'a JSON object of Firestore values, for example {"k": {"stringValue": "v"}}';
const MAP_ENTRY_MSG = 'every map entry must be a Firestore value, for example {"stringValue": "v"}';
const REF_MSG = "a document path has an even number of non-empty segments";
const GEO_RANGE = "latitude in -90..90, longitude in -180..180";

const CASES: Case[] = [
  { type: "string", text: " keep spaces ", ok: { stringValue: " keep spaces " } },
  { type: "null", text: "ignored", ok: { nullValue: null } },
  { type: "boolean", text: " TRUE ", ok: { booleanValue: true } },
  { type: "boolean", text: "false", ok: { booleanValue: false } },
  { type: "boolean", text: "yes", err: "true or false" },
  { type: "boolean", text: "", err: "true or false" },
  { type: "number", text: " 7 ", ok: { integerValue: "7" } },
  { type: "number", text: "+7", ok: { integerValue: "7" } },
  { type: "number", text: "9223372036854775807", ok: { integerValue: "9223372036854775807" } },
  { type: "number", text: "9223372036854775808", err: "integer out of the 64-bit range" },
  { type: "number", text: "-9223372036854775808", ok: { integerValue: "-9223372036854775808" } },
  { type: "number", text: "-9223372036854775809", err: "integer out of the 64-bit range" },
  { type: "number", text: "2.50", ok: { doubleValue: 2.5 } },
  { type: "number", text: "1e3", ok: { doubleValue: 1000 } },
  { type: "number", text: "", err: "integer or decimal" },
  { type: "number", text: "abc", err: "integer or decimal" },
  { type: "number", text: "Infinity", err: "integer or decimal" },
  { type: "number", text: "NaN", kind: "integer", err: "integer or decimal" },
  { type: "number", text: "7", kind: "double", ok: { doubleValue: 7 } },
  { type: "number", text: " -Infinity ", kind: "double", ok: { doubleValue: "-Infinity" } },
  { type: "number", text: "NaN", kind: "double", ok: { doubleValue: "NaN" } },
  { type: "number", text: "7", kind: "integer", ok: { integerValue: "7" } },
  {
    type: "timestamp",
    text: " 2026-01-02T03:04:05Z ",
    ok: { timestampValue: "2026-01-02T03:04:05Z" },
  },
  {
    type: "timestamp",
    text: "2026-01-02T03:04:05.123456789+09:00",
    ok: { timestampValue: "2026-01-02T03:04:05.123456789+09:00" },
  },
  { type: "timestamp", text: "2026-01-02T03:04:05", err: "RFC 3339 timestamp" },
  { type: "timestamp", text: "2026-01-02 03:04:05Z", err: "RFC 3339 timestamp" },
  { type: "timestamp", text: "2026-13-40T03:04:05Z", err: "RFC 3339 timestamp" },
  { type: "timestamp", text: "2026-01-02T03:04:05.1234567890Z", err: "RFC 3339 timestamp" },
  {
    type: "geopoint",
    text: " 90 , -180 ",
    ok: { geoPointValue: { latitude: 90, longitude: -180 } },
  },
  { type: "geopoint", text: "-90, 180", ok: { geoPointValue: { latitude: -90, longitude: 180 } } },
  { type: "geopoint", text: "90.1, 0", err: GEO_RANGE },
  { type: "geopoint", text: "-90.1, 0", err: GEO_RANGE },
  { type: "geopoint", text: "0, 180.1", err: GEO_RANGE },
  { type: "geopoint", text: "0, -180.1", err: GEO_RANGE },
  { type: "geopoint", text: "1", err: "latitude, longitude" },
  { type: "geopoint", text: "1, 2, 3", err: "latitude, longitude" },
  { type: "geopoint", text: "a, 2", err: "latitude, longitude" },
  { type: "geopoint", text: "1, b", err: "latitude, longitude" },
  { type: "reference", text: "users/alice", ok: { referenceValue: `${ROOT}/users/alice` } },
  {
    type: "reference",
    text: " users/alice/posts/p1 ",
    ok: { referenceValue: `${ROOT}/users/alice/posts/p1` },
  },
  {
    type: "reference",
    text: "projects/other/databases/x/documents/a/b",
    ok: { referenceValue: "projects/other/databases/x/documents/a/b" },
  },
  { type: "reference", text: "", err: "a document path is required" },
  { type: "reference", text: "   ", err: "a document path is required" },
  { type: "reference", text: "users", err: REF_MSG },
  { type: "reference", text: "users//alice", err: REF_MSG },
  { type: "reference", text: "users/alice/", err: REF_MSG },
  { type: "reference", text: "projects/p/databases/d/documents/a", err: REF_MSG },
  { type: "bytes", text: "aGVs\nbG8=", ok: { bytesValue: "aGVsbG8=" } },
  { type: "bytes", text: "", ok: { bytesValue: "" } },
  { type: "bytes", text: "aGVsbG8", err: "base64" },
  { type: "bytes", text: "aGVs!G8=", err: "base64" },
  { type: "bytes", text: "aGVsbG===", err: "base64" },
  { type: "array", text: "", ok: { arrayValue: { values: [] } } },
  {
    type: "array",
    text: '[{"stringValue":"a"},{"nullValue":null}]',
    ok: { arrayValue: { values: [{ stringValue: "a" }, { nullValue: null }] } },
  },
  { type: "array", text: "[1]", err: ARRAY_MSG },
  { type: "array", text: "{}", err: ARRAY_MSG },
  { type: "array", text: "[", err: "Unexpected end of JSON input" },
  { type: "map", text: "", ok: { mapValue: { fields: {} } } },
  {
    type: "map",
    text: '{"k":{"integerValue":"1"}}',
    ok: { mapValue: { fields: { k: { integerValue: "1" } } } },
  },
  { type: "map", text: "[]", err: MAP_MSG },
  { type: "map", text: "null", err: MAP_MSG },
  { type: "map", text: '"s"', err: MAP_MSG },
  { type: "map", text: '{"k":1}', err: MAP_ENTRY_MSG },
  {
    type: "map",
    text: "{",
    err: "Expected property name or '}' in JSON at position 1 (line 1 column 2)",
  },
];

describe("parseField", () => {
  it.each(CASES)("$type $text", (c) => {
    const r = parseField(c.type, c.text, ROOT, c.kind);
    if ("ok" in c) {
      expect(r._unsafeUnwrap()).toEqual(c.ok);
    } else {
      expect(r._unsafeUnwrapErr()).toBe(c.err);
    }
  });
});

// The nested-value validator, one shape at a time, through the array parser.
const NESTED: { json: string; ok: boolean }[] = [
  { json: '[{"nullValue":null}]', ok: true },
  { json: '[{"nullValue":0}]', ok: false },
  { json: '[{"booleanValue":true}]', ok: true },
  { json: '[{"booleanValue":"true"}]', ok: false },
  { json: '[{"integerValue":"+12"}]', ok: true },
  { json: '[{"integerValue":"1.5"}]', ok: false },
  { json: '[{"integerValue":12}]', ok: false },
  { json: '[{"doubleValue":1.5}]', ok: true },
  { json: '[{"doubleValue":"NaN"}]', ok: true },
  { json: '[{"doubleValue":"Infinity"}]', ok: true },
  { json: '[{"doubleValue":"-Infinity"}]', ok: true },
  { json: '[{"doubleValue":"1.5"}]', ok: false },
  { json: '[{"doubleValue":null}]', ok: false },
  { json: '[{"stringValue":"s"}]', ok: true },
  { json: '[{"stringValue":1}]', ok: false },
  { json: '[{"timestampValue":"t"}]', ok: true },
  { json: '[{"timestampValue":1}]', ok: false },
  { json: '[{"referenceValue":"r"}]', ok: true },
  { json: '[{"referenceValue":null}]', ok: false },
  { json: '[{"bytesValue":"b"}]', ok: true },
  { json: '[{"bytesValue":[]}]', ok: false },
  { json: '[{"geoPointValue":{"latitude":1,"longitude":2}}]', ok: true },
  { json: '[{"geoPointValue":{"latitude":"1","longitude":2}}]', ok: false },
  { json: '[{"geoPointValue":{"latitude":1,"longitude":"2"}}]', ok: false },
  { json: '[{"geoPointValue":[1,2]}]', ok: false },
  { json: '[{"geoPointValue":null}]', ok: false },
  { json: '[{"arrayValue":{}}]', ok: true },
  { json: '[{"arrayValue":{"values":[{"stringValue":"x"}]}}]', ok: true },
  { json: '[{"arrayValue":{"values":[1]}}]', ok: false },
  { json: '[{"arrayValue":{"values":{}}}]', ok: false },
  { json: '[{"arrayValue":[]}]', ok: false },
  { json: '[{"arrayValue":null}]', ok: false },
  { json: '[{"arrayValue":"s"}]', ok: false },
  { json: '[{"arrayValue":5}]', ok: false },
  { json: '[{"mapValue":{}}]', ok: true },
  { json: '[{"mapValue":{"fields":{"k":{"stringValue":"x"}}}}]', ok: true },
  { json: '[{"mapValue":{"fields":{"k":1}}}]', ok: false },
  { json: '[{"mapValue":{"fields":[]}}]', ok: false },
  { json: '[{"mapValue":{"fields":null}}]', ok: false },
  { json: '[{"mapValue":[]}]', ok: false },
  { json: '[{"mapValue":"m"}]', ok: false },
  { json: '[{"stringValue":"a","integerValue":"1"}]', ok: false },
  { json: "[{}]", ok: false },
  { json: '[{"otherValue":1}]', ok: false },
  { json: "[null]", ok: false },
  { json: "[[]]", ok: false },
  { json: '["s"]', ok: false },
];

describe("nested Firestore values", () => {
  it.each(NESTED)("$json is valid: $ok", ({ json, ok }) => {
    expect(parseField("array", json, ROOT).isOk()).toBe(ok);
  });
});

describe("field names", () => {
  it("accepts up to 1500 characters without control characters", () => {
    expect(validFieldName("a")).toBe(true);
    expect(validFieldName("a".repeat(1500))).toBe(true);
    expect(validFieldName("a".repeat(1501))).toBe(false);
    expect(validFieldName("")).toBe(false);
    expect(validFieldName("a b")).toBe(false);
    expect(validFieldName("ab")).toBe(false);
    expect(validFieldName("ab")).toBe(false);
    expect(validFieldName("ab")).toBe(false);
    expect(validFieldName("a b")).toBe(true);
    expect(validFieldName("a.b")).toBe(true);
    expect(validFieldName("a~b")).toBe(true);
  });

  it("names the field in a parse error", () => {
    const bad = parseFields([{ name: "n", type: "boolean", text: "maybe" }], ROOT);
    expect(bad._unsafeUnwrapErr()).toEqual({ field: "n", message: "true or false" });
    const ctl = parseFields([{ name: "a", type: "string", text: "" }], ROOT);
    expect(ctl._unsafeUnwrapErr()).toEqual({
      field: "a",
      message: "a field needs a name without control characters",
    });
  });

  it("re-parses a field whose type changed even when it is not marked dirty", () => {
    const field: EditableField = {
      name: "v",
      type: "string",
      text: "1",
      original: { integerValue: "1" },
      dirty: false,
    };
    expect(parseFields([field], ROOT)._unsafeUnwrap()).toEqual({ v: { stringValue: "1" } });
    expect(parseFields([{ ...field, type: "number" }], ROOT)._unsafeUnwrap()).toEqual({
      v: { integerValue: "1" },
    });
    expect(
      parseFields([{ ...field, type: "number", text: "2", dirty: true }], ROOT)._unsafeUnwrap(),
    ).toEqual({ v: { integerValue: "2" } });
  });

  it("keeps the declared field order", () => {
    const parsed = parseFields(
      [
        { name: "z", type: "string", text: "" },
        { name: "a", type: "string", text: "" },
      ],
      ROOT,
    )._unsafeUnwrap();
    expect(Object.keys(parsed)).toEqual(["z", "a"]);
  });
});

describe("diffFields and applyFieldDiff", () => {
  it("compares nested wire values structurally", () => {
    const a: FsValue = {
      mapValue: { fields: { list: { arrayValue: { values: [{ integerValue: "1" }] } } } },
    };
    const same: FsValue = JSON.parse(JSON.stringify(a)) as FsValue;
    const longer: FsValue = {
      mapValue: {
        fields: {
          list: { arrayValue: { values: [{ integerValue: "1" }, { integerValue: "2" }] } },
        },
      },
    };
    const renamed: FsValue = {
      mapValue: { fields: { other: { arrayValue: { values: [{ integerValue: "1" }] } } } },
    };
    const extraKey: FsValue = {
      mapValue: {
        fields: {
          list: { arrayValue: { values: [{ integerValue: "1" }] } },
          more: { nullValue: null },
        },
      },
    };
    expect(diffFields({ v: a }, { v: same }).fieldPaths).toEqual([]);
    expect(diffFields({ v: a }, { v: longer }).fieldPaths).toEqual(["v"]);
    expect(diffFields({ v: a }, { v: renamed }).fieldPaths).toEqual(["v"]);
    expect(diffFields({ v: a }, { v: extraKey }).fieldPaths).toEqual(["v"]);
    expect(
      diffFields({ v: { arrayValue: { values: [] } } }, { v: { mapValue: {} } }).fieldPaths,
    ).toEqual(["v"]);
    expect(
      diffFields({ v: { stringValue: "1" } }, { v: { integerValue: "1" } }).fieldPaths,
    ).toEqual(["v"]);
    expect(
      diffFields({ v: { integerValue: "1" } }, { v: { integerValue: "2" } }).fieldPaths,
    ).toEqual(["v"]);
  });

  it("lists each changed name once and only carries values that are present after", () => {
    const d = diffFields({ a: { nullValue: null } }, { a: { booleanValue: true } });
    expect(d).toEqual({ fields: { a: { booleanValue: true } }, fieldPaths: ["a"] });
    expect(diffFields({}, {})).toEqual({ fields: {}, fieldPaths: [] });
  });

  it("applies deletes and sets over the latest document, keeping untouched fields", () => {
    expect(
      applyFieldDiff(
        { keep: { integerValue: "1" }, drop: { integerValue: "2" }, set: { integerValue: "3" } },
        {
          fields: { set: { integerValue: "30" }, add: { integerValue: "4" } },
          fieldPaths: ["drop", "set", "add"],
        },
      ),
    ).toEqual({
      keep: { integerValue: "1" },
      set: { integerValue: "30" },
      add: { integerValue: "4" },
    });
  });
});

describe("defaults and paths", () => {
  it("offers a type-appropriate starting text", () => {
    expect(defaultText("boolean")).toBe("true");
    expect(defaultText("number")).toBe("0");
    expect(defaultText("geopoint")).toBe("0, 0");
    expect(defaultText("array")).toBe("[]");
    expect(defaultText("map")).toBe("{}");
    expect(defaultText("string")).toBe("");
    expect(defaultText("null")).toBe("");
    expect(defaultText("reference")).toBe("");
    expect(defaultText("bytes")).toBe("");
    const ts = defaultText("timestamp");
    expect(ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(parseField("timestamp", ts, ROOT).isOk()).toBe(true);
  });

  it("reads path segments", () => {
    expect(relativePath("users/alice")).toBe("users/alice");
    expect(lastSegment("users/alice/")).toBe("alice");
    expect(lastSegment("")).toBe("");
    expect(lastSegment("/users")).toBe("users");
  });
});

describe("survivors of the first mutation run", () => {
  it("offers the editor types in a fixed order", () => {
    expect(FIELD_TYPES).toEqual([
      "string",
      "number",
      "boolean",
      "null",
      "timestamp",
      "geopoint",
      "reference",
      "array",
      "map",
      "bytes",
    ]);
  });

  it("only strips a documents prefix at the start of a reference", () => {
    expect(summarize({ referenceValue: "x/projects/p/databases/d/documents/a/b" })).toBe(
      "x/projects/p/databases/d/documents/a/b",
    );
    expect(summarize({ integerValue: "9007199254740993" })).toBe("9007199254740992");
  });

  it("anchors the timestamp shape at both ends", () => {
    expect(parseField("timestamp", "x2026-01-02T03:04:05Z", ROOT).isErr()).toBe(true);
    expect(parseField("timestamp", "2026-01-02T03:04:05Z x", ROOT).isErr()).toBe(true);
  });

  it("rejects a nested container with one bad member among good ones", () => {
    expect(
      parseField("array", '[{"arrayValue":{"values":[{"stringValue":"x"},1]}}]', ROOT).isErr(),
    ).toBe(true);
    expect(
      parseField(
        "array",
        '[{"mapValue":{"fields":{"a":{"stringValue":"x"},"b":1}}}]',
        ROOT,
      ).isErr(),
    ).toBe(true);
    expect(parseField("map", '{"a":{"stringValue":"x"},"b":1}', ROOT).isErr()).toBe(true);
  });

  it("rejects an even-length reference with an empty segment", () => {
    expect(parseField("reference", "users//alice/x", ROOT)._unsafeUnwrapErr()).toBe(REF_MSG);
  });

  it("yields ordinary writable, deletable properties", () => {
    const parsed = parseFields([{ name: "a", type: "string", text: "1" }], ROOT)._unsafeUnwrap();
    parsed.a = { stringValue: "2" };
    expect(parsed.a).toEqual({ stringValue: "2" });
    delete parsed.a;
    expect(Object.keys(parsed)).toEqual([]);
    const diffed = diffFields({}, { b: { nullValue: null } }).fields;
    diffed.b = { booleanValue: true };
    delete diffed.b;
    expect(Object.keys(diffed)).toEqual([]);
    const applied = applyFieldDiff({ c: { nullValue: null } }, { fields: {}, fieldPaths: [] });
    applied.c = { booleanValue: true };
    delete applied.c;
    expect(Object.keys(applied)).toEqual([]);
  });

  it("compares arrays element by element and records key by key", () => {
    const list = (values: FsValue[]): FsValue => ({ arrayValue: { values } });
    expect(
      diffFields(
        { v: list([{ integerValue: "1" }, { integerValue: "2" }]) },
        { v: list([{ integerValue: "1" }, { integerValue: "3" }]) },
      ).fieldPaths,
    ).toEqual(["v"]);
    const map = (fields: Record<string, FsValue>): FsValue => ({ mapValue: { fields } });
    expect(
      diffFields(
        { v: map({ a: { integerValue: "1" }, b: { integerValue: "2" } }) },
        { v: map({ a: { integerValue: "1" }, b: { integerValue: "3" } }) },
      ).fieldPaths,
    ).toEqual(["v"]);
    // An array and an array-like record are different values.
    const arrayLike = {
      arrayValue: { values: { 0: { integerValue: "1" } } },
    } as unknown as FsValue;
    expect(diffFields({ v: list([{ integerValue: "1" }]) }, { v: arrayLike }).fieldPaths).toEqual([
      "v",
    ]);
    expect(diffFields({ v: arrayLike }, { v: list([{ integerValue: "1" }]) }).fieldPaths).toEqual([
      "v",
    ]);
    expect(
      diffFields({ v: { stringValue: "ab" } }, { v: { stringValue: "ac" } }).fieldPaths,
    ).toEqual(["v"]);
  });

  it("treats a leading /documents/ marker and trailing slashes consistently", () => {
    expect(relativePath("/documents/a/b")).toBe("a/b");
    expect(parentPath("users/alice/")).toBe("users");
    expect(isDocumentPath("users/alice/")).toBe(true);
    expect(isDocumentPath("/users/")).toBe(false);
  });
});
