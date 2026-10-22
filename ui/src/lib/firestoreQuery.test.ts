import { describe, expect, it } from "vitest";
import {
  compileQuery,
  defaultQuery,
  decodeSharedQuery,
  encodeSharedQuery,
  parseQueryValue,
  type QueryDraft,
} from "./firestoreQuery";

const root = "projects/demo-app/databases/named-db/documents";
const build = (draft: Partial<QueryDraft> = {}, path = "parents/p/children") =>
  compileQuery(root, path, { ...defaultQuery(), ...draft });

describe("typed server queries", () => {
  it("copies only validated row fields from shared JSON", () => {
    const row = { field: "x", op: "EQUAL", type: "string", text: "v" } as const;
    const untrusted = Object.fromEntries([
      ...Object.entries(row),
      ["__proto__", { unexpected: true }],
      ["unused", 1],
    ]);
    const decoded = decodeSharedQuery(
      JSON.stringify({ ...defaultQuery(), filters: [untrusted] }),
    )._unsafeUnwrap();
    expect(decoded.filters).toEqual([row]);
    expect(Object.hasOwn(decoded.filters[0] ?? {}, "__proto__")).toBe(false);
  });
  it("rejects prototype-shaped unknown REST tags without throwing", () => {
    for (const key of ["toString", "constructor", "__proto__"]) {
      const text = JSON.stringify([Object.fromEntries([[key, "not a REST value"]])]);
      expect(parseQueryValue("array", text, root).isErr()).toBe(true);
    }
  });
  it("uses the parent document endpoint and preserves nested versus literal field paths", () => {
    const result = build({
      filters: [
        { field: "nested.value", op: "EQUAL", type: "integer", text: "9223372036854775807" },
        { field: "`literal.dot`", op: "EQUAL", type: "double", text: "1" },
      ],
      orders: [{ field: "nested.value", direction: "DESCENDING" }],
      limit: "7",
    })._unsafeUnwrap();
    expect(result.path).toBe(
      "firestore/v1/projects/demo-app/databases/named-db/documents/parents/p:runQuery",
    );
    expect(result.body.structuredQuery).toEqual({
      from: [{ collectionId: "children" }],
      where: {
        compositeFilter: {
          op: "AND",
          filters: [
            {
              fieldFilter: {
                field: { fieldPath: "nested.value" },
                op: "EQUAL",
                value: { integerValue: "9223372036854775807" },
              },
            },
            {
              fieldFilter: {
                field: { fieldPath: "`literal.dot`" },
                op: "EQUAL",
                value: { doubleValue: 1 },
              },
            },
          ],
        },
      },
      orderBy: [{ field: { fieldPath: "nested.value" }, direction: "DESCENDING" }],
      limit: 7,
    });
    expect(build({}, "space here/parent/children")._unsafeUnwrap().path).toContain(
      "space%20here/parent:runQuery",
    );
  });

  it("keeps each scalar wire type and validates exact integer range", () => {
    for (const [type, text, expected] of [
      ["string", "1", { stringValue: "1" }],
      ["integer", "-9223372036854775808", { integerValue: "-9223372036854775808" }],
      ["double", "1", { doubleValue: 1 }],
      ["double", "NaN", { doubleValue: "NaN" }],
      ["boolean", "false", { booleanValue: false }],
      ["null", "", { nullValue: null }],
      ["reference", "users/a", { referenceValue: `${root}/users/a` }],
      [
        "timestamp",
        "2026-10-23T00:00:00.123456789Z",
        { timestampValue: "2026-10-23T00:00:00.123456789Z" },
      ],
    ] as const)
      expect(parseQueryValue(type, text, root)._unsafeUnwrap()).toEqual(expected);
    for (const [type, text] of [
      ["integer", "1.5"],
      ["integer", "9223372036854775808"],
      ["boolean", "maybe"],
      ["timestamp", "yesterday"],
      ["reference", "users"],
      ["array", '[{"integerValue":"9223372036854775808"}]'],
      ["map", '{"x":{"booleanValue":"false"}}'],
    ] as const)
      expect(parseQueryValue(type, text, root).isErr()).toBe(true);
  });

  it("encodes typed arrays/maps, OR, null and NaN unary filters without guessing plain JSON", () => {
    expect(
      parseQueryValue("array", '[{"integerValue":"2"},{"stringValue":"2"}]', root)._unsafeUnwrap(),
    ).toEqual({ arrayValue: { values: [{ integerValue: "2" }, { stringValue: "2" }] } });
    expect(
      parseQueryValue("map", '{"nested":{"referenceValue":"users/a"}}', root)._unsafeUnwrap(),
    ).toEqual({ mapValue: { fields: { nested: { referenceValue: `${root}/users/a` } } } });
    const result = build({
      mode: "OR",
      filters: [
        { field: "missing", op: "EQUAL", type: "null", text: "" },
        { field: "score", op: "NOT_EQUAL", type: "double", text: "NaN" },
      ],
    })._unsafeUnwrap();
    expect(result.body.structuredQuery.where).toEqual({
      compositeFilter: {
        op: "OR",
        filters: [
          { unaryFilter: { field: { fieldPath: "missing" }, op: "IS_NULL" } },
          { unaryFilter: { field: { fieldPath: "score" }, op: "IS_NOT_NAN" } },
        ],
      },
    });
    expect(parseQueryValue("array", '[1,"x"]', root).isErr()).toBe(true);
  });

  it("rejects invalid local combinations but preserves backend semantic validation", () => {
    for (const filters of [
      [{ field: "x", op: "IN", type: "string", text: "a" }],
      [{ field: "x", op: "IN", type: "array", text: "[]" }],
      [{ field: "__name__", op: "EQUAL", type: "string", text: "a" }],
      [{ field: "x", op: "GREATER_THAN", type: "null", text: "" }],
    ] as const)
      expect(build({ filters: [...filters] }).isErr()).toBe(true);
    expect(
      build({
        mode: "OR",
        filters: [
          { field: "x", op: "NOT_IN", type: "array", text: '[{"integerValue":"1"}]' },
          { field: "x", op: "NOT_EQUAL", type: "integer", text: "2" },
        ],
      }).isOk(),
    ).toBe(true);
    for (const limit of ["", "0", "-1", "1.5", "2147483648"])
      expect(build({ limit }).isErr()).toBe(true);
    for (const path of ["", "a/doc", "a//b"]) expect(build({}, path).isErr()).toBe(true);
  });

  it("round-trips versioned share drafts and rejects malformed, oversized and unknown input", () => {
    const draft = {
      ...defaultQuery(),
      filters: [{ field: "名", op: "EQUAL", type: "string", text: "日本語😀" }],
    } as QueryDraft;
    expect(decodeSharedQuery(encodeSharedQuery(draft))._unsafeUnwrap()).toEqual(draft);
    for (const input of [
      "not json",
      JSON.stringify({ ...draft, version: 2 }),
      JSON.stringify({ ...draft, mode: ["AND"] }),
      JSON.stringify({ ...draft, orders: [{ field: "x", direction: ["ASCENDING"] }] }),
      JSON.stringify({
        ...draft,
        filters: [{ field: "x", op: "FAKE", type: "integer", text: "1" }],
      }),
      "x".repeat(32_769),
    ])
      expect(decodeSharedQuery(input).isErr()).toBe(true);
  });
});
