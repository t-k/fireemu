import { afterEach, describe, expect, it, vi } from "vitest";
import { compileQuery, defaultQuery } from "../lib/firestoreQuery";
import { loadMissingIndexes, runQuery } from "./firestoreQuery";

vi.mock("../config", () => ({ controlToken: () => "test-token" }));
afterEach(() => vi.unstubAllGlobals());
const root = "projects/demo-app/databases/named-db/documents";
const query = () => compileQuery(root, "parents/p/children", defaultQuery())._unsafeUnwrap();
const reply = (body: unknown, status = 200) =>
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockImplementation(() => Promise.resolve(new Response(JSON.stringify(body), { status }))),
  );

describe("Firestore runQuery transport", () => {
  it("preserves literal prototype-shaped field names in parsed documents", async () => {
    reply([
      {
        document: {
          name: `${root}/parents/p/children/a`,
          fields: Object.fromEntries([["__proto__", { stringValue: "literal" }]]),
        },
      },
    ]);
    const fields = (await runQuery(query()))._unsafeUnwrap().documents[0]?.fields;
    expect(Object.hasOwn(fields ?? {}, "__proto__")).toBe(true);
    expect(fields?.["__proto__"]).toEqual({ stringValue: "literal" });
  });
  it("posts a real structured query with owner authentication and preserves metadata rows", async () => {
    reply([
      { readTime: "2026-10-23T00:00:00Z" },
      {
        document: {
          name: `${root}/parents/p/children/a`,
          fields: { n: { integerValue: "9223372036854775807" } },
        },
        readTime: "now",
      },
    ]);
    const result = (await runQuery(query()))._unsafeUnwrap();
    expect(result.documents).toHaveLength(1);
    expect(result.metadata).toHaveLength(1);
    expect(result.rows).toHaveLength(2);
    expect(fetch).toHaveBeenCalledWith(
      `/ui/api/${query().path}`,
      expect.objectContaining({
        method: "POST",
        headers: { authorization: "Bearer test-token", "content-type": "application/json" },
        body: JSON.stringify(query().body),
      }),
    );
    expect((await runQuery(query()))._unsafeUnwrap().documents[0]?.fields?.n).toEqual({
      integerValue: "9223372036854775807",
    });
  });

  it("preserves HTTP status, RPC code and genuine error array message instead of an empty success", async () => {
    reply(
      [
        {
          error: {
            code: 400,
            status: "FAILED_PRECONDITION",
            message: "The query requires an index: original details",
          },
        },
      ],
      400,
    );
    expect((await runQuery(query()))._unsafeUnwrapErr()).toEqual({
      status: 400,
      code: "FAILED_PRECONDITION",
      message: "The query requires an index: original details",
    });
    reply({ error: { status: "PERMISSION_DENIED", message: "Denied" } }, 403);
    expect((await runQuery(query()))._unsafeUnwrapErr().status).toBe(403);
    reply([{ error: { status: "INVALID_ARGUMENT", message: "stream error" } }]);
    expect((await runQuery(query())).isErr()).toBe(true);
  });

  it("rejects unknown and malformed success shapes while accepting an actual empty array", async () => {
    for (const body of [
      { documents: [] },
      [{}],
      ["not a row"],
      [{ document: {} }],
      [{ document: { name: "x", fields: { x: { integerValue: "bad" } } } }],
    ]) {
      reply(body);
      expect((await runQuery(query())).isErr()).toBe(true);
    }
    reply([]);
    expect((await runQuery(query()))._unsafeUnwrap().documents).toEqual([]);
    reply({ unexpected: true });
    expect((await runQuery(query()))._unsafeUnwrapErr()).toMatchObject({
      status: 0,
      code: "INVALID_RESPONSE",
    });
  });
});

describe("session-scoped missing index reports", () => {
  it("filters the full named-database identity and preserves dropped/truncated state", async () => {
    reply({
      count: 2,
      missingIndexes: [
        {
          project: "demo-app",
          database: "named-db",
          name: "projects/demo-app/databases/named-db",
          index: {},
          message: "index A",
        },
        {
          project: "demo-app",
          database: "(default)",
          name: "projects/demo-app/databases/(default)",
          index: {},
          message: "index B",
        },
      ],
      indexesJson: {},
      truncated: true,
      dropped: 3,
    });
    const result = (await loadMissingIndexes("trial / 1", root))._unsafeUnwrap();
    expect(result.missingIndexes).toHaveLength(1);
    expect(result.dropped).toBe(3);
    expect(result.truncated).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      "/ui/api/control/v1/sessions/trial%20%2F%201/firestore/missingIndexes",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("retains unavailable reporting as a FAILED_PRECONDITION error, never an empty list", async () => {
    reply({ error: "FAILED_PRECONDITION : report mode is disabled" }, 409);
    const result = await loadMissingIndexes("default", root);
    expect(result._unsafeUnwrapErr()).toEqual({
      status: 409,
      message: "FAILED_PRECONDITION : report mode is disabled",
    });
  });
});
