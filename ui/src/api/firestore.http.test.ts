import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { setApiBase } from "./client";
import {
  createDocument,
  deleteCollection,
  deleteDocument,
  documentsRoot,
  getDocument,
  listCollectionIds,
  listDocuments,
  setDocument,
  updateDocument,
} from "./firestore";
import { startTestServer } from "./testServer";
import type { FsDocument } from "../lib/firestoreValue";

let server: Awaited<ReturnType<typeof startTestServer>>;
const ROOT = documentsRoot("demo-app", "(default)");
const API = `/ui/api/firestore/v1/${ROOT}`;
const JSON_HEADERS = { "content-type": "application/json" };
const json = (body: unknown, status = 200) => ({
  status,
  headers: JSON_HEADERS,
  body: JSON.stringify(body),
});

beforeAll(async () => {
  server = await startTestServer();
  setApiBase(server.base);
  window.__FIREEMU__ = { controlToken: "tok" };
});
afterAll(async () => {
  await server.close();
});
afterEach(() => {
  server.seen.length = 0;
  server.script.clear();
});

describe("Firestore REST calls", () => {
  it("names the documents root", () => {
    expect(ROOT).toBe("projects/demo-app/databases/(default)/documents");
  });

  it("lists collection IDs with the page size and an optional token", async () => {
    server.script.set(`POST ${API}:listCollectionIds`, json({ collectionIds: ["a"] }));
    expect((await listCollectionIds(ROOT, ""))._unsafeUnwrap()).toEqual({ collectionIds: ["a"] });
    expect(JSON.parse(server.seen[0]!.body)).toEqual({ pageSize: 300 });
    server.script.set(`POST ${API}/users/a%23b:listCollectionIds`, json({}));
    await listCollectionIds(ROOT, "users/a#b", "next");
    expect(server.seen[1]!.url).toBe(`${API}/users/a%23b:listCollectionIds`);
    expect(JSON.parse(server.seen[1]!.body)).toEqual({ pageSize: 300, pageToken: "next" });
  });

  it("lists documents including missing ones, fifty at a time", async () => {
    server.script.set(`GET ${API}/cities`, json({ documents: [] }));
    await listDocuments(ROOT, "cities");
    expect(server.seen[0]!.url).toBe(`${API}/cities?pageSize=50&showMissing=true`);
    await listDocuments(ROOT, "cities", "t/1");
    expect(server.seen[1]!.url).toBe(`${API}/cities?pageSize=50&showMissing=true&pageToken=t%2F1`);
  });

  it("reads, replaces, creates and deletes a document at an encoded path", async () => {
    const doc: FsDocument = { name: `${ROOT}/cities/a b`, fields: {} };
    server.script.set(`GET ${API}/cities/a%20b`, json(doc));
    expect((await getDocument(ROOT, "cities/a b"))._unsafeUnwrap()).toEqual(doc);

    server.script.set(`PATCH ${API}/cities/a%20b`, json(doc));
    await setDocument(ROOT, "cities/a b", { n: { integerValue: "1" } });
    expect(server.seen[1]!.method).toBe("PATCH");
    expect(JSON.parse(server.seen[1]!.body)).toEqual({ fields: { n: { integerValue: "1" } } });

    server.script.set(`POST ${API}/cities`, json(doc));
    await createDocument(ROOT, "cities", "", { n: { integerValue: "1" } });
    expect(server.seen[2]!.url).toBe(`${API}/cities`);
    await createDocument(ROOT, "cities", "a#b", {});
    expect(server.seen[3]!.url).toBe(`${API}/cities?documentId=a%23b`);
    expect(JSON.parse(server.seen[3]!.body)).toEqual({ fields: {} });

    server.script.set(`DELETE ${API}/cities/a%20b`, json({}));
    expect((await deleteDocument(ROOT, "cities/a b")).isOk()).toBe(true);
    expect(server.seen[4]!.method).toBe("DELETE");
  });

  it("updates only the masked fields under the captured update time", async () => {
    server.script.set(`PATCH ${API}/cities/x`, json({ name: `${ROOT}/cities/x` }));
    await updateDocument(ROOT, "cities/x", { a: { nullValue: null } }, ["a", "b.c"], "T1");
    const url = new URL(`http://h${server.seen[0]!.url}`);
    expect(url.pathname).toBe(`${API}/cities/x`);
    expect(url.searchParams.getAll("updateMask.fieldPaths")).toEqual(["a", "`b.c`"]);
    expect(url.searchParams.get("currentDocument.updateTime")).toBe("T1");
    expect(JSON.parse(server.seen[0]!.body)).toEqual({ fields: { a: { nullValue: null } } });
  });

  it("surfaces an error answer", async () => {
    server.script.set(
      `GET ${API}/cities/none`,
      json({ error: { code: 404, status: "NOT_FOUND", message: "missing" } }, 404),
    );
    expect((await getDocument(ROOT, "cities/none"))._unsafeUnwrapErr()).toEqual({
      status: 404,
      code: "NOT_FOUND",
      message: "missing",
    });
  });
});

/** A collection page: `count` documents named `${path}/d{i}` starting at `from`. */
const docs = (path: string, from: number, count: number, existing = true): FsDocument[] =>
  Array.from({ length: count }, (_, i) => ({
    name: `${ROOT}/${path}/d${from + i}`,
    ...(existing ? { fields: {}, createTime: "T" } : {}),
  }));

describe("deleteCollection", () => {
  it("walks subcollection pages before deleting, commits in chunks of 100 and reports progress", async () => {
    // top: 130 documents over three pages; d0 has two subcollections (paged), each with one doc.
    server.script.set(`GET ${API}/top`, (req) => {
      const token = new URL(`http://h${req.url}`).searchParams.get("pageToken");
      if (token === null) return json({ documents: docs("top", 0, 50), nextPageToken: "p2" });
      if (token === "p2") return json({ documents: docs("top", 50, 50), nextPageToken: "p3" });
      return json({ documents: docs("top", 100, 30) });
    });
    server.script.set(`POST ${API}/top/d0:listCollectionIds`, (req) =>
      JSON.parse(req.body).pageToken === "c2"
        ? json({ collectionIds: ["s2"] })
        : json({ collectionIds: ["s1"], nextPageToken: "c2" }),
    );
    for (let i = 1; i < 130; i += 1) {
      server.script.set(`POST ${API}/top/d${i}:listCollectionIds`, json({}));
    }
    server.script.set(`GET ${API}/top/d0/s1`, json({ documents: docs("top/d0/s1", 0, 1) }));
    server.script.set(`GET ${API}/top/d0/s2`, json({ documents: docs("top/d0/s2", 0, 1) }));
    server.script.set(`POST ${API}/top/d0/s1/d0:listCollectionIds`, json({}));
    server.script.set(`POST ${API}/top/d0/s2/d0:listCollectionIds`, json({}));
    server.script.set(`POST /ui/api/firestore/v1/${ROOT}:commit`, json({}));

    const progress: number[] = [];
    const r = await deleteCollection(ROOT, "top", (n) => progress.push(n));
    expect(r._unsafeUnwrap()).toBe(132);
    expect(progress).toEqual([1, 2, 52, 102, 132]);

    const commits = server.seen
      .filter((s) => s.url.endsWith(":commit"))
      .map((s) => (JSON.parse(s.body) as { writes: { delete: string }[] }).writes);
    expect(commits.map((w) => w.length)).toEqual([1, 1, 50, 50, 30]);
    expect(commits[0]![0]!.delete).toBe(`${ROOT}/top/d0/s1/d0`);
    expect(commits[1]![0]!.delete).toBe(`${ROOT}/top/d0/s2/d0`);
    expect(commits[2]![0]!.delete).toBe(`${ROOT}/top/d0`);
    // The children of d0 are gone before d0's own page is committed.
    const order = server.seen.map((s) => `${s.method} ${s.url.split("?")[0]}`);
    expect(order.indexOf(`POST /ui/api/firestore/v1/${ROOT}:commit`)).toBeLessThan(
      order.indexOf(`GET ${API}/top`, 1),
    );
  });

  it("splits a page of more than 100 documents into commits of at most 100", async () => {
    server.script.set(`GET ${API}/wide`, json({ documents: docs("wide", 0, 50) }));
    // The page size the server honours is its business: answer 250 at once.
    server.script.set(`GET ${API}/wide`, json({ documents: docs("wide", 0, 250) }));
    for (let i = 0; i < 250; i += 1) {
      server.script.set(`POST ${API}/wide/d${i}:listCollectionIds`, json({}));
    }
    server.script.set(`POST /ui/api/firestore/v1/${ROOT}:commit`, json({}));
    const progress: number[] = [];
    expect((await deleteCollection(ROOT, "wide", (n) => progress.push(n)))._unsafeUnwrap()).toBe(
      250,
    );
    expect(progress).toEqual([100, 200, 250]);
  });

  it("skips missing documents in commits but still walks their subcollections", async () => {
    server.script.set(`GET ${API}/m`, json({ documents: docs("m", 0, 1, false) }));
    server.script.set(`POST ${API}/m/d0:listCollectionIds`, json({ collectionIds: ["s"] }));
    server.script.set(`GET ${API}/m/d0/s`, json({ documents: docs("m/d0/s", 0, 1) }));
    server.script.set(`POST ${API}/m/d0/s/d0:listCollectionIds`, json({}));
    server.script.set(`POST /ui/api/firestore/v1/${ROOT}:commit`, json({}));
    expect((await deleteCollection(ROOT, "m"))._unsafeUnwrap()).toBe(1);
    const commits = server.seen.filter((s) => s.url.endsWith(":commit"));
    expect(commits.length).toBe(1);
    expect(JSON.parse(commits[0]!.body)).toEqual({ writes: [{ delete: `${ROOT}/m/d0/s/d0` }] });
  });

  it("counts a document with only fields, or only a createTime, as existing", async () => {
    server.script.set(
      `GET ${API}/f`,
      json({
        documents: [
          { name: `${ROOT}/f/d0`, fields: {} },
          { name: `${ROOT}/f/d1`, createTime: "T" },
        ],
      }),
    );
    server.script.set(`POST ${API}/f/d0:listCollectionIds`, json({}));
    server.script.set(`POST ${API}/f/d1:listCollectionIds`, json({}));
    server.script.set(`POST /ui/api/firestore/v1/${ROOT}:commit`, json({}));
    expect((await deleteCollection(ROOT, "f"))._unsafeUnwrap()).toBe(2);
  });

  it("deletes nothing and reports zero for an empty collection", async () => {
    server.script.set(`GET ${API}/empty`, json({}));
    expect((await deleteCollection(ROOT, "empty"))._unsafeUnwrap()).toBe(0);
    expect(server.seen.filter((s) => s.url.endsWith(":commit")).length).toBe(0);
  });

  it.each([
    ["listing documents", (s: typeof server) => s.script.delete(`GET ${API}/e`)],
    [
      "listing subcollections",
      (s: typeof server) => s.script.delete(`POST ${API}/e/d0:listCollectionIds`),
    ],
    ["a nested listing", (s: typeof server) => s.script.delete(`GET ${API}/e/d0/s`)],
    ["a commit", (s: typeof server) => s.script.delete(`POST /ui/api/firestore/v1/${ROOT}:commit`)],
  ])("stops at the first failure while %s", async (_what, breakIt) => {
    server.script.set(`GET ${API}/e`, json({ documents: docs("e", 0, 2) }));
    server.script.set(`POST ${API}/e/d0:listCollectionIds`, json({ collectionIds: ["s"] }));
    server.script.set(`POST ${API}/e/d1:listCollectionIds`, json({}));
    server.script.set(`GET ${API}/e/d0/s`, json({ documents: docs("e/d0/s", 0, 1) }));
    server.script.set(`POST ${API}/e/d0/s/d0:listCollectionIds`, json({}));
    server.script.set(`POST /ui/api/firestore/v1/${ROOT}:commit`, json({}));
    breakIt(server);
    const e = (await deleteCollection(ROOT, "e"))._unsafeUnwrapErr();
    expect(e.status).toBe(404);
    expect(e.message).toMatch(/^no script for /);
  });
});
