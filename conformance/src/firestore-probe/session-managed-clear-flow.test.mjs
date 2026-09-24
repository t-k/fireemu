import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const prefix = "projects/fireemu-oracle-sbx/databases/(default)/documents/";
const v3Specs = [
  ["g500a", 498, 1],
  ["g500b", 498, 1],
  ["g2000a", 1400, 599],
  ["g2000b", 1400, 599],
  ["g1000a", 998, 1],
  ["g1000b", 998, 1],
];
const resourceNames = (specs) =>
  specs.map(
    ([tag, collectionLength, documentLength]) =>
      `${prefix}${tag.padEnd(collectionLength, "c")}/${"d".repeat(documentLength)}`,
  );
const names = resourceNames(v3Specs);
const legacyNames = resourceNames([
  ["barrayname100012116n31", 998, 1],
  ["barrayname100012121n32", 998, 1],
  ["barrayname100012123n33", 998, 1],
  ["barrayname20007179n45", 1400, 599],
  ["barrayname20007183n47", 1400, 599],
  ["barrayname20007184n49", 1400, 599],
]);

async function observeCollector({
  failureMode,
  initialJournalStatus,
  scopeNames = names,
  visibleNames = [scopeNames[0]],
  arrayLength = [19_999, 20_000, 7_184, 7_185, 12_123, 12_124],
  suffixStarts = [],
  initialState,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-array-shrink-"));
  const input = join(directory, "programs.json");
  const output = join(directory, "results.json");
  const meta = join(directory, "meta.json");
  const journal = join(directory, "managed.json");
  await writeFile(input, JSON.stringify([{ id: "empty", steps: [] }]));
  if (initialJournalStatus)
    await writeFile(journal, JSON.stringify({ status: initialJournalStatus }));
  const requests = [];
  const records = new Map(
    scopeNames.map((name, index) => {
      const relative = name.split("/documents/")[1];
      const [collection, document] = relative.split("/");
      const length = Array.isArray(arrayLength) ? arrayLength[index] : arrayLength;
      return [
        name,
        {
          collection,
          document,
          values: Array.from({ length: length - (suffixStarts[index] ?? 0) }, (_, value) => ({
            integerValue: String(value + (suffixStarts[index] ?? 0)),
          })),
          updateTime: initialState?.get(name)?.updateTime ?? "t0",
          deleted: false,
        },
      ];
    }),
  );
  for (const [name, state] of initialState ?? []) {
    if (records.has(name)) Object.assign(records.get(name), state);
  }
  const visible = new Set(visibleNames);
  const server = createServer(async (request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    const body = await new Promise((resolve) => {
      let value = "";
      request.on("data", (chunk) => (value += chunk));
      request.on("end", () => resolve(value));
    });
    requests.push({ method: request.method, pathname, body });
    const send = (status, value) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(value));
    };
    if (pathname.endsWith("/documents:listCollectionIds")) {
      send(200, {
        collectionIds: [
          ...new Set(
            [...records]
              .filter(([name, record]) => visible.has(name) && !record.deleted)
              .map(([, record]) => record.collection),
          ),
        ],
      });
    } else if (
      [...records.values()].some((record) => pathname.endsWith(`/documents/${record.collection}`))
    ) {
      const collection = [...records.values()].find((record) =>
        pathname.endsWith(`/documents/${record.collection}`),
      ).collection;
      send(200, {
        documents: [...records]
          .filter(
            ([name, record]) =>
              visible.has(name) && record.collection === collection && !record.deleted,
          )
          .map(([name]) => ({ name, createTime: "2026-01-01T00:00:00Z" })),
      });
    } else if (
      [...records.values()].some((record) =>
        pathname.endsWith(`/${record.document}:listCollectionIds`),
      )
    ) {
      send(200, {});
    } else if (
      [...records.values()].some((record) =>
        pathname.endsWith(`/${record.collection}/${record.document}`),
      )
    ) {
      const [name, record] = [...records].find(([, item]) =>
        pathname.endsWith(`/${item.collection}/${item.document}`),
      );
      send(
        record.deleted ? 404 : 200,
        record.deleted
          ? { error: { status: "NOT_FOUND" } }
          : {
              name,
              updateTime: record.updateTime,
              fields: { a: { arrayValue: { values: record.values } } },
            },
      );
    } else if (pathname.endsWith("/documents:commit")) {
      const writes = JSON.parse(body).writes;
      if (writes[0].transform) {
        const name = writes[0].transform.document;
        const record = records.get(name);
        if (failureMode === "cas") {
          send(409, { error: { status: "ABORTED", message: "stale updateTime" } });
        } else if (failureMode === "partial" && record.transformCommits === 1) {
          send(503, { error: { status: "UNAVAILABLE", message: "interrupted after one commit" } });
        } else {
          assert.equal(writes[0].currentDocument.updateTime, record.updateTime);
          const removed = new Set(
            writes[0].transform.fieldTransforms[0].removeAllFromArray.values.map(
              (value) => value.integerValue,
            ),
          );
          record.values = record.values.filter((value) => !removed.has(value.integerValue));
          record.updateTime = `t${Number(record.updateTime.slice(1)) + 1}`;
          record.transformCommits = (record.transformCommits ?? 0) + 1;
          send(200, { writeResults: [{ updateTime: record.updateTime }] });
        }
      } else if (
        failureMode === "race-before-retry" &&
        records.get(writes[0].delete).values.length === 0
      ) {
        const record = records.get(writes[0].delete);
        assert.equal(writes[0].currentDocument.updateTime, record.updateTime);
        record.updateTime = "recreated-before-retry";
        send(409, { error: { status: "ABORTED", message: "concurrent recreation" } });
      } else if (failureMode === "race-before-delete") {
        const record = records.get(writes[0].delete);
        assert.equal(writes[0].currentDocument.updateTime, record.updateTime);
        record.updateTime = "recreated-after-preflight";
        send(409, { error: { status: "ABORTED", message: "concurrent recreation" } });
      } else if (
        failureMode === "race-before-shrink" &&
        records.get(writes[0].delete).values.length > 0
      ) {
        const record = records.get(writes[0].delete);
        record.updateTime = "recreated-before-shrink";
        send(400, {
          error: {
            status: "INVALID_ARGUMENT",
            message: "Transaction too big. Decrease transaction size.",
          },
        });
      } else if (failureMode === "delete" || records.get(writes[0].delete).values.length > 0) {
        send(400, {
          error: {
            status: "INVALID_ARGUMENT",
            message: "Transaction too big. Decrease transaction size.",
          },
        });
      } else {
        records.get(writes[0].delete).deleted = true;
        send(200, { writeResults: [{ updateTime: records.get(writes[0].delete).updateTime }] });
      }
    } else if (pathname.endsWith("/documents:runQuery")) {
      const query = JSON.parse(body).structuredQuery;
      const queriedCollection = query.from[0].collectionId;
      const matching = [...records]
        .filter(
          ([name, record]) =>
            visible.has(name) && record.collection === queriedCollection && !record.deleted,
        )
        .map(([name]) => name);
      if (failureMode === "prefight" && matching.length) matching.push(`${prefix}g500a/other`);
      if (
        failureMode === "preflight-second" &&
        queriedCollection === records.get(scopeNames[1]).collection
      ) {
        matching.push(`${prefix}${queriedCollection}/unexpected`);
      }
      if (
        failureMode === "group" &&
        records.get(scopeNames[0]).deleted &&
        queriedCollection === records.get(scopeNames[0]).collection
      )
        matching.push(scopeNames[0]);
      send(
        200,
        matching.map((name) => ({ document: { name } })),
      );
    } else if (pathname.endsWith("/documents:batchGet")) {
      const requestedNames = JSON.parse(body).documents;
      send(
        200,
        requestedNames.map((name) =>
          failureMode === "readback" && records.get(name)?.deleted
            ? { found: { name } }
            : { missing: name },
        ),
      );
    } else {
      send(404, { error: { status: "NOT_FOUND" } });
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  let failure;
  try {
    await execFileAsync("node", [new URL("./session.mjs", import.meta.url).pathname], {
      env: {
        ...process.env,
        FIRESTORE_PROBE_TARGET: "production",
        FIRESTORE_PROBE_SCHEME: "http",
        FIRESTORE_PROBE_HOST: `127.0.0.1:${port}`,
        FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
        FIRESTORE_PROBE_IN: input,
        FIRESTORE_PROBE_OUT: output,
        FIRESTORE_PROBE_META_OUT: meta,
        FIRESTORE_PROBE_TOKEN: "test-only",
        FIRESTORE_PROBE_MAX_REQUESTS: "1000",
        FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(scopeNames),
        FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: journal,
        FIRESTORE_PROBE_MANAGED_POLL_MS: "1",
      },
      timeout: 10_000,
    });
  } catch (error) {
    failure = error;
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
  const snapshot = new Map(
    [...records].map(([name, record]) => [name, { ...record, values: [...record.values] }]),
  );
  return { directory, output, meta, requests, failure, snapshot };
}

test("collector array-removes bounded chunks with updateTime CAS before exact deletion", async () => {
  const result = await observeCollector();
  try {
    assert.equal(result.failure, undefined);
    const transforms = result.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes[0].transform !== undefined;
    });
    assert.equal(transforms.length, 20);
    assert.deepEqual(
      transforms.map(
        (request) =>
          JSON.parse(request.body).writes[0].transform.fieldTransforms[0].removeAllFromArray.values
            .length,
      ),
      [...Array(19).fill(1024), 543],
    );
    assert.deepEqual(
      transforms.map((request) => JSON.parse(request.body).writes[0].currentDocument.updateTime),
      Array.from({ length: 20 }, (_, index) => `t${index}`),
    );
    assert.ok(result.requests.some((request) => request.pathname.endsWith("/documents:batchGet")));
    assert.ok(result.requests.some((request) => request.pathname.endsWith("/documents:runQuery")));
    assert.deepEqual(JSON.parse(await readFile(result.output, "utf8")), { empty: { steps: {} } });
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("collector rejects an unexpected array length before transforming", async () => {
  const result = await observeCollector({ arrayLength: 1024 });
  try {
    assert.ok(result.failure);
    assert.equal(
      result.requests.some((request) => {
        if (!request.pathname.endsWith("/documents:commit")) return false;
        return JSON.parse(request.body).writes[0].transform !== undefined;
      }),
      false,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("collector applies bounded shrink and verification to the six frozen legacy names", async () => {
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames,
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
  });
  try {
    assert.equal(result.failure, undefined);
    const transforms = result.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes[0].transform !== undefined;
    });
    assert.equal(transforms.length, 60);
    assert.ok(
      transforms.every((request) =>
        Boolean(JSON.parse(request.body).writes[0].currentDocument.updateTime),
      ),
    );
    assert.ok(result.requests.some((request) => request.pathname.endsWith("/documents:batchGet")));
    assert.ok(result.requests.some((request) => request.pathname.endsWith("/documents:runQuery")));
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("collector completes bounded shrink and exact cleanup for all six frozen corpus-v3 names", async () => {
  const lengths = [19_999, 20_000, 7_184, 7_185, 12_123, 12_124];
  const result = await observeCollector({ arrayLength: lengths, visibleNames: names });
  try {
    assert.equal(result.failure, undefined);
    const transforms = result.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes[0].transform !== undefined;
    });
    assert.equal(transforms.length, 80);
    const perDocument = new Map(names.map((name) => [name, 0]));
    for (const request of transforms) {
      const write = JSON.parse(request.body).writes[0];
      const name = write.transform.document;
      perDocument.set(name, perDocument.get(name) + 1);
      assert.ok(write.currentDocument.updateTime);
      assert.ok(write.transform.fieldTransforms[0].removeAllFromArray.values.length <= 1024);
    }
    assert.deepEqual([...perDocument.values()], [20, 20, 8, 8, 12, 12]);
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:batchGet")).length,
      7,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:runQuery")).length,
      30,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:commit")).length,
      92,
    );
    const deletes = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .flatMap((request) => JSON.parse(request.body).writes)
      .filter((write) => write.delete);
    assert.equal(deletes.length, 12);
    assert.ok(deletes.every((write) => write.currentDocument?.updateTime));
    for (const [name, chunks] of perDocument) {
      const pair = deletes.filter((write) => write.delete === name);
      assert.deepEqual(
        pair.map((write) => write.currentDocument.updateTime),
        ["t0", `t${chunks}`],
      );
    }
    const meta = JSON.parse(await readFile(result.meta, "utf8"));
    assert.equal(meta.requestCount, 162);
    const scopedRequestCount = result.requests.filter(
      (request) =>
        request.pathname.endsWith("/documents:commit") ||
        request.pathname.endsWith("/documents:batchGet") ||
        request.pathname.endsWith("/documents:runQuery") ||
        (request.method === "GET" &&
          names.some((name) => request.pathname.endsWith(name.split("/documents/")[1]))),
    ).length;
    assert.equal(scopedRequestCount, 147);
    assert.ok(scopedRequestCount <= 160);
    assert.deepEqual(JSON.parse(await readFile(result.output, "utf8")), { empty: { steps: {} } });
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("collector blocks explicit partial debris after an interrupted transform response", async () => {
  const first = await observeCollector({ failureMode: "partial" });
  try {
    assert.ok(first.failure);
    const firstTransforms = first.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes[0].transform !== undefined;
    });
    assert.equal(firstTransforms.length, 2);
    assert.equal(first.snapshot.get(names[0]).values.length, 19_999 - 1_024);
    const resumed = await observeCollector({ initialState: first.snapshot });
    try {
      assert.ok(resumed.failure);
      assert.match(String(resumed.failure.stderr), /partial debris requires operator recovery/);
      const writes = resumed.requests.filter((request) => {
        if (!request.pathname.endsWith("/documents:commit")) return false;
        return JSON.parse(request.body).writes.some((write) => write.transform || write.delete);
      });
      assert.equal(writes.length, 0);
      await assert.rejects(readFile(resumed.output), /ENOENT/);
    } finally {
      await rm(resumed.directory, { recursive: true, force: true });
    }
  } finally {
    await rm(first.directory, { recursive: true, force: true });
  }
});

test("managed delete uses preflight updateTime and stops on a concurrent recreation", async () => {
  const result = await observeCollector({ failureMode: "race-before-delete" });
  try {
    assert.ok(result.failure);
    const deletes = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .map((request) => JSON.parse(request.body).writes[0])
      .filter((write) => write.delete);
    assert.equal(deletes.length, 1);
    assert.equal(deletes[0].currentDocument.updateTime, "t0");
    assert.equal(
      result.requests.some((request) => {
        if (!request.pathname.endsWith("/documents:commit")) return false;
        return JSON.parse(request.body).writes[0].transform !== undefined;
      }),
      false,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("array shrink refuses a target recreated after preflight", async () => {
  const result = await observeCollector({ failureMode: "race-before-shrink" });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /changed after global preflight/);
    const commits = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .map((request) => JSON.parse(request.body).writes[0]);
    assert.equal(commits.filter((write) => write.delete).length, 1);
    assert.equal(commits.filter((write) => write.transform).length, 0);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("shrunk retry delete uses the verified updateTime and stops on a concurrent recreation", async () => {
  const result = await observeCollector({ failureMode: "race-before-retry" });
  try {
    assert.ok(result.failure);
    const commits = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .map((request) => JSON.parse(request.body).writes[0]);
    const deletes = commits.filter((write) => write.delete);
    assert.deepEqual(
      deletes.map((write) => write.currentDocument.updateTime),
      ["t0", "t20"],
    );
    assert.equal(commits.filter((write) => write.transform).length, 20);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("stale updateTime stops array shrink before delete and output", async () => {
  const result = await observeCollector({ failureMode: "cas" });
  try {
    assert.ok(result.failure);
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:commit")).length,
      2,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("a refused delete after shrinking stops without bulk-delete fallback", async () => {
  const result = await observeCollector({ failureMode: "delete" });
  try {
    assert.ok(result.failure);
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith(":bulkDeleteDocuments")),
      false,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:commit")).length,
      22,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("unexpected collection-group document stops before array mutation", async () => {
  const result = await observeCollector({ failureMode: "prefight" });
  try {
    assert.ok(result.failure);
    assert.equal(
      result.requests.some((request) => {
        if (!request.pathname.endsWith("/documents:commit")) return false;
        return JSON.parse(request.body).writes[0].transform !== undefined;
      }),
      false,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("all six target groups are preflighted before any target mutation", async () => {
  const result = await observeCollector({ failureMode: "preflight-second", visibleNames: names });
  try {
    assert.ok(result.failure);
    const writes = result.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes.some((write) => write.transform || write.delete);
    });
    assert.equal(writes.length, 0);
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:runQuery")).length,
      2,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("typed found readback prevents output after delete", async () => {
  const result = await observeCollector({ failureMode: "readback" });
  try {
    assert.ok(result.failure);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("non-empty collection-group confirmation prevents output after delete", async () => {
  const result = await observeCollector({ failureMode: "group" });
  try {
    assert.ok(result.failure);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("unfinished journal prevents another recording before any request", async () => {
  const result = await observeCollector({ initialJournalStatus: "active" });
  try {
    assert.ok(result.failure);
    assert.equal(result.requests.length, 0);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});
