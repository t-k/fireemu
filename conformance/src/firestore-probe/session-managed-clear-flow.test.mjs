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
  extraNames = [],
  visibleNames = [scopeNames[0]],
  arrayLength = [19_999, 20_000, 7_184, 7_185, 12_123, 12_124],
  suffixStarts = [],
  initialState,
  programCount = 1,
  omitEmptyValues = false,
  childCollectionNames = [],
  extraChildPageCollections = [],
  recoveryOnly = false,
  deleteAckShape = "update-time",
  deleteReadbackMode,
} = {}) {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-array-shrink-"));
  const input = join(directory, "programs.json");
  const output = join(directory, "results.json");
  const meta = join(directory, "meta.json");
  const journal = join(directory, "managed.json");
  await writeFile(
    input,
    JSON.stringify(
      Array.from({ length: programCount }, (_, index) => ({ id: `empty-${index}`, steps: [] })),
    ),
  );
  if (initialJournalStatus)
    await writeFile(journal, JSON.stringify({ status: initialJournalStatus }));
  const requests = [];
  const legacyLengths = [12_116, 12_121, 12_123, 7_179, 7_183, 7_184];
  const records = new Map(
    [...scopeNames, ...extraNames].map((name, index) => {
      const relative = name.split("/documents/")[1];
      const [collection, document] = relative.split("/");
      const scopeIndex = scopeNames.indexOf(name);
      const length =
        scopeIndex >= 0
          ? Array.isArray(arrayLength)
            ? arrayLength[scopeIndex]
            : arrayLength
          : (legacyLengths[extraNames.indexOf(name)] ?? 0);
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
        pathname.endsWith(`/${record.collection}/${record.document}:listCollectionIds`),
      )
    ) {
      const record = [...records.values()].find((item) =>
        pathname.endsWith(`/${item.collection}/${item.document}:listCollectionIds`),
      );
      const pageToken = new URL(request.url, "http://127.0.0.1").searchParams.get("pageToken");
      send(200, {
        collectionIds: childCollectionNames.includes(record.collection) ? ["nested"] : [],
        ...(extraChildPageCollections.includes(record.collection) && !pageToken
          ? { nextPageToken: "second-page" }
          : {}),
      });
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
              fields: {
                a: {
                  arrayValue:
                    omitEmptyValues && record.values.length === 0 ? {} : { values: record.values },
                },
              },
            },
      );
    } else if (pathname.endsWith("/documents:commit")) {
      const writes = JSON.parse(body).writes;
      if (writes[0].transform) {
        const name = writes[0].transform.document;
        const record = records.get(name);
        if (failureMode === "cas") {
          send(409, { error: { status: "ABORTED", message: "stale updateTime" } });
        } else if (
          (failureMode === "halve-chunk" || failureMode === "unrelated-transform-400") &&
          writes[0].transform.fieldTransforms[0].removeAllFromArray.values.length > 64
        ) {
          send(400, {
            error: {
              status: "INVALID_ARGUMENT",
              message:
                failureMode === "halve-chunk"
                  ? "Transaction too big. Decrease transaction size."
                  : "permission denied for test",
            },
          });
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
        send(
          200,
          deleteAckShape === "malformed"
            ? { writeResults: "invalid" }
            : deleteAckShape === "multiple"
              ? { writeResults: [{}, {}] }
              : deleteAckShape === "missing"
                ? {}
                : deleteAckShape === "without-update-time"
                  ? { writeResults: [{}] }
                  : { writeResults: [{ updateTime: records.get(writes[0].delete).updateTime }] },
        );
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
      if (
        failureMode === "legacy-group-member" &&
        legacyNames.some((name) => name.split("/documents/")[1].split("/")[0] === queriedCollection)
      ) {
        matching.push(`${prefix}${queriedCollection}/unexpected`);
      }
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
        requestedNames.map((name) => {
          const record = records.get(name);
          if (deleteReadbackMode === "present" && requestedNames.length === 1 && record?.deleted) {
            return {
              found: {
                name,
                updateTime: record.updateTime,
                fields: { a: { arrayValue: { values: record.values } } },
              },
            };
          }
          if (
            ["unknown", "error"].includes(deleteReadbackMode) &&
            requestedNames.length === 1 &&
            record?.deleted
          ) {
            return deleteReadbackMode === "error"
              ? { error: { status: "UNAVAILABLE" } }
              : { unexpected: true };
          }
          return failureMode === "legacy-disappears-during-audit" && name === legacyNames[0]
            ? { missing: name }
            : failureMode === "readback" && record?.deleted
              ? { found: { name } }
              : record && visible.has(name) && !record.deleted
                ? {
                    found: {
                      name,
                      updateTime: record.updateTime,
                      fields: {
                        a: {
                          arrayValue:
                            omitEmptyValues && record.values.length === 0
                              ? {}
                              : { values: record.values },
                        },
                      },
                    },
                  }
                : { missing: name };
        }),
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
        ...(recoveryOnly ? { FIRESTORE_PROBE_RECOVERY_MODE: "recover-legacy" } : {}),
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
  return { directory, output, meta, journal, requests, failure, snapshot };
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
    assert.deepEqual(JSON.parse(await readFile(result.output, "utf8")), {
      "empty-0": { steps: {} },
    });
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

test("legacy recovery mode preflights all names before bounded CAS shrink and exact deletes", async () => {
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames,
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
  });
  try {
    assert.equal(result.failure, undefined);
    const firstWrite = result.requests.findIndex((request) =>
      request.pathname.endsWith("/documents:commit"),
    );
    const preflightGroups = result.requests
      .slice(0, firstWrite)
      .filter((request) => request.pathname.endsWith("/documents:runQuery"));
    assert.equal(preflightGroups.length, 6);
    assert.equal(
      result.requests
        .slice(0, firstWrite)
        .filter((request) => request.pathname.endsWith(":listCollectionIds")).length,
      6,
    );
    const writes = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .flatMap((request) => JSON.parse(request.body).writes);
    assert.ok(writes.length > 6);
    assert.ok(
      writes.every((write) => legacyNames.includes(write.delete ?? write.transform?.document)),
    );
    assert.ok(writes.every((write) => write.currentDocument?.updateTime));
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith(":bulkDeleteDocuments")),
      false,
    );
    assert.equal(
      await readFile(result.output, "utf8").then(
        () => true,
        () => false,
      ),
      false,
    );
    assert.equal(JSON.parse(await readFile(result.meta, "utf8")).requestCount <= 1000, true);
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "complete");
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy recovery proves exact absence when a delete result omits updateTime", async () => {
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames.slice(1),
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
    deleteAckShape: "without-update-time",
  });
  try {
    assert.equal(result.failure, undefined);
    const deletes = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .flatMap((request) => JSON.parse(request.body).writes)
      .filter((write) => write.delete);
    assert.equal(deletes.length, 5);
    assert.ok(deletes.every((write) => write.delete !== legacyNames[0]));
    assert.ok(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:batchGet") &&
          JSON.parse(request.body).documents.length === 1,
      ),
    );
    const journal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.equal(journal.status, "complete");
    assert.deepEqual(journal.deletedNames, legacyNames.slice(1));
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy recovery stops on malformed, missing, or multiple delete results", async (t) => {
  for (const deleteAckShape of ["malformed", "missing", "multiple"]) {
    await t.test(deleteAckShape, async () => {
      const result = await observeCollector({
        scopeNames: legacyNames,
        visibleNames: [legacyNames[0]],
        arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
        recoveryOnly: true,
        deleteAckShape,
      });
      try {
        assert.ok(result.failure);
        const deleteWrites = result.requests
          .filter((request) => request.pathname.endsWith("/documents:commit"))
          .flatMap((request) => JSON.parse(request.body).writes)
          .filter((write) => write.delete);
        assert.equal(deleteWrites.length, 1);
        assert.equal(
          result.requests.filter(
            (request) =>
              request.pathname.endsWith("/documents:batchGet") &&
              JSON.parse(request.body).documents.length === 1,
          ).length,
          0,
        );
        assert.equal(
          JSON.parse(await readFile(result.journal, "utf8")).status,
          "preflight-complete",
        );
      } finally {
        await rm(result.directory, { recursive: true, force: true });
      }
    });
  }
});

test("legacy recovery stops when delete acknowledgement readback is not exact absence", async (t) => {
  for (const deleteReadbackMode of ["present", "unknown", "error"]) {
    await t.test(deleteReadbackMode, async () => {
      const result = await observeCollector({
        scopeNames: legacyNames,
        visibleNames: [legacyNames[0]],
        arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
        recoveryOnly: true,
        deleteAckShape: "without-update-time",
        deleteReadbackMode,
      });
      try {
        assert.ok(result.failure);
        assert.match(String(result.failure.stderr), /exact delete typed absence was not proved/);
        assert.equal(
          result.requests.filter(
            (request) =>
              request.pathname.endsWith("/documents:batchGet") &&
              JSON.parse(request.body).documents.length === 1,
          ).length,
          1,
        );
        assert.equal(
          JSON.parse(await readFile(result.journal, "utf8")).status,
          "preflight-complete",
        );
      } finally {
        await rm(result.directory, { recursive: true, force: true });
      }
    });
  }
});

test("legacy recovery accepts six typed-absent names without entering ordinary corpus clearing", async () => {
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: [],
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
  });
  try {
    assert.equal(result.failure, undefined);
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith("/documents:commit")),
      false,
    );
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith(":bulkDeleteDocuments")),
      false,
    );
    assert.equal(
      result.requests.some((request) => request.pathname.includes("/emulator/v1/")),
      false,
    );
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "complete");
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy recovery accepts deterministic suffixes and halves only exact size refusals", async () => {
  const legacyLengths = [12_116, 12_121, 12_123, 7_179, 7_183, 7_184];
  const result = await observeCollector({
    scopeNames: legacyNames,
    arrayLength: legacyLengths,
    suffixStarts: [legacyLengths[0] - 300, ...legacyLengths.slice(1)],
    visibleNames: [legacyNames[0]],
    failureMode: "halve-chunk",
    recoveryOnly: true,
  });
  try {
    assert.equal(result.failure, undefined);
    const transforms = result.requests.filter((request) => {
      if (!request.pathname.endsWith("/documents:commit")) return false;
      return JSON.parse(request.body).writes[0].transform !== undefined;
    });
    assert.ok(transforms.length > 8);
    assert.ok(
      transforms.some(
        (request) =>
          JSON.parse(request.body).writes[0].transform.fieldTransforms[0].removeAllFromArray.values
            .length <= 64,
      ),
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }

  const unsafe = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames,
    arrayLength: legacyLengths,
    recoveryOnly: true,
    childCollectionNames: [legacyNames[2].split("/documents/")[1].split("/")[0]],
  });
  try {
    assert.ok(unsafe.failure);
    assert.equal(
      unsafe.requests.some((request) => request.pathname.endsWith("/documents:commit")),
      false,
    );
  } finally {
    await rm(unsafe.directory, { recursive: true, force: true });
  }

  const unexpectedGroup = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames,
    arrayLength: legacyLengths,
    failureMode: "legacy-group-member",
    recoveryOnly: true,
  });
  try {
    assert.ok(unexpectedGroup.failure);
    assert.equal(
      unexpectedGroup.requests.some((request) => request.pathname.endsWith("/documents:commit")),
      false,
    );
  } finally {
    await rm(unexpectedGroup.directory, { recursive: true, force: true });
  }

  const refusal = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: [legacyNames[0]],
    arrayLength: legacyLengths,
    suffixStarts: [legacyLengths[0] - 128, ...legacyLengths.slice(1)],
    failureMode: "unrelated-transform-400",
    recoveryOnly: true,
  });
  try {
    assert.ok(refusal.failure);
    assert.equal(
      refusal.requests.filter((request) => request.pathname.endsWith("/documents:commit")).length,
      1,
    );
  } finally {
    await rm(refusal.directory, { recursive: true, force: true });
  }
});

test("collector completes bounded shrink and exact cleanup for all six frozen corpus-v3 names", async () => {
  const lengths = [19_999, 20_000, 7_184, 7_185, 12_123, 12_124];
  const result = await observeCollector({
    arrayLength: lengths,
    visibleNames: names,
    omitEmptyValues: true,
  });
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
      8,
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
    assert.equal(meta.requestCount, 163);
    const scopedRequestCount = result.requests.filter(
      (request) =>
        request.pathname.endsWith("/documents:commit") ||
        request.pathname.endsWith("/documents:batchGet") ||
        request.pathname.endsWith("/documents:runQuery") ||
        (request.method === "GET" &&
          names.some((name) => request.pathname.endsWith(name.split("/documents/")[1]))),
    ).length;
    assert.equal(scopedRequestCount, 148);
    assert.ok(scopedRequestCount <= 160);
    assert.deepEqual(JSON.parse(await readFile(result.output, "utf8")), {
      "empty-0": { steps: {} },
    });
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("68 empty programs avoid repeated shrink preflight requests and stay within the cap", async () => {
  const result = await observeCollector({ programCount: 68, visibleNames: [] });
  try {
    assert.equal(result.failure, undefined);
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:runQuery")).length,
      6,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:batchGet")).length,
      1,
    );
    assert.equal(JSON.parse(await readFile(result.meta, "utf8")).requestCount, 76);
    const output = JSON.parse(await readFile(result.output, "utf8"));
    assert.equal(Object.keys(output).length, 68);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 accepts legacy documents already removed by the old delete-only operation", async () => {
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: names,
  });
  try {
    assert.equal(result.failure, undefined);
    const oldCollectionIds = new Set(
      legacyNames.map((name) => name.split("/documents/")[1].split("/")[0]),
    );
    assert.ok(
      result.requests
        .filter((request) => request.pathname.endsWith("/documents:commit"))
        .flatMap((request) => JSON.parse(request.body).writes)
        .every(
          (write) =>
            !oldCollectionIds.has(
              (write.delete ?? write.transform?.document)?.split("/documents/")[1]?.split("/")[0],
            ),
        ),
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 skips only validated legacy debris and never writes old roots", async () => {
  const legacyLengths = [12_116, 12_121, 12_123, 7_179, 7_183, 7_184];
  const suffixStarts = [...Array(6).fill(0), ...legacyLengths.map((length) => length - 128)];
  const result = await observeCollector({
    scopeNames: names,
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    arrayLength: [19_999, 20_000, 7_184, 7_185, 12_123, 12_124],
    suffixStarts,
    programCount: 68,
  });
  try {
    assert.equal(result.failure, undefined);
    assert.ok(JSON.parse(await readFile(result.meta, "utf8")).requestCount <= 1000);
    const writes = result.requests
      .filter((request) => request.pathname.endsWith("/documents:commit"))
      .flatMap((request) => JSON.parse(request.body).writes);
    assert.ok(writes.some((write) => names.includes(write.delete)));
    assert.ok(
      writes.every((write) => !legacyNames.includes(write.delete ?? write.transform?.document)),
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:runQuery")).length,
      30,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:batchGet")).length,
      8,
    );
    const scopedRequestCount = result.requests.filter(
      (request) =>
        request.pathname.endsWith("/documents:commit") ||
        request.pathname.endsWith("/documents:batchGet") ||
        request.pathname.endsWith("/documents:runQuery") ||
        (request.pathname.endsWith(":listCollectionIds") &&
          [...names, ...legacyNames].some((name) =>
            request.pathname.endsWith(`${name.split("/documents/")[1]}:listCollectionIds`),
          )) ||
        (request.method === "GET" &&
          [...names, ...legacyNames].some((name) =>
            request.pathname.endsWith(name.split("/documents/")[1]),
          )),
    ).length;
    assert.equal(scopedRequestCount, 160);
    assert.ok(scopedRequestCount <= 160);
    for (const name of legacyNames) {
      const debris = result.snapshot.get(name);
      assert.equal(debris.deleted, false);
      assert.equal(debris.values.length, 128);
      assert.equal(
        debris.values[0].integerValue,
        String(legacyLengths[legacyNames.indexOf(name)] - 128),
      );
    }
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 rejects unknown members of a legacy debris group before any write", async () => {
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    failureMode: "legacy-group-member",
  });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /collection group contains an unexpected document/);
    assert.equal(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:commit") &&
          JSON.parse(request.body).writes.some((write) => write.delete || write.transform),
      ),
      false,
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 fails closed when an old document disappears between group and typed reads", async () => {
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    failureMode: "legacy-disappears-during-audit",
  });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /changed during its read-only scope audit/);
    assert.equal(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:commit") &&
          JSON.parse(request.body).writes.some((write) => write.delete || write.transform),
      ),
      false,
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 rejects child collections under legacy debris before any write", async () => {
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    childCollectionNames: [legacyNames[2].split("/documents/")[1].split("/")[0]],
  });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /unexpected subcollections/);
    assert.equal(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:commit") &&
          JSON.parse(request.body).writes.some((write) => write.delete || write.transform),
      ),
      false,
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 rejects a non-suffix legacy array before any write", async () => {
  const initialState = new Map([
    [legacyNames[0], { values: [{ integerValue: "5" }, { integerValue: "7" }] }],
  ]);
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    initialState,
  });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /deterministic suffix/);
    assert.equal(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:commit") &&
          JSON.parse(request.body).writes.some((write) => write.delete || write.transform),
      ),
      false,
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy audit request cap stops before any v3 write", async () => {
  const result = await observeCollector({
    extraNames: legacyNames,
    visibleNames: [...names, ...legacyNames],
    extraChildPageCollections: [legacyNames[0].split("/documents/")[1].split("/")[0]],
  });
  try {
    assert.ok(result.failure);
    assert.match(String(result.failure.stderr), /cap reached before network send/);
    assert.equal(
      result.requests.some(
        (request) =>
          request.pathname.endsWith("/documents:commit") &&
          JSON.parse(request.body).writes.some((write) => write.delete || write.transform),
      ),
      false,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/documents:runQuery")).length,
      6,
    );
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
      8,
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
