import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sendDeleteAfterWriteAhead, writePrivateJsonDurably } from "./sandbox-session.mjs";
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
const deleteSpecs = ["rest", "commit", "batch-write"].flatMap((route) =>
  [12_112, 12_113].map((length) => [
    `del${route.replaceAll("-", "")}${length}DELETE_RUN_ID`,
    979,
    1,
  ]),
);
const resourceNames = (specs) =>
  specs.map(
    ([tag, collectionLength, documentLength]) =>
      `${prefix}${tag.padEnd(collectionLength, "c")}/${"d".repeat(documentLength)}`,
  );
const names = resourceNames(v3Specs);
const allV3Names = [...names, ...resourceNames(deleteSpecs)];
const defaultDeleteRunId = "a".repeat(32);
const legacyNames = resourceNames([
  ["barrayname100012116n31", 998, 1],
  ["barrayname100012121n32", 998, 1],
  ["barrayname100012123n33", 998, 1],
  ["barrayname20007179n45", 1400, 599],
  ["barrayname20007183n47", 1400, 599],
  ["barrayname20007184n49", 1400, 599],
]);

test("durable journal replacement syncs the file before the parent directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-durable-journal-"));
  const journal = join(directory, "journal.json");
  const syncOrder = [];
  try {
    await writePrivateJsonDurably(
      journal,
      { status: "deleting", names: legacyNames },
      {
        syncFile: async (handle) => {
          syncOrder.push("file");
          await handle.sync();
        },
        syncDirectory: async (handle) => {
          syncOrder.push("directory");
          await handle.sync();
        },
      },
    );
    assert.deepEqual(JSON.parse(await readFile(journal, "utf8")), {
      status: "deleting",
      names: legacyNames,
    });
    assert.deepEqual(syncOrder, ["file", "directory"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy recovery does not send DELETE when write-ahead journal flush fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-durable-journal-failure-"));
  const journal = join(directory, "journal.json");
  const oldEntry = JSON.stringify({ status: "preflight-complete", deletedNames: [] });
  const sends = [];
  try {
    await writeFile(journal, oldEntry, { mode: 0o600 });
    await assert.rejects(
      sendDeleteAfterWriteAhead(
        () =>
          writePrivateJsonDurably(
            journal,
            { status: "deleting", deletedNames: [], deleteIntent: legacyNames[0] },
            { syncFile: async () => Promise.reject(new Error("injected file sync failure")) },
          ),
        async () => sends.push("DELETE"),
      ),
      /durably persist private journal/,
    );
    assert.deepEqual(sends, []);
    assert.equal(await readFile(journal, "utf8"), oldEntry);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy recovery fails closed at every journal durability boundary", async () => {
  for (const failurePoint of ["write", "file-sync", "rename", "directory-sync"]) {
    const directory = await mkdtemp(join(tmpdir(), "fireemu-journal-durability-boundary-"));
    const journal = join(directory, "journal.json");
    const oldEntry = JSON.stringify({ status: "preflight-complete", deletedNames: [] });
    const sends = [];
    const fail = async () => {
      throw new Error(`injected ${failurePoint} failure`);
    };
    const operations = {
      ...(failurePoint === "write" ? { writeTemp: fail } : {}),
      ...(failurePoint === "file-sync" ? { syncFile: fail } : {}),
      ...(failurePoint === "rename" ? { renameTemp: fail } : {}),
      ...(failurePoint === "directory-sync" ? { syncDirectory: fail } : {}),
    };
    try {
      await writeFile(journal, oldEntry, { mode: 0o600 });
      await assert.rejects(
        sendDeleteAfterWriteAhead(
          () =>
            writePrivateJsonDurably(
              journal,
              { status: "deleting", deletedNames: [], deleteIntent: legacyNames[0] },
              operations,
            ),
          async () => sends.push("DELETE"),
        ),
        /durably persist private journal/,
        failurePoint,
      );
      assert.deepEqual(sends, [], failurePoint);
      if (failurePoint !== "directory-sync") {
        assert.equal(await readFile(journal, "utf8"), oldEntry, failurePoint);
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});

async function observeCollector({
  failureMode,
  initialJournalStatus,
  initialJournal,
  initialDeltaJournal,
  scopeNames = names,
  extraNames = [],
  visibleNames = [scopeNames[0]],
  arrayLength = [
    19_999, 20_000, 7_184, 7_185, 12_123, 12_124, 12_112, 12_113, 12_112, 12_113, 12_112, 12_113,
  ],
  suffixStarts = [],
  initialState,
  programCount = 1,
  omitEmptyValues = false,
  childCollectionNames = [],
  extraChildPageCollections = [],
  recoveryOnly = false,
  recoveryMode,
  deleteAckShape = "production",
  deleteReadbackMode,
  deleteRunId = defaultDeleteRunId,
  programs,
  inputCorpus,
  deltaV3 = false,
  deltaLockHeld = true,
  corpusDigest = "c".repeat(64),
  hostOverride,
} = {}) {
  const runtimeName = (name) => name.replaceAll("DELETE_RUN_ID", deleteRunId);
  scopeNames = scopeNames.map(runtimeName);
  extraNames = extraNames.map(runtimeName);
  visibleNames = visibleNames.map(runtimeName);
  const directory = await mkdtemp(join(tmpdir(), "fireemu-array-shrink-"));
  const input = join(directory, "programs.json");
  const output = join(directory, "results.json");
  const meta = join(directory, "meta.json");
  const journal = join(directory, "managed.json");
  const deltaJournal = join(directory, "delta-cleanup.json");
  await writeFile(
    input,
    JSON.stringify(
      inputCorpus ??
        programs ??
        Array.from({ length: programCount }, (_, index) => ({ id: `empty-${index}`, steps: [] })),
    ),
  );
  if (initialJournal) await writeFile(journal, JSON.stringify(initialJournal));
  if (initialDeltaJournal) await writeFile(deltaJournal, JSON.stringify(initialDeltaJournal));
  else if (initialJournalStatus)
    await writeFile(journal, JSON.stringify({ status: initialJournalStatus }));
  const requests = [];
  const journalAtDeleteRequests = [];
  const journalAtSeedRequests = [];
  const probeSeededNames = new Set();
  const injectedPreDeleteFailures = new Set();
  const probeCandidateDeletedNames = new Set();
  const injectedCandidatePostFailures = new Set();
  const injectedCandidateGroupFailures = new Set();
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
    if (pathname.endsWith("/documents:commit") || pathname.endsWith("/documents:batchWrite")) {
      const writes = JSON.parse(body).writes;
      if (
        writes.some((write) => write.delete) &&
        (recoveryOnly ||
          writes.some(
            (write) => scopeNames.includes(write.delete) && !legacyNames.includes(write.delete),
          ))
      ) {
        journalAtDeleteRequests.push(
          JSON.parse(await readFile(deltaV3 ? deltaJournal : journal, "utf8")),
        );
      }
    }
    const send = (status, value) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(value));
    };
    if (pathname.endsWith("):bulkDeleteDocuments")) {
      const requested = JSON.parse(body).collectionIds;
      assert.ok(
        requested.every((collection) =>
          scopeNames.some((name) => name.split("/documents/")[1].split("/")[0] === collection),
        ),
      );
      for (const record of records.values()) {
        if (requested.includes(record.collection)) record.deleted = true;
      }
      send(200, { name: "projects/fireemu-oracle-sbx/databases/(default)/operations/delta-test" });
    } else if (pathname.endsWith("/operations/delta-test")) {
      send(200, {
        name: "projects/fireemu-oracle-sbx/databases/(default)/operations/delta-test",
        done: true,
      });
    } else if (pathname.endsWith("/documents:listCollectionIds")) {
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
      if (request.method === "DELETE") {
        if (failureMode === "candidate-refused") {
          send(400, {
            error: {
              status: "INVALID_ARGUMENT",
              message: "Transaction too big. Decrease transaction size.",
            },
          });
        } else if (failureMode === "candidate-wrong-refusal") {
          send(403, { error: { status: "PERMISSION_DENIED", message: "forbidden" } });
        } else {
          record.deleted = true;
          probeCandidateDeletedNames.add(name);
          send(200, {});
        }
      } else if (request.method === "PATCH") {
        const patch = JSON.parse(body);
        record.values = patch.fields.a.arrayValue.values;
        record.deleted = false;
        visible.add(name);
        probeSeededNames.add(name);
        journalAtSeedRequests.push(JSON.parse(await readFile(deltaJournal, "utf8")));
        if (failureMode === "patch-after-apply-dropped") {
          response.destroy();
        } else {
          send(200, { updateTime: record.updateTime });
        }
      } else if (
        ["pre-delete-malformed", "pre-delete-404", "pre-delete-wrong-length"].includes(
          failureMode,
        ) &&
        probeSeededNames.has(name) &&
        !injectedPreDeleteFailures.has(name) &&
        !record.deleted
      ) {
        injectedPreDeleteFailures.add(name);
        if (failureMode === "pre-delete-404") send(404, { error: { status: "NOT_FOUND" } });
        else if (failureMode === "pre-delete-wrong-length") {
          send(200, {
            name,
            updateTime: record.updateTime,
            fields: { a: { arrayValue: { values: record.values.slice(1) } } },
          });
        } else send(200, { name: `${name}-unexpected`, updateTime: record.updateTime, fields: {} });
      } else if (!visible.has(name) && !probeSeededNames.has(name)) {
        send(404, { error: { status: "NOT_FOUND" } });
      } else
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
                      omitEmptyValues && record.values.length === 0
                        ? {}
                        : { values: record.values },
                  },
                },
              },
        );
    } else if (
      pathname.endsWith("/documents:commit") ||
      pathname.endsWith("/documents:batchWrite")
    ) {
      const writes = JSON.parse(body).writes;
      if (writes[0].update) {
        const record = records.get(writes[0].update.name);
        assert.ok(record, `seed must address managed test resource ${writes[0].update.name}`);
        record.values = writes[0].update.fields.a.arrayValue.values;
        record.deleted = false;
        probeSeededNames.add(writes[0].update.name);
        send(200, { writeResults: [{}] });
      } else if (writes[0].transform) {
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
        if (deleteAckShape === "uncertain") {
          send(503, { error: { status: "UNAVAILABLE" } });
          return;
        }
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
                  : deleteAckShape === "update-time"
                    ? { writeResults: [{ updateTime: records.get(writes[0].delete).updateTime }] }
                    : { writeResults: [{}] },
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
      const candidateName = [...probeCandidateDeletedNames].find(
        (name) => records.get(name)?.collection === queriedCollection,
      );
      if (
        failureMode === "candidate-group-nonempty" &&
        candidateName &&
        !injectedCandidateGroupFailures.has(queriedCollection)
      ) {
        injectedCandidateGroupFailures.add(queriedCollection);
        matching.push(candidateName);
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
          if (
            failureMode === "candidate-post-untyped" &&
            probeCandidateDeletedNames.has(name) &&
            record?.deleted &&
            !injectedCandidatePostFailures.has(name)
          ) {
            injectedCandidatePostFailures.add(name);
            return { unexpected: true };
          }
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
    await execFileAsync("node", [new URL("./sandbox-session.mjs", import.meta.url).pathname], {
      env: {
        ...process.env,
        FIRESTORE_PROBE_TARGET: "production",
        FIRESTORE_PROBE_SCHEME: "http",
        FIRESTORE_PROBE_HOST: hostOverride ?? `127.0.0.1:${port}`,
        FIRESTORE_PROBE_PROJECT: "fireemu-oracle-sbx",
        FIRESTORE_PROBE_IN: input,
        FIRESTORE_PROBE_OUT: output,
        FIRESTORE_PROBE_META_OUT: meta,
        FIRESTORE_PROBE_TOKEN: "test-only",
        FIRESTORE_PROBE_MAX_REQUESTS: "1000",
        FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(scopeNames),
        FIRESTORE_PROBE_DELETE_RUN_ID: deleteRunId,
        FIRESTORE_PROBE_CORPUS_DIGEST: corpusDigest,
        FIRESTORE_PROBE_SOURCE_GIT_SHA: "d".repeat(40),
        FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: journal,
        ...(deltaV3
          ? {
              FIRESTORE_PROBE_DELTA_V3: "1",
              ...(deltaLockHeld ? { FIRESTORE_PROBE_DELTA_LOCK_HELD: "1" } : {}),
              FIRESTORE_PROBE_DELTA_JOURNAL: deltaJournal,
              FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: undefined,
              FIRESTORE_PROBE_MAX_REQUESTS: String(
                recoveryMode === "recover-delta-v3" && initialDeltaJournal
                  ? 430 - initialDeltaJournal.httpRequestCount
                  : 430,
              ),
            }
          : {}),
        FIRESTORE_PROBE_MANAGED_POLL_MS: "1",
        ...(recoveryMode || recoveryOnly
          ? { FIRESTORE_PROBE_RECOVERY_MODE: recoveryMode ?? "recover-legacy" }
          : {}),
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
  return {
    directory,
    output,
    meta,
    journal,
    deltaJournal,
    requests,
    journalAtDeleteRequests,
    journalAtSeedRequests,
    failure,
    snapshot,
  };
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
    assert.equal(result.journalAtDeleteRequests.length, 5);
    const intents = result.journalAtDeleteRequests.map((entry) => entry.deleteIntent);
    assert.deepEqual(
      intents.map(({ action, name, priorDeletedNames }) => ({
        action,
        name,
        priorDeletedNames,
      })),
      legacyNames.slice(1).map((name, index) => ({
        action: "commit-delete",
        name,
        priorDeletedNames: legacyNames.slice(1, index + 1),
      })),
    );
    assert.ok(intents.every((intent) => typeof intent.updateTime === "string"));
    assert.deepEqual(
      intents.map((intent) => intent.updateTime),
      deletes.map((write) => write.currentDocument.updateTime),
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("uncertain legacy delete acknowledgement leaves the write-ahead intent", async () => {
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: [legacyNames[0]],
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
    deleteAckShape: "uncertain",
  });
  try {
    assert.ok(result.failure);
    assert.equal(result.journalAtDeleteRequests.length, 1);
    const journal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.deepEqual(journal.deleteIntent, {
      action: "commit-delete",
      name: legacyNames[0],
      priorDeletedNames: [],
      updateTime: "t12",
    });
    assert.deepEqual(journal.deletedNames, []);
    assert.equal(journal.status, "deleting");
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy recovery resumes a pending intent when typed preflight proves the target absent", async () => {
  const target = legacyNames[0];
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames.slice(1),
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
    initialJournal: {
      schemaVersion: 1,
      mode: "recover-legacy",
      status: "deleting",
      project: "fireemu-oracle-sbx",
      database: "(default)",
      names: legacyNames,
      deletedNames: [],
      deleteIntent: {
        action: "commit-delete",
        name: target,
        priorDeletedNames: [],
        updateTime: "t12",
      },
    },
  });
  try {
    assert.equal(result.failure, undefined);
    assert.equal(result.journalAtDeleteRequests.length, 5);
    const journal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.equal(journal.status, "complete");
    assert.deepEqual(journal.deletedNames, legacyNames);
    assert.equal(journal.deleteIntent, undefined);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("legacy recovery preserves a typed-absent name from a journal created before write-ahead intents", async () => {
  const alreadyAbsent = legacyNames[0];
  const result = await observeCollector({
    scopeNames: legacyNames,
    visibleNames: legacyNames.slice(1),
    arrayLength: [12_116, 12_121, 12_123, 7_179, 7_183, 7_184],
    recoveryOnly: true,
    initialJournal: {
      schemaVersion: 1,
      mode: "recover-legacy",
      status: "preflight-complete",
      project: "fireemu-oracle-sbx",
      database: "(default)",
      names: legacyNames,
      presentNames: legacyNames.slice(1),
      absentNames: [alreadyAbsent],
    },
  });
  try {
    assert.equal(result.failure, undefined);
    const journal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.equal(journal.status, "complete");
    assert.deepEqual(journal.deletedNames, legacyNames.slice(1));
    assert.deepEqual(journal.verifiedAbsentNames, [alreadyAbsent]);
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
        const journal = JSON.parse(await readFile(result.journal, "utf8"));
        assert.equal(journal.status, "deleting");
        assert.equal(journal.deleteIntent.name, legacyNames[0]);
        assert.deepEqual(journal.deletedNames, []);
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
        assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "deleting");
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

test("delta-v3 loopback run uses only six source-bound names and a separate resumable bulk-delete journal", async () => {
  const { prepareSandboxCorpus } = await import("../fs-data-write-sandbox-run.mjs");
  const { corpus } = await prepareSandboxCorpus();
  const digest = createHash("sha256").update(JSON.stringify(corpus)).digest("hex");
  const routes = ["rest", "commit", "batch-write"];
  const ids = new Set(
    routes.flatMap((route) =>
      [12112, 12113].map((count) => `writes/limits/near-limit-delete-refusal/${route}/${count}`),
    ),
  );
  const restPrograms = corpus.restPrograms.filter((program) => ids.has(program.id));
  const streamRecipes = corpus.streamRecipes.filter(
    (recipe) => recipe.id === "writes/write-stream-terminal/response-before-half-close",
  );
  const deltaNames = restPrograms.map((program) => program.steps[0].body.writes[0].update.name);
  const counts = restPrograms.map((program) => Number(program.id.split("/").at(-1)));
  const packet = {
    schemaVersion: 1,
    sourceCorpusSha256: digest,
    restPrograms,
    streamRecipes,
    restRequestCount: 30,
  };
  const lockDenied = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: counts,
    deltaV3: true,
    deltaLockHeld: false,
    corpusDigest: digest,
    inputCorpus: packet,
  });
  assert.match(lockDenied.failure?.stderr ?? "", /delta-v3 requires its separate journal/);
  assert.equal(lockDenied.requests.length, 0);
  const foreignName = deltaNames[0]
    .replace("DELETE_RUN_ID", defaultDeleteRunId)
    .replace(/\/d$/, "/foreign");
  const foreign = await observeCollector({
    scopeNames: deltaNames,
    extraNames: [foreignName],
    visibleNames: [...deltaNames, foreignName],
    arrayLength: counts,
    deltaV3: true,
    corpusDigest: digest,
    inputCorpus: packet,
  });
  assert.ok(foreign.failure);
  assert.equal(
    foreign.requests.some((request) => request.pathname.endsWith("):bulkDeleteDocuments")),
    false,
  );
  const child = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: counts,
    childCollectionNames: [
      deltaNames[2]
        .replaceAll("DELETE_RUN_ID", defaultDeleteRunId)
        .split("/documents/")[1]
        .split("/")[0],
    ],
    deltaV3: true,
    corpusDigest: digest,
    inputCorpus: packet,
  });
  assert.ok(child.failure);
  assert.equal(
    child.requests.some((request) => request.pathname.endsWith("):bulkDeleteDocuments")),
    false,
  );
  const result = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: counts,
    deltaV3: true,
    corpusDigest: digest,
    inputCorpus: packet,
  });
  assert.ifError(result.failure);
  const journal = JSON.parse(await readFile(join(result.directory, "delta-cleanup.json"), "utf8"));
  assert.equal(journal.mode, "cleanup-delta-v3");
  assert.equal(journal.status, "complete");
  assert.equal(
    journal.writerExclusivity,
    "task-lock-held; run-specific six collection groups have no external writer",
  );
  assert.deepEqual(
    journal.names,
    deltaNames.map((name) => name.replaceAll("DELETE_RUN_ID", defaultDeleteRunId)),
  );
  assert.ok(journal.httpRequestCount <= 430);
  assert.ok(journal.managedRequestCount <= 400);
  assert.equal(
    JSON.parse(await readFile(result.meta, "utf8")).requestCount,
    result.requests.length,
  );
  assert.equal(
    result.requests.filter(
      (request) =>
        request.pathname ===
        "/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:listCollectionIds",
    ).length,
    0,
  );
  const bulkDeleteRequests = result.requests.filter((request) =>
    request.pathname.endsWith("):bulkDeleteDocuments"),
  );
  assert.ok(bulkDeleteRequests.length <= 2);
  for (const request of bulkDeleteRequests) {
    const collectionIds = JSON.parse(request.body).collectionIds;
    assert.ok(collectionIds.length > 0 && collectionIds.length <= 6);
    assert.ok(
      collectionIds.every((id) =>
        deltaNames.some(
          (name) =>
            name
              .replaceAll("DELETE_RUN_ID", defaultDeleteRunId)
              .split("/documents/")[1]
              .split("/")[0] === id,
        ),
      ),
    );
  }
  assert.ok(
    result.requests.every(
      (request) =>
        request.pathname !==
        "/emulator/v1/projects/fireemu-oracle-sbx/databases/(default)/documents",
    ),
  );
  const outcome = JSON.parse(await readFile(result.output, "utf8"));
  assert.ok(Object.values(outcome).every((entry) => entry.conditionEvidence === "complete"));
  const second = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: counts,
    deltaV3: true,
    deleteRunId: "f".repeat(32),
    corpusDigest: digest,
    inputCorpus: packet,
  });
  assert.ifError(second.failure);
  const secondJournal = JSON.parse(
    await readFile(join(second.directory, "delta-cleanup.json"), "utf8"),
  );
  assert.notEqual(journal.runId, secondJournal.runId);
  assert.notDeepEqual(journal.names, secondJournal.names);
  assert.equal(secondJournal.status, "complete");
  await rm(result.directory, { recursive: true, force: true });
  await rm(second.directory, { recursive: true, force: true });
});

test("delta-v3 recovery resolves a durable candidate DELETE intent by fresh typed reads without replay", async () => {
  const runId = "e".repeat(32);
  const deltaNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const sourceCorpusDigest = "c".repeat(64);
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-delta-v3",
    status: "write-ahead-mutation",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: sourceCorpusDigest,
    sourceGitSha: "d".repeat(40),
    writerExclusivity: "task-lock-held; run-specific six collection groups have no external writer",
    names: deltaNames,
    httpRequestCount: 30,
    managedRequestCount: 0,
    bulkDeleteIntent: null,
    bulkDeleteOperation: null,
    pendingMutation: {
      name: deltaNames[0],
      method: "DELETE",
      stepId: "delete",
      url: `https://firestore.googleapis.com/v1/${deltaNames[0]}`,
      bodySha256: createHash("sha256").update("").digest("hex"),
    },
  };
  const present = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
    deleteRunId: runId,
    deltaV3: true,
    recoveryMode: "recover-delta-v3",
    initialDeltaJournal: journal,
    corpusDigest: sourceCorpusDigest,
  });
  try {
    assert.ifError(present.failure);
    assert.equal(
      present.requests.some(
        (request) => request.pathname === `/v1/${deltaNames[0]}` && request.method === "DELETE",
      ),
      false,
    );
    const recovered = JSON.parse(
      await readFile(join(present.directory, "delta-cleanup.json"), "utf8"),
    );
    assert.equal(recovered.status, "complete");
    assert.equal(recovered.pendingMutation, null);
    assert.equal(recovered.lastMutation.recoveredOutcome, "target-present");
  } finally {
    await rm(present.directory, { recursive: true, force: true });
  }

  const absent = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames.slice(1),
    arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
    deleteRunId: runId,
    deltaV3: true,
    recoveryMode: "recover-delta-v3",
    initialDeltaJournal: journal,
    corpusDigest: sourceCorpusDigest,
  });
  try {
    assert.ifError(absent.failure);
    assert.equal(
      absent.requests.some(
        (request) => request.pathname === `/v1/${deltaNames[0]}` && request.method === "DELETE",
      ),
      false,
    );
    const recovered = JSON.parse(
      await readFile(join(absent.directory, "delta-cleanup.json"), "utf8"),
    );
    assert.equal(recovered.status, "complete");
    assert.equal(recovered.lastMutation.recoveredOutcome, "target-absent");
  } finally {
    await rm(absent.directory, { recursive: true, force: true });
  }

  for (const route of ["commit", "batch-write"]) {
    const target = deltaNames.find((candidate) =>
      candidate.split("/documents/")[1].startsWith(`del${route.replaceAll("-", "")}`),
    );
    const path = `/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:${route === "commit" ? "commit" : "batchWrite"}`;
    const method = "POST";
    const routeJournal = {
      ...journal,
      pendingMutation: {
        name: target,
        method,
        stepId: "delete",
        url: `https://firestore.googleapis.com${path}`,
        bodySha256: createHash("sha256")
          .update(JSON.stringify({ writes: [{ delete: target }] }))
          .digest("hex"),
      },
    };
    const routeResult = await observeCollector({
      scopeNames: deltaNames,
      visibleNames: deltaNames,
      arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
      deleteRunId: runId,
      deltaV3: true,
      recoveryMode: "recover-delta-v3",
      initialDeltaJournal: routeJournal,
      corpusDigest: sourceCorpusDigest,
    });
    try {
      assert.ifError(routeResult.failure);
      assert.equal(
        routeResult.requests.some((request) => request.pathname === path),
        false,
      );
      const recovered = JSON.parse(
        await readFile(join(routeResult.directory, "delta-cleanup.json"), "utf8"),
      );
      assert.equal(recovered.status, "complete");
      assert.equal(recovered.lastMutation.recoveredOutcome, "target-present");
    } finally {
      await rm(routeResult.directory, { recursive: true, force: true });
    }
  }
});

test("delta-v3 recovery refuses an uncertain bulk-delete start without resending", async () => {
  const runId = "e".repeat(32);
  const deltaNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-delta-v3",
    status: "bulk-delete-intent",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    writerExclusivity: "task-lock-held; run-specific six collection groups have no external writer",
    names: deltaNames,
    httpRequestCount: 30,
    managedRequestCount: 1,
    bulkDeleteIntent: {
      collectionIds: deltaNames.map((name) => name.split("/documents/")[1].split("/")[0]),
      names: deltaNames,
    },
    bulkDeleteOperation: null,
    pendingMutation: null,
  };
  const result = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
    deleteRunId: runId,
    deltaV3: true,
    recoveryMode: "recover-delta-v3",
    initialDeltaJournal: journal,
    corpusDigest: journal.corpusDigest,
  });
  try {
    assert.match(result.failure?.stderr ?? "", /uncertain.*do not resend/);
    assert.equal(result.requests.length, 0);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("delta-v3 recovery re-entry polls the journaled LRO without starting another delete", async () => {
  const runId = "e".repeat(32);
  const deltaNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const collectionIds = deltaNames.map((name) => name.split("/documents/")[1].split("/")[0]);
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-delta-v3",
    status: "bulk-delete-active",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    writerExclusivity: "task-lock-held; run-specific six collection groups have no external writer",
    names: deltaNames,
    httpRequestCount: 31,
    managedRequestCount: 2,
    bulkDeleteIntent: { collectionIds, names: deltaNames },
    bulkDeleteOperation: "projects/fireemu-oracle-sbx/databases/(default)/operations/delta-test",
    pendingMutation: null,
  };
  const result = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: [],
    arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
    deleteRunId: runId,
    deltaV3: true,
    recoveryMode: "recover-delta-v3",
    initialDeltaJournal: journal,
    corpusDigest: journal.corpusDigest,
  });
  try {
    assert.ifError(result.failure);
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith(":bulkDeleteDocuments")).length,
      0,
    );
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith("/operations/delta-test"))
        .length,
      1,
    );
    const recovered = JSON.parse(
      await readFile(join(result.directory, "delta-cleanup.json"), "utf8"),
    );
    assert.equal(recovered.status, "complete");
    assert.equal(recovered.bulkDeleteOperation, null);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("delta-v3 recovery resolves a real commit seed intent after either crash window without replay", async () => {
  const { prepareSandboxCorpus } = await import("../fs-data-write-sandbox-run.mjs");
  const { corpus } = await prepareSandboxCorpus();
  const seed = corpus.restPrograms.find(
    (program) => program.id === "writes/limits/near-limit-delete-refusal/rest/12112",
  ).steps[0];
  const runId = "e".repeat(32);
  const deltaNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const name = deltaNames[0];
  const update = structuredClone(seed.body.writes[0].update);
  update.name = update.name
    .replaceAll("DELETE_RUN_ID", runId)
    .replaceAll("PROJECT", "fireemu-oracle-sbx");
  const seedBody = JSON.stringify({ writes: [{ update }] });
  const journal = (bodySha256) => ({
    schemaVersion: 1,
    mode: "cleanup-delta-v3",
    status: "write-ahead-mutation",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    writerExclusivity: "task-lock-held; run-specific six collection groups have no external writer",
    names: deltaNames,
    httpRequestCount: 30,
    managedRequestCount: 0,
    bulkDeleteIntent: null,
    bulkDeleteOperation: null,
    pendingMutation: {
      name,
      method: "POST",
      stepId: "seed",
      url: "https://firestore.googleapis.com/v1/projects/fireemu-oracle-sbx/databases/(default)/documents:commit",
      bodySha256,
    },
  });
  for (const [outcome, visibleNames] of [
    ["target-present", deltaNames],
    ["target-absent", deltaNames.slice(1)],
  ]) {
    const initialJournal = journal(createHash("sha256").update(seedBody).digest("hex"));
    const result = await observeCollector({
      scopeNames: deltaNames,
      visibleNames,
      arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
      deleteRunId: runId,
      deltaV3: true,
      recoveryMode: "recover-delta-v3",
      initialDeltaJournal: initialJournal,
      corpusDigest: initialJournal.corpusDigest,
    });
    try {
      assert.ifError(result.failure);
      assert.equal(
        result.requests.some((request) => {
          if (request.method !== "POST" || !request.pathname.endsWith("/documents:commit"))
            return false;
          const writes = JSON.parse(request.body).writes;
          return writes.some(
            (write) => write.update?.name === name && write.update.fields?.a?.arrayValue,
          );
        }),
        false,
      );
      const recovered = JSON.parse(
        await readFile(join(result.directory, "delta-cleanup.json"), "utf8"),
      );
      assert.equal(recovered.status, "complete");
      assert.equal(recovered.lastMutation.recoveredOutcome, outcome);
    } finally {
      await rm(result.directory, { recursive: true, force: true });
    }
  }
});

test("delta-v3 recovery resolves an actual PATCH seed helper intent after an uncertain response", async () => {
  const { prepareSandboxCorpus } = await import("../fs-data-write-sandbox-run.mjs");
  const { corpus } = await prepareSandboxCorpus();
  const runId = "f".repeat(32);
  const deltaNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const programs = corpus.restPrograms
    .filter((program) => program.id.startsWith("writes/limits/near-limit-delete-refusal/"))
    .map((program) => structuredClone(program));
  const name = deltaNames[0];
  const recipe = programs.find((program) => program.id.endsWith("/rest/12112"));
  recipe.seed = [
    {
      path: `/v1/${name.replaceAll(runId, "DELETE_RUN_ID")}`,
      fields: recipe.steps[0].body.writes[0].update.fields,
    },
  ];
  const failed = await observeCollector({
    scopeNames: deltaNames,
    visibleNames: deltaNames,
    arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
    deleteRunId: runId,
    deltaV3: true,
    failureMode: "patch-after-apply-dropped",
    inputCorpus: {
      schemaVersion: 1,
      sourceCorpusSha256: "c".repeat(64),
      restPrograms: programs,
      streamRecipes: [
        {
          id: "writes/write-stream-terminal/response-before-half-close",
          transport: "grpc",
          maxFrames: 2,
        },
      ],
      restRequestCount: 30,
    },
  });
  try {
    const patchRequest = failed.requests.find(
      (request) => request.method === "PATCH" && request.pathname === `/v1/${name}`,
    );
    assert.ok(
      patchRequest,
      `the real seed() helper must issue its PATCH request: failure=${failed.failure}; requests=${JSON.stringify(failed.requests.slice(0, 5))}`,
    );
    assert.ok(failed.failure, "injected lost PATCH acknowledgement must stop the child");
    const intent = failed.journalAtSeedRequests[0]?.pendingMutation;
    assert.equal(intent.method, "PATCH");
    assert.equal(intent.stepId, "seed");
    assert.equal(intent.url.endsWith(`/v1/${name}`), true);
    assert.equal(
      intent.bodySha256,
      createHash("sha256").update(patchRequest.body).digest("hex"),
      "the durable intent must bind the exact transmitted PATCH body",
    );
    const initialDeltaJournal = JSON.parse(await readFile(failed.deltaJournal, "utf8"));
    assert.equal(initialDeltaJournal.pendingMutation.bodySha256, intent.bodySha256);

    const recovered = await observeCollector({
      scopeNames: deltaNames,
      visibleNames: deltaNames,
      arrayLength: [12_112, 12_113, 12_112, 12_113, 12_112, 12_113],
      deleteRunId: runId,
      deltaV3: true,
      recoveryMode: "recover-delta-v3",
      initialDeltaJournal,
      corpusDigest: initialDeltaJournal.corpusDigest,
    });
    try {
      assert.ifError(recovered.failure);
      assert.equal(
        recovered.requests.some(
          (request) => request.method === "PATCH" && request.pathname === `/v1/${name}`,
        ),
        false,
        "recovery must resolve the ambiguous PATCH without replay",
      );
      const finalJournal = JSON.parse(await readFile(recovered.deltaJournal, "utf8"));
      assert.equal(finalJournal.status, "complete");
      assert.equal(finalJournal.lastMutation.recoveredOutcome, "target-present");
    } finally {
      await rm(recovered.directory, { recursive: true, force: true });
    }
  } finally {
    await rm(failed.directory, { recursive: true, force: true });
  }
});

test("two corpus-v3 recordings write each twelve-name cleanup intent before deleting", async () => {
  const runtimeScopes = [];
  for (const runId of ["a".repeat(32), "b".repeat(32)]) {
    const result = await observeCollector({
      scopeNames: allV3Names,
      visibleNames: allV3Names,
      arrayLength: [
        19_999, 20_000, 7_184, 7_185, 12_123, 12_124, 12_112, 12_113, 12_112, 12_113, 12_112,
        12_113,
      ],
      deleteRunId: runId,
    });
    try {
      assert.equal(result.failure, undefined);
      const newNames = allV3Names.slice(6).map((name) => name.replaceAll("DELETE_RUN_ID", runId));
      const intents = result.journalAtDeleteRequests.filter((entry) =>
        newNames.includes(entry.deleteIntent?.name),
      );
      assert.equal(intents.length, 12);
      assert.ok(
        intents.every(
          (entry) =>
            entry.schemaVersion === 1 &&
            entry.mode === "cleanup-corpus-v3" &&
            entry.status === "deleting" &&
            ["delete attempt", "delete retry"].includes(entry.deleteIntent.action) &&
            typeof entry.deleteIntent.updateTime === "string",
        ),
      );
      assert.ok(JSON.parse(await readFile(result.meta, "utf8")).requestCount <= 1000);
      for (const name of newNames) assert.equal(result.snapshot.get(name).deleted, true);
      const finalJournal = JSON.parse(await readFile(result.journal, "utf8"));
      assert.equal(finalJournal.status, "complete");
      assert.equal(finalJournal.runId, runId);
      assert.equal(finalJournal.corpusDigest, "c".repeat(64));
      assert.equal(finalJournal.sourceGitSha, "d".repeat(40));
      assert.deepEqual(
        finalJournal.verifiedAbsentNames,
        allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId)),
      );
      runtimeScopes.push(
        new Set(newNames.map((name) => name.split("/documents/")[1].split("/")[0])),
      );
    } finally {
      await rm(result.directory, { recursive: true, force: true });
    }
  }
  assert.equal(
    [...runtimeScopes[0]].some((collection) => runtimeScopes[1].has(collection)),
    false,
  );
});

test("a failed, wrong-name or wrong-length pre-delete read blocks candidate DELETE but not cleanup", async () => {
  const name = allV3Names[6];
  const seedValues = Array.from({ length: 12_112 }, (_, index) => ({
    integerValue: String(index),
  }));
  const program = {
    id: "writes/limits/near-limit-delete-refusal/rest/12112",
    seed: [],
    steps: [
      {
        id: "seed",
        method: "POST",
        path: "/v1/projects/PROJECT/databases/(default)/documents:commit",
        body: {
          writes: [{ update: { name, fields: { a: { arrayValue: { values: seedValues } } } } }],
        },
      },
      {
        id: "before-delete",
        method: "GET",
        path: `/v1/${name}`,
      },
      { id: "delete", method: "DELETE", path: `/v1/${name}` },
      { id: "after-delete", method: "GET", path: `/v1/${name}` },
      {
        id: "group-after-delete",
        method: "POST",
        path: "/v1/projects/PROJECT/databases/(default)/documents:runQuery",
        body: {
          structuredQuery: {
            from: [
              { collectionId: name.split("/documents/")[1].split("/")[0], allDescendants: true },
            ],
            select: { fields: [{ fieldPath: "__name__" }] },
            limit: 2,
          },
        },
      },
    ],
  };
  for (const failureMode of ["pre-delete-malformed", "pre-delete-404", "pre-delete-wrong-length"]) {
    const result = await observeCollector({
      scopeNames: allV3Names,
      visibleNames: allV3Names,
      failureMode,
      programs: [program],
    });
    try {
      assert.equal(result.failure, undefined);
      assert.equal(
        result.requests.some((request) => request.method === "DELETE"),
        false,
      );
      const output = JSON.parse(await readFile(result.output, "utf8"))[program.id];
      assert.equal(output.steps.delete.code, "indeterminate");
      assert.equal(output.steps["after-delete"].code, "not-run");
      assert.equal(output.conditionEvidence, "indeterminate");
      assert.ok(result.requests.some((request) => request.pathname.endsWith("/documents:commit")));
      assert.equal(
        result.snapshot.get(name.replaceAll("DELETE_RUN_ID", defaultDeleteRunId)).deleted,
        true,
      );
    } finally {
      await rm(result.directory, { recursive: true, force: true });
    }
  }
});

test("candidate DELETE condition evidence requires fresh typed absence and an empty group", async () => {
  const name = allV3Names[6];
  const values = Array.from({ length: 12_112 }, (_, index) => ({ integerValue: String(index) }));
  const collectionId = name.split("/documents/")[1].split("/")[0];
  const program = {
    id: "writes/limits/near-limit-delete-refusal/rest/12112",
    steps: [
      {
        id: "seed",
        method: "POST",
        path: "/v1/projects/PROJECT/databases/(default)/documents:commit",
        body: { writes: [{ update: { name, fields: { a: { arrayValue: { values } } } } }] },
      },
      { id: "before-delete", method: "GET", path: `/v1/${name}` },
      { id: "delete", method: "DELETE", path: `/v1/${name}` },
      {
        id: "after-delete",
        method: "POST",
        path: "/v1/projects/PROJECT/databases/(default)/documents:batchGet",
        body: { documents: [name] },
      },
      {
        id: "group-after-delete",
        method: "POST",
        path: "/v1/projects/PROJECT/databases/(default)/documents:runQuery",
        body: {
          structuredQuery: {
            from: [{ collectionId, allDescendants: true }],
            select: { fields: [{ fieldPath: "__name__" }] },
            limit: 2,
          },
        },
      },
    ],
  };
  for (const failureMode of [undefined, "candidate-refused"]) {
    const result = await observeCollector({
      scopeNames: allV3Names,
      visibleNames: allV3Names,
      failureMode,
      programs: [program],
    });
    try {
      assert.equal(result.failure, undefined);
      const output = JSON.parse(await readFile(result.output, "utf8"))[program.id];
      assert.equal(output.conditionEvidence, "complete");
    } finally {
      await rm(result.directory, { recursive: true, force: true });
    }
  }
  for (const failureMode of [
    "candidate-post-untyped",
    "candidate-group-nonempty",
    "candidate-wrong-refusal",
  ]) {
    const result = await observeCollector({
      scopeNames: allV3Names,
      visibleNames: allV3Names,
      failureMode,
      programs: [program],
    });
    try {
      assert.equal(result.failure, undefined);
      const output = JSON.parse(await readFile(result.output, "utf8"))[program.id];
      assert.equal(output.conditionEvidence, "indeterminate");
      assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "complete");
      assert.equal(
        result.snapshot.get(name.replaceAll("DELETE_RUN_ID", defaultDeleteRunId)).deleted,
        true,
      );
    } finally {
      await rm(result.directory, { recursive: true, force: true });
    }
  }
});

test("corpus-v3 recovery resumes only the journaled twelve names without replaying recipes", async () => {
  const runId = "e".repeat(32);
  const runtimeNames = allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status: "deleting",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    names: runtimeNames,
    deletedNames: [],
    deleteIntent: {
      action: "delete attempt",
      name: runtimeNames[0],
      updateTime: "t0",
      priorDeletedNames: [],
    },
  };
  const result = await observeCollector({
    scopeNames: allV3Names,
    visibleNames: allV3Names,
    deleteRunId: runId,
    initialJournal: journal,
    recoveryMode: "recover-v3",
  });
  try {
    assert.equal(result.failure, undefined);
    const finalJournal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.equal(finalJournal.status, "complete");
    assert.equal(finalJournal.runId, runId);
    assert.deepEqual(finalJournal.names, runtimeNames);
    assert.deepEqual(finalJournal.verifiedAbsentNames, runtimeNames);
    for (const name of runtimeNames) assert.equal(result.snapshot.get(name).deleted, true);
    assert.equal(
      result.requests.some((request) => request.method === "DELETE"),
      false,
    );
    assert.ok(result.requests.every((request) => !request.pathname.includes("emulator/v1")));
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 recovery resolves a write-ahead intent when the target is already absent", async () => {
  const runId = "f".repeat(32);
  const runtimeNames = allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status: "deleting",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    names: runtimeNames,
    deletedNames: [],
    deleteIntent: {
      action: "delete attempt",
      name: runtimeNames[0],
      updateTime: "t0",
      priorDeletedNames: [],
    },
  };
  const result = await observeCollector({
    scopeNames: allV3Names,
    visibleNames: runtimeNames.slice(1),
    initialState: new Map([[runtimeNames[0], { deleted: true }]]),
    deleteRunId: runId,
    initialJournal: journal,
    recoveryMode: "recover-v3",
  });
  try {
    assert.equal(result.failure, undefined);
    const finalJournal = JSON.parse(await readFile(result.journal, "utf8"));
    assert.equal(finalJournal.status, "complete");
    assert.ok(finalJournal.deletedNames.includes(runtimeNames[0]));
    for (const request of result.requests.filter((entry) =>
      entry.pathname.endsWith("/documents:commit"),
    )) {
      const writes = JSON.parse(request.body).writes;
      assert.ok(
        writes.every((write) => (write.delete ?? write.transform?.document) !== runtimeNames[0]),
      );
    }
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 recovery stops on a foreign group member before any mutation", async () => {
  const runId = "9".repeat(32);
  const runtimeNames = allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status: "prepared",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    names: runtimeNames,
    deletedNames: [],
    deleteIntent: null,
  };
  const result = await observeCollector({
    scopeNames: allV3Names,
    visibleNames: allV3Names,
    failureMode: "preflight-second",
    deleteRunId: runId,
    initialJournal: journal,
    recoveryMode: "recover-v3",
  });
  try {
    assert.match(String(result.failure), /unexpected collection-group document/);
    assert.equal(
      result.requests.some((request) => {
        if (!request.pathname.endsWith("/documents:commit")) return false;
        return JSON.parse(request.body).writes.some((write) => write.delete || write.transform);
      }),
      false,
    );
    assert.notEqual(JSON.parse(await readFile(result.journal, "utf8")).status, "complete");
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 recovery refuses nested child collections before any mutation", async () => {
  const runId = "a".repeat(32);
  const runtimeNames = allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status: "prepared",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    names: runtimeNames,
    deletedNames: [],
    deleteIntent: null,
  };
  const result = await observeCollector({
    scopeNames: allV3Names,
    visibleNames: allV3Names,
    childCollectionNames: [runtimeNames[0].split("/documents/")[1].split("/")[0]],
    deleteRunId: runId,
    initialJournal: journal,
    recoveryMode: "recover-v3",
  });
  try {
    assert.match(String(result.failure), /child collection/);
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith("/documents:commit")),
      false,
    );
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "recovering");
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("corpus-v3 recovery detects a child collection under an absent frozen parent before mutation", async () => {
  const runId = "b".repeat(32);
  const runtimeNames = allV3Names.map((name) => name.replaceAll("DELETE_RUN_ID", runId));
  const orphanedName = runtimeNames[0];
  const journal = {
    schemaVersion: 1,
    mode: "cleanup-corpus-v3",
    status: "deleting",
    project: "fireemu-oracle-sbx",
    database: "(default)",
    runId,
    corpusDigest: "c".repeat(64),
    sourceGitSha: "d".repeat(40),
    names: runtimeNames,
    deletedNames: [orphanedName],
    deleteIntent: null,
  };
  const result = await observeCollector({
    scopeNames: allV3Names,
    visibleNames: runtimeNames.slice(1),
    initialState: new Map([[orphanedName, { deleted: true }]]),
    childCollectionNames: [orphanedName.split("/documents/")[1].split("/")[0]],
    deleteRunId: runId,
    initialJournal: journal,
    recoveryMode: "recover-v3",
  });
  try {
    assert.match(String(result.failure), /child collection/);
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith("/documents:commit")),
      false,
    );
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "recovering");
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

test("v3 remote host is blocked before any production request", async () => {
  const result = await observeCollector({ hostOverride: "localhost:8080" });
  try {
    assert.match(result.failure?.stderr ?? "", /generic broad clear is disabled/);
    assert.equal(result.requests.length, 0);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});
