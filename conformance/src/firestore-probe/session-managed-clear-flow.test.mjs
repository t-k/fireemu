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
const names = ["g500a", "g500b", "g2000a", "g2000b", "g1000a", "g1000b"].map(
  (collection) => `${prefix}${collection}/d`,
);
const operation = "projects/fireemu-oracle-sbx/databases/(default)/operations/test_1";

async function observeCollector({ unexpectedGroupDocument, operationError, initialJournalStatus }) {
  const directory = await mkdtemp(join(tmpdir(), "fireemu-managed-flow-"));
  const input = join(directory, "programs.json");
  const output = join(directory, "results.json");
  const meta = join(directory, "meta.json");
  const journal = join(directory, "managed.json");
  await writeFile(input, JSON.stringify([{ id: "empty", steps: [] }]));
  if (initialJournalStatus)
    await writeFile(journal, JSON.stringify({ status: initialJournalStatus }));
  const requests = [];
  let deleted = false;
  let journalAtStart;
  let journalAtPoll;
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
      send(200, { collectionIds: deleted ? [] : ["g500a"] });
    } else if (pathname.endsWith("/documents/g500a")) {
      send(200, { documents: [{ name: names[0], createTime: "2026-01-01T00:00:00Z" }] });
    } else if (pathname.endsWith("/documents/g500a/d:listCollectionIds")) {
      send(200, {});
    } else if (pathname.endsWith("/documents:commit")) {
      send(400, {
        error: {
          status: "INVALID_ARGUMENT",
          message: "Transaction too big. Decrease transaction size.",
        },
      });
    } else if (pathname.endsWith("/documents:runQuery")) {
      send(
        200,
        deleted
          ? []
          : [
              { document: { name: names[0] } },
              ...(unexpectedGroupDocument ? [{ document: { name: `${prefix}g500a/other` } }] : []),
            ],
      );
    } else if (pathname.endsWith(":bulkDeleteDocuments")) {
      journalAtStart = JSON.parse(await readFile(journal, "utf8"));
      send(200, { name: operation });
    } else if (pathname.endsWith(`/v1/${operation}`)) {
      journalAtPoll = JSON.parse(await readFile(journal, "utf8"));
      deleted = !operationError;
      send(200, {
        name: operation,
        done: true,
        ...(operationError ? { error: { message: "failed" } } : {}),
      });
    } else if (pathname.endsWith("/documents:batchGet")) {
      send(200, [{ missing: names[0] }]);
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
        FIRESTORE_PROBE_MAX_REQUESTS: "40",
        FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(names),
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
  const observed = {
    directory,
    input,
    output,
    meta,
    journal,
    requests,
    journalAtStart,
    journalAtPoll,
    failure,
  };
  return observed;
}

test("collector journals scope then operation and verifies typed absence", async () => {
  const result = await observeCollector({ unexpectedGroupDocument: false });
  try {
    assert.equal(result.failure, undefined);
    assert.equal(result.journalAtStart.status, "starting");
    assert.equal(result.journalAtPoll.status, "active");
    assert.equal(result.journalAtPoll.operation, operation);
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "complete");
    assert.deepEqual(JSON.parse(await readFile(result.output, "utf8")), { empty: { steps: {} } });
    assert.equal(
      result.requests.filter((request) => request.pathname.endsWith(":bulkDeleteDocuments")).length,
      1,
    );
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("unexpected document in collection group prevents managed deletion and output", async () => {
  const result = await observeCollector({ unexpectedGroupDocument: true });
  try {
    assert.ok(result.failure);
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith(":bulkDeleteDocuments")),
      false,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
    assert.ok(JSON.parse(await readFile(result.meta, "utf8")).requestCount > 0);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("failed operation remains journaled and never reads back or writes output", async () => {
  const result = await observeCollector({ operationError: true });
  try {
    assert.ok(result.failure);
    assert.equal(JSON.parse(await readFile(result.journal, "utf8")).status, "active");
    assert.equal(
      result.requests.some((request) => request.pathname.endsWith("/documents:batchGet")),
      false,
    );
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test("an unfinished journal prevents another recording before any network send", async () => {
  const result = await observeCollector({ initialJournalStatus: "active" });
  try {
    assert.ok(result.failure);
    assert.equal(result.requests.length, 0);
    await assert.rejects(readFile(result.output), /ENOENT/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});
