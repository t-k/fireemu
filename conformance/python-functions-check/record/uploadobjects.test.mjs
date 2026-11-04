// The deploy's own upload object: named by the generateUploadUrl answer in the CLI log, adopted by that name, deleted once by
// generation, read back; any other new object in the upload bucket is reported and keeps the cleanup unverified. The sources
// bucket (the build's copies) is inventory only.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  putClass,
  uploadEventFromLine,
  uploadEventsFromCliOutput,
  withUploadEvents,
} from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import { isOwnUploadObject, sourceBuckets, uploadBucket } from "./plan.mjs";
import { readbackRun, uploadObjectEntries } from "./readback.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const [UPLOADS, SOURCES] = sourceBuckets(NUMBER);
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send, options = {}) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: wrapSend(world.send, world),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...options,
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const path = (request) => new URL(request.url).pathname;
const RECORDED = readFileSync(
  new URL("../../src/shared/fixtures/gen2-debug-lines.2026-10-26.txt", import.meta.url),
  "utf8",
);
const [RECEIPT_LINE, PUT_LINE] = RECORDED.trimEnd().split("\n");

test("which names may be adopted: a plain object name in this project's upload bucket, nothing else", () => {
  assert.equal(uploadBucket(NUMBER), UPLOADS);
  for (const name of [
    "a",
    "a1b2.zip",
    "514cacbe-3258-46fd-9a02-54b7485b11c1.zip",
    "A_b-c.d",
    "a".repeat(255),
  ])
    assert.equal(isOwnUploadObject(NUMBER, UPLOADS, name), true, name);
  for (const name of [
    "",
    ".hidden",
    "-dash.zip",
    "x/y.zip",
    "/abs.zip",
    "a/../b.zip",
    "has space.zip",
    "a\nb",
    "a".repeat(256),
    undefined,
    null,
    5,
    "é.zip",
  ])
    assert.equal(isOwnUploadObject(NUMBER, UPLOADS, name), false, String(name));
  assert.equal(isOwnUploadObject(NUMBER, SOURCES, "pcps/function-source.zip"), false);
  assert.equal(isOwnUploadObject(NUMBER, SOURCES, "a.zip"), false);
  assert.equal(isOwnUploadObject(NUMBER, "someone-elses-bucket", "a.zip"), false);
  assert.equal(isOwnUploadObject("999999999999", UPLOADS, "a.zip"), false);
});

test("an object can be read or deleted only after the run adopted it, only in the upload bucket, only by generation", () => {
  const g = createGuard(RUN, NUMBER);
  const url = (bucket, name, query = "") =>
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}${query}`;
  const gen = "?ifGenerationMatch=1760000000000001";
  for (const method of ["GET", "DELETE"])
    assert.equal(
      g.allow({ method, url: url(UPLOADS, "a.zip", method === "DELETE" ? gen : "") }),
      false,
    );
  assert.equal(g.adoptObject(UPLOADS, "a.zip"), true);
  assert.equal(
    g.adoptObject(SOURCES, "pcps/function-source.zip"),
    false,
    "the sources bucket is never adopted",
  );
  assert.equal(g.adoptObject("another-bucket", "a.zip"), false);
  assert.equal(g.adoptObject(UPLOADS, "x/y.zip"), false);
  assert.deepEqual(g.adoptedObjects(), [`${UPLOADS}/a.zip`]);
  assert.equal(g.allow({ method: "GET", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(
    g.allow({ method: "GET", url: url(UPLOADS, "a.zip", "?fields=bucket,name,generation") }),
    true,
  );
  assert.equal(g.allow({ method: "GET", url: url(UPLOADS, "a.zip", "?fields=media") }), false);
  assert.equal(g.allow({ method: "GET", url: url(UPLOADS, "a.zip", "?alt=media") }), false);
  assert.equal(g.isMutation({ method: "GET", url: url(UPLOADS, "a.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip", gen) }), true);
  assert.equal(g.isMutation({ method: "DELETE", url: url(UPLOADS, "a.zip", gen) }), true);
  assert.equal(
    g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip") }),
    false,
    "a delete without a generation",
  );
  assert.equal(
    g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip", "?ifGenerationMatch=x") }),
    false,
  );
  assert.equal(
    g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip", "?ifGenerationMatch=") }),
    false,
  );
  assert.equal(
    g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip", gen + "&generation=1") }),
    false,
    "no other query key",
  );
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "b.zip", gen) }), false);
  assert.equal(
    g.allow({ method: "DELETE", url: url(SOURCES, "pcps/function-source.zip", gen) }),
    false,
  );
  assert.equal(g.allow({ method: "GET", url: url(SOURCES, "pcps/function-source.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip", gen), json: {} }), false);
  assert.equal(g.allow({ method: "PATCH", url: url(UPLOADS, "a.zip", gen), json: {} }), false);
  assert.equal(
    g.allow({
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${UPLOADS}/o/a.zip%${gen}`,
    }),
    false,
  );
  assert.equal(
    g.allow({
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${UPLOADS}/o/a/b.zip${gen}`,
    }),
    false,
    "an unencoded slash is another route",
  );
});

test("the recorded production lines parse to the receipt and the PUT status, and the signed URL is never kept", () => {
  const receipt = uploadEventFromLine(RECEIPT_LINE);
  assert.equal(receipt.type, "receipt");
  assert.equal(
    receipt.bucket,
    "gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com",
  );
  assert.equal(receipt.object, "514cacbe-3258-46fd-9a02-54b7485b11c1.zip");
  assert.deepEqual(Object.keys(receipt).toSorted(), ["bucket", "object", "type"]);
  assert.deepEqual(uploadEventFromLine(PUT_LINE), {
    type: "put-status",
    bucket: receipt.bucket,
    object: receipt.object,
    status: 200,
  });
  const signed =
    '[2026-10-26T18:25:00.891Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions:generateUploadUrl {"uploadUrl":"https://storage.googleapis.com/b/o.zip?X-Goog-Signature=SECRET","storageSource":{"bucket":"b","object":"o.zip"}}';
  assert.equal(JSON.stringify(uploadEventFromLine(signed)).includes("SECRET"), false);
  assert.deepEqual(
    uploadEventsFromCliOutput(["noise", RECEIPT_LINE, "more", PUT_LINE].join("\r\n")),
    [receipt, uploadEventFromLine(PUT_LINE)],
  );
  for (const line of [
    "",
    "<<< [apiv2][body] POST https://x/functions:generateUploadUrl not-json",
    '<<< [apiv2][body] POST https://x/functions:generateUploadUrl {"uploadUrl":"https://storage.googleapis.com/b/o.zip"}',
    '<<< [apiv2][body] POST https://x/functions:generateUploadUrl {"storageSource":{"bucket":1,"object":"o"}}',
    '<<< [apiv2][body] GET https://x/functions:generateUploadUrl {"storageSource":{"bucket":"b","object":"o"}}',
    ">>> [apiv2][status] PUT https://storage.googleapis.com/b/o.zip 200",
    "<<< [apiv2][status] GET https://storage.googleapis.com/b/o.zip 200",
    "<<< [apiv2][status] PUT https://example.com/b/o.zip 200",
    "<<< [apiv2][status] PUT https://storage.googleapis.com/b/o.zip 20",
  ])
    assert.equal(uploadEventFromLine(line), null, line);
});

test("the upload class of a PUT: confirmed by a 2xx, refused only by definite 4xx answers, unknown otherwise", () => {
  assert.equal(putClass([200]), "confirmed");
  assert.equal(putClass([503, 200]), "confirmed");
  assert.equal(putClass([204]), "confirmed");
  assert.equal(putClass([403]), "refused");
  assert.equal(putClass([400, 403]), "refused");
  assert.equal(putClass([]), "unknown");
  assert.equal(putClass([503]), "unknown");
  assert.equal(putClass([503, 400]), "unknown");
  assert.equal(putClass([408]), "unknown");
  assert.equal(putClass([429]), "unknown");
  assert.equal(putClass([499]), "unknown");
  assert.equal(putClass([302]), "unknown");
  assert.equal(putClass([199]), "unknown");
  assert.equal(putClass([300]), "unknown");
  assert.equal(putClass([399]), "unknown");
  assert.equal(putClass([400]), "refused");
  assert.equal(putClass([499 - 1]), "refused");
  assert.equal(putClass([500]), "unknown");
});

test("the CLI result carries the events of the deploy's stdout file, and nothing for another action or an unreadable file", () => {
  const directory = mkdtempSync(join(tmpdir(), "pcu-"));
  try {
    writeFileSync(join(directory, "cli-deploy-stdout.txt"), [RECEIPT_LINE, PUT_LINE].join("\n"));
    const result = { action: "deploy", exitCode: 0 };
    const withEvents = withUploadEvents(result, directory);
    assert.equal(withEvents.exitCode, 0);
    assert.equal(withEvents.uploadEvents.length, 2);
    assert.deepEqual(withUploadEvents({ action: "delete" }, directory), { action: "delete" });
    assert.deepEqual(withUploadEvents({ action: "dry-run" }, directory), { action: "dry-run" });
    assert.equal(withUploadEvents(result, join(directory, "missing")).uploadEvents, null);
    assert.equal(withUploadEvents(undefined, directory), undefined);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a clean run deletes the one object the receipt named, once, by generation, reads it back, and leaves the build's copies", async () => {
  const { result, world, journal } = await go();
  const deleted = result.cleanup.uploadObjectsDeleted;
  assert.equal(deleted.length, 1);
  assert.equal(deleted[0].bucket, UPLOADS);
  assert.equal(deleted[0].name, world.upload);
  assert.equal(deleted[0].class, "2xx");
  assert.equal(deleted[0].status, 204);
  assert.deepEqual(deleted[0].putStatuses, [200]);
  assert.equal(deleted[0].generation, world.generations.get(UPLOADS + "/" + world.upload));
  assert.deepEqual(
    world.sourceBuckets.get(UPLOADS),
    ["old-upload.zip"],
    "the object that was there stays, the receipt's is gone",
  );
  assert.equal(world.sourceBuckets.get(SOURCES).length, 13, "the build's copies stay");
  const deletes = journal.filter(
    (r) => r.state === "before-send" && r.id.startsWith("delete-upload-object"),
  );
  assert.equal(deletes.length, 1);
  assert.match(deletes[0].url, new RegExp(`\\?ifGenerationMatch=${deleted[0].generation}$`));
  assert.equal(new Set(ids(journal)).size, ids(journal).length);
  assert.equal(result.cleanup.readBack["upload-object-1"], true);
  const order = ids(journal);
  assert.ok(
    order.indexOf("upload-object-1-metadata") >
      order.indexOf("delete-package-fireemu--oracle--events__us--central1__pcea%2Fcache"),
  );
  assert.ok(order.indexOf("delete-upload-object-1") > order.indexOf("upload-object-1-metadata"));
  assert.ok(
    order.indexOf("readback-gone-upload-object-1") > order.indexOf("delete-upload-object-1"),
  );
  assert.deepEqual(result.cleanup.uploadObjectsUnexplained, []);
  assert.deepEqual(result.cleanup.uploadReasons, []);
  assert.deepEqual(result.inventory.sourceObjects.uploads, { added: [], removed: [] });
  assert.equal(result.inventory.sourceObjects.sources.added.length, 13);
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, true);
  assert.equal(result.outcome, "pycheck-recorded");
});

test("an object that was in the bucket before the run stays, and the receipt's one is still the only delete", async () => {
  const world = createWorld({ runId: RUN });
  world.sourceBuckets.get(UPLOADS).push("older-upload.zip");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.deepEqual(world.sourceBuckets.get(UPLOADS), ["old-upload.zip", "older-upload.zip"]);
  assert.equal(result.cleanup.uploadObjectsDeleted.length, 1);
  assert.equal(result.outcome, "pycheck-recorded");
});

test("any other new object in the upload bucket is left, reported, and keeps the cleanup unverified", async () => {
  for (const name of ["someone-elses.zip", "has space.zip", "x/y.zip"]) {
    const { result, world } = await go({}, (send, w) => async (request) => {
      if (
        request.method === "GET" &&
        path(request).endsWith("/o") &&
        request.url.includes("gcf-v2-uploads") &&
        w.cliRuns.includes("deploy") &&
        !w.sourceBuckets.get(UPLOADS).includes(name)
      )
        w.sourceBuckets.get(UPLOADS).push(name);
      return send(request);
    });
    assert.deepEqual(result.cleanup.uploadObjectsUnexplained, [{ bucket: UPLOADS, name }]);
    assert.ok(world.sourceBuckets.get(UPLOADS).includes(name), "never deleted");
    assert.equal(
      result.cleanup.uploadObjectsDeleted.length,
      1,
      "the receipt's object is still deleted",
    );
    assert.equal(result.cleanup.verified, false);
    assert.equal(result.outcome, "pycheck-needs-recovery");
    assert.equal(result.closureReady, false);
  }
});

test("a new object in the sources bucket is inventory only: never read by name, never deleted, never blocks", async () => {
  const { result, world, journal } = await go({}, (send, w) => async (request) => {
    if (
      request.method === "GET" &&
      path(request).endsWith("/o") &&
      request.url.includes("gcf-v2-sources") &&
      w.cliRuns.includes("deploy") &&
      !w.sourceBuckets.get(SOURCES).includes("pcps/older.zip")
    )
      w.sourceBuckets.get(SOURCES).push("pcps/older.zip");
    return send(request);
  });
  assert.ok(world.sourceBuckets.get(SOURCES).includes("pcps/older.zip"));
  assert.equal(result.inventory.sourceObjects.sources.added.length, 14);
  assert.ok(
    !journal.some(
      (r) => r.state === "before-send" && r.url?.includes("gcf-v2-sources") && r.method !== "GET",
    ),
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.outcome, "pycheck-recorded");
});

test("a deploy that printed no receipt is reported: its object is unexplained and nothing is deleted by guesswork", async () => {
  const { result, world } = await go({ uploadLines: "none" });
  assert.deepEqual(result.cleanup.uploadReasons, ["no-receipt"]);
  assert.equal(result.cleanup.uploadObjectsDeleted.length, 0);
  assert.equal(result.cleanup.uploadObjectsUnexplained.length, 1);
  assert.ok(world.sourceBuckets.get(UPLOADS).includes(world.upload));
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pycheck-needs-recovery");
});

test("a CLI log that cannot be read, or a CLI that did not end by itself without a receipt, is reported", async () => {
  for (const [patch, reason] of [
    [{ uploadEvents: null }, "receipt-log-unreadable"],
    [{ exitCode: null, signal: "SIGKILL", uploadEvents: [] }, "killed-without-receipt"],
    [{ exitCode: null, timedOut: true, uploadEvents: [] }, "killed-without-receipt"],
    [{ exitCode: null, error: "boom", uploadEvents: [] }, "killed-without-receipt"],
    [{ exitCode: 0, uploadEvents: [] }, "no-receipt"],
  ]) {
    const world = createWorld({ runId: RUN, uploadLines: "none" });
    const result = await record({
      runId: RUN,
      projectNumber: NUMBER,
      accessToken: "tok-abcdefgh",
      save: async () => {},
      send: world.send,
      runCli: async (args) => {
        const r = await world.runCli(args);
        return args.action === "deploy" ? { ...r, ...patch } : r;
      },
      clock: () => world.now,
      sleep: async (ms) => world.advance(ms),
    });
    assert.ok(result.cleanup.uploadReasons.includes(reason), reason + JSON.stringify(patch));
    assert.equal(result.cleanup.uploadObjectsDeleted.length, 0);
    assert.equal(result.cleanup.verified, false);
  }
  // A failed deploy (exit 1, no receipt) made no upload that anyone saw: nothing to report.
  const world = createWorld({ runId: RUN, uploadLines: "none", failDeploy: true });
  const failed = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.deepEqual(failed.cleanup.uploadReasons, []);
});

test("a refused upload PUT made nothing: the receipt is not deleted and nothing is unexplained", async () => {
  const { result, world } = await go({ uploadLines: "refused" });
  assert.equal(world.upload !== null, true);
  assert.deepEqual(result.cleanup.uploadObjectsDeleted, []);
  assert.deepEqual(result.cleanup.uploadObjectsUnexplained, []);
  assert.deepEqual(result.cleanup.uploadReasons, []);
  assert.equal(result.cleanup.verified, true);
});

test("a receipt for an object nobody made is unconfirmed: reported, not deleted, the run does not close", async () => {
  const { result } = await go({ uploadLines: "extra" });
  assert.deepEqual(result.cleanup.uploadReasons, [
    "receipt-unconfirmed:99999999-0000-0000-0000-000000000000.zip",
  ]);
  assert.equal(result.cleanup.uploadObjectsDeleted.length, 1);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pycheck-needs-recovery");
});

test("a delete that did not take effect leaves the object to recover; an unknown delete is never re-sent and keeps the run open", async () => {
  let hit = 0;
  const refused = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("gcf-v2-uploads") && hit++ === 0)
      return error(500, "INTERNAL");
    return send(request);
  });
  assert.equal(refused.result.cleanup.readBack["upload-object-1"], false);
  assert.equal(refused.result.cleanup.verified, false);
  assert.equal(refused.result.outcome, "pycheck-needs-recovery");
  assert.equal(refused.result.unknownMutations, 1);
  assert.equal(ids(refused.journal).filter((id) => id === "delete-upload-object-1").length, 1);
  let sent = 0;
  const took = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("gcf-v2-uploads") && sent++ === 0) {
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.equal(took.result.closureReady, false);
  assert.equal(took.result.readBackRequired, true);
  assert.equal(
    took.result.vanishedAfterCreate.length,
    0,
    "the object was never confirmed as a create, so it is not 'vanished'",
  );
  const refused4xx = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("gcf-v2-uploads")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(refused4xx.result.outcome, "pycheck-auth-stop", "a 403 on a write is a stop");
});

test("a generation that moved between the read and the delete is refused by the precondition and the object stays", async () => {
  const { result, world } = await go({}, (send, w) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("gcf-v2-uploads"))
      w.generations.set(UPLOADS + "/" + w.upload, "42");
    return send(request);
  });
  assert.equal(result.cleanup.uploadObjectsDeleted[0].status, 412);
  assert.ok(world.sourceBuckets.get(UPLOADS).includes(world.upload));
  assert.equal(result.cleanup.readBack["upload-object-1"], false);
  assert.equal(result.cleanup.verified, false);
  assert.equal(result.outcome, "pycheck-needs-recovery");
});

test("an object that reads 404 or cannot be read when its metadata is asked for is not deleted", async () => {
  const gone = await go({}, (send, w) => async (request) => {
    if (request.method === "GET" && request.url.includes("?fields=bucket,name,generation"))
      w.sourceBuckets.get(UPLOADS).splice(0);
    return send(request);
  });
  assert.equal(gone.result.cleanup.uploadObjectsDeleted.length, 0);
  assert.deepEqual(gone.result.cleanup.uploadReasons, [
    `confirmed-upload-absent:${gone.world.upload}`,
  ]);
  assert.equal(gone.result.cleanup.verified, false);
  const unreadable = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("?fields=bucket,name,generation")
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(unreadable.result.cleanup.uploadObjectsDeleted.length, 0);
  assert.deepEqual(unreadable.result.cleanup.uploadReasons, [
    `object-unreadable:${unreadable.world.upload}`,
  ]);
  const wrong = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("?fields=bucket,name,generation")
        ? reply(200, { bucket: UPLOADS, name: "another.zip", generation: "7" })
        : send(request),
  );
  assert.equal(wrong.result.cleanup.uploadObjectsDeleted.length, 0);
  assert.equal(wrong.result.cleanup.uploadReasons.length, 1);
  const badGeneration = await go(
    {},
    (send) => async (request) =>
      request.method === "GET" && request.url.includes("?fields=bucket,name,generation")
        ? reply(200, {
            bucket: UPLOADS,
            name: request.url.split("/o/")[1].split("?")[0],
            generation: "x1",
          })
        : send(request),
  );
  assert.equal(badGeneration.result.cleanup.uploadObjectsDeleted.length, 0);
  assert.equal(badGeneration.result.cleanup.uploadReasons.length, 1);
});

test("a bucket that cannot be read before the run gives nothing to delete and an incomplete read; paging is followed to five pages", async () => {
  const before = await go({}, (send) => {
    let first = true;
    return async (request) => {
      if (request.method === "GET" && request.url.includes("gcf-v2-uploads") && first) {
        first = false;
        return error(403, "PERMISSION_DENIED");
      }
      return send(request);
    };
  });
  assert.equal(before.result.cleanup.uploadObjectsDeleted.length, 0);
  assert.ok(before.result.cleanup.uploadReasons.includes("upload-baseline-unreadable"));
  assert.equal(before.result.closureReady, false);
  const paged = await go({ sourcePageSize: 5 });
  assert.equal(paged.result.cleanup.uploadObjectsDeleted.length, 1);
  assert.equal(paged.result.cleanup.verified, true);
  const endless = await go({ sourcePageSize: 2 });
  assert.ok(endless.result.incompleteReads.some((r) => r.class === "more-than-five-pages"));
  assert.equal(endless.result.closureReady, false);
  assert.ok(!ids(endless.journal).some((id) => id.endsWith("-page-6")));
});

test("buckets that do not exist give nothing to delete and no incomplete read; a deploy that left no receipt is reported", async () => {
  const { result } = await go({ withSourceBuckets: false });
  assert.deepEqual(result.cleanup.uploadObjectsDeleted, []);
  assert.deepEqual(result.incompleteReads, []);
  assert.deepEqual(result.cleanup.uploadReasons, ["no-receipt"]);
});

test("a failed deploy with no receipt deletes nothing and is not an unexplained upload", async () => {
  const failed = await go({ failDeploy: true });
  assert.deepEqual(failed.result.cleanup.uploadObjectsDeleted, []);
  assert.deepEqual(failed.result.cleanup.uploadReasons, []);
  assert.equal(failed.result.cleanup.verified, true);
});

test("the A2 read-back reads each deleted object by name with its own allowlist, and a leftover is not absent", async () => {
  const { world, result } = await go();
  const base = {
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    bucket: result.bucket,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  };
  const clean = await readbackRun({ ...base, send: world.send });
  assert.equal(clean.allAbsent, true);
  assert.deepEqual(
    Object.keys(clean.names).filter((n) => n.startsWith("upload-object-")),
    ["upload-object-1"],
  );
  world.sourceBuckets.get(UPLOADS).push(result.cleanup.uploadObjectsDeleted[0].name);
  const left = await readbackRun({ ...base, send: world.send });
  assert.equal(left.allAbsent, false);
  assert.deepEqual(
    uploadObjectEntries([
      { bucket: "b", name: "n" },
      { bucket: UPLOADS },
      null,
      { name: "x" },
      "s",
      { bucket: 1, name: 2 },
    ]),
    [{ bucket: "b", name: "n" }],
  );
  assert.deepEqual(uploadObjectEntries(undefined), []);
});

test("a bucket listing of exactly five pages is read to its end and is not flagged", async () => {
  const world = createWorld({ runId: RUN, sourcePageSize: 4 });
  for (let i = 0; i < 16; i++) world.sourceBuckets.get(UPLOADS).push(`older-${i}.zip`);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.ok(ids(journal).includes("cleanup-source-objects-uploads-page-5"));
  assert.ok(!ids(journal).includes("cleanup-source-objects-uploads-page-6"));
  assert.ok(
    !result.incompleteReads.some((r) => r.class === "more-than-five-pages"),
    JSON.stringify(result.incompleteReads),
  );
  assert.equal(result.cleanup.uploadObjectsDeleted.length, 1);
});
