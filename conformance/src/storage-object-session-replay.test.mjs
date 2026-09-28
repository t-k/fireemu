import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { replayLocalSessions } from "./storage-object/session-replay.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  dialect = "firebase",
  failChunk = false,
  cancellationUnsupported = false,
  uncertainFinish = false,
} = {}) {
  const bucket = "example.appspot.com",
    origin = "http://127.0.0.1:9199";
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket,
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
    (row) => row.id === `storage-object/${dialect}/resumable-upload`,
  );
  const sessions = new Map(),
    objects = new Map(),
    captures = [],
    deleted = [],
    reservations = [];
  const sender = createLocalStorageSender({
    plan,
    origin,
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async (row) => reservations.push(row),
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href),
        id = url.searchParams.get("upload_id");
      if (id) {
        const session = sessions.get(id);
        assert.ok(session);
        const command = init.headers["x-goog-upload-command"];
        if (init.method === "DELETE" || command === "cancel") {
          if (cancellationUnsupported) return new Response(null, { status: 501 });
          if (!session.done) {
            session.cancelled = true;
            session.chunks = [];
          }
          return new Response(null, { status: dialect === "gcs" ? 499 : 200 });
        }
        const query = command === "query" || init.headers["content-range"]?.startsWith("bytes */");
        const received = session.chunks.reduce((sum, bytes) => sum + bytes.length, 0);
        if (query)
          return dialect === "firebase"
            ? new Response(null, {
                status: 200,
                headers: {
                  "x-goog-upload-status": session.cancelled
                    ? "cancelled"
                    : session.done
                      ? "final"
                      : "active",
                  "x-goog-upload-size-received": `${received}`,
                },
              })
            : session.cancelled
              ? new Response(null, { status: 400 })
              : session.done
                ? Response.json(objects.get(session.name).metadata)
                : new Response(null, {
                    status: 308,
                    headers: received ? { range: `bytes=0-${received - 1}` } : {},
                  });
        if (failChunk) throw new Error(`failed fetch ${href}`);
        if (command === "upload" && init.headers["x-goog-upload-offset"] === "1")
          return new Response(null, { status: 400 });
        session.chunks.push(Buffer.from(init.body));
        const finish =
          command === "upload, finalize" ||
          init.headers["content-range"] === "bytes 262144-262146/262147";
        if (finish) {
          session.done = true;
          const bytes = Buffer.concat(session.chunks);
          const metadata = {
            kind: "storage#object",
            bucket,
            name: session.name,
            generation: "9007199254740993",
            metageneration: "1",
            size: `${bytes.length}`,
          };
          objects.set(session.name, { bytes, metadata });
          if (uncertainFinish) throw new Error(`failed finalize ${href}`);
          return Response.json(metadata, {
            headers: dialect === "firebase" ? { "x-goog-upload-status": "final" } : {},
          });
        }
        return new Response(null, {
          status: dialect === "firebase" ? 200 : 308,
          headers:
            dialect === "firebase"
              ? { "x-goog-upload-status": "active" }
              : { range: "bytes=0-262143" },
        });
      }
      if (init.method === "POST") {
        const name = url.searchParams.get("name"),
          sessionId = `private_session_${sessions.size}`;
        sessions.set(sessionId, { name, chunks: [], done: false, cancelled: false });
        const uri = `${origin}${url.pathname}?name=${encodeURIComponent(name)}&${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable&upload_id=${sessionId}`;
        return new Response(null, {
          status: 200,
          headers:
            dialect === "firebase"
              ? { "x-goog-upload-status": "active", "x-goog-upload-url": uri }
              : { location: uri },
        });
      }
      if (url.pathname === `/storage/v1/b/${bucket}/o`)
        return Response.json({
          items: [...objects.values()]
            .map((row) => row.metadata)
            .filter((row) => row.name.startsWith(url.searchParams.get("prefix"))),
        });
      const name = decodeURIComponent(url.pathname.split("/o/")[1]),
        object = objects.get(name);
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (init.method === "DELETE") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
        deleted.push(name);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      return url.searchParams.get("alt") === "media"
        ? new Response(object.bytes)
        : Response.json(object.metadata);
    },
  });
  return {
    sender,
    sessions,
    objects,
    captures,
    deleted,
    reservations,
    run: () =>
      replayLocalSessions({ sender, recipe, bucket, onCapture: async (row) => captures.push(row) }),
  };
}

test("Firebase completion, wrong offset and cancellation finish with owned cleanup", async () => {
  const run = fixture();
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(run.deleted.length, 1);
  assert.equal(run.objects.size, 0);
  assert.deepEqual(result.unresolved, []);
  assert.equal([...run.sessions.values()].filter((row) => row.cancelled).length, 2);
  assert.equal(result.requests, run.reservations.length);
  assert.equal(JSON.stringify(result).includes("private_session"), false);
});
test("GCS exact progress completes without cancelling a confirmed completed session", async () => {
  const run = fixture({ dialect: "gcs" });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(run.deleted.length, 1);
  assert.equal(run.objects.size, 0);
  assert.deepEqual(result.unresolved, []);
});
test("unsupported GCS cancellation retains the active session even when the object is absent", async () => {
  const run = fixture({ dialect: "gcs", failChunk: true, cancellationUnsupported: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(run.deleted.length, 0);
  assert.equal(result.unresolved.length, 1);
  assert.equal(JSON.stringify(result).includes("private_session"), false);
});
test("a lost finish reply cannot authorize deleting the unconfirmed published object", async () => {
  const run = fixture({ uncertainFinish: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(run.deleted.length, 0);
  assert.equal(run.objects.size, 1);
  assert.equal(result.unresolved.length, 1);
  assert.equal(JSON.stringify(result).includes("private_session"), false);
});
