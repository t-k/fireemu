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
  uriName = "own",
  recordedShapes = false,
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
          return new Response(null, {
            status: dialect === "gcs" ? 499 : 200,
            // Production (probe-v4): a Firebase cancel says `cancelled`, in a text/plain answer.
            ...(recordedShapes && dialect === "firebase"
              ? {
                  headers: {
                    "content-type": "text/plain; charset=utf-8",
                    "x-goog-upload-status": "cancelled",
                  },
                }
              : {}),
          });
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
                  // Production (probe-v4): an active session also says its chunk granularity, and a
                  // cancelled one says no size.
                  ...(recordedShapes && session.cancelled
                    ? {}
                    : { "x-goog-upload-size-received": `${received}` }),
                  ...(recordedShapes && !session.cancelled && !session.done
                    ? { "x-goog-upload-chunk-granularity": "262144" }
                    : {}),
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
          return recordedShapes
            ? new Response("Client uploaded to the wrong offset (1 instead of 0).", {
                status: 400,
                headers: { "content-type": "text/plain; charset=utf-8" },
              })
            : new Response(null, { status: 400 });
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
        const uriNames = {
          own: `name=${encodeURIComponent(name)}&`,
          missing: "",
          other: `name=${encodeURIComponent(`${name}-other`)}&`,
        };
        const uri = `${origin}${url.pathname}?${uriNames[uriName]}${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable&upload_id=${sessionId}`;
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

test("a session URL that lacks the initiate's name, or names another object, is refused before any chunk", async () => {
  for (const dialect of ["firebase", "gcs"])
    for (const uriName of ["missing", "other"]) {
      const run = fixture({ dialect, uriName });
      const result = await run.run();
      // The server opened a session the sender cannot address, so the run cannot call it clean.
      assert.equal(result.status, "LOCAL_NEEDS_RECOVERY", `${dialect} ${uriName}`);
      assert.equal(result.failure.reason, "LOCAL_SESSION_REQUEST_OR_PROOF_FAILED");
      assert.equal(result.unresolved.length, 1);
      assert.ok([...run.sessions.values()].every((row) => row.chunks.length === 0));
      assert.equal(JSON.stringify(result).includes("private_session"), false);
    }
});

test("the Firebase sessions, with the answers probe-v4 recorded for the wrong-offset chunk, the queries and the cancel, complete with owned cleanup", async () => {
  const run = fixture({ recordedShapes: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(result.unresolved, []);
  assert.equal(run.objects.size, 0);
  assert.equal([...run.sessions.values()].filter((row) => row.cancelled).length, 2);
  // The wrong-offset chunk took no bytes, and the session it left alive was then cancelled.
  const wrong = run.captures.find((row) => row.operationId === "wrong-offset");
  assert.equal(wrong.status, 400);
  assert.match(Buffer.from(wrong.bodyBase64, "base64").toString(), /wrong offset/);
  const afterCancel = run.captures.find((row) => row.operationId === "query-after-cancel-wrong");
  assert.equal(afterCancel.headers["x-goog-upload-status"], "cancelled");
  assert.equal("x-goog-upload-size-received" in afterCancel.headers, false);
});
