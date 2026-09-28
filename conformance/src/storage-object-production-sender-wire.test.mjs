import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test, { afterEach, beforeEach } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import {
  createProductionStorageSender,
  verifyProductionRecipeTerminal,
} from "./storage-object/sender.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const argv = [...process.execArgv];
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = [...argv];
});
const ownerToken = "SYNTHETIC_SENDER_WIRE_OWNER_TOKEN_123456789";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const recipes = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes;
const recipeIds = [
  ...recipes.map((row) => row.id),
  ...buildAuthCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runId: "recordone",
  }).recipes.map((row) => row.id),
];

async function memoryTls(respond, action) {
  const original = tls.connect,
    connections = [];
  tls.connect = (options) => {
    const connection = { options, bytes: Buffer.alloc(0) };
    connections.push(connection);
    let responded = false;
    const socket = new Duplex({
      read() {},
      write(bytes, encoding, done) {
        connection.bytes = Buffer.concat([connection.bytes, bytes]);
        socket.bytesWritten += bytes.length;
        const boundary = connection.bytes.indexOf("\r\n\r\n"),
          length = /content-length: (\d+)/i.exec(connection.bytes.toString())?.[1];
        if (
          !responded &&
          boundary >= 0 &&
          connection.bytes.length === boundary + 4 + Number(length)
        ) {
          responded = true;
          try {
            connection.head = connection.bytes.subarray(0, boundary).toString();
            connection.body = connection.bytes.subarray(boundary + 4);
            const result = respond(connection),
              body = result.raw ?? Buffer.from(JSON.stringify(result.data));
            const response = Buffer.concat([
              Buffer.from(
                `HTTP/1.1 ${result.status} Synthetic\r\nContent-Length: ${body.length}\r\n${result.status === 204 ? "" : `Content-Type: ${result.raw ? "application/octet-stream" : "application/json"}\r\n`}Connection: close\r\n\r\n`,
              ),
              body,
            ]);
            queueMicrotask(() => {
              for (let offset = 0; offset < response.length; offset += 37)
                options.onread.callback(
                  Math.min(37, response.length - offset),
                  response.subarray(offset, offset + 37),
                );
              socket.push(null);
            });
          } catch (error) {
            done(error);
            return;
          }
        }
        done();
      },
    });
    Object.assign(socket, {
      bytesWritten: 0,
      authorized: true,
      encrypted: true,
      alpnProtocol: "http/1.1",
      setTimeout() {
        return this;
      },
      setNoDelay() {
        return this;
      },
      setKeepAlive() {
        return this;
      },
    });
    queueMicrotask(() => socket.emit("secureConnect"));
    return socket;
  };
  try {
    return await action(connections);
  } finally {
    tls.connect = original;
  }
}

async function fixture(action, changes = {}) {
  const directory = mkdtempSync(join(tmpdir(), "storage-object-sender-wire-"));
  chmodSync(directory, 0o700);
  const objects = new Map(),
    reserves = [],
    byteReserves = [],
    journals = [],
    senders = new Map();
  let generation = 1n,
    wire;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => {
      reserves.push(row);
    },
    recipeLifecycle: {
      recipeIds,
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: (proof) =>
        verifyProductionRecipeTerminal(senders.get(proof.recipeToken), proof),
    },
  });
  const verifyAdmission = (context) =>
    context.recording === counter.snapshot().recording && context.phase === counter.snapshot().mode;
  const clockDescriptor = Object.getOwnPropertyDescriptor(performance, "now");
  let monotonic = 1000;
  Object.defineProperty(performance, "now", {
    configurable: true,
    value: () => (monotonic += 1000),
  });
  try {
    await counter.start();
    const recipe = recipes[0],
      recipeToken = await counter.beginRecipe(recipe.id);
    wire = createProductionWireTransport({
      plan,
      resources: {
        projectNumber: "123456789012",
        apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
        rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
      },
      captureDirectory: directory,
      onByteReserve: async (row) => {
        byteReserves.push(row);
      },
      verifyAdmission,
      ownerAuthorization: () => `Bearer ${ownerToken}`,
      accountAuthorization: () => assert.fail("this recipe has no Firebase account credential"),
    });
    const sender = createProductionStorageSender({
      plan,
      recipeToken,
      wire,
      verifyAdmission,
      onJournal: async (row) => {
        journals.push(row);
      },
    });
    senders.set(recipeToken, sender);
    await memoryTls(
      (row) => {
        assert.equal(row.options.servername, row.options.host);
        assert.equal(row.options.rejectUnauthorized, true);
        const [method, target] = row.head.split(" "),
          url = new URL(target, `https://${row.options.host}`);
        assert.ok(
          ["storage.googleapis.com", "firebasestorage.googleapis.com"].includes(row.options.host),
        );
        const authorization = /\r\nauthorization: ([^\r\n]+)/i.exec(row.head)?.[1];
        if (authorization === undefined) {
          assert.equal(/x-goog-user-project:/i.test(row.head), false);
          assert.equal(changes.anonymous, true);
          return { status: 403, data: { error: { code: 403, message: "Forbidden" } } };
        }
        assert.equal(authorization, `Bearer ${ownerToken}`);
        assert.match(row.head, /x-goog-user-project: example-project/i);
        if (method === "GET" && url.pathname.endsWith("/o"))
          return {
            status: 200,
            data: {
              kind: "storage#objects",
              items: [...objects.values()]
                .map((item) => item.metadata)
                .filter((item) => item.name.startsWith(url.searchParams.get("prefix"))),
            },
          };
        const name =
          url.searchParams.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
        assert.equal(name.startsWith(plan.recordings[0].prefix), true);
        if (method === "POST") {
          assert.ok(journals.some((journal) => journal.name === name && journal.method === "POST"));
          const metadata = {
            kind: "storage#object",
            bucket: plan.bucket,
            name,
            generation: `${generation++}`,
            metageneration: "1",
            size: `${row.body.length}`,
          };
          objects.set(name, { metadata, bytes: Buffer.from(row.body) });
          return { status: 200, data: metadata };
        }
        const object = objects.get(name);
        if (!object) return { status: 404, data: { error: { code: 404, message: "Not Found" } } };
        if (method === "DELETE") {
          assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
          objects.delete(name);
          return { status: 204, raw: Buffer.alloc(0) };
        }
        return url.searchParams.get("alt") === "media"
          ? { status: 200, raw: object.bytes }
          : { status: 200, data: object.metadata };
      },
      async (connections) => {
        await action({
          sender,
          counter,
          wire,
          recipe,
          recipeToken,
          objects,
          reserves,
          byteReserves,
          journals,
          connections,
          directory,
        });
      },
    );
  } finally {
    if (wire) await wire.close();
    if (clockDescriptor) Object.defineProperty(performance, "now", clockDescriptor);
    else delete performance.now;
    rmSync(directory, { recursive: true });
  }
}

test("the shared production sender connects actual framing, capture, wire and recipe terminal evidence", async () => {
  await fixture(async (f) => {
    const result = await replayLocalBasic({
      sender: f.sender,
      recipe: f.recipe,
      bucket: plan.bucket,
    });
    assert.equal(result.status, "LOCAL_COMPLETE");
    assert.equal(f.objects.size, 0);
    assert.equal(f.counter.snapshot().total, f.connections.length);
    assert.equal(f.wire.snapshot().attempts, f.connections.length);
    assert.equal(f.wire.snapshot().readAfterHaltBytes, 0);
    assert.equal(f.byteReserves.length, f.connections.length);
    assert.ok(f.byteReserves.every((row) => row.requestReservedBytes > 0));
    for (const row of f.reserves) assert.match(row.operationId, /^r1\/p1\/[a-f0-9]{64}$/);
    await f.counter.finishRecipe(f.recipeToken);
    assert.equal(f.counter.snapshot().completedRecipes[0], 1);
    const files = readdirSync(f.directory);
    assert.equal(files.length, f.wire.snapshot().attempts * 4);
    const check = (bytes) => {
      for (const secret of [
        ownerToken,
        encodeURIComponent(ownerToken),
        Buffer.from(ownerToken).toString("base64"),
      ])
        assert.equal(bytes.includes(Buffer.from(secret)), false);
    };
    const inspect = (value) => {
      if (typeof value === "string") {
        check(Buffer.from(value));
        check(Buffer.from(value, "base64"));
        try {
          check(Buffer.from(decodeURIComponent(value)));
        } catch (error) {
          if (!(error instanceof URIError)) throw error;
        }
      } else if (value && typeof value === "object")
        for (const child of Object.values(value)) inspect(child);
    };
    for (const name of files) {
      const path = join(f.directory, name),
        info = statSync(path),
        saved = readFileSync(path);
      assert.equal(info.isFile(), true);
      assert.equal(info.mode & 0o777, 0o600);
      check(saved);
      inspect(JSON.parse(saved.toString()));
    }
  });
});

test("explicit anonymous declarations reach the actual wire without owner or quota headers", async () => {
  await fixture(
    async (f) => {
      await f.sender.start();
      await f.sender.admitNamespace();
      const name = f.recipe.objects[0];
      const result = await f.sender.sendStep({
        id: "anonymous-media",
        dialect: "firebase",
        method: "GET",
        path: `/v0/b/${plan.bucket}/o/${encodeURIComponent(name)}`,
        objectName: name,
        query: { alt: "media" },
        credential: "none",
      });
      assert.equal(result.status, 403);
      assert.equal(f.connections.length, 2);
      assert.equal(f.wire.snapshot().attempts, 2);
      assert.equal(f.counter.snapshot().total, 2);
      assert.equal(f.connections[1].options.host, "firebasestorage.googleapis.com");
    },
    { anonymous: true },
  );
});
