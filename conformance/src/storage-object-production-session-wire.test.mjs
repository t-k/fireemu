import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test, { afterEach, beforeEach } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import {
  claimStage3RecipeContext,
  createStage3RequestCounter,
} from "./storage-object/request-counter.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import { createProductionStorageSender } from "./storage-object/sender.mjs";

const argv = [...process.execArgv];
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = [...argv];
});
const digest = (value) => createHash("sha256").update(value).digest("hex");
const owner = "SYNTHETIC_SESSION_WIRE_OWNER_123456789_abcdefgh";
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const recipes = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes;
const recipeIds = [
  ...recipes.map((recipe) => recipe.id),
  ...buildAuthCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runId: "recordone",
  }).recipes.map((recipe) => recipe.id),
];
const bodyFor = (step) =>
  step.body?.json
    ? Buffer.from(JSON.stringify(step.body.json))
    : step.body?.base64
      ? Buffer.from(step.body.base64, "base64")
      : Buffer.alloc(0);

async function fixture(dialect, action, changes = {}) {
  const directory = mkdtempSync(join(tmpdir(), "storage-object-session-wire-"));
  chmodSync(directory, 0o700);
  const connections = [],
    reservations = [],
    bytes = [];
  const journals = [];
  const originalConnect = tls.connect,
    originalNow = performance.now;
  let clock = 0,
    wire,
    admitted = true;
  performance.now = () => (clock += 1000);
  try {
    const counter = createStage3RequestCounter(plan, {
      onStart: async () => {},
      onReserve: async (row) => {
        reservations.push(row);
      },
      recipeLifecycle: {
        recipeIds,
        onBegin: async () => {},
        onFinish: async () => {},
        verifyTerminal: () => true,
      },
    });
    await counter.start();
    const recipe = recipes.find((row) => row.id === `storage-object/${dialect}/resumable-upload`);
    // Prior recipes are omitted synthetic setup, never aggregate completion evidence.
    for (const id of recipeIds.slice(0, recipeIds.indexOf(recipe.id))) {
      const token = await counter.beginRecipe(id);
      counter.beginCleanup(token);
      await counter.finishRecipe(token);
    }
    const token = await counter.beginRecipe(recipe.id),
      context = changes.useSender ? null : claimStage3RecipeContext(token, plan);
    await context?.counter.start();
    const start = recipe.steps.find((step) => step.id === "initiate");
    const host = dialect === "gcs" ? "storage.googleapis.com" : "firebasestorage.googleapis.com";
    const path =
      dialect === "gcs" ? `/upload/storage/v1/b/${plan.bucket}/o` : `/v0/b/${plan.bucket}/o`;
    const uploadId = "SYNTHETIC/SESSION_CAPABILITY+abcdefgh123456789";
    const uri = `https://${host}${path}?upload_id=${encodeURIComponent(uploadId).replaceAll("%2F", "%2f")}&name=${encodeURIComponent(start.objectName).replaceAll("%2F", "%2f")}&${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable`;
    tls.connect = (options) => {
      const connection = { options, bytes: Buffer.alloc(0) };
      connections.push(connection);
      let responded = false;
      const socket = new Duplex({
        read() {},
        write(chunk, encoding, done) {
          connection.bytes = Buffer.concat([connection.bytes, chunk]);
          socket.bytesWritten += chunk.length;
          const end = connection.bytes.indexOf("\r\n\r\n"),
            length = /content-length: (\d+)/i.exec(connection.bytes.toString())?.[1];
          if (!responded && end >= 0 && connection.bytes.length === end + 4 + Number(length)) {
            responded = true;
            try {
              connection.head = connection.bytes.subarray(0, end).toString();
              connection.body = connection.bytes.subarray(end + 4);
              const [method, target] = connection.head.split(" "),
                requested = new URL(target, `https://${options.host}`),
                collection = method === "GET" && requested.pathname.endsWith("/o"),
                initiation = method === "POST" && !requested.searchParams.has("upload_id");
              assert.equal(options.servername, collection ? "storage.googleapis.com" : host);
              assert.equal(options.rejectUnauthorized, true);
              assert.match(connection.head, new RegExp(`Authorization: Bearer ${owner}`));
              let status = 200,
                headers = [];
              if (initiation)
                headers = [
                  [dialect === "gcs" ? "Location" : "X-Goog-Upload-URL", changes.uri ?? uri],
                ];
              else if (!collection) {
                assert.equal(
                  connection.head.split("\r\n")[0].split(" ")[1],
                  new URL(uri).pathname + new URL(uri).search,
                );
                if (dialect === "gcs") {
                  status = 308;
                  headers.push(["Range", "bytes=0-262143"]);
                }
              }
              if (dialect === "firebase" && !collection)
                headers.push(
                  ["X-Goog-Upload-Status", "active"],
                  [
                    "X-Goog-Upload-Size-Received",
                    !initiation && connection.body.length === 262144 ? "262144" : "0",
                  ],
                );
              const body = Buffer.from(
                collection
                  ? JSON.stringify({ kind: "storage#objects", items: [] })
                  : initiation
                    ? (changes.initialBody ?? "")
                    : "",
              );
              const response = Buffer.concat([
                Buffer.from(
                  `HTTP/1.1 ${status} Synthetic\r\nContent-Length: ${body.length}\r\n${headers.map(([name, value]) => `${name}: ${value}\r\n`).join("")}Connection: close\r\n\r\n`,
                ),
                body,
              ]);
              queueMicrotask(() => {
                for (let offset = 0; offset < response.length; offset += 29)
                  options.onread.callback(
                    Math.min(29, response.length - offset),
                    response.subarray(offset, offset + 29),
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
    wire = createProductionWireTransport({
      plan,
      resources: {
        projectNumber: "100000000001",
        apiKeyResource: "projects/100000000001/locations/global/keys/example-key",
        rulesetResource: "projects/example-project/rulesets/example-ruleset",
      },
      captureDirectory: directory,
      onByteReserve: async (row) => {
        bytes.push(row);
      },
      verifyAdmission: (row) => {
        changes.onAdmission?.();
        return admitted && row.recording === 1 && row.phase === counter.snapshot().mode;
      },
      ownerAuthorization: () => `Bearer ${owner}`,
      accountAuthorization: () => {
        throw new Error("UNUSED_SYNTHETIC_ACCOUNT");
      },
    });
    assert.equal(typeof wire.bindSession, "function", "actual response session binding is missing");
    assert.equal(typeof wire.fetchSession, "function", "session dispatch is missing");
    const sender = changes.useSender
      ? createProductionStorageSender({
          plan,
          recipeToken: token,
          wire,
          verifyAdmission: (row) =>
            admitted && row.recording === 1 && row.phase === counter.snapshot().mode,
          onJournal: async (row) => {
            journals.push(row);
          },
        })
      : null;
    if (sender) {
      await sender.start();
      await sender.admitNamespace();
      sender.admitObject(start.objectName);
    }
    const send = (step, capability, override = {}) => {
      const operationId = context.dispatchOperationId(step.id);
      return context.counter.send(step.id, () => {
        const init = {
          method: step.method,
          headers: step.headers,
          body: bodyFor(step),
          operationId,
          accountingPhase: counter.snapshot().mode,
          ...override,
        };
        return step.sessionUriReference
          ? wire.fetchSession(1, capability, step, init)
          : wire.fetchStorage(1, step, init);
      });
    };
    await action({
      wire,
      sender,
      journals,
      start,
      recipe,
      send,
      uri,
      uploadId,
      connections,
      reservations,
      bytes,
      counter,
      directory,
      beginCleanup: () => context.counter.beginCleanup(),
      revoke: () => {
        admitted = false;
      },
    });
  } finally {
    await wire?.close();
    tls.connect = originalConnect;
    performance.now = originalNow;
    rmSync(directory, { recursive: true });
  }
}

test("actual initiation responses mint private capabilities and preserve the opaque session target", async () => {
  for (const dialect of ["gcs", "firebase"])
    await fixture(dialect, async (f) => {
      const response = await f.send(f.start),
        capability = f.wire.bindSession(1, response);
      assert.equal(capability.sessionUriSha256, digest(f.uri));
      assert.equal(Object.isFrozen(capability), true);
      assert.equal(capability.uri, undefined);
      const steps = f.recipe.steps.filter((step) => step.sessionUriReference).slice(0, 2);
      for (const step of steps) await f.send(step, capability);
      assert.equal(f.connections.length, 3);
      assert.equal(f.reservations.length, 3);
      assert.equal(f.bytes.length, 3);
      assert.equal(f.wire.snapshot().attempts, 3);
      assert.equal(readdirSync(f.directory).length, 12);
      const check = (value) => {
        if (typeof value !== "string") {
          if (value && typeof value === "object")
            for (const child of Object.values(value)) check(child);
          return;
        }
        const copies = [value];
        for (const encoded of [value, ...(value.match(/[A-Za-z0-9+/_-]{8,}={0,2}/g) ?? [])]) {
          const decoded = Buffer.from(encoded, "base64").toString("utf8");
          copies.push(decoded);
        }
        for (const copy of copies.slice()) {
          try {
            copies.push(decodeURIComponent(copy));
          } catch (error) {
            if (!(error instanceof URIError)) throw error;
          }
        }
        for (const copy of copies)
          for (const secret of [f.uri, f.uploadId, owner])
            assert.equal(copy.includes(secret), false);
      };
      for (const name of readdirSync(f.directory)) {
        const path = join(f.directory, name),
          saved = readFileSync(path, "utf8");
        assert.equal(statSync(path).mode & 0o777, 0o600);
        check(saved);
        check(JSON.parse(saved));
      }
    });
});

test("public Response header mutation cannot replace the private captured session URI", async () => {
  await fixture("gcs", async (f) => {
    const response = await f.send(f.start);
    response.headers.set("location", "https://foreign.example/forged");
    const capability = f.wire.bindSession(1, response);
    assert.equal(capability.sessionUriSha256, digest(f.uri));
    await f.send(f.recipe.steps[1], capability);
    assert.equal(f.connections.length, 2);
  });
});

test("forged, cloned, wrong-record and repeated response bindings cannot authorize more HTTP", async () => {
  for (const invalid of ["forged", "clone", "wrong-record", "repeat"])
    await fixture("gcs", async (f) => {
      const response = await f.send(f.start);
      if (invalid === "repeat") f.wire.bindSession(1, response);
      assert.throws(
        () =>
          f.wire.bindSession(
            invalid === "wrong-record" ? 2 : 1,
            invalid === "forged"
              ? new Response(null, { headers: { location: f.uri } })
              : invalid === "clone"
                ? { ...response, headers: new Headers(response.headers) }
                : response,
          ),
        /PRODUCTION.*SESSION/,
      );
      assert.equal(f.connections.length, 1);
      assert.equal(f.bytes.length, 1);
    });
});

test("admission re-entry cannot mint a second capability or hide a failed binding", async () => {
  for (const swallow of [false, true]) {
    let hook;
    await fixture(
      "gcs",
      async (f) => {
        const response = await f.send(f.start);
        let inner, outer;
        hook = () => {
          hook = null;
          try {
            inner = f.wire.bindSession(1, response);
          } catch (error) {
            if (!swallow) throw error;
          }
        };
        assert.throws(() => {
          outer = f.wire.bindSession(1, response);
        }, /PRODUCTION_SESSION/);
        assert.equal(inner, undefined);
        assert.equal(outer, undefined);
        assert.equal(f.wire.snapshot().failed, true);
        assert.throws(() => f.wire.bindSession(1, response), /PRODUCTION_SESSION/);
        assert.equal(f.connections.length, 1);
        assert.equal(f.bytes.length, 1);
      },
      {
        onAdmission() {
          hook?.();
        },
      },
    );
  }
});

test("closing or dispatching through an admission callback cannot publish a session capability", async () => {
  for (const kind of ["close", "dispatch"]) {
    let hook, pending;
    await fixture(
      "gcs",
      async (f) => {
        const response = await f.send(f.start);
        hook = () => {
          hook = null;
          const step = f.recipe.steps[4];
          pending =
            kind === "close"
              ? f.wire.close()
              : f.wire
                  .fetchStorage(1, step, {
                    method: step.method,
                    headers: step.headers,
                    body: bodyFor(step),
                    operationId: `r1/p${recipes.indexOf(f.recipe) + 1}/${digest(step.id)}`,
                    accountingPhase: "subject",
                  })
                  .catch((error) => error);
        };
        let rejection;
        try {
          f.wire.bindSession(1, response);
        } catch (error) {
          rejection = error;
        }
        await pending;
        assert.match(rejection?.message ?? "", /PRODUCTION_SESSION/);
        assert.equal(f.wire.snapshot().failed, true);
        assert.equal(f.connections.length, 1);
        assert.equal(f.bytes.length, 1);
      },
      {
        onAdmission() {
          hook?.();
        },
      },
    );
  }
});

test("session dispatch requires the original capability, declaration and body binding", async () => {
  for (const invalid of ["clone", "reference", "declaration", "body", "headers", "operation"])
    await fixture("gcs", async (f) => {
      const response = await f.send(f.start),
        capability = f.wire.bindSession(1, response),
        original = f.recipe.steps[1];
      const step =
        invalid === "reference"
          ? {
              ...original,
              sessionUriReference: { ...original.sessionUriReference, expectedName: "foreign" },
            }
          : invalid === "declaration"
            ? { ...original, continuation: { ...original.continuation, afterStep: "foreign" } }
            : original;
      const init =
        invalid === "body"
          ? { body: Buffer.from("forged") }
          : invalid === "headers"
            ? { headers: { ...step.headers, "x-unknown": "1" } }
            : invalid === "operation"
              ? { operationId: `r1/p1/${digest(step.id)}` }
              : {};
      await assert.rejects(
        f.send(step, invalid === "clone" ? { ...capability } : capability, init),
        /PRODUCTION/,
      );
      assert.equal(f.connections.length, 1);
      assert.equal(f.bytes.length, 1);
    });
});

test("revoked admission and foreign session URI fail closed before continuation dispatch", async () => {
  await fixture("gcs", async (f) => {
    const response = await f.send(f.start),
      capability = f.wire.bindSession(1, response);
    f.revoke();
    await assert.rejects(f.send(f.recipe.steps[1], capability), /PRODUCTION/);
    assert.equal(f.connections.length, 1);
    assert.equal(f.bytes.length, 1);
  });
  await fixture(
    "gcs",
    async (f) => {
      await assert.rejects(f.send(f.start), /PRODUCTION/);
      assert.equal(f.connections.length, 1);
      assert.equal(f.wire.snapshot().failed, true);
    },
    { uri: "https://foreign.example/forged" },
  );
});

test("only canonical owned initiation bytes and the recipe operation can mint session provenance", async () => {
  for (const invalid of ["body", "headers", "operation", "declaration", "query", "proxy"])
    await fixture("gcs", async (f) => {
      let step = f.start;
      const override =
        invalid === "body"
          ? { body: Buffer.from("{}") }
          : invalid === "headers"
            ? { headers: {} }
            : invalid === "operation"
              ? { operationId: `r1/p1/${digest(step.id)}` }
              : {};
      if (invalid === "declaration") step = { ...step, credential: "none" };
      if (invalid === "query") step = { ...step, query: { ...step.query, uploadType: "media" } };
      if (invalid === "proxy") {
        const revocable = Proxy.revocable(step, {});
        step = revocable.proxy;
        revocable.revoke();
      }
      await assert.rejects(
        invalid === "proxy"
          ? f.wire.fetchStorage(1, step, {
              method: f.start.method,
              headers: f.start.headers,
              body: bodyFor(f.start),
              operationId: `r1/p${recipeIds.indexOf(f.recipe.id) + 1}/${digest(f.start.id)}`,
              accountingPhase: "subject",
            })
          : f.send(step, undefined, override),
        /PRODUCTION/,
      );
      assert.equal(f.connections.length, 0);
      assert.equal(f.bytes.length, 0);
    });
});

test("a foreign initiation body cannot establish a private session capability", async () => {
  await fixture(
    "gcs",
    async (f) => {
      await assert.rejects(f.send(f.start), /PRODUCTION/);
      assert.equal(f.connections.length, 1);
      assert.equal(f.wire.snapshot().failed, true);
    },
    { initialBody: "unrecognized initiation body" },
  );
});

test("binding itself requires fresh admission and latches its failure", async () => {
  await fixture("gcs", async (f) => {
    const response = await f.send(f.start);
    f.revoke();
    assert.throws(() => f.wire.bindSession(1, response), /PRODUCTION_SESSION/);
    assert.equal(f.wire.snapshot().failed, true);
    assert.equal(f.connections.length, 1);
  });
});

test("session declarations retain their subject and cleanup accounting phases", async () => {
  for (const invalid of [false, true])
    await fixture("firebase", async (f) => {
      const response = await f.send(f.start),
        capability = f.wire.bindSession(1, response);
      f.beginCleanup();
      const step = f.recipe.cleanup.find((row) => row.sessionUriReference);
      if (invalid) {
        await assert.rejects(
          f.send(step, capability, { accountingPhase: "subject" }),
          /PRODUCTION/,
        );
        assert.equal(f.connections.length, 1);
      } else {
        await f.send(step, capability);
        assert.equal(f.connections.length, 2);
        assert.equal(f.reservations.at(-1).phase, "cleanup");
        assert.equal(f.bytes.at(-1).phase, "cleanup");
      }
    });
});

test("a canonical session continuation is attempted only once", async () => {
  await fixture("gcs", async (f) => {
    const response = await f.send(f.start),
      capability = f.wire.bindSession(1, response);
    await f.send(f.recipe.steps[1], capability);
    await assert.rejects(f.send(f.recipe.steps[1], capability), /PRODUCTION/);
    assert.equal(f.connections.length, 2);
    assert.equal(f.bytes.length, 2);
  });
});

test("the actual shared sender and wire bind the same original initiation response in both dialects", async () => {
  for (const dialect of ["gcs", "firebase"])
    await fixture(
      dialect,
      async (f) => {
        await f.sender.sendStep(f.start);
        const binding = f.sender.bindSession({ recipe: f.recipe, initiateOperationId: "initiate" });
        assert.equal(binding.sessionUriSha256, digest(f.uri));
        await f.sender.sendSessionStep({ recipe: f.recipe, stepIndex: 1 });
        if (dialect === "firebase")
          await f.sender.sendSessionStep({ recipe: f.recipe, stepIndex: 2 });
        assert.equal(f.reservations.length, f.connections.length);
        assert.equal(f.bytes.length, f.connections.length);
        assert.equal(f.wire.snapshot().attempts, f.connections.length);
        assert.equal(f.journals.length, 2);
        assert.equal(f.journals[1].continuationOf, "initiate");
        assert.equal(f.journals[1].sessionUriSha256, digest(f.uri));
        assert.equal(JSON.stringify(f.journals).includes(f.uri), false);
        assert.deepEqual(f.sender.unresolved(), [f.start.objectName]);
        // The fixture stops at active progress; it does not claim recipe terminal completion.
      },
      { useSender: true },
    );
});
