import assert from "node:assert/strict";
import test from "node:test";
import { collectManagement, localTransport } from "./storage-rules/management-local.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { fixtureDigest, managementSteps, sha256 } from "./storage-rules/management-compare.mjs";

export const binding = {
  bucket: "local.example.test",
  prefix: "STORAGE-RULES/test-run/",
  uidA: "test-user-a",
  uidB: "test-user-b",
};
export const provenance = Object.fromEntries(
  [
    "binarySha256",
    "collectorSha256",
    "judgeSha256",
    "corpusSha256",
    "fixtureSha256",
    "configSha256",
  ].map((key) => [key, "a".repeat(64)]),
);
provenance.fixtureSha256 = fixtureDigest(binding);
provenance.binarySourceCommit = "b".repeat(40);
export function wireResponse(status, text, contentType = "application/json") {
  const bytes = Buffer.from(text);
  return {
    status,
    bytes,
    headers: new Headers({
      "content-type": contentType,
      "content-length": String(bytes.length),
      "x-content-type-options": "nosniff",
      "cache-control": "private, max-age=0",
    }),
  };
}
/** Independent state model for installed source and owned objects. */
export function stateTransport({ failOn, corruptInvalid = false, seed = 0 } = {}) {
  let source = null;
  const objects = new Map();
  const calls = [];
  const [, switched] = buildCorpus(binding).managementPrograms;
  return {
    calls,
    objects,
    transport: async (action) => {
      calls.push(action);
      if (failOn === action.kind) throw new Error("injected transport failure");
      if (action.kind === "list")
        return wireResponse(200, JSON.stringify({ items: [...objects.values()] }));
      if (action.kind === "captured") return action.response;
      if (action.kind === "snapshot")
        return wireResponse(
          200,
          JSON.stringify({ loaded: source !== null, ...(source === null ? {} : { source }) }),
        );
      if (action.kind === "clear") {
        source = null;
        return wireResponse(200, "{}");
      }
      if (action.kind === "activate") {
        if (action.source.includes("allow get: if ;")) {
          if (corruptInvalid && source !== null) source = null;
          return wireResponse(400, "invalid");
        }
        source = action.source;
        return wireResponse(200, "{}");
      }
      if (action.kind === "seed") {
        objects.set(action.name, { name: action.name, generation: String(100 + seed), seed });
        return wireResponse(200, JSON.stringify(objects.get(action.name)));
      }
      const object = objects.get(action.name);
      if (action.method === "DELETE") {
        assert.equal(action.query.ifGenerationMatch, object.generation);
        objects.delete(action.name);
        return wireResponse(204, "");
      }
      if (action.caller === "user-a") {
        if (source === null) return wireResponse(400, "missing release");
        const allowed =
          source === switched.sourceA
            ? action.name === switched.objectA
            : source === switched.sourceB
              ? action.name === switched.objectB
              : false;
        if (!allowed) return wireResponse(403, "denied");
      }
      if (!object) return wireResponse(404, "missing");
      return action.media
        ? wireResponse(200, "next", "text/plain")
        : wireResponse(200, JSON.stringify(object));
    },
  };
}

export async function localFixture(options = {}) {
  const model = stateTransport(options);
  const result = await collectManagement({
    binding,
    profile: "strict",
    provenance,
    transport: model.transport,
  });
  return { result, model };
}

test("collector records the closed management steps and cleans every owned object", async () => {
  const { result, model } = await localFixture();
  assert.deepEqual(result.errors, []);
  assert.equal(result.rows.length, managementSteps(binding).length);
  assert.equal(new Set(result.rows.map((r) => r.id)).size, result.rows.length);
  assert.equal(model.objects.size, 0);
  assert.deepEqual(
    result.localOnly.map((r) => r.id),
    [
      "before-identity",
      "before-allow",
      "before-deny",
      "invalid",
      "after-identity",
      "after-allow",
      "after-deny",
    ],
  );
  const before = result.localOnly[0],
    after = result.localOnly[4];
  assert.equal(before.sourceSha256, after.sourceSha256);
  assert.equal(before.sourceSha256, sha256(buildCorpus(binding).managementPrograms[1].sourceA));
  assert.deepEqual(
    result.localOnly.map((r) => r.response.status),
    [200, 200, 403, 400, 200, 200, 403],
  );
});

test("collector always cleans owned objects after a source activation failure", async () => {
  const { result, model } = await localFixture({ failOn: "activate" });
  assert.ok(result.errors.some((r) => r.kind === "COLLECTION_FAILED"));
  assert.ok(result.errors.some((r) => r.kind === "MISSING_STEPS"));
  assert.equal(model.objects.size, 0);
  assert.equal(model.calls.at(-1).kind, "list");
});

test("collector retains invalid effective state changes as evidence", async () => {
  const { result } = await localFixture({ corruptInvalid: true });
  assert.notEqual(result.localOnly[0].sourceSha256, result.localOnly[4].sourceSha256);
  assert.equal(result.localOnly[5].response.status, 400);
});

test("generated object generations leave the management effect model invariant", async () => {
  for (let seed = 0; seed < 24; seed++) {
    const { result, model } = await localFixture({ seed });
    assert.deepEqual(result.errors, []);
    assert.equal(model.objects.size, 0);
    assert.deepEqual(
      result.rows.filter((r) => r.id.endsWith("/subject")).map((r) => r.response.status),
      [400, 200, 403, 403, 200, 400],
    );
  }
});

test("transport rejects remote endpoints before calling fetch", () => {
  for (const storageHost of [
    "example.com:1234",
    "localhost:1234",
    "127.0.0.1:1/path",
    "127.0.0.1:12@evil.test",
  ])
    assert.throws(
      () =>
        localTransport({
          storageHost,
          controlUrl: "http://127.0.0.1:1234/",
          controlToken: "test-control",
          userToken: "test-user",
          binding,
        }),
      /loopback/,
    );
  assert.throws(
    () =>
      localTransport({
        storageHost: "127.0.0.1:1234",
        controlUrl: "http://evil.test/",
        controlToken: "test-control",
        userToken: "test-user",
        binding,
      }),
    /control/,
  );
});

test("transport preserves owned path and user-a versus Admin dialect", async () => {
  const calls = [];
  const transport = localTransport({
    storageHost: "127.0.0.1:1234",
    controlUrl: "http://127.0.0.1:1235/",
    controlToken: "test-control",
    userToken: "test-user",
    binding,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return new Response("next", { status: 200 });
    },
  });
  for (const caller of ["user-a", "admin"])
    await transport({
      kind: "storage",
      name: `${binding.prefix}object.bin`,
      media: true,
      caller,
      method: "GET",
      query: {},
    });
  assert.match(calls[0].url, /\/v0\//);
  assert.equal(calls[0].init.headers.authorization, "Firebase test-user");
  assert.match(calls[1].url, /\/storage\/v1\//);
  assert.equal(calls[1].init.headers.authorization, "Bearer owner");
  assert.equal(calls[0].init.redirect, "error");
  await assert.rejects(transport({ kind: "storage", name: "foreign/object.bin" }), /owned/);
});

test("collector retains object and release baseline absence and final prefix emptiness", async () => {
  const { result } = await localFixture();
  for (const index of [3, 4, 5])
    for (const type of ["metadata", "media"])
      assert.equal(
        result.rows.find((r) => r.id === `management/control-${index}/baseline-${type}`)?.response
          .status,
        404,
      );
  for (const id of [
    "preflight/release/entry/bucket",
    "preflight/release/entry/bucketless",
    "release/final/bucket",
    "release/final/bucketless",
  ])
    assert.equal(result.rows.find((r) => r.id === id)?.effect.absent, true);
  assert.equal(result.rows.find((r) => r.id === "management/prefix-empty")?.response.status, 200);
});

/** Runs the collector over the state model, letting `override(action, model)` answer first. */
async function collectWith(override, { profile = "strict", transport } = {}) {
  const model = stateTransport();
  const wrapped = async (action) => (await override(action, model)) ?? model.transport(action);
  return {
    model,
    result: await collectManagement({
      binding,
      profile,
      provenance,
      transport: transport ?? wrapped,
    }),
  };
}
const errorMessages = (result) => result.errors.map((e) => `${e.kind}: ${e.message ?? ""}`);

test("collector refuses unusable input before any request is sent", async () => {
  const model = stateTransport();
  for (const bad of [
    { binding: { ...binding, bucket: "" } },
    { binding: { ...binding, prefix: "" } },
    { profile: "other" },
    { profile: undefined },
    { transport: undefined },
    { transport: "not a function" },
  ])
    await assert.rejects(
      collectManagement({
        binding,
        profile: "strict",
        provenance,
        transport: model.transport,
        ...bad,
      }),
      /binding|invalid local management input/i,
      JSON.stringify(Object.keys(bad)),
    );
  assert.equal(model.calls.length, 0, "nothing was sent");
  const emulator = await collectManagement({
    binding,
    profile: "emulator",
    provenance,
    transport: model.transport,
  });
  assert.deepEqual(emulator.errors, [], "the emulator profile is accepted too");
});

test("collector fails closed on each unusable answer and still cleans up", async () => {
  let installed = null;
  const cases = [
    [
      "an unavailable rules snapshot",
      (a) => (a.kind === "snapshot" ? wireResponse(500, "down") : undefined),
      /COLLECTION_FAILED: rules snapshot unavailable/,
    ],
    [
      "an activation that did not load the rules",
      async (a, m) => {
        if (a.kind === "activate") installed = a.source;
        if (a.kind === "snapshot" && installed !== null)
          return wireResponse(200, JSON.stringify({ loaded: false, source: installed }));
        return undefined;
      },
      /COLLECTION_FAILED: source identity failed compile\//,
    ],
    [
      "a refused activation whose source is nevertheless installed",
      async (a, m) => {
        if (a.kind === "activate" && !a.source.includes("allow get: if ;")) {
          await m.transport(a);
          return wireResponse(500, "refused");
        }
        return undefined;
      },
      /COLLECTION_FAILED: source identity failed compile\//,
    ],
    [
      "an owned object that exists before the seed",
      (a, m) =>
        a.kind === "storage" && a.name && !a.method?.startsWith("DELETE") && m.objects.size === 0
          ? wireResponse(200, JSON.stringify({ name: a.name, generation: "1" }))
          : undefined,
      /COLLECTION_FAILED: owned object not initially absent/,
    ],
    [
      "a refused seed",
      (a) => (a.kind === "seed" ? wireResponse(403, "no") : undefined),
      /COLLECTION_FAILED: seed refused/,
    ],
  ];
  for (const [label, override, expected] of cases) {
    installed = null;
    const { result } = await collectWith(override);
    assert.match(errorMessages(result).join("\n"), expected, label);
    assert.ok(
      result.errors.some((e) => e.kind === "COLLECTION_FAILED"),
      `${label}: the collection is marked failed`,
    );
  }
});

test("owned cleanup reports a refused delete and an object that is still present", async () => {
  const refused = await collectWith((a) =>
    a.kind === "storage" && a.method === "DELETE" ? wireResponse(403, "no") : undefined,
  );
  assert.match(
    errorMessages(refused.result).join("\n"),
    /OWNED_CLEANUP_FAILED: owned cleanup delete refused/,
  );
  const present = await collectWith((a) => {
    if (a.kind === "storage" && a.method === "DELETE") return wireResponse(204, "");
    return undefined;
  });
  assert.match(
    errorMessages(present.result).join("\n"),
    /OWNED_CLEANUP_FAILED: owned cleanup absence unavailable/,
  );
});

test("an absence row says the rules are loaded when the snapshot says so", async () => {
  let first = true;
  const { result } = await collectWith((a) => {
    if (a.kind === "snapshot" && first) {
      first = false;
      return wireResponse(200, JSON.stringify({ loaded: true, source: "x" }));
    }
    return undefined;
  });
  const rows = result.rows.filter((r) => r.id.startsWith("preflight/release/entry/"));
  assert.equal(rows[0].effect.absent, false, "the first snapshot reported loaded rules");
  assert.equal(rows[1].effect.absent, true);
});

test("transport validates every host, the control endpoint and both tokens", () => {
  const base = {
    storageHost: "127.0.0.1:1234",
    controlUrl: "http://127.0.0.1:1235/",
    controlToken: "test-control",
    userToken: "test-user",
    binding,
  };
  assert.doesNotThrow(() => localTransport(base));
  assert.doesNotThrow(() => localTransport({ ...base, authHost: "[::1]:1236" }));
  for (const authHost of ["example.com:1236", "localhost:1236", "127.0.0.1:1/x"])
    assert.throws(() => localTransport({ ...base, authHost }), /loopback/, authHost);
  for (const controlUrl of ["https://127.0.0.1:1235/", "http://user:pw@127.0.0.1:1235/"])
    assert.throws(() => localTransport({ ...base, controlUrl }), /control/, controlUrl);
  for (const patch of [{ controlToken: "" }, { controlToken: undefined }, { userToken: "" }])
    assert.throws(() => localTransport({ ...base, ...patch }), /control\/token/);
});

test("transport sends the control, seed and list requests as the management runner expects", async () => {
  const calls = [];
  const transport = localTransport({
    storageHost: "127.0.0.1:1234",
    controlUrl: "http://127.0.0.1:1235/",
    controlToken: "test-control",
    userToken: "test-user",
    binding,
    fetchImpl: async (url, init) => {
      calls.push({ url: new URL(String(url)), init });
      return new Response("{}", { status: 200 });
    },
  });
  await transport({ kind: "snapshot" });
  await transport({ kind: "clear" });
  await transport({ kind: "activate", source: "rules" });
  await transport({ kind: "list" });
  await transport({ kind: "seed", name: `${binding.prefix}seed.bin` });
  const [snapshot, clear, activate, list, seed] = calls;
  assert.equal(snapshot.init.method, "GET");
  assert.equal(clear.init.method, "DELETE", "clear removes the rules");
  for (const control of [snapshot, clear]) {
    assert.equal(control.url.pathname, "/storage/rules");
    assert.equal(control.init.headers.authorization, "Bearer test-control");
  }
  assert.equal(activate.init.method, "PUT");
  assert.equal(activate.url.pathname, "/internal/setRules");
  assert.deepEqual(JSON.parse(activate.init.body), {
    rules: { files: [{ name: "storage.rules", content: "rules" }] },
  });
  assert.equal(list.url.pathname, `/storage/v1/b/${binding.bucket}/o`);
  assert.equal(list.url.searchParams.get("prefix"), binding.prefix);
  assert.equal(list.url.searchParams.get("maxResults"), "1", "the prefix check lists one entry");
  assert.equal(list.init.headers.authorization, "Bearer owner");
  assert.equal(seed.init.method, "POST");
  assert.equal(seed.url.pathname, `/upload/storage/v1/b/${binding.bucket}/o`);
  assert.equal(seed.url.searchParams.get("uploadType"), "media");
  assert.equal(seed.url.searchParams.get("name"), `${binding.prefix}seed.bin`);
  assert.equal(
    seed.url.searchParams.get("ifGenerationMatch"),
    "0",
    "a seed never overwrites an existing object",
  );
  assert.equal(seed.init.headers["content-type"], "text/plain");
  assert.equal(seed.init.body, "next");
});
