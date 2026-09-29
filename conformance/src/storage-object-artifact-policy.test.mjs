import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";

const api = await import("./storage-object/production-artifact-policy.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const resources = {
  projectNumber: "123456789012",
  apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
  rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
};
const limits = {
  maxValues: 128,
  maxUtf8Bytes: 131072,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
const secret = "SYNTHETIC_ARTIFACT_SECRET_+/opaque";
const hash = (value) => createHash("sha256").update(value).digest("hex");
function fixture(action) {
  assert.equal(typeof api.createProductionArtifactProfile, "function");
  const registry = createProductionSecretRegistry(limits);
  const profile = api.createProductionArtifactProfile({
    plan,
    resources,
    secretRegistry: registry,
  });
  try {
    return action({ registry, profile });
  } finally {
    registry.close();
  }
}
function assertNoCopies(value) {
  const bytes = Buffer.from(JSON.stringify(value));
  for (const copy of [
    secret,
    encodeURIComponent(secret),
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("base64url"),
  ])
    assert.equal(bytes.includes(Buffer.from(copy)), false);
}

for (const kind of [
  "intent",
  "journal",
  "control-proof",
  "owner-proof",
  "auth-proof",
  "rules-proof",
  "configuration-change",
  "ledger",
  "manifest",
  "export",
  "error",
])
  test(`${kind} snapshots commit cross-field secret copies while preserving public status and the original memory value`, () => {
    fixture(({ registry, profile }) => {
      registry.register(secret);
      for (const copy of [
        secret,
        encodeURIComponent(secret),
        Buffer.from(secret).toString("base64"),
        Buffer.from(secret).toString("base64url"),
      ]) {
        const value = {
          recording: 1,
          status: 200,
          namespaceEmpty: true,
          name: plan.recordings[0].prefix + "simple/object.bin",
          body: { contentDisposition: copy },
          ownedGeneration: "90071992547409931234",
          ownedUid: secret,
          bodySha256: secret,
        };
        const before = JSON.stringify(value),
          result = api.sanitizeProductionArtifact(profile, { kind, value });
        assert.equal(result.taskSecretStatus, "AVAILABLE");
        assert.equal(result.mode, "TYPED_REDACTED_ARTIFACT");
        assert.equal(result.data.status, 200);
        assert.equal(result.data.namespaceEmpty, true);
        assert.equal(result.data.name, value.name);
        assert.equal(result.data.ownedGeneration.sha256, hash(value.ownedGeneration));
        assert.equal(result.data.ownedUid.sha256, hash(secret));
        assert.equal(result.data.bodySha256.sha256, hash(secret));
        assert.equal(result.source.sha256, hash(before));
        assert.equal(result.source.byteLength, Buffer.byteLength(before));
        assert.equal(JSON.stringify(value), before);
        assertNoCopies(result);
      }
    });
  });

test("original profiles reject copies, proxies, getter configuration and arbitrary raw value allowlists", () => {
  fixture(({ registry, profile }) => {
    let hooks = 0;
    const proxy = new Proxy(profile, {
        get() {
          hooks++;
          throw new Error();
        },
      }),
      revoked = Proxy.revocable(profile, {});
    revoked.revoke();
    for (const value of [{ ...profile }, proxy, revoked.proxy, null]) {
      assert.equal(api.isProductionArtifactProfile(value), false);
      assert.equal(api.originalProductionArtifactContext(value), null);
      assert.throws(
        () => api.productionArtifactFailureCode(value),
        /invalid production artifact profile/,
      );
      assert.throws(
        () => api.sanitizeProductionArtifact(value, { kind: "journal", value: { status: 200 } }),
        /invalid production artifact profile/,
      );
    }
    assert.equal(api.isProductionArtifactProfile(profile), true);
    const original = api.originalProductionArtifactContext(profile);
    assert.equal(original.secretRegistry, registry);
    assert.deepEqual(original.runIds, ["recordone", "recordtwo"]);
    assert.equal(Object.isFrozen(original), true);
    assert.equal(Object.isFrozen(original.runIds), true);
    assert.equal(api.productionArtifactFailureCode(profile), null);
    for (const input of [
      { plan, resources, secretRegistry: registry, rawValues: [secret] },
      {
        get plan() {
          hooks++;
          return plan;
        },
        resources,
        secretRegistry: registry,
      },
      { plan, resources: { ...resources, apiKey: secret }, secretRegistry: registry },
      { plan: { ...plan, maxRequests: 1 }, resources, secretRegistry: registry },
      { plan, resources, secretRegistry: { ...registry } },
    ])
      assert.throws(
        () => api.createProductionArtifactProfile(input),
        /invalid production artifact profile/,
      );
    assert.equal(hooks, 0);
  });
});

test("unknown fields, shapes and hidden input hooks commit the whole artifact and close the shared task", () => {
  for (const make of [
    () => ({ metadata: { opaqueProducerField: secret } }),
    () => ({ body: { [secret]: "opaque" } }),
    () => ({
      body: new Proxy(
        { status: 200 },
        {
          get() {
            throw new Error("UNEXPECTED_GETTER");
          },
        },
      ),
    }),
    () => ({ body: Buffer.from(secret) }),
    () => ({
      body: {
        get contentDisposition() {
          throw new Error("UNEXPECTED_GETTER");
        },
      },
    }),
    () => {
      const rows = [];
      rows.length = 2;
      return { rows };
    },
    () => ({ body: NaN }),
  ])
    fixture(({ registry, profile }) => {
      registry.register(secret);
      const result = api.sanitizeProductionArtifact(profile, { kind: "journal", value: make() });
      assert.equal(result.taskSecretStatus, "UNAVAILABLE");
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.data, null);
      assertNoCopies(result);
      assert.throws(() => registry.openScan());
      const next = api.sanitizeProductionArtifact(profile, {
        kind: "export",
        value: { body: { contentDisposition: secret } },
      });
      assert.equal(next, null);
      assert.equal(api.productionArtifactFailureCode(profile), "artifact-uncheckable");
    });
});

test("credential authority requires the entire original token even when a registered prefix already matches", () => {
  for (const credentialField of ["refreshToken", "idToken", "access_token", "apiKey"])
    fixture(({ registry, profile }) => {
      const prefix = "SYNTHETIC_ARTIFACT_PREFIX",
        suffix = "NEW_COMPONENT_opaque",
        token = `GOCSPX-${prefix}_${suffix}`;
      registry.register(prefix);
      const result = api.sanitizeProductionArtifact(profile, {
        kind: "auth-proof",
        value: { body: { [credentialField]: token } },
      });
      assert.equal(result.taskSecretStatus, "UNAVAILABLE");
      assert.equal(result.data, null);
      assert.throws(() => registry.openScan());
    });
  fixture(({ registry, profile }) => {
    const token = "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N";
    registry.register(token);
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "auth-proof",
      value: { body: { refreshToken: token } },
    });
    assert.equal(result.taskSecretStatus, "AVAILABLE");
    assert.equal(result.data.body.refreshToken.sha256, hash(token));
  });
});

test("unregistered credential-looking copies halt even outside a credential field", () => {
  fixture(({ registry, profile }) => {
    const token = "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ACT_TOKEN";
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "journal",
      value: { body: { contentDisposition: token } },
    });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(result.data, null);
    assert.throws(() => registry.openScan());
  });
});

test("even a known resource literal or numeric field is committed when it copies a registered credential", () => {
  fixture(({ registry, profile }) => {
    registry.register(resources.apiKeyResource);
    registry.register("200");
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "manifest",
      value: { apiKeyResource: resources.apiKeyResource, status: 200 },
    });
    assert.equal(result.taskSecretStatus, "AVAILABLE");
    assert.equal(result.data.apiKeyResource.sha256, hash(resources.apiKeyResource));
    assert.equal(result.data.status.sha256, hash("200"));
  });
});

test("serialized byte, dense array, depth and node bounds fail before persistence", () => {
  fixture(({ profile }) => {
    const value = { rows: Array(256).fill("!".repeat(8192)) },
      limit = 2097152;
    const excess = Buffer.byteLength(JSON.stringify(value)) - limit;
    value.rows[255] = value.rows[255].slice(0, -excess);
    assert.equal(Buffer.byteLength(JSON.stringify(value)), limit);
    assert.equal(
      api.sanitizeProductionArtifact(profile, { kind: "manifest", value }).taskSecretStatus,
      "AVAILABLE",
    );
    value.rows[255] += "!";
    assert.equal(
      api.sanitizeProductionArtifact(profile, { kind: "manifest", value }).taskSecretStatus,
      "UNAVAILABLE",
    );
  });
  for (const value of [
    { rows: Array(257).fill(null) },
    { body: "x".repeat(8193) },
    { rows: Array.from({ length: 64 }, () => ({ rows: Array(64).fill(null) })) },
    Array.from({ length: 17 }).reduce((body) => ({ body }), {}),
  ])
    fixture(({ profile }) =>
      assert.equal(
        api.sanitizeProductionArtifact(profile, { kind: "manifest", value }).taskSecretStatus,
        "UNAVAILABLE",
      ),
    );
});

test("scan work exhaustion withholds uncheckable output and closes later artifact calls", () => {
  fixture(({ profile, registry }) => {
    const value = { rows: Array(256).fill("x".repeat(8192)) };
    const excess = Buffer.byteLength(JSON.stringify(value)) - 2097152;
    value.rows[255] = value.rows[255].slice(0, -excess);
    const body = JSON.stringify(value);
    const result = api.sanitizeProductionArtifact(profile, { kind: "manifest", value });
    assert.equal(result, null);
    assert.equal(api.productionArtifactFailureCode(profile), "artifact-uncheckable");
    assert.equal(Buffer.byteLength(body), 2097152);
    assert.equal(registry.snapshot().failed, true);
    assert.equal(registry.snapshot().closed, true);
    assert.throws(() => registry.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
    assert.equal(
      api.sanitizeProductionArtifact(profile, { kind: "journal", value: { status: 200 } }),
      null,
    );
  });
});

test("a labelled credential accepts only the complete registered string, including opaque password values", () => {
  for (const value of [
    "opaque-unregistered-password",
    null,
    true,
    123,
    ["opaque-unregistered-password"],
    { body: "opaque-unregistered-password" },
  ])
    fixture(({ profile, registry }) => {
      const result = api.sanitizeProductionArtifact(profile, {
        kind: "intent",
        value: { password: value },
      });
      assert.equal(result.taskSecretStatus, "UNAVAILABLE");
      assert.equal(result.data, null);
      assert.equal(registry.snapshot().closed, true);
    });
  fixture(({ profile, registry }) => {
    const password = "opaque-registered-password";
    registry.register(password);
    const result = api.sanitizeProductionArtifact(profile, { kind: "intent", value: { password } });
    assert.equal(result.taskSecretStatus, "AVAILABLE");
    assert.equal(result.data.password.sha256, hash(password));
  });
});
test("the record field cap is exact even when all supplied names belong to the closed privacy vocabulary", () => {
  const names =
    `type recording phase operationId sequence status recipeId stepId bucket prefix name objectName method
ownedGeneration ownedMetageneration ownedUid ownedUidSha256 accountRef accountMutation absent slotId placement
bodyByteLength bodySha256 stage adcSha256 adcType clientId principalSha256 scopeSha256 accessTokenSha256
accessTokenByteLength exchangeBodySha256 tokeninfoBodySha256 deadlineMonotonicMs uidSha256 tokenSha256 tokenByteLength
responseBodySha256 checkpoint sourceSha256 releaseBodySha256 rulesetBodySha256 bucketlessBodySha256 bucketlessAbsent
label pages releaseCount exhausted state releaseName rulesetName releaseAbsent rulesetAbsent namespaceEmpty
continuationOf ifGenerationMatch credentialProof rulesSourceSha256 loaded localOnly rulesetResource apiKeyResource projectId projectNumber runId rows`.split(
      /\s+/,
    );
  fixture(({ profile }) =>
    assert.equal(
      api.sanitizeProductionArtifact(profile, {
        kind: "manifest",
        value: Object.fromEntries(names.slice(0, 64).map((name) => [name, null])),
      }).taskSecretStatus,
      "AVAILABLE",
    ),
  );
  fixture(({ profile }) =>
    assert.equal(
      api.sanitizeProductionArtifact(profile, {
        kind: "manifest",
        value: Object.fromEntries(names.slice(0, 65).map((name) => [name, null])),
      }).taskSecretStatus,
      "UNAVAILABLE",
    ),
  );
});

test("unknown kinds and hostile reflection cannot invoke an input hook", () => {
  fixture(({ profile, registry }) => {
    let hooks = 0;
    const value = new Proxy(
      { status: 200 },
      {
        getPrototypeOf() {
          hooks++;
          throw new Error();
        },
      },
    );
    const result = api.sanitizeProductionArtifact(profile, { kind: "journal", value });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(hooks, 0);
    assert.equal(registry.snapshot().closed, true);
  });
  fixture(({ profile, registry }) => {
    let hooks = 0;
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "undeclared-kind",
      get value() {
        hooks++;
        return {};
      },
    });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(hooks, 0);
    assert.equal(registry.snapshot().closed, true);
  });
});

test("a plain unknown kind and a known field name copied from the registry stop the task", () => {
  fixture(({ profile, registry }) => {
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "undeclared-kind",
      value: { status: 200 },
    });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(registry.snapshot().closed, true);
  });
  fixture(({ profile, registry }) => {
    registry.register("contentDisposition");
    const result = api.sanitizeProductionArtifact(profile, {
      kind: "journal",
      value: { body: { contentDisposition: "opaque" } },
    });
    assert.equal(result.taskSecretStatus, "UNAVAILABLE");
    assert.equal(result.data, null);
    assert.equal(registry.snapshot().closed, true);
  });
});

for (const [name, secretValue, value] of [
  ["fixed type", "SHA256_OF_ORIGINAL_BYTES", { body: "opaque" }],
  ["projected digest", hash("opaque"), { body: "opaque" }],
  ["source digest", hash(JSON.stringify({ body: "opaque" })), { body: "opaque" }],
  [
    "unknown fallback digest",
    hash(JSON.stringify({ metadata: { future: "opaque" } })),
    { metadata: { future: "opaque" } },
  ],
])
  test(`${name} collisions with a registered credential withhold every persistable artifact`, () => {
    fixture(({ profile, registry }) => {
      registry.register(secretValue);
      const before = JSON.stringify(value);
      assert.equal(api.sanitizeProductionArtifact(profile, { kind: "journal", value }), null);
      assert.equal(registry.snapshot().closed, true);
      assert.equal(api.productionArtifactFailureCode(profile), "artifact-withheld-privacy");
      assert.equal(JSON.stringify(value), before);
      assert.equal(
        api.sanitizeProductionArtifact(profile, { kind: "manifest", value: { status: 200 } }),
        null,
      );
    });
  });
