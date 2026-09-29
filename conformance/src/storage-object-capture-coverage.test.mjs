import assert from "node:assert/strict";
import test from "node:test";
import { storageCaptureBodyIsCovered } from "./storage-object/production-capture-body.mjs";
const module = await import("./storage-object/production-capture-coverage.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const name = "storage-object/recordone/coverage/object";
const bucket = "example.appspot.com";
const storageUrl = `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
const jsonHeaders = [
  ["Content-Type", "application/json"],
  ["Connection", "close"],
];
function profile(kind = "storage", url = storageUrl, changes = {}) {
  assert.equal(typeof module.createProductionCaptureProfile, "function");
  return module.createProductionCaptureProfile({
    kind,
    objectName: kind === "storage" ? name : null,
    method: kind === "storage" ? "GET" : "POST",
    url,
    sessionPhase: null,
    ...changes,
  });
}
function covered(capability, value, changes = {}) {
  assert.equal(typeof module.productionCaptureIsCovered, "function");
  return module.productionCaptureIsCovered(capability, {
    url: storageUrl,
    direction: "response",
    status: 200,
    complete: true,
    headers: jsonHeaders,
    body: Buffer.from(JSON.stringify(value)),
    bodyKind: "json",
    expectedObjectNames: [name],
    expectedBucket: bucket,
    ...changes,
  });
}
test("Storage schema coverage survives a known secret copy and rejects unknown fields and types", () => {
  const p = profile();
  assert.equal(covered(p, { name, contentDisposition: "SYNTHETIC_REGISTERED_COPY" }), true);
  for (const value of [
    { futureCapability: "SYNTHETIC_UNKNOWN" },
    { name, generation: 1 },
    { metadata: { futureCapability: "SYNTHETIC_UNKNOWN" } },
    { name: "foreign/object" },
  ])
    assert.equal(covered(p, value), false);
});
test("unknown and opaque public headers reject coverage before body projection", () => {
  for (const header of [
    ["X-New-Capability", "wrapper-SYNTHETIC_UNKNOWN-suffix"],
    ["Server", "wrapper-SYNTHETIC_UNKNOWN-suffix"],
    ["Content-Type", "application/json; capability=SYNTHETIC_UNKNOWN"],
    ["Date", "SYNTHETIC_UNKNOWN"],
    ["Content-Length", "999"],
    ["Authorization", "Unknown SYNTHETIC_UNKNOWN"],
  ])
    assert.equal(covered(profile(), { name }, { headers: [...jsonHeaders, header] }), false);
  assert.equal(
    covered(
      profile(),
      { name },
      {
        headers: [
          ...jsonHeaders,
          ["Server", "UploadServer"],
          ["Transfer-Encoding", "chunked"],
          ["X-Guploader-Uploadid", "SYNTHETIC_UPLOAD_ID"],
          ["Date", "Tue, 29 Sep 2026 00:00:00 GMT"],
        ],
      },
    ),
    true,
  );
});
test("profile identity, route, direction, completion and actual status cannot be substituted", () => {
  const p = profile();
  assert.equal(covered(structuredClone(p), { name }), false);
  for (const change of [
    { url: "https://storage.googleapis.com/foreign" },
    { direction: "unknown" },
    { complete: false },
    { status: null },
    { status: 103 },
    { status: 302 },
  ])
    assert.equal(covered(p, { name }, change), false);
  assert.throws(
    () => profile("owner-tokeninfo", "https://oauth2.googleapis.com/token"),
    /invalid production capture profile/,
  );
});
test("media success needs payload authority while declared JSON denial remains committed", () => {
  const p = profile("storage", `${storageUrl}?alt=media`);
  assert.equal(covered(p, { name }, { url: `${storageUrl}?alt=media`, bodyKind: "media" }), false);
  assert.equal(
    covered(
      p,
      { error: { code: 403, message: "Forbidden" } },
      { url: `${storageUrl}?alt=media`, bodyKind: "media", status: 403 },
    ),
    true,
  );
  assert.equal(
    covered(p, { name }, { url: `${storageUrl}?alt=media`, bodyKind: "media", status: 403 }),
    false,
  );
});
for (const [kind, url, value, method] of [
  [
    "project-binding",
    "https://cloudresourcemanager.googleapis.com/v1/projects/example-project",
    {
      projectId: "example-project",
      projectNumber: "123456789012",
      lifecycleState: "ACTIVE",
      name: "Example Project",
      createTime: "2026-09-29T00:00:00Z",
      labels: {},
    },
    "GET",
  ],
  [
    "default-bucket",
    "https://firebasestorage.googleapis.com/v1alpha/projects/example-project/defaultBucket",
    {
      name: "projects/example-project/defaultBucket",
      location: "US-CENTRAL1",
      bucket: { name: bucket },
    },
    "GET",
  ],
  [
    "bucket-config",
    `https://storage.googleapis.com/storage/v1/b/${bucket}`,
    {
      kind: "storage#bucket",
      name: bucket,
      id: bucket,
      projectNumber: "123456789012",
      metageneration: "1",
      generation: "2",
      location: "US-CENTRAL1",
      locationType: "region",
      storageClass: "STANDARD",
      timeCreated: "2026-09-29T00:00:00Z",
      updated: "2026-09-29T00:00:00Z",
      iamConfiguration: {
        bucketPolicyOnly: { enabled: true },
        uniformBucketLevelAccess: { enabled: true },
        publicAccessPrevention: "inherited",
      },
      softDeletePolicy: {
        retentionDurationSeconds: "604800",
        effectiveTime: "2026-09-29T00:00:00Z",
      },
      versioning: { enabled: false },
    },
    "GET",
  ],
  [
    "auth-config",
    "https://identitytoolkit.googleapis.com/admin/v2/projects/example-project/config",
    {
      name: "projects/example-project/config",
      subtype: "FIREBASE_AUTH",
      signIn: {
        email: { enabled: true, passwordRequired: true },
        phoneNumber: { enabled: false, testPhoneNumbers: {} },
        anonymous: { enabled: false },
        allowDuplicateEmails: false,
        hashConfig: {
          algorithm: "SCRYPT",
          signerKey: Buffer.from("SYNTHETIC_SIGNER").toString("base64"),
          saltSeparator: Buffer.from("SYNTHETIC_SEPARATOR").toString("base64"),
          rounds: 8,
          memoryCost: 14,
        },
      },
      authorizedDomains: ["localhost", "example.firebaseapp.com"],
      client: {
        apiKey: "SYNTHETIC_API_KEY",
        permissions: { disabledUserSignup: false, disabledUserDeletion: false },
        firebaseSubdomain: "example",
      },
      monitoring: { requestLogging: { enabled: false } },
      multiTenant: { allowTenants: false },
      mfa: { state: "DISABLED", enabledProviders: [], providerConfigs: [] },
      emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
    },
    "GET",
  ],
  [
    "api-key-metadata",
    "https://apikeys.googleapis.com/v2/projects/123456789012/locations/global/keys/synthetic",
    {
      name: "projects/123456789012/locations/global/keys/synthetic",
      uid: "synthetic",
      displayName: "Example key",
      createTime: "2026-09-29T00:00:00Z",
      restrictions: {
        apiTargets: [
          { service: "identitytoolkit.googleapis.com" },
          { service: "securetoken.googleapis.com" },
        ],
      },
      etag: "synthetic-etag",
    },
    "GET",
  ],
  [
    "owner-tokeninfo",
    "https://oauth2.googleapis.com/tokeninfo",
    {
      sub: "synthetic-subject",
      azp: "synthetic-client",
      aud: "synthetic-client",
      scope: "synthetic-scope",
      expires_in: "3600",
    },
    "POST",
  ],
  [
    "owner-exchange",
    "https://oauth2.googleapis.com/token",
    { access_token: "SYNTHETIC_ACCESS", token_type: "Bearer", expires_in: 3600 },
    "POST",
  ],
  [
    "rules-release",
    `https://firebaserules.googleapis.com/v1/projects/example-project/releases/firebase.storage/${bucket}`,
    {
      name: `projects/example-project/releases/firebase.storage/${bucket}`,
      rulesetName: "projects/example-project/rulesets/synthetic",
      createTime: "2026-09-29T00:00:00Z",
    },
    "GET",
  ],
  [
    "rules-ruleset",
    "https://firebaserules.googleapis.com/v1/projects/example-project/rulesets/synthetic",
    {
      name: "projects/example-project/rulesets/synthetic",
      source: { files: [{ name: "storage.rules", content: "synthetic rules source" }] },
    },
    "GET",
  ],
  [
    "auth-admin-lookup",
    "https://identitytoolkit.googleapis.com/v1/projects/example-project/accounts:lookup",
    {
      users: [
        {
          localId: "synthetic-uid",
          email: "synthetic@example.com",
          passwordHash: "SYNTHETIC_HASH",
          salt: "SYNTHETIC_SALT",
        },
      ],
    },
    "POST",
  ],
  [
    "auth-signup",
    "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=SYNTHETIC_API_KEY",
    {
      localId: "synthetic-uid",
      email: "synthetic@example.com",
      idToken: "SYNTHETIC_ID",
      refreshToken: "SYNTHETIC_REFRESH",
      expiresIn: "3600",
    },
    "POST",
  ],
])
  test(`normal committed controls have a closed response schema (${kind})`, () => {
    const p = profile(kind, url, { method });
    assert.equal(covered(p, value, { url }), true);
    assert.equal(covered(p, { ...value, futureCapability: "SYNTHETIC_UNKNOWN" }, { url }), false);
  });
test("configuration response schemas reject unclassified nested fields instead of accepting an object generically", () => {
  for (const [kind, url, value] of [
    [
      "project-binding",
      "https://cloudresourcemanager.googleapis.com/v1/projects/example-project",
      {
        projectId: "example-project",
        projectNumber: "123456789012",
        labels: { environment: { futureCapability: "SYNTHETIC_UNKNOWN" } },
      },
    ],
    [
      "bucket-config",
      `https://storage.googleapis.com/storage/v1/b/${bucket}`,
      {
        kind: "storage#bucket",
        name: bucket,
        iamConfiguration: {
          uniformBucketLevelAccess: { enabled: true, futureCapability: "SYNTHETIC_UNKNOWN" },
        },
      },
    ],
    [
      "auth-config",
      "https://identitytoolkit.googleapis.com/admin/v2/projects/example-project/config",
      {
        name: "projects/example-project/config",
        subtype: "FIREBASE_AUTH",
        signIn: {
          email: { enabled: true, passwordRequired: true, futureCapability: "SYNTHETIC_UNKNOWN" },
        },
      },
    ],
    [
      "api-key-metadata",
      "https://apikeys.googleapis.com/v2/projects/123456789012/locations/global/keys/synthetic",
      {
        name: "projects/123456789012/locations/global/keys/synthetic",
        restrictions: {
          apiTargets: [
            { service: "identitytoolkit.googleapis.com", futureCapability: "SYNTHETIC_UNKNOWN" },
          ],
        },
      },
    ],
  ])
    assert.equal(covered(profile(kind, url, { method: "GET" }), value, { url }), false);
});
test("nonempty configuration maps cannot grant privacy coverage to opaque components", () => {
  for (const [kind, url, value] of [
    [
      "project-binding",
      "https://cloudresourcemanager.googleapis.com/v1/projects/example-project",
      {
        projectId: "example-project",
        projectNumber: "123456789012",
        labels: { environment: "opaque-capability" },
      },
    ],
    [
      "project-binding",
      "https://cloudresourcemanager.googleapis.com/v1/projects/example-project",
      {
        projectId: "example-project",
        projectNumber: "123456789012",
        tags: { environment: "opaque-capability" },
      },
    ],
    [
      "bucket-config",
      `https://storage.googleapis.com/storage/v1/b/${bucket}`,
      { kind: "storage#bucket", name: bucket, labels: { environment: "opaque-capability" } },
    ],
    [
      "api-key-metadata",
      "https://apikeys.googleapis.com/v2/projects/123456789012/locations/global/keys/synthetic",
      {
        name: "projects/123456789012/locations/global/keys/synthetic",
        annotations: { environment: "prefix[opaque-capability]suffix" },
      },
    ],
  ])
    assert.equal(covered(profile(kind, url, { method: "GET" }), value, { url }), false);
});

test("session acknowledgements require the canonical phase and status instead of the literal OK alone", () => {
  const ack = { body: Buffer.from("OK"), headers: [["Connection", "close"]] };
  assert.equal(covered(profile(), {}, ack), false);
  const url = `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=resumable&name=${encodeURIComponent(name)}`;
  const p = profile("storage", url, { method: "POST", sessionPhase: "initiate" });
  assert.equal(
    covered(
      p,
      {},
      {
        ...ack,
        url,
        headers: [
          ...ack.headers,
          [
            "Location",
            `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=resumable&upload_id=SYNTHETIC_UPLOAD`,
          ],
        ],
      },
    ),
    true,
  );
  assert.equal(covered(p, {}, { ...ack, url }), false);
});
test("profile getters and proxy traps are never invoked", () => {
  let calls = 0;
  const supplied = {
    kind: "storage",
    method: "GET",
    url: storageUrl,
    sessionPhase: null,
    objectName: name,
  };
  for (const value of [
    new Proxy(supplied, {
      ownKeys() {
        calls++;
        throw new Error();
      },
    }),
    Object.defineProperty({ ...supplied }, "kind", {
      enumerable: true,
      get() {
        calls++;
        return "storage";
      },
    }),
  ])
    assert.throws(
      () => module.createProductionCaptureProfile(value),
      /invalid production capture profile/,
    );
  assert.equal(calls, 0);
});

test("coverage snapshots header arrays and original Buffer bytes without invoking hooks", () => {
  let hooks = 0;
  const p = profile(),
    body = Buffer.from(JSON.stringify({ name }));
  Object.defineProperty(body, "length", {
    get() {
      hooks++;
      return 0;
    },
  });
  Object.defineProperty(body, "byteLength", {
    get() {
      hooks++;
      return 0;
    },
  });
  assert.equal(covered(p, {}, { body }), true);
  assert.equal(
    storageCaptureBodyIsCovered(body, { expectedObjectNames: [name], expectedBucket: bucket }),
    true,
  );
  const headers = [["Connection", "close"]];
  Object.defineProperty(headers, "0", {
    enumerable: true,
    get() {
      hooks++;
      return ["Connection", "close"];
    },
  });
  assert.equal(covered(p, { name }, { headers }), false);
  const options = Object.defineProperty({}, "expectedObjectNames", {
    enumerable: true,
    get() {
      hooks++;
      return [name];
    },
  });
  assert.equal(storageCaptureBodyIsCovered(Buffer.from(JSON.stringify({ name })), options), false);
  assert.equal(hooks, 0);
});

for (const dialect of ["gcs", "firebase"])
  test(`session URI coverage agrees with the canonical dialect (${dialect})`, () => {
    const origin =
      dialect === "gcs"
        ? "https://storage.googleapis.com"
        : "https://firebasestorage.googleapis.com";
    const path = dialect === "gcs" ? `/upload/storage/v1/b/${bucket}/o` : `/v0/b/${bucket}/o`;
    const url = `${origin}${path}?name=${encodeURIComponent(name)}${dialect === "gcs" ? "&uploadType=resumable" : ""}`;
    const uri = `${origin}${path}?${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable&name=${encodeURIComponent(name)}&upload_id=SYNTHETIC%2fCAPABILITY`;
    const headers =
      dialect === "gcs"
        ? [["Location", uri]]
        : [
            ["X-Goog-Upload-URL", uri],
            ["X-Goog-Upload-Status", "active"],
          ];
    assert.equal(
      covered(
        profile("storage", url, { method: "POST", sessionPhase: "initiate" }),
        {},
        { url, body: Buffer.alloc(0), headers },
      ),
      true,
    );
  });
