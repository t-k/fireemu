import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, mkdtemp, writeFile, chmod, symlink, realpath, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { supplementPlan, SUPPLEMENT_PATHS } from "./storage-object/supplement.mjs";

let api = {};
try {
  api = await import("./storage-object/supplement-record.mjs");
} catch (error) {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
}
const digest = (value) => createHash("sha256").update(value).digest("hex");

test("strict authority JSON rejects duplicate and escaped duplicate keys and non-data objects", () => {
  assert.equal(typeof api.parseSupplementJson, "function");
  assert.throws(
    () => api.parseSupplementJson('{"schemaVersion":2,"schemaVersion":1}'),
    /DUPLICATE/,
  );
  assert.throws(() => api.parseSupplementJson('{"name":1,"na\\u006de":2}'), /DUPLICATE/);
  assert.throws(() => api.parseSupplementJson('{"x":{"a":1,"a":2}}'), /DUPLICATE/);
  assert.deepEqual(api.parseSupplementJson('{"a":[1,"name",{"b":2}]}'), {
    a: [1, "name", { b: 2 }],
  });
});

test("original five role rows are byte-exact and never issue native authority", async (context) => {
  assert.equal(typeof api.verifyOriginalRoleRows, "function");
  const path = process.env.FIREEMU_STORAGE_OBJECT_TEST_ROLE_FIXTURE;
  if (!path) {
    context.skip("private canonical role fixture required for final positive gate");
    return;
  }
  const bytes = await readFile(path);
  assert.equal(digest(bytes), "194aa9daa43817c996152813914af979b48715ca0e9371d43d7a4814dfaa1119");
  const fixture = JSON.parse(bytes);
  assert.equal(fixture.kind, "ORIGINAL_ROLE_ROWS_TEST_FIXTURE_NOT_AUTHORITY");
  const result = api.verifyOriginalRoleRows(fixture.rows);
  assert.equal(result.sendAuthorized, false);
  assert.equal(result.actor, "Codex（調整役。台帳790/795によるClaude代行）");
  for (let index = 0; index < 5; index++) {
    const changed = structuredClone(fixture.rows);
    changed[index].rawWithoutLF += " ";
    assert.throws(() => api.verifyOriginalRoleRows(changed), /ROLE/);
    changed[index].sha256 = digest(changed[index].rawWithoutLF);
    assert.throws(() => api.verifyOriginalRoleRows(changed), /ROLE/);
  }
  assert.throws(() => api.verifyOriginalRoleRows(fixture.rows.slice(1)), /ROLE/);
});

test("Root production entry rejects caller supplied authority and imported modules perform no native IO", async () => {
  assert.equal(typeof api.runRootSupplement, "function");
  for (const facade of [
    { approved: true },
    { fetch: () => true },
    { epoch: {} },
    { currentPath: "/tmp/fake" },
  ])
    await assert.rejects(api.runRootSupplement(facade), /NO_ARGUMENTS/);
  assert.equal(
    api
      .productionInputPaths()
      .current.endsWith("/docs.local/runs/storage-object-native-supplement/current.json"),
    true,
  );
});

function localPacket() {
  const files = [
    ...SUPPLEMENT_PATHS,
    "conformance/src/storage-object-compare/normalize.mjs",
    "conformance/src/storage-object-compare/compare.mjs",
  ].map((path) => ({ path, sha256: "b".repeat(64) }));
  const ref = { path: "/local-only/not-authority.json", sha256: "c".repeat(64) };
  return {
    schemaVersion: 2,
    kind: "ROOT_STORAGE_OBJECT_SUPPLEMENT",
    actor: api.ROOT_ACTOR,
    basis: api.ROOT_BASIS,
    foundation: api.ORIGINAL_ROLE_PINS.map(([line, sha256]) => ({ line, sha256 })),
    source: {
      commit: "a".repeat(40),
      node: "v24.14.0",
      files,
      closureSha256: digest(JSON.stringify(files)),
      planSha256: digest(JSON.stringify(supplementPlan())),
    },
    grant: {
      taskId: "STORAGE-OBJECT-SANDBOX",
      stage: "record1",
      recording: 1,
      runId: "a".repeat(20),
      nonce: "d".repeat(64),
      issuedAt: "2026-10-03T00:00:00Z",
      expiresAt: "2026-10-03T01:00:00Z",
      maxPhysicalRequests: 67,
      campaignId: "local-test-only",
      writes: true,
      retries: 0,
      redirects: 0,
      stopOnUnknown: true,
    },
    adc: {
      path: "/local-only/fake-adc.json",
      expectedSha256: "e".repeat(64),
      expectedClientId: "prior-client",
      expectedQuotaProjectId: "fireemu-oracle-query",
    },
    principal: {
      subject: "prior-subject",
      clientId: "prior-client",
      requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
    },
    principalReceipt: ref,
    target: {
      projectId: "fireemu-oracle-query",
      projectNumber: "123456789",
      bucket: "fireemu-oracle-query.firebasestorage.app",
      firebaseMappingReceipt: ref,
    },
    rules: {
      releaseName:
        "projects/fireemu-oracle-query/releases/firebase.storage/fireemu-oracle-query.firebasestorage.app",
      rulesetName: "projects/fireemu-oracle-query/rulesets/local",
      createTime: "2026-10-03T00:00:00Z",
      updateTime: "2026-10-03T00:00:00Z",
      sourceSha256: "f".repeat(64),
      acceptedReceipt: ref,
    },
    cost: ref,
  };
}
test("closed packet rejects old actor, weak approval, changed source and all enlarged request grants", () => {
  assert.equal(typeof api.validateSupplementPacket, "function");
  const packet = localPacket();
  assert.equal(api.validateSupplementPacket(packet).sendAuthorized, false);
  for (const change of [
    (value) => {
      value.approved = true;
    },
    (value) => {
      value.actor = "Claude";
    },
    (value) => {
      value.foundation.pop();
    },
    (value) => {
      value.source.files[0].sha256 = "0".repeat(64);
    },
    (value) => {
      value.grant.maxPhysicalRequests = 68;
    },
    (value) => {
      value.grant.retries = 1;
    },
    (value) => {
      value.grant.redirects = 1;
    },
    (value) => {
      value.grant.stopOnUnknown = false;
    },
    (value) => {
      value.adc.expectedClientId = "other";
    },
    (value) => {
      value.target.projectId = "other";
    },
  ]) {
    const changed = structuredClone(packet);
    change(changed);
    assert.throws(() => api.validateSupplementPacket(changed));
  }
  const precheck = structuredClone(packet);
  precheck.grant.stage = "precheck";
  precheck.grant.recording = 0;
  precheck.grant.maxPhysicalRequests = 8;
  precheck.grant.writes = false;
  precheck.rules = null;
  assert.throws(() => api.validateSupplementPacket(precheck), /GRANT/);
});

test("fresh raw E<V<GO keeps all roles and rejects latest replacement, targeted and delegation revocations", async (context) => {
  assert.equal(typeof api.verifySupplementDecisionRows, "function");
  const path = process.env.FIREEMU_STORAGE_OBJECT_TEST_ROLE_FIXTURE;
  if (!path) {
    context.skip("canonical positive fixture required for final gate");
    return;
  }
  const fixture = JSON.parse(await readFile(path));
  const packet = localPacket();
  const packetSha256 = digest(JSON.stringify(packet));
  const lines = Array.from({ length: 800 }, () => "local-test-only unused row");
  for (const row of fixture.rows) lines[row.line - 1] = row.rawWithoutLF;
  const references = {};
  for (const kind of ["E", "V", "GO"]) {
    const row = {
      kind,
      actor: api.ROOT_ACTOR,
      basis: api.ROOT_BASIS,
      foundation: packet.foundation,
      taskId: packet.grant.taskId,
      stage: packet.grant.stage,
      nonce: packet.grant.nonce,
      packetSha256,
      sourceCommit: packet.source.commit,
      review: {
        path: "/local-only/independent-review.json",
        sha256: "a".repeat(64),
        reviewer: "independent-codex-gpt-6.1-sol",
        decision: "APPROVE",
        must: 0,
        should: 0,
      },
      at: "2026-10-03T00:00:00Z",
    };
    const raw = "local-test-only OBJECT-SUPPLEMENT-V2 " + JSON.stringify(row);
    lines.push(raw);
    references[kind] = { line: lines.length, sha256: digest(raw) };
  }
  const verify = (ownerText, refs = references) =>
    api.verifySupplementDecisionRows({ ownerText, packet, packetSha256, references: refs });
  assert.equal(verify(lines.join("\n")).sendAuthorized, false);
  assert.throws(
    () => verify(lines.join("\n"), { ...references, E: references.GO }),
    /DECISION|ORDER/,
  );
  assert.throws(() => verify([...lines, lines.at(-1)].join("\n")), /LATEST/);
  for (const revocation of [
    `REVOKED packetSha256=${packetSha256}`,
    `REVOKED sourceCommit=${packet.source.commit.slice(0, 12)}`,
    "REVOKED STORAGE-OBJECT",
    "REVOKED 調整役への委任",
  ])
    assert.throws(() => verify([...lines, revocation].join("\n")), /REVOCATION/);
  assert.equal(
    verify([...lines, `REVOKED STORAGE-OBJECT packetSha256=${"0".repeat(64)}`].join("\n"))
      .sendAuthorized,
    false,
  );
});

test("one-pair owner request is POST form, tokeninfo is same-owner empty body, and no URL token", () => {
  assert.equal(typeof api.supplementOwnerRequest, "function");
  const exchange = api.supplementOwnerRequest("oauth", Buffer.from("grant_type=refresh_token"));
  const identity = api.supplementOwnerRequest("tokeninfo", Buffer.alloc(0));
  assert.equal(exchange.method, "POST");
  assert.equal(exchange.url, "https://oauth2.googleapis.com/token");
  assert.equal(identity.method, "POST");
  assert.equal(identity.url, "https://oauth2.googleapis.com/tokeninfo");
  assert.equal(identity.body.length, 0);
  assert.equal(Object.hasOwn(identity.headers, "authorization"), false);
  assert.throws(() => api.supplementOwnerRequest("tokeninfo", Buffer.from("access_token=fake")));
  assert.throws(() => api.supplementOwnerRequest("renewal", Buffer.alloc(0)));
});

test("token proof requires prior subject/client/scopes and actual bounded lifetime", () => {
  assert.equal(typeof api.verifySupplementTokenInfo, "function");
  const principal = {
    subject: "prior-subject",
    clientId: "prior-client",
    requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
  };
  const data = {
    sub: principal.subject,
    aud: principal.clientId,
    azp: principal.clientId,
    scope: principal.requiredScopes[0],
    expires_in: "3600",
  };
  assert.equal(
    api.verifySupplementTokenInfo({ data, principal, requestStartedAtMs: 100, receivedAtMs: 200 })
      .deadlineMonotonicMs,
    3600100,
  );
  for (const delta of [
    { sub: "other" },
    { aud: "other" },
    { azp: "other" },
    { scope: "other" },
    { expires_in: "0" },
    { expires_in: "3601" },
  ])
    assert.throws(() =>
      api.verifySupplementTokenInfo({
        data: { ...data, ...delta },
        principal,
        requestStartedAtMs: 100,
        receivedAtMs: 200,
      }),
    );
  assert.throws(() =>
    api.verifySupplementTokenInfo({ data, principal, requestStartedAtMs: 200, receivedAtMs: 100 }),
  );
});

test("native environment overrides stop before fixed Root inputs or credentials are read", async () => {
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    await assert.rejects(api.runRootSupplement(), /NATIVE_ENV_OVERRIDE/);
  } finally {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
});

test("local ADC primitive uses real file identity/hash/mode and does not issue native authority", async () => {
  assert.equal(typeof api.inspectLocalSupplementAdc, "function");
  const directory = await mkdtemp(join(await realpath(tmpdir()), "object-supplement-adc-"));
  const path = join(directory, "fake-adc.json");
  const body = JSON.stringify({
    type: "authorized_user",
    client_id: "fake-client",
    client_secret: "fake-secret",
    refresh_token: "fake-refresh",
    quota_project_id: "fake-project",
  });
  const input = {
    path,
    expectedSha256: digest(body),
    expectedClientId: "fake-client",
    expectedQuotaProjectId: "fake-project",
  };
  try {
    await writeFile(path, body, { mode: 0o600 });
    assert.equal((await api.inspectLocalSupplementAdc(input)).sendAuthorized, false);
    await assert.rejects(
      api.inspectLocalSupplementAdc({ ...input, expectedSha256: "0".repeat(64) }),
      /ADC/,
    );
    await chmod(path, 0o644);
    await assert.rejects(api.inspectLocalSupplementAdc(input), /UNSAFE_FILE/);
    await chmod(path, 0o600);
    await chmod(directory, 0o777);
    await assert.rejects(api.inspectLocalSupplementAdc(input), /UNSAFE_PARENT/);
    await chmod(directory, 0o700);
    const alias = join(directory, "alias.json");
    await symlink(path, alias);
    await assert.rejects(api.inspectLocalSupplementAdc({ ...input, path: alias }));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
