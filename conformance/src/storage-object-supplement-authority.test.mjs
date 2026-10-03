import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, mkdtemp, writeFile, chmod, symlink, realpath, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
    const alias = join(directory, "alias.json");
    await symlink(path, alias);
    await assert.rejects(api.inspectLocalSupplementAdc({ ...input, path: alias }));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
