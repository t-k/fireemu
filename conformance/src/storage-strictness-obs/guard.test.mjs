import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  classifyRequest,
  GuardError,
  isUnknownStatus,
  isSuccess,
  RequestBudget,
  requests,
  SEND_FLAG,
  targetOf,
} from "./guard.mjs";
import { createProductionClient } from "./wire.mjs";
import { rehearsalConfig } from "./rehearse.mjs";

const target = targetOf({
  project: "fireemu-oracle-query",
  defaultBucket: "fireemu-oracle-query.firebasestorage.app",
  runId: "ss-0123abcd",
});
const authenticated = (r, local = false) => ({
  ...r,
  headers: {
    ...r.headers,
    ...(r.auth === "malformed" || (!local && r.auth !== "none")
      ? { authorization: r.auth === "malformed" ? "Firebase not-a-jwt" : "Bearer synthetic-owner" }
      : {}),
  },
});

test("every planned request is classified in production and loopback modes", () => {
  for (const t of [target, { ...target, local: "http://127.0.0.1:9199" }]) {
    for (const r of Object.values(requests(t, "EU")))
      assert.equal(classifyRequest(t, authenticated(r, Boolean(t.local)), "EU").case, r.case);
  }
});

test("near misses cannot escape the exact request vocabulary", () => {
  const plan = requests(target);
  const get = authenticated(plan.A1);
  for (const [from, to] of [
    ["storage.googleapis.com", "example.com"],
    ["storage.googleapis.com", "storage.googleapis.com.evil.example"],
    ["storage.googleapis.com", "firebasestorage.googleapis.com"],
    ["storage.googleapis.com", "storage.googleapis.com:443"],
    ["storage.googleapis.com", "storage.googleapis.com:8443"],
    ["https://", "http://"],
    ["https://", "https://user:pw@"],
    [target.missingBucket, "other-bucket"],
    ["/o/x", "/o/y"],
    ["/o/x", "/o/%78"],
    [target.missingBucket, target.tempBucket],
    [target.missingBucket, target.defaultBucket],
  ])
    assert.throws(
      () => classifyRequest(target, { ...get, url: get.url.replace(from, to) }),
      GuardError,
    );
  for (const suffix of [
    "?alt=media",
    "?unknown=1",
    "#fragment",
    "?access_token=synthetic",
    "/../x",
  ])
    assert.throws(() => classifyRequest(target, { ...get, url: get.url + suffix }), GuardError);
  for (const id of ["W4", "F1", "F2", "K6"]) {
    const request = authenticated(plan[id]);
    assert.throws(
      () =>
        classifyRequest(target, {
          ...request,
          url: request.url.replace("ss-0123abcd", "ss-ffffffff"),
        }),
      GuardError,
    );
  }
  assert.throws(
    () =>
      classifyRequest(target, {
        ...authenticated(plan.W3),
        url: plan.W3.url.replace("cors%2Fo.txt", "outside.txt"),
      }),
    GuardError,
  );
  for (const request of [
    {
      ...authenticated(plan.W1),
      body: plan.W1.body.replace(target.tempBucket, target.missingBucket),
    },
    { ...authenticated(plan.W1), body: plan.W1.body.replace("true", "false") },
    { ...authenticated(plan.W4), body: "fires" },
    { ...authenticated(plan.P4), url: plan.P4.url + "&prefix=other" },
    { ...authenticated(plan.A1), method: "DELETE" },
    {
      ...authenticated(plan.C1),
      headers: { ...plan.C1.headers, authorization: "Bearer synthetic" },
    },
    {
      ...authenticated(plan.A1),
      headers: { authorization: "Bearer synthetic", host: "example.com" },
    },
  ])
    assert.throws(() => classifyRequest(target, request), GuardError);
});

test("local mode rejects production hosts and credentials", () => {
  const local = { ...target, local: "http://localhost:9199" };
  assert.throws(() => classifyRequest(local, authenticated(requests(target).P1)), GuardError);
  assert.throws(() => classifyRequest(local, authenticated(requests(local).P1)), GuardError);
  for (const url of [
    "https://storage.googleapis.com",
    "http://example.com",
    "http://user@localhost:9199",
    "http://localhost:9199/path",
  ])
    assert.throws(() => targetOf({ ...target, local: url }), GuardError);
  const config = rehearsalConfig(target);
  assert.equal(config.profile, "strict");
  assert.equal(config.storage.undeclaredBuckets, "refuse");
  assert.deepEqual(config.storage.buckets, [target.defaultBucket, target.tempBucket]);
  assert.equal(config.storage.defaultBucket, "firebasestorage.app");
});

test("the budget admits sixty requests and refuses the sixty-first without incrementing", () => {
  const budget = new RequestBudget();
  for (let i = 1; i <= 60; i++) assert.equal(budget.take(), i);
  assert.throws(() => budget.take(), GuardError);
  assert.equal(budget.count, 60);
});

test("unknown statuses include informational, redirect, server and missing answers", () => {
  for (const status of [null, undefined, NaN, 0, 199, 300, 302, 399, 500, 599])
    assert.equal(isUnknownStatus(status), true);
  for (const status of [200, 204, 299, 400, 403, 404, 409, 412, 499])
    assert.equal(isUnknownStatus(status), false);
});

test("production refuses without the launch flag before invoking any fetch", () => {
  let calls = 0;
  for (const send of [false, true])
    assert.throws(
      () =>
        createProductionClient(target, {
          send,
          token: "synthetic",
          env: {},
          fetchImpl: () => {
            calls++;
          },
        }),
      /flag/,
    );
  assert.equal(calls, 0);
});

test("the credential-isolated guard process has an empty HOME and no credential overrides", () => {
  const home = mkdtempSync(join(tmpdir(), "strictness-home-"));
  try {
    const env = { ...process.env, HOME: home };
    for (const key of Object.keys(env))
      if (
        key === "GOOGLE_APPLICATION_CREDENTIALS" ||
        key.startsWith("CLOUDSDK_") ||
        key === SEND_FLAG
      )
        delete env[key];
    const code = `
      import assert from 'node:assert/strict';
      import { readdirSync } from 'node:fs';
      import { createProductionClient } from ${JSON.stringify(new URL("./wire.mjs", import.meta.url).href)};
      assert.deepEqual(readdirSync(process.env.HOME), []);
      assert.equal(Object.keys(process.env).some(k => k === 'GOOGLE_APPLICATION_CREDENTIALS' || k.startsWith('CLOUDSDK_')), false);
      assert.equal(process.env.STORAGE_STRICTNESS_OBS_PRODUCTION_SEND, undefined);
      assert.throws(() => createProductionClient(${JSON.stringify(target)}, {send: true, token: 'synthetic'}), /flag/);
      console.log('isolated guard passed');
    `;
    assert.equal(
      execFileSync(process.execPath, ["--input-type=module", "-e", code], {
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim(),
      "isolated guard passed",
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("status predicates distinguish every adjacent boundary", () => {
  for (const [status, unknown, success] of [
    [199, true, false],
    [200, false, true],
    [299, false, true],
    [300, true, false],
    [399, true, false],
    [400, false, false],
    [499, false, false],
    [500, true, false],
    [200.5, true, false],
    [null, true, false],
  ]) {
    assert.equal(isUnknownStatus(status), unknown, String(status));
    assert.equal(isSuccess(status), success, String(status));
  }
});

test("request classification rejects independently changed scope and request fields", () => {
  const plan = requests(target);
  const request = authenticated(plan.W1);
  for (const key of ["tempBucket", "missingBucket", "prefix", "local"])
    assert.throws(
      () =>
        classifyRequest(
          { ...target, [key]: key === "local" ? "http://localhost:80" : "different" },
          request,
        ),
      GuardError,
      key,
    );
  for (const changed of [
    { case: "not-planned" },
    { url: request.url + "&extra=1" },
    { method: "GET" },
    { body: "different" },
    { headers: {} },
    { headers: { ...request.headers, authorization: "Bearer two words" } },
    { headers: { ...request.headers, authorization: "Basic synthetic" } },
  ])
    assert.throws(() => classifyRequest(target, { ...request, ...changed }), GuardError);
  const malformed = authenticated(plan.F1);
  assert.throws(
    () => classifyRequest(target, { ...malformed, headers: { authorization: "Bearer synthetic" } }),
    GuardError,
  );
  assert.throws(() => requests(target, "x".repeat(65)), GuardError);
  assert.doesNotThrow(() => requests(target, "x".repeat(64)));
  assert.deepEqual(JSON.parse(plan.W1.body).cors[1], {
    origin: ["http://localhost:3000"],
    method: ["PUT", "GET"],
    responseHeader: ["Content-Type"],
    maxAgeSeconds: 600,
  });
  for (const local of [
    "ftp://localhost",
    "http://localhost/?x=1",
    "http://localhost/#x",
    "http://localhost:123/a",
  ])
    assert.throws(() => targetOf({ ...target, local }), GuardError);
});
