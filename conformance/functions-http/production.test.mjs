import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertAdmission,
  assertOwnedImage,
  assertPublicReadback,
  expiredAt,
  preflightCliSideEffects,
  summarizeCliOutput,
} from "./production.mjs";

test("stage 3 admission requires terminal stage 2, a quiet shared project and a 30-minute gap", () => {
  const lines = [
    {
      ts: "2026-09-25T09:00:00Z",
      project: "fireemu-oracle-query",
      taskId: "STORAGE-OBJECT-SANDBOX",
      outcome: "prepared",
    },
    {
      ts: "2026-09-25T09:10:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 2,
      outcome: "prepared",
    },
  ];
  assert.doesNotThrow(() => assertAdmission(lines, "2026-09-25T09:41:00Z"));
  assert.throws(() => assertAdmission(lines, "2026-09-25T09:39:59Z"), /30 minutes/);
  assert.throws(() => assertAdmission(lines.slice(0, 1), "2026-09-25T10:00:00Z"), /stage 2/);
  assert.throws(
    () =>
      assertAdmission(
        [
          ...lines,
          { ts: "2026-09-25T09:20:00Z", project: "fireemu-oracle-query", event: "started" },
        ],
        "2026-09-25T10:00:00Z",
      ),
    /active/,
  );
  assert.throws(
    () =>
      assertAdmission(
        [
          ...lines,
          {
            ts: "2026-09-25T09:20:00Z",
            project: "fireemu-oracle-query",
            taskId: "FUNCTIONS-HTTP-SANDBOX",
            stage: 3,
            event: "started",
          },
        ],
        "2026-09-25T10:00:00Z",
      ),
    /stage 3 attempt/,
  );
});

test("only a new image of the reserved function and repository can be removed", () => {
  const image =
    "us-central1-docker.pkg.dev/fireemu-oracle-query/gcf-artifacts/fireemu--oracle--query__us--central1__fireemu_http_probe@sha256:" +
    "a".repeat(64);
  assert.deepEqual(assertOwnedImage(image, "http"), {
    packageId: "fireemu--oracle--query__us--central1__fireemu_http_probe",
    digest: "sha256:" + "a".repeat(64),
    tag: null,
  });
  assert.deepEqual(
    assertOwnedImage(image.replace(`@sha256:${"a".repeat(64)}`, ":build-123"), "http"),
    {
      packageId: "fireemu--oracle--query__us--central1__fireemu_http_probe",
      digest: null,
      tag: "build-123",
    },
  );
  assert.throws(
    () => assertOwnedImage(image.replace("fireemu-oracle-query", "other-project"), "http"),
    /image/,
  );
  assert.throws(
    () => assertOwnedImage(image.replace("fireemu_http_probe", "other"), "http"),
    /image/,
  );
});

test("IAM readback permits only the intended service-level public invoker binding", () => {
  assertPublicReadback({ bindings: [{ role: "roles/run.invoker", members: ["allUsers"] }] }, true);
  assertPublicReadback({ bindings: [] }, false);
  assert.throws(
    () =>
      assertPublicReadback({ bindings: [{ role: "roles/editor", members: ["allUsers"] }] }, true),
    /allUsers/,
  );
  assert.throws(() => assertPublicReadback({ bindings: [] }, true), /public invoker/);
});

test("expiration requires a signed token and a real past exp", () => {
  const header = Buffer.from('{"alg":"RS256"}').toString("base64url");
  const payload = Buffer.from('{"exp":1000}').toString("base64url");
  const token = `${header}.${payload}.signature`;
  assert.equal(expiredAt(token), 1000);
  assert.throws(() => expiredAt(`${header}.${payload}.`), /signed/);
});

test("CLI output reports auto API enablement without revealing captured text", () => {
  assert.deepEqual(summarizeCliOutput("Deploy complete!", 0), {
    exitCode: 0,
    autoEnabledApi: false,
  });
  assert.deepEqual(summarizeCliOutput("Enabling API run.googleapis.com...", 0), {
    exitCode: 0,
    autoEnabledApi: true,
  });
  assert.deepEqual(
    summarizeCliOutput("ensuring required API run.googleapis.com is enabled...", 0),
    { exitCode: 0, autoEnabledApi: false },
  );
});

test("CLI preflight refuses disabled Pub/Sub or a repository without cleanup policy", async () => {
  const names = [
    "cloudfunctions",
    "cloudbuild",
    "artifactregistry",
    "run",
    "eventarc",
    "pubsub",
    "storage",
  ].map((name) => ({ config: { name: `${name}.googleapis.com` } }));
  const repo = {
    name: "projects/fireemu-oracle-query/locations/us-central1/repositories/gcf-artifacts",
    cleanupPolicies: { held: { action: "DELETE" } },
  };
  const control = async (_method, url) =>
    url.includes("serviceusage.googleapis.com")
      ? { value: { services: names } }
      : { status: 200, value: repo };
  await preflightCliSideEffects(control);
  await assert.rejects(
    () =>
      preflightCliSideEffects(async (method, url) => {
        const result = await control(method, url);
        if (url.includes("serviceusage"))
          result.value.services = names.filter(
            (row) => row.config.name !== "pubsub.googleapis.com",
          );
        return result;
      }),
    /disabled required API/,
  );
  await assert.rejects(
    () =>
      preflightCliSideEffects(async (method, url) => {
        const result = await control(method, url);
        if (url.includes("artifactregistry")) result.value = { ...repo, cleanupPolicies: {} };
        return result;
      }),
    /cleanup policy/,
  );
});
