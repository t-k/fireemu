import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  assertAdmission,
  assertOwnedImage,
  assertPublicReadback,
  assertReviewApproval,
  expiredAt,
  preflightCliSideEffects,
  readPrivateProjectIdentity,
  readServiceAgentGrants,
  serviceAgentGrantChanges,
  summarizeCliOutput,
  writeCliDiagnostic,
} from "./production.mjs";

test("stage 3 approval accepts only one authoritative decision block", () => {
  const sha = "a".repeat(40);
  const digest = "b".repeat(64);
  const block = `Decision: APPROVE\ngitSha: ${sha}\ncorpusDigest: ${digest}\n`;
  assert.doesNotThrow(() => assertReviewApproval(block, sha, digest));
  assert.throws(
    () =>
      assertReviewApproval(
        `Decision: REJECT\ngitSha: ${sha}\ncorpusDigest: ${digest}\n\n${block}`,
        sha,
        digest,
      ),
    /APPROVE/,
  );
  assert.throws(
    () => assertReviewApproval(`# Review\n\n\`\`\`\n${block}\`\`\`\n`, sha, digest),
    /APPROVE/,
  );
  assert.throws(() => assertReviewApproval(`${block}\nDecision: REJECT\n`, sha, digest), /APPROVE/);
  assert.throws(
    () => assertReviewApproval(`${block}\n## Decision: REJECT\n`, sha, digest),
    /APPROVE/,
  );
  assert.throws(
    () => assertReviewApproval(block.replace(sha, "c".repeat(40)), sha, digest),
    /APPROVE/,
  );
});

test("stage 3 admission requires terminal stage 2, a quiet shared project and a 30-minute gap", () => {
  const lines = [
    {
      ts: "2026-09-25T09:00:00Z",
      project: "fireemu-oracle-query",
      taskId: "STORAGE-OBJECT-SANDBOX",
      corpusDigest: "fdd462cdae23ee9ccf17e3679622acf8e94781ba88b41d4f1d7d1b46f2785cc0",
      outcome: "preparation-complete",
    },
    {
      ts: "2026-09-25T09:10:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      corpusDigest: "54f45a96a4360969f093aa4469381710506022e4fd259ae2f2deefb876123c3c",
      outcome: "prepared",
    },
    {
      ts: "2026-09-24T08:23:52Z",
      project: "fireemu-oracle-query",
      taskId: "FS-CONFIG-LIFECYCLE-EXPLORE",
      event: "started",
    },
    {
      ts: "2026-09-24T08:24:23Z",
      project: "fireemu-oracle-query",
      taskId: "FS-CONFIG-LIFECYCLE-EXPLORE",
      event: "finished",
      outcome: { e1omit: { state: "SUCCESSFUL" } },
    },
  ];
  assert.doesNotThrow(() => assertAdmission(lines, "2026-09-25T09:41:00Z"));
  assert.throws(() => assertAdmission(lines, "2026-09-25T09:39:59Z"), /30 minutes/);
  assert.throws(
    () =>
      assertAdmission(
        lines.filter((line) => line.taskId !== "FUNCTIONS-HTTP-SANDBOX"),
        "2026-09-25T10:00:00Z",
      ),
    /stage 2/,
  );
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

test("failed CLI output is retained privately with credentials and email removed", async () => {
  const runDir = await mkdtemp(join(tmpdir(), "functions-http-cli-diagnostic-"));
  try {
    const output = [
      "Error: Permission denied: cloudfunctions.functions.create",
      "client.apiKey: AIza12345678901234567890123456789012345",
      "Authorization: Bearer ya29.secret-value",
      "owner@example.com",
    ].join("\n");
    const file = await writeCliDiagnostic(output, 1, "cliDeploy", 1, runDir);
    const details = JSON.parse(await readFile(file, "utf8"));
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal(details.exitCode, 1);
    assert.equal(details.kind, "cliDeploy");
    assert.match(details.output, /Permission denied: cloudfunctions.functions.create/);
    assert.doesNotMatch(details.output, /AIza|ya29|owner@example.com|client\.apiKey/);
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
});

test("CLI preflight requires the reviewed APIs and exact repository cleanup policy", async () => {
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
    format: "DOCKER",
    mode: "STANDARD_REPOSITORY",
    cleanupPolicies: {
      "firebase-functions-cleanup": {
        id: "firebase-functions-cleanup",
        condition: { tagState: "ANY", olderThan: "86400s" },
        action: "DELETE",
      },
    },
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
  for (const changed of [
    { cleanupPolicies: { held: { action: "DELETE" } } },
    { cleanupPolicyDryRun: true },
    { format: "MAVEN" },
    { cleanupPolicies: {}, labels: { "firebase-functions-cleanup-opted-out": "true" } },
  ]) {
    await assert.rejects(
      () =>
        preflightCliSideEffects(async (method, url) => {
          const result = await control(method, url);
          if (url.includes("artifactregistry")) result.value = { ...repo, ...changed };
          return result;
        }),
      /cleanup policy/,
    );
  }
});

test("project IAM readback records only Pub/Sub and Eventarc service-agent grants", async () => {
  const projectNumber = "1".repeat(13);
  const calls = [];
  const before = await readServiceAgentGrants(async (method, url, body, kind) => {
    calls.push({ method, url, body, kind });
    return { status: 200, value: { bindings: [] } };
  }, projectNumber);
  assert.deepEqual(calls, [
    {
      method: "POST",
      url:
        "https://cloudresourcemanager.googleapis.com/v3/projects/" +
        projectNumber +
        ":getIamPolicy",
      body: { options: { requestedPolicyVersion: 3 } },
      kind: "control",
    },
  ]);
  const after = await readServiceAgentGrants(
    async () => ({
      status: 200,
      value: {
        bindings: [
          {
            role: "roles/pubsub.serviceAgent",
            members: [
              "serviceAccount:service-" + projectNumber + "@gcp-sa-pubsub.iam.gserviceaccount.com",
            ],
          },
          {
            role: "roles/eventarc.serviceAgent",
            members: [
              "serviceAccount:service-" +
                projectNumber +
                "@gcp-sa-eventarc.iam.gserviceaccount.com",
            ],
          },
          { role: "roles/owner", members: ["user:someone@example.com"] },
        ],
      },
    }),
    projectNumber,
  );
  assert.deepEqual(serviceAgentGrantChanges(before, after), [
    { kind: "eventarc", role: "roles/eventarc.serviceAgent" },
    { kind: "pubsub", role: "roles/pubsub.serviceAgent" },
  ]);
  assert.throws(() => serviceAgentGrantChanges(after, before), /service-agent grant disappeared/);
});

test("project number is loaded only from a private identity file for the reviewed project", async () => {
  const runDir = await mkdtemp(join(tmpdir(), "functions-http-project-identity-"));
  const file = join(runDir, "project.json");
  const projectNumber = "2".repeat(13);
  try {
    const content = JSON.stringify({ projectId: "fireemu-oracle-query", projectNumber });
    const contentSha = createHash("sha256").update(content).digest("hex");
    await writeFile(file, content, {
      mode: 0o600,
    });
    assert.equal(await readPrivateProjectIdentity(file, contentSha), projectNumber);
    await assert.rejects(
      () => readPrivateProjectIdentity(file, "0".repeat(64)),
      /private project identity/,
    );
    await writeFile(file, JSON.stringify({ projectId: "other-project", projectNumber }));
    await assert.rejects(() => readPrivateProjectIdentity(file), /private project identity/);
    await writeFile(
      file,
      JSON.stringify({ projectId: "fireemu-oracle-query", projectNumber: "abc" }),
    );
    await assert.rejects(() => readPrivateProjectIdentity(file), /private project identity/);
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
});
