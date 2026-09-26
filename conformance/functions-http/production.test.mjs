import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import * as production from "./production.mjs";

import {
  assertAdmission,
  assertFourthOwnerDecision,
  assertOwnedImage,
  assertPublicReadback,
  assertReviewApproval,
  cliEnvironment,
  expiredAt,
  preflightCliSideEffects,
  readPrivateProjectIdentity,
  readRecoveryReadback,
  readServiceAgentGrants,
  retryAccounting,
  serviceAgentGrantChanges,
  summarizeCliOutput,
  writeCliDiagnostic,
} from "./production.mjs";

const require = createRequire(import.meta.url);
const { Client } = require("../node_modules/firebase-tools/lib/apiv2.js");

test("Firebase CLI sends the reviewed project as its quota project", () => {
  const environment = cliEnvironment("/private/owner-adc.json", "/private/isolated-config", {
    GOOGLE_CLOUD_QUOTA_PROJECT: "unrelated-project",
    FIREBASE_TOKEN: "unreviewed-token",
  });
  assert.equal(environment.GOOGLE_CLOUD_QUOTA_PROJECT, "fireemu-oracle-query");
  assert.equal(environment.GOOGLE_APPLICATION_CREDENTIALS, "/private/owner-adc.json");
  assert.equal(environment.XDG_CONFIG_HOME, "/private/isolated-config");
  assert.equal(environment.FIREBASE_TOKEN, "");
  const prior = process.env.GOOGLE_CLOUD_QUOTA_PROJECT;
  try {
    process.env.GOOGLE_CLOUD_QUOTA_PROJECT = environment.GOOGLE_CLOUD_QUOTA_PROJECT;
    const request = new Client({ urlPrefix: "https://firebase.googleapis.com" }).addRequestHeaders({
      headers: new Headers(),
    });
    assert.equal(request.headers.get("x-goog-user-project"), "fireemu-oracle-query");
  } finally {
    if (prior === undefined) delete process.env.GOOGLE_CLOUD_QUOTA_PROJECT;
    else process.env.GOOGLE_CLOUD_QUOTA_PROJECT = prior;
  }
});

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

test("fourth send requires one owner decision binding packet, commit and added budget", () => {
  const packetSha = "a".repeat(64);
  const gitSha = "b".repeat(40);
  const scope = `packetSha256=${packetSha}; runnerCommit=${gitSha}; addedBudgetUsd=0.56; stage3CapUsd=9.56; taskCapUsd=10.56; maxDirectHttp=881; maxCliDeploy=19; maxCliDelete=17; approved`;
  const row = `- 2026-09-26 | FUNCTIONS-HTTP stage3 fourth send | ${scope} | オーナー（このセッションへの直接の返答「承認」） | docs.local/reviews/2026-09-26-functions-http-stage3-fourth-presend-packet.md`;
  assert.doesNotThrow(() => assertFourthOwnerDecision(`${row}\n`, packetSha, gitSha));
  for (const content of [
    "",
    `${row}\n${row}\n`,
    row.replace(packetSha, "c".repeat(64)),
    row.replace(gitSha, "d".repeat(40)),
    row.replace("addedBudgetUsd=0.56", "addedBudgetUsd=0"),
    row.replace("stage3CapUsd=9.56", "stage3CapUsd=9"),
    row.replace("taskCapUsd=10.56", "taskCapUsd=10"),
    row.replace("maxDirectHttp=881", "maxDirectHttp=882"),
    row.replace("; approved", "; proposed"),
    row.replace("オーナー（このセッションへの直接の返答「承認」）", "調整役（レビュー済み）"),
  ]) {
    assert.throws(() => assertFourthOwnerDecision(content, packetSha, gitSha), /owner decision/);
  }
});

test("stage 3 fourth attempt requires three recovered attempts, quiet project and 30-minute gap", () => {
  const firstRunDir = "/private/functions-http-first";
  const secondRunDir = "/private/functions-http-second";
  const thirdRunDir = "/private/functions-http-third";
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
    {
      ts: "2026-09-25T09:20:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "started",
      gitSha: "50f3625e3d2eb1b5f85879eb6210e2cf8b212649",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      runDir: firstRunDir,
    },
    {
      ts: "2026-09-25T09:20:19Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "change",
      action: "service-identity-generation-possible",
    },
    {
      ts: "2026-09-25T09:20:20Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "needs-recovery",
      gitSha: "50f3625e3d2eb1b5f85879eb6210e2cf8b212649",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      runDir: firstRunDir,
      requests: { invocation: 0, cliDeploy: 1 },
    },
    {
      ts: "2026-09-25T09:50:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "finished",
      gitSha: "50f3625e3d2eb1b5f85879eb6210e2cf8b212649",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      outcome: "recovered-no-observation",
      recoveryReadbackSha256: "50817abfe8246b7c3b7ea85d96f79ba6015d14ee75d1076cb700fd728e8031e5",
      recoveryRequests: 5,
      runDir: firstRunDir,
    },
    {
      ts: "2026-09-25T10:20:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "started",
      gitSha: "fa536544c99009ab733fe3b1bc324a5afa6c361f",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      runDir: secondRunDir,
      attempt: 2,
      reservationLedgerTs: "2026-09-25T13:05:04.913Z",
    },
    {
      ts: "2026-09-25T10:20:19Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "change",
      action: "service-identity-generation-possible",
    },
    {
      ts: "2026-09-25T10:20:20Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "needs-recovery",
      gitSha: "fa536544c99009ab733fe3b1bc324a5afa6c361f",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      runDir: secondRunDir,
      attempt: 2,
      requests: { invocation: 0, cliDeploy: 1 },
    },
    {
      ts: "2026-09-25T10:50:00Z",
      project: "fireemu-oracle-query",
      taskId: "FUNCTIONS-HTTP-SANDBOX",
      stage: 3,
      event: "finished",
      gitSha: "fa536544c99009ab733fe3b1bc324a5afa6c361f",
      corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
      outcome: "recovered-no-observation",
      recoveryReadbackSha256: "1a1354889e8a29129a9f9039cc63230a99419d9a59c34916fb93af7bc0722cb8",
      recoveryRequests: 5,
      runDir: secondRunDir,
      attempt: 2,
    },
  ];
  const thirdBase = {
    project: "fireemu-oracle-query",
    taskId: "FUNCTIONS-HTTP-SANDBOX",
    stage: 3,
    gitSha: "8078b372535a19cd34b9b085fb9e049f5927c272",
    corpusDigest: "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea",
    runDir: thirdRunDir,
    attempt: 3,
  };
  lines.push(
    {
      ...thirdBase,
      ts: "2026-09-25T11:20:00Z",
      event: "started",
      reservationLedgerTs: "2026-09-25T13:05:04.913Z",
    },
    {
      ts: "2026-09-25T11:20:10Z",
      project: thirdBase.project,
      taskId: thirdBase.taskId,
      stage: 3,
      event: "change",
      action: "public-invoker-revoked",
    },
    {
      ts: "2026-09-25T11:20:11Z",
      project: thirdBase.project,
      taskId: thirdBase.taskId,
      stage: 3,
      event: "change",
      action: "function-deleted",
    },
    {
      ts: "2026-09-25T11:20:12Z",
      project: thirdBase.project,
      taskId: thirdBase.taskId,
      stage: 3,
      event: "change",
      action: "service-identity-generation-possible",
    },
    {
      ...thirdBase,
      ts: "2026-09-25T11:20:13Z",
      event: "needs-recovery",
      requests: { invocation: 0, control: 9, cleanup: 8, cliDeploy: 1, cliDelete: 1 },
      estimatedUsd: 0.57,
    },
    {
      ...thirdBase,
      ts: "2026-09-25T11:20:14Z",
      event: "change",
      action: "function-created-cli-confirmed",
    },
    {
      ...thirdBase,
      ts: "2026-09-25T11:20:15Z",
      event: "change",
      action: "firebaseextensions-api-enable-attempted",
    },
    {
      ...thirdBase,
      ts: "2026-09-25T11:20:16Z",
      event: "change",
      action: "firebaseextensions-api-enabled-readback",
    },
    {
      ...thirdBase,
      ts: "2026-09-25T11:50:00Z",
      event: "finished",
      outcome: "recovered-no-observation",
      recoveryReadbackSha256: "8f9e32ea545246edc21c122f86de1b1feb95901e0ee8a6bc730ef3b8c206ce37",
      recoveryBuildReadbackSha256:
        "7a13b7d55e71b15962d8e0d3883bb8a427865cb05f3f75527fd41a6f97be0312",
      recoveryRequests: 8,
      regionalBuildCount: 1,
      firebaseextensionsApiState: "ENABLED",
      priorAttemptEstimatedUsd: 0.57,
    },
  );
  assert.doesNotThrow(() =>
    assertAdmission(lines, "2026-09-25T12:21:00Z", firstRunDir, secondRunDir, thirdRunDir),
  );
  assert.throws(
    () => assertAdmission(lines, "2026-09-25T12:19:59Z", firstRunDir, secondRunDir, thirdRunDir),
    /30 minutes/,
  );
  assert.throws(
    () =>
      assertAdmission(
        lines.filter((line) => line.event !== "finished" || line.runDir !== secondRunDir),
        "2026-09-25T12:21:00Z",
        firstRunDir,
        secondRunDir,
        thirdRunDir,
      ),
    /recovered/,
  );
  assert.throws(
    () =>
      assertAdmission(
        lines.filter((line) => line.taskId !== "FUNCTIONS-HTTP-SANDBOX"),
        "2026-09-25T12:21:00Z",
        firstRunDir,
        secondRunDir,
        thirdRunDir,
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
        "2026-09-25T12:21:00Z",
        firstRunDir,
        secondRunDir,
        thirdRunDir,
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
        "2026-09-25T12:21:00Z",
        firstRunDir,
        secondRunDir,
        thirdRunDir,
      ),
    /stage 3 attempt/,
  );
  const invalidReadback = structuredClone(lines);
  invalidReadback.at(-1).recoveryReadbackSha256 = "0".repeat(64);
  assert.throws(
    () =>
      assertAdmission(
        invalidReadback,
        "2026-09-25T12:21:00Z",
        firstRunDir,
        secondRunDir,
        thirdRunDir,
      ),
    /recovery evidence/,
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
    "firebaseextensions",
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
  const calls = [];
  const control = async (method, url) => {
    calls.push({ method, url });
    if (url.includes("serviceusage.googleapis.com")) return { value: { services: names } };
    if (url.includes("artifactregistry.googleapis.com")) return { status: 200, value: repo };
    if (url.includes("firebase.googleapis.com")) {
      return { status: 200, value: { projectId: "fireemu-oracle-query" } };
    }
    throw new Error("unreviewed preflight URL");
  };
  await preflightCliSideEffects(control);
  assert.deepEqual(calls.at(-1), {
    method: "GET",
    url: "https://firebase.googleapis.com/v1beta1/projects/fireemu-oracle-query/adminSdkConfig",
  });
  await assert.rejects(
    () =>
      preflightCliSideEffects(async (method, url) =>
        url.includes("firebase.googleapis.com")
          ? { status: 200, value: { projectId: "wrong-project" } }
          : control(method, url),
      ),
    /Admin SDK config/,
  );
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
        if (url.includes("serviceusage"))
          result.value.services = names.filter(
            (row) => row.config.name !== "firebaseextensions.googleapis.com",
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

test("retry reads the exact private absence result before production requests", async () => {
  const runDir = await mkdtemp(join(tmpdir(), "functions-http-recovery-readback-"));
  const file = join(runDir, "readback.json");
  const firstRunDir = "/private/functions-http-first";
  const result = {
    project: "fireemu-oracle-query",
    runDir: firstRunDir,
    requests: 5,
    outcome: "no-function-service-package-or-build-observed",
    readbacks: { function: "absent", service: "absent", package: "absent", builds: [] },
  };
  try {
    const content = JSON.stringify(result);
    const sha = createHash("sha256").update(content).digest("hex");
    await writeFile(file, content, { mode: 0o600 });
    assert.deepEqual(await readRecoveryReadback(file, sha, firstRunDir), result);
    const changed = JSON.stringify({ ...result, readbacks: { ...result.readbacks, builds: [{}] } });
    await writeFile(file, changed);
    const changedSha = createHash("sha256").update(changed).digest("hex");
    await assert.rejects(
      () => readRecoveryReadback(file, changedSha, firstRunDir),
      /recovery readback/,
    );
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
});

test("fourth attempt accepts only the pinned third recovery and terminal build results", async () => {
  const runDir = await mkdtemp(join(tmpdir(), "functions-http-third-readback-"));
  const firstFile = join(runDir, "recovery-readback.json");
  const buildFile = join(runDir, "recovery-build-readback.json");
  const thirdRunDir = "/private/functions-http-third";
  const first = {
    project: "fireemu-oracle-query",
    runDir: thirdRunDir,
    requests: 6,
    outcome: "incomplete",
    error: "build creation time is invalid",
    readbacks: {
      firebaseextensionsApi: "ENABLED",
      function: "absent",
      service: "absent",
      package: "absent",
    },
  };
  const build = {
    project: "fireemu-oracle-query",
    requests: 2,
    outcome: "regional-builds-terminal",
    builds: [
      {
        id: "build-1",
        status: "SUCCESS",
        createTime: "2026-09-25T15:31:11.874615528Z",
        finishTime: "2026-09-25T15:31:45.693235Z",
      },
    ],
  };
  const sha = (text) => createHash("sha256").update(text).digest("hex");
  try {
    await writeFile(firstFile, JSON.stringify(first), { mode: 0o600 });
    await writeFile(buildFile, JSON.stringify(build), { mode: 0o600 });
    assert.equal(typeof production.readThirdRecoveryReadbacks, "function");
    await production.readThirdRecoveryReadbacks(
      firstFile,
      sha(JSON.stringify(first)),
      buildFile,
      sha(JSON.stringify(build)),
      thirdRunDir,
    );
    const disabled = {
      ...first,
      readbacks: { ...first.readbacks, firebaseextensionsApi: "DISABLED" },
    };
    await writeFile(firstFile, JSON.stringify(disabled));
    await assert.rejects(
      () =>
        production.readThirdRecoveryReadbacks(
          firstFile,
          sha(JSON.stringify(disabled)),
          buildFile,
          sha(JSON.stringify(build)),
          thirdRunDir,
        ),
      /third recovery readback/,
    );
    const working = { ...build, builds: [{ ...build.builds[0], status: "WORKING" }] };
    await writeFile(firstFile, JSON.stringify(first));
    await writeFile(buildFile, JSON.stringify(working));
    await assert.rejects(
      () =>
        production.readThirdRecoveryReadbacks(
          firstFile,
          sha(JSON.stringify(first)),
          buildFile,
          sha(JSON.stringify(working)),
          thirdRunDir,
        ),
      /third recovery build/,
    );
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
});

test("fourth attempt accounts for the successful prior build within the extended reservation", () => {
  assert.deepEqual(retryAccounting({ cliDeploy: 16, invocation: 136 }), {
    estimatedUsd: 8.95,
    priorAttemptResidualAllowanceUsd: 0.04,
    thirdAttemptConservativeUsd: 0.57,
    cumulativeEstimatedUsd: 9.56,
  });
  assert.throws(() => retryAccounting({ cliDeploy: 17, invocation: 136 }), /stage 3 budget/);
});
