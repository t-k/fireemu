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
      gitSha: "2410f0c237ecbee5d3059de009c787f494ff6b66",
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
      gitSha: "2410f0c237ecbee5d3059de009c787f494ff6b66",
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
      gitSha: "2410f0c237ecbee5d3059de009c787f494ff6b66",
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
      gitSha: "2c1863b513630740f1082d6227b3797e6dcd83f6",
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
      gitSha: "2c1863b513630740f1082d6227b3797e6dcd83f6",
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
      gitSha: "2c1863b513630740f1082d6227b3797e6dcd83f6",
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
    gitSha: "eb629aa87035b366ecdacb7804546bf20bb1c49d",
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

// ---- Gen2 source upload cleanup (FH-UPLOAD-1..6) ----

const UPLOAD_NUMBER = "123456789012";
const UPLOAD_OBJECT = "9be229fd-1507-4797-ab4b-69f2fda6e54a.zip";

async function uploadWorld(overrides = {}) {
  const { createFakeGcs, FAKE_BUCKET, SECRET_MARKER, answer } =
    await import("../src/shared/gen2-source-uploads.fake.mjs");
  const { openSourceUploads } = await import("../src/shared/gen2-source-uploads.mjs");
  const { createBudget } = await import("./harness.mjs");
  const dir = await mkdtemp(join(tmpdir(), "functions-http-uploads-"));
  const gcs = createFakeGcs();
  const budget = createBudget();
  const functions = { present: overrides.functionPresent ?? false, record: null };
  if (functions.present) {
    functions.record = {
      name: "projects/fireemu-oracle-query/locations/us-central1/functions/fireemuHttpProbe",
      buildConfig: { source: { storageSource: { bucket: FAKE_BUCKET, object: UPLOAD_OBJECT } } },
    };
  }
  const control = async (method, url, body, kind = "control", allowed = [200]) => {
    budget.take(kind);
    let reply;
    if (url.startsWith("https://storage.googleapis.com/")) {
      reply = await gcs.send(method, url);
    } else if (url.includes("/functions/") && method === "GET") {
      reply = functions.present
        ? { status: 200, value: functions.record, bytes: 10 }
        : { status: 404, value: {}, bytes: 2 };
    } else {
      reply = { status: 404, value: {}, bytes: 2 };
    }
    if (allowed !== "any" && !allowed.includes(reply.status))
      throw new Error(`status ${reply.status}`);
    return reply;
  };
  const uploads = openSourceUploads({
    ledgerPath: join(dir, "owned-uploads.jsonl"),
    runId: "run-f",
    projectNumber: UPLOAD_NUMBER,
    region: "us-central1",
    send: production.storageSend(control),
    requestsLeft: () => 244 - budget.snapshot().upload,
  });
  const logs = [];
  const deps = {
    log: async (action) => logs.push(action),
    run: async () => {
      functions.present = false;
    },
  };
  return {
    dir,
    gcs,
    budget,
    control,
    uploads,
    logs,
    deps,
    functions,
    answer,
    SECRET_MARKER,
    FAKE_BUCKET,
  };
}

test("deploy debug lines are dropped from the CLI output that is judged and stored", () => {
  const output = [
    "i  functions: deploying",
    '[2026-10-26T01:02:03.456Z] <<< [apiv2][body] POST https://x/functions:generateUploadUrl {"uploadUrl":"u"}',
    "+  Deploy complete!",
  ].join("\n");
  assert.equal(
    production.withoutDebugLines(output),
    "i  functions: deploying\n+  Deploy complete!",
  );
  assert.equal(
    production.withoutDebugLines("Enabling API run.googleapis.com"),
    "Enabling API run.googleapis.com",
  );
});

test("a stored CLI diagnostic never keeps a signed upload URL", async () => {
  const runDir = await mkdtemp(join(tmpdir(), "functions-http-cli-signed-"));
  try {
    const output = [
      "Error: upload failed",
      "PUT https://storage.googleapis.com/b/o.zip?GoogleAccessId=a%40b&X-Goog-Signature=SECRET-MARKER-9f3a",
      "  at retry X-Goog-Signature=SECRET-MARKER-9f3a",
    ].join("\n");
    const file = await writeCliDiagnostic(output, 1, "cliDeploy", 1, runDir);
    assert.doesNotMatch(await readFile(file, "utf8"), /SECRET-MARKER|X-Goog-Signature=/);
  } finally {
    await rm(runDir, { recursive: true, force: true });
  }
});

test("upload bucket requests are counted as upload requests and stop at the ceiling", async () => {
  const world = await uploadWorld();
  try {
    const send = production.storageSend(world.control);
    const reply = await send(
      "GET",
      `https://storage.googleapis.com/storage/v1/b/${world.FAKE_BUCKET}/o`,
    );
    assert.equal(reply.status, 200);
    assert.equal(world.budget.snapshot().upload, 1);
    const { BOUNDS } = await import("./harness.mjs");
    for (let n = 1; n < BOUNDS.upload; n += 1) world.budget.take("upload");
    await assert.rejects(
      () => send("GET", "https://storage.googleapis.com/storage/v1/b/x/o"),
      /ceiling/,
    );
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("cleanup of a deploy that failed after the upload deletes the owned object and closes", async () => {
  const world = await uploadWorld();
  try {
    const upload = await world.uploads.beginDeploy("program:http");
    const state = {
      started: true,
      cleaned: false,
      upload,
      deployTrack: { exited: true, onReceipt: (r) => upload.receipt(r) },
    };
    world.gcs.put(UPLOAD_OBJECT);
    state.deployTrack.onReceipt({ bucket: world.FAKE_BUCKET, object: UPLOAD_OBJECT });
    await production.cleanupTarget(
      world.control,
      "http",
      "/adc",
      world.budget,
      world.dir,
      state,
      world.deps,
    );
    assert.equal(state.cleanupError, undefined);
    assert.equal(state.cleaned, true);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    assert.deepEqual(world.logs, ["source-upload-deleted"]);
    assert.equal(world.uploads.report().closureReady, true);
    assert.ok(
      world.budget.snapshot().upload >= 4,
      "list, list, metadata, delete and read-back are counted",
    );
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("cleanup takes the receipt from a function record that is still there", async () => {
  const world = await uploadWorld({ functionPresent: true });
  try {
    const upload = await world.uploads.beginDeploy("program:http");
    const state = { started: true, cleaned: false, upload, deployTrack: { exited: false } };
    world.gcs.put(UPLOAD_OBJECT);
    await production.cleanupTarget(
      world.control,
      "http",
      "/adc",
      world.budget,
      world.dir,
      state,
      world.deps,
    );
    assert.equal(state.cleanupError, undefined);
    assert.equal(state.cleaned, true);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT), "the receipt came from the function record");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a refused upload DELETE leaves the target uncleaned and the ledger open", async () => {
  const world = await uploadWorld();
  try {
    const upload = await world.uploads.beginDeploy("program:http");
    const state = { started: true, cleaned: false, upload, deployTrack: { exited: true } };
    world.gcs.put(UPLOAD_OBJECT);
    upload.receipt({ bucket: world.FAKE_BUCKET, object: UPLOAD_OBJECT });
    world.gcs.override({ method: "DELETE", url: UPLOAD_OBJECT }, world.answer(403));
    await production.cleanupTarget(
      world.control,
      "http",
      "/adc",
      world.budget,
      world.dir,
      state,
      world.deps,
    );
    assert.equal(state.cleaned, false);
    assert.match(state.cleanupError, /source upload not cleaned/);
    assert.deepEqual(world.logs, []);
    assert.equal(world.uploads.report().closureReady, false);
    assert.equal(world.gcs.count("DELETE"), 1);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("an unfinished deploy upload (no explanation of the bucket) is never called cleaned", async () => {
  const world = await uploadWorld();
  try {
    const upload = await world.uploads.beginDeploy("program:http");
    const state = { started: true, cleaned: false, upload, deployTrack: { exited: true } };
    world.gcs.put(UPLOAD_OBJECT); // an upload nobody has a receipt for
    await production.cleanupTarget(
      world.control,
      "http",
      "/adc",
      world.budget,
      world.dir,
      state,
      world.deps,
    );
    assert.equal(state.cleaned, false);
    assert.match(state.cleanupError, /unexplained-object/);
    assert.ok(world.gcs.objects.has(UPLOAD_OBJECT), "an object without a receipt is never deleted");
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("the run never closes with an open source upload ledger, whatever else it recorded", () => {
  const open = { closureReady: false, reasons: ["owned-not-deleted:b/o"] };
  assert.deepEqual(
    production.withUploadClosure(open, { outcome: "recorded", reason: undefined, residual: false }),
    {
      outcome: "stopped-needs-review",
      reason: "source upload ledger is not closed (1 open)",
      residual: true,
    },
  );
  assert.deepEqual(
    production.withUploadClosure(open, {
      outcome: "stopped-needs-review",
      reason: "x",
      residual: false,
    }),
    {
      outcome: "stopped-needs-review",
      reason: "x; source upload ledger is not closed (1 open)",
      residual: true,
    },
  );
  const closed = { closureReady: true, reasons: [] };
  assert.deepEqual(
    production.withUploadClosure(closed, {
      outcome: "recorded",
      reason: undefined,
      residual: false,
    }),
    { outcome: "recorded", reason: undefined, residual: false },
  );
});

// ---- the deploy CLI child (a bounded harmless native child stands in for firebase-tools) ----

async function runFakeCli(body, kind, track) {
  const { createBudget } = await import("./harness.mjs");
  const dir = await mkdtemp(join(tmpdir(), "functions-http-fake-cli-"));
  const script = join(dir, "fake-cli.mjs");
  await writeFile(script, body);
  const runDir = join(dir, "run");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(runDir));
  const budget = createBudget();
  let error;
  let summary;
  try {
    summary = await production.cli(["deploy"], "/adc", budget, kind, runDir, track, [
      process.execPath,
      script,
    ]);
  } catch (caught) {
    error = caught;
  }
  const diagnostics = (await import("node:fs/promises"))
    .readdir(runDir)
    .then((names) => names.filter((name) => name.startsWith("cli-")));
  return { dir, runDir, error, summary, diagnostics: await diagnostics };
}

const FAKE_RECEIPT_SCRIPT = (tail) => `
const body = JSON.stringify({
  uploadUrl: "https://storage.googleapis.com/gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com/${UPLOAD_OBJECT}?X-Goog-Signature=SECRET-MARKER-9f3a",
  storageSource: { bucket: "gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com", object: "${UPLOAD_OBJECT}" },
});
console.log("i  functions: deploying");
console.log("[2026-10-26T01:02:03.456Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions:generateUploadUrl " + body);
console.log("ARGV " + JSON.stringify(process.argv.slice(2)));
${tail}
`;

test("a deploy CLI runs with --debug, hands over its receipt and ends by itself", async () => {
  const seen = [];
  const track = { onReceipt: (receipt) => seen.push(receipt) };
  const run = await runFakeCli(FAKE_RECEIPT_SCRIPT("process.exit(0);"), "cliDeploy", track);
  try {
    assert.equal(run.error, undefined);
    assert.equal(run.summary.exitCode, 0);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].object, UPLOAD_OBJECT);
    assert.equal(track.exited, true);
  } finally {
    await rm(run.dir, { recursive: true, force: true });
  }
});

test("a failing deploy CLI still hands over its receipt, and its diagnostic keeps no debug line", async () => {
  const seen = [];
  const track = { onReceipt: (receipt) => seen.push(receipt) };
  const run = await runFakeCli(
    FAKE_RECEIPT_SCRIPT(
      'const { writeFileSync } = await import("node:fs"); writeFileSync("firebase-debug.log", "signed"); console.error("Error: Failed to create function"); process.exit(1);',
    ),
    "cliDeploy",
    track,
  );
  try {
    assert.match(run.error.message, /cliDeploy failed/);
    assert.equal(run.error.indeterminate, true);
    assert.equal(seen.length, 1);
    assert.equal(track.exited, true, "exit code 1 is the CLI ending by itself");
    await assert.rejects(
      () => stat(new URL("firebase-debug.log", import.meta.url)),
      { code: "ENOENT" },
      "the CLI debug log, which holds signed URLs, is removed",
    );
    assert.equal(run.diagnostics.length, 1);
    const stored = await readFile(join(run.runDir, run.diagnostics[0]), "utf8");
    assert.match(stored, /Failed to create function/);
    assert.match(stored, /--debug/, "the argv echo is a normal line");
    assert.doesNotMatch(stored, /SECRET-MARKER|generateUploadUrl|X-Goog-Signature/);
  } finally {
    await rm(run.dir, { recursive: true, force: true });
  }
});

test("a deploy CLI killed by a signal is not an exit by itself, and its receipt is kept", async () => {
  const seen = [];
  const track = { onReceipt: (receipt) => seen.push(receipt) };
  const run = await runFakeCli(
    FAKE_RECEIPT_SCRIPT('process.kill(process.pid, "SIGKILL"); await new Promise(() => {});'),
    "cliDeploy",
    track,
  );
  try {
    assert.ok(run.error);
    assert.equal(seen.length, 1);
    assert.equal(track.exited, false);
  } finally {
    await rm(run.dir, { recursive: true, force: true });
  }
});

test("only a deploy gets --debug; a delete CLI is run as before", async () => {
  const withTrack = await runFakeCli(FAKE_RECEIPT_SCRIPT("process.exit(0);"), "cliDeploy", {
    onReceipt() {},
  });
  const without = await runFakeCli(
    'console.log("ARGV " + JSON.stringify(process.argv.slice(2)));\nprocess.exit(3);',
    "cliDelete",
    undefined,
  );
  try {
    assert.equal(withTrack.error, undefined);
    assert.equal(without.error.indeterminate, false);
    const stored = await readFile(join(without.runDir, without.diagnostics[0]), "utf8");
    assert.doesNotMatch(stored, /--debug/);
    assert.match(stored, /--project/);
  } finally {
    await rm(withTrack.dir, { recursive: true, force: true });
    await rm(without.dir, { recursive: true, force: true });
  }
});

// ---- deploy to terminal decision, with the deploy CLI replaced by a harmless child ----

async function deployThenCleanUp({ script, putObject }) {
  const world = await uploadWorld();
  const scriptPath = join(world.dir, "fake-cli.mjs");
  await writeFile(scriptPath, script);
  await import("node:fs/promises").then(({ mkdir }) => mkdir(join(world.dir, "run")));
  const run = (args, adc, budget, kind, runDir, track) => {
    // the upload happens while the CLI runs, after the baseline was taken
    if (putObject) world.gcs.put(UPLOAD_OBJECT);
    return production.cli(args, adc, budget, kind, runDir, track, [process.execPath, scriptPath]);
  };
  const state = { started: false, cleaned: false };
  let deployError;
  try {
    await production.deployTarget(
      "http",
      "functions-http/http/request-shape",
      state,
      world.uploads,
      "/adc",
      world.budget,
      join(world.dir, "run"),
      run,
    );
  } catch (error) {
    deployError = error;
  }
  await production.cleanupTarget(
    world.control,
    "http",
    "/adc",
    world.budget,
    join(world.dir, "run"),
    state,
    world.deps,
  );
  return { world, state, deployError };
}

test("a deploy that failed after the upload is cleaned from the CLI receipt and the run may close", async () => {
  const { world, state, deployError } = await deployThenCleanUp({
    script: FAKE_RECEIPT_SCRIPT(
      'console.error("Error: Failed to create function"); process.exit(1);',
    ),
    putObject: true,
  });
  try {
    assert.equal(deployError.indeterminate, true);
    assert.equal(state.started, true);
    assert.equal(state.cleanupError, undefined);
    assert.equal(state.cleaned, true);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    const closed = production.withUploadClosure(world.uploads.report(), {
      outcome: "recorded",
      reason: undefined,
      residual: false,
    });
    assert.equal(closed.residual, false);
    assert.equal(world.budget.snapshot().cliDeploy, 1);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a deploy CLI that dies after the receipt but before the upload keeps the run open", async () => {
  const { world, state } = await deployThenCleanUp({
    script: FAKE_RECEIPT_SCRIPT(
      'process.kill(process.pid, "SIGKILL"); await new Promise(() => {});',
    ),
    putObject: false,
  });
  try {
    assert.equal(state.cleaned, false);
    assert.match(state.cleanupError, /source upload not cleaned/);
    const closed = production.withUploadClosure(world.uploads.report(), {
      outcome: "recorded",
      reason: undefined,
      residual: false,
    });
    assert.equal(closed.residual, true);
    assert.equal(closed.outcome, "stopped-needs-review");
    assert.equal(world.gcs.count("DELETE"), 0);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a deploy that never reached the upload leaves nothing to clean", async () => {
  const { world, state } = await deployThenCleanUp({
    script: 'console.error("Error: auth failed"); process.exit(1);',
    putObject: false,
  });
  try {
    assert.equal(state.cleaned, true);
    assert.equal(world.gcs.count("DELETE"), 0);
    assert.equal(world.uploads.report().closureReady, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

// ---- a whole program through observeProgram, with fake REST, a harmless deploy child and a fake fetch ----

const FH_FUNCTION =
  "projects/fireemu-oracle-query/locations/us-central1/functions/fireemuHttpProbe";
const FH_SERVICE = "projects/fireemu-oracle-query/locations/us-central1/services/fireemuhttpprobe";
const FH_PACKAGE =
  "projects/fireemu-oracle-query/locations/us-central1/repositories/gcf-artifacts/packages/fireemu--oracle--query__us--central1__fireemu_http_probe";
const FH_DIGEST = `sha256:${"ab".repeat(32)}`;
const FH_VERSION = `${FH_PACKAGE}/versions/${FH_DIGEST}`;

async function observeWorld({ deployScript, deleteStatus }) {
  const base = await uploadWorld();
  const { FAKE_BUCKET } = base;
  const deployed = { present: false, versionExists: false, bindings: [] };
  const control = async (method, url, body, kind = "control", allowed = [200]) => {
    base.budget.take(kind);
    const reply = (status, value = {}) => ({ status, value, bytes: 10 });
    let result;
    if (url.startsWith("https://storage.googleapis.com/")) {
      result = await base.gcs.send(method, url);
    } else if (url === `https://cloudfunctions.googleapis.com/v2/${FH_FUNCTION}`) {
      result = deployed.present
        ? reply(200, {
            name: FH_FUNCTION,
            environment: "GEN_2",
            buildConfig: {
              runtime: "nodejs22",
              entryPoint: "fireemuHttpProbe",
              source: { storageSource: { bucket: FAKE_BUCKET, object: UPLOAD_OBJECT } },
            },
            serviceConfig: {
              service: FH_SERVICE,
              uri: "https://fireemuhttpprobe-abc-uc.a.run.app",
            },
          })
        : reply(404);
    } else if (url === `https://run.googleapis.com/v2/${FH_SERVICE}`) {
      result = deployed.present
        ? reply(200, {
            name: FH_SERVICE,
            template: {
              containers: [
                {
                  image: `us-central1-docker.pkg.dev/fireemu-oracle-query/gcf-artifacts/fireemu--oracle--query__us--central1__fireemu_http_probe@${FH_DIGEST}`,
                },
              ],
            },
          })
        : reply(404);
    } else if (url === `https://run.googleapis.com/v2/${FH_SERVICE}:getIamPolicy`) {
      result = reply(200, { bindings: deployed.bindings });
    } else if (url === `https://run.googleapis.com/v2/${FH_SERVICE}:setIamPolicy`) {
      deployed.bindings = body.policy.bindings;
      result = reply(200, body.policy);
    } else if (url === `https://artifactregistry.googleapis.com/v1/${FH_PACKAGE}`) {
      result = deployed.versionExists ? reply(200, { name: FH_PACKAGE }) : reply(404);
    } else if (
      url === `https://artifactregistry.googleapis.com/v1/${FH_PACKAGE}/versions?pageSize=1000`
    ) {
      result = reply(200, deployed.versionExists ? { versions: [{ name: FH_VERSION }] } : {});
    } else if (url === `https://artifactregistry.googleapis.com/v1/${FH_VERSION}?force=true`) {
      deployed.versionExists = false;
      result = reply(200);
    } else if (url === `https://artifactregistry.googleapis.com/v1/${FH_VERSION}`) {
      result = deployed.versionExists ? reply(200, { name: FH_VERSION }) : reply(404);
    } else {
      throw new Error(`unexpected request ${method} ${url}`);
    }
    if (allowed !== "any" && !allowed.includes(result.status))
      throw new Error(`status ${result.status}`);
    return result;
  };
  // a fresh upload helper on the same fake storage, counting through this control
  const { openSourceUploads } = await import("../src/shared/gen2-source-uploads.mjs");
  const { BOUNDS } = await import("./harness.mjs");
  const uploads = openSourceUploads({
    ledgerPath: join(base.dir, "observe-uploads.jsonl"),
    runId: "run-o",
    projectNumber: UPLOAD_NUMBER,
    region: "us-central1",
    send: production.storageSend(control),
    requestsLeft: () => BOUNDS.upload - base.budget.snapshot().upload,
  });
  const scriptPath = join(base.dir, "fake-cli.mjs");
  await writeFile(scriptPath, deployScript);
  await import("node:fs/promises").then(({ mkdir }) => mkdir(join(base.dir, "run")));
  const calls = [];
  const run = async (args, adc, budget, kind, runDir, track) => {
    calls.push(kind);
    if (kind === "cliDelete") {
      budget.take("cliDelete");
      deployed.present = false;
      return { exitCode: 0 };
    }
    base.gcs.put(UPLOAD_OBJECT);
    deployed.versionExists = true;
    deployed.present = /process\.exit\(0\)/.test(deployScript);
    return production.cli(args, adc, budget, kind, runDir, track, [process.execPath, scriptPath]);
  };
  if (deleteStatus)
    base.gcs.override({ method: "DELETE", url: UPLOAD_OBJECT }, base.answer(deleteStatus));
  const corpus = JSON.parse(await readFile(new URL("./corpus.json", import.meta.url), "utf8"));
  const program = corpus.programs[0];
  const recordings = [{}, {}];
  const fetchImpl = async () =>
    new Response('{"ok":1}\n', { status: 200, headers: { "content-type": "application/json" } });
  let error;
  try {
    await production.observeProgram(
      program,
      control,
      "/adc",
      base.budget,
      join(base.dir, "run"),
      recordings,
      { stopped: false },
      uploads,
      { run, log: base.deps.log, fetchImpl },
    );
  } catch (caught) {
    error = caught;
  }
  return { ...base, uploads, error, recordings, program, calls };
}

test("a whole program: deploy, observe, clean up, and the source upload is deleted by generation", async () => {
  const world = await observeWorld({ deployScript: FAKE_RECEIPT_SCRIPT("process.exit(0);") });
  try {
    assert.equal(world.error, undefined);
    assert.ok(world.recordings[0][world.program.id]);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT));
    const deletes = world.gcs.requests.filter((request) => request.method === "DELETE");
    assert.equal(deletes.length, 1);
    assert.match(deletes[0].url, /ifGenerationMatch=\d+$/);
    assert.equal(world.uploads.report().closureReady, true);
    assert.ok(
      world.logs.includes("function-deployed") && world.logs.includes("source-upload-deleted"),
    );
    const used = world.budget.snapshot();
    assert.ok(used.upload >= 5 && used.upload <= 244, `upload requests ${used.upload}`);
    assert.deepEqual(world.calls, ["cliDeploy", "cliDelete"]);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a whole program whose deploy failed after the upload still deletes the upload and asks for review", async () => {
  const world = await observeWorld({
    deployScript: FAKE_RECEIPT_SCRIPT(
      'console.error("Error: Failed to create function"); process.exit(1);',
    ),
  });
  try {
    assert.equal(world.error.residual, true, "a failed deploy is never a clean run");
    assert.match(world.error.message, /cleanup requires review/);
    assert.ok(!world.gcs.objects.has(UPLOAD_OBJECT), "the upload object is gone");
    assert.equal(world.uploads.report().closureReady, true);
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

test("a whole program whose upload cannot be deleted leaves the responsibility open", async () => {
  const world = await observeWorld({
    deployScript: FAKE_RECEIPT_SCRIPT("process.exit(0);"),
    deleteStatus: 403,
  });
  try {
    assert.equal(world.error.residual, true);
    assert.match(world.error.message, /cleanup requires review/);
    assert.ok(world.gcs.objects.has(UPLOAD_OBJECT));
    assert.equal(world.uploads.report().closureReady, false);
    assert.equal(
      production.withUploadClosure(world.uploads.report(), {
        outcome: "recorded",
        reason: undefined,
        residual: false,
      }).residual,
      true,
    );
  } finally {
    await rm(world.dir, { recursive: true, force: true });
  }
});

// ---- the REST control and the deploy child, the parts the fakes above stand in for ----

async function withStubbedFetch(handler, body) {
  const original = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), method: init?.method });
    return handler(String(url), init);
  };
  try {
    return await body(seen);
  } finally {
    globalThis.fetch = original;
  }
}

test("the REST control reaches Cloud Storage, passes any status when asked and reports bytes", async () => {
  const { createBudget } = await import("./harness.mjs");
  const adc = { refresh_token: "r", client_id: "c", client_secret: "s" };
  const handler = (url) =>
    url.startsWith("https://oauth2.googleapis.com/")
      ? new Response(JSON.stringify({ access_token: "t", expires_in: 3600 }))
      : new Response('{"error":{"code":412}}', { status: 412 });
  await withStubbedFetch(handler, async (seen) => {
    const budget = createBudget();
    const control = production.createControl(adc, budget);
    const reply = await control(
      "DELETE",
      "https://storage.googleapis.com/storage/v1/b/b/o/x?ifGenerationMatch=1",
      undefined,
      "upload",
      "any",
    );
    assert.equal(reply.status, 412);
    assert.equal(reply.bytes, '{"error":{"code":412}}'.length);
    assert.equal(budget.snapshot().upload, 2, "the token refresh and the request");
    await assert.rejects(
      () =>
        control(
          "GET",
          "https://storage.googleapis.com/storage/v1/b/b/o",
          undefined,
          "upload",
          [200],
        ),
      /returned 412/,
    );
    await assert.rejects(
      () => control("GET", "https://evil.example/storage/v1/b/b/o", undefined, "upload", "any"),
      /unreviewed REST host/,
    );
    assert.ok(seen.every((request) => !request.url.startsWith("https://evil.example")));
  });
});

test("a deploy CLI that is stopped by the runner and exits on its own is still not an exit by itself", async () => {
  const track = { onReceipt() {} };
  const run = await runFakeCli(
    `process.on("SIGTERM", () => process.exit(7));
for (let i = 0; i < 17_000; i += 1) process.stdout.write("x ".repeat(500) + "\\n");
setInterval(() => {}, 1000);`,
    "cliDeploy",
    track,
  );
  try {
    assert.ok(run.error);
    assert.equal(track.exited, false);
  } finally {
    await rm(run.dir, { recursive: true, force: true });
  }
});

test("a receipt on the last line, with no newline, is still read when the CLI ends", async () => {
  const seen = [];
  const track = { onReceipt: (receipt) => seen.push(receipt) };
  const run = await runFakeCli(
    `const body = JSON.stringify({ storageSource: { bucket: "b", object: "${UPLOAD_OBJECT}" } });
process.stdout.write("<<< [apiv2][body] POST https://x/v2/p/functions:generateUploadUrl " + body);`,
    "cliDeploy",
    track,
  );
  try {
    assert.equal(run.error, undefined);
    assert.equal(seen.length, 1);
  } finally {
    await rm(run.dir, { recursive: true, force: true });
  }
});

test("the upload bound is the reviewed number and a budget can be exhausted", async () => {
  const { BOUNDS, createBudget } = await import("./harness.mjs");
  assert.equal(BOUNDS.upload, 16 * 15 + 4);
  const budget = createBudget();
  for (let n = 0; n < BOUNDS.upload; n += 1) budget.take("upload");
  assert.throws(() => budget.take("upload"), /upload ceiling 244 reached/);
  assert.equal(budget.snapshot().upload, 244);
});
