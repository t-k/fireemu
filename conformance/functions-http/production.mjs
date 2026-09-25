// Bounded FUNCTIONS-HTTP production observation. This module has no network side effects on import.

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { appendFile, mkdir, open, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  PROJECT,
  REGION,
  createBudget,
  expectedFunctionName,
  invalidSignatureToken,
  validateCorpus,
  validateFunctionRecord,
  withPublicInvoker,
  withoutPublicInvoker,
} from "./harness.mjs";
import { runCases } from "./session.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = resolve(HERE, "..");
const ROOT = resolve(CONFORMANCE, "..");
const COMMON_GIT = execFileSync(
  "git",
  ["rev-parse", "--path-format=absolute", "--git-common-dir"],
  { cwd: ROOT, encoding: "utf8" },
).trim();
const PRIVATE_ROOT = join(dirname(COMMON_GIT), "docs.local");
const LEDGER = join(PRIVATE_ROOT, "runs/sandbox-ledger.jsonl");
const LOCK = `${LEDGER}.lock`;
const KEY_FILE = join(
  PRIVATE_ROOT,
  "oracle-credentials/fireemu-oracle-query-auth-key-20260925.json",
);
const SANDBOX_DOC = join(PRIVATE_ROOT, "sandbox-oracles.md");
const CLI = join(CONFORMANCE, "node_modules/firebase-tools/lib/bin/firebase.js");
const TASK = "FUNCTIONS-HTTP-SANDBOX";
const CORPUS_SHA = "836c138ba213546428e700e7ecb51644089bb5b0cdc91946eb9904a648106bea";
const FIXTURE_SHA = "0c481ec6b6ec87db71a2f90550238ce69ec2b923c7a92b7ea5171cb7909886a5";
const FIREBASE_CONFIG_SHA = "0b76734c83f808f8842ee093177fc9ecc2fda2ec9f9d06e025436a0d7f9f7197";
const FIXTURE_PACKAGE_SHA = "5a2a9739e294a24104b837a940a65dd38746140dd64fd5744ac85f1d13c4043c";
const FIXTURE_LOCK_SHA = "9d0a9bc3287ad79bc66ee7174c2486dd078d18e77b2c27d612c3c8712d703eeb";
const AUTH_HOST = "https://identitytoolkit.googleapis.com";
const FUNCTION_HOST = "https://cloudfunctions.googleapis.com";
const RUN_HOST = "https://run.googleapis.com";
const ARTIFACT_HOST = "https://artifactregistry.googleapis.com";
const SERVICE_USAGE_HOST = "https://serviceusage.googleapis.com";
const RESOURCE = `projects/${PROJECT}/locations/${REGION}`;
const REPOSITORY = `${RESOURCE}/repositories/gcf-artifacts`;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const EXPOSURE_MS = 60 * 60 * 1000;

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const now = () => new Date().toISOString();
const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
let changeHeadingWritten = false;

async function logChange(action, detail) {
  const ts = now();
  const entry = {
    ts,
    event: "change",
    project: PROJECT,
    database: null,
    taskId: TASK,
    stage: 3,
    action,
    detail,
    requests: null,
    estimatedUsd: 0,
  };
  await appendFile(LEDGER, `${JSON.stringify(entry)}\n`);
  if (!changeHeadingWritten) {
    await appendFile(SANDBOX_DOC, "\n## FUNCTIONS-HTTP stage 3 configuration changes\n\n");
    changeHeadingWritten = true;
  }
  await appendFile(SANDBOX_DOC, `- ${ts}: ${action}: ${detail}.\n`);
}

export function assertAdmission(lines, currentTime = now()) {
  const relevant = lines.filter((line) => line.project === PROJECT);
  const storage = relevant.some(
    (line) => line.taskId === "STORAGE-OBJECT-SANDBOX" && line.outcome === "prepared",
  );
  const stage2 = relevant.some(
    (line) => line.taskId === TASK && line.stage === 2 && line.outcome === "prepared",
  );
  if (!storage || !stage2)
    throw new Error("Storage and FUNCTIONS-HTTP stage 2 must both finish successfully");
  if (
    relevant.some((line) => line.taskId === TASK && line.stage === 3 && line.event === "started")
  ) {
    throw new Error("a stage 3 attempt already exists; recovery or a new review is required");
  }
  const active = new Map();
  for (const line of relevant) {
    if (line.event === "started") active.set(line.taskId, true);
    else if (line.outcome && !line.outcome.startsWith("reserved")) active.delete(line.taskId);
  }
  if (active.size) throw new Error("another shared-project recording is active");
  const terminal = relevant
    .filter((line) => line.outcome && !line.outcome.startsWith("reserved"))
    .map((line) => Date.parse(line.ts));
  const last = Math.max(...terminal);
  if (!Number.isFinite(last) || Date.parse(currentTime) - last < 30 * 60 * 1000) {
    throw new Error("30 minutes have not elapsed after the last shared-project finish line");
  }
}

const estimatedUsd = (requests) =>
  Math.min(
    9,
    Math.ceil((0.01 + requests.cliDeploy * 0.55 + requests.invocation * 0.001) * 100) / 100,
  );

export function assertOwnedImage(image, target) {
  const name = packageId(target);
  const prefix = `${REGION}-docker.pkg.dev/${PROJECT}/gcf-artifacts/${name}`;
  if (!image?.startsWith(prefix))
    throw new Error("image differs from the owned function and repository");
  const suffix = image.slice(prefix.length);
  const digestMatch = /^@sha256:([a-f0-9]{64})$/.exec(suffix);
  if (digestMatch) return { packageId: name, digest: `sha256:${digestMatch[1]}`, tag: null };
  const tagMatch = /^:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/.exec(suffix);
  if (tagMatch) return { packageId: name, digest: null, tag: tagMatch[1] };
  throw new Error("image differs from the owned function and repository");
}

function packageId(target) {
  const encodePart = (part) =>
    part
      .replaceAll("_", "__")
      .replaceAll("-", "--")
      .replace(/^[A-Z]/, (letter) => `${letter.toLowerCase()}-${letter.toLowerCase()}`)
      .replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
  return [PROJECT, REGION, expectedFunctionName(target)].map(encodePart).join("__");
}

export function assertPublicReadback(policy, expectedPublic) {
  if (!policy || !Array.isArray(policy.bindings)) throw new Error("IAM policy readback is invalid");
  const roles = policy.bindings
    .filter(({ members }) => members?.includes("allUsers"))
    .map(({ role }) => role);
  if (roles.some((role) => role !== "roles/run.invoker"))
    throw new Error("allUsers has an unreviewed role");
  if (roles.includes("roles/run.invoker") !== expectedPublic)
    throw new Error("public invoker readback differs from expectation");
}

export function expiredAt(token) {
  const parts = token?.split(".");
  if (parts?.length !== 3 || !parts[2]) throw new Error("production ID token must be signed");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (!Number.isInteger(payload.exp) || payload.exp < 1)
    throw new Error("production ID token has no exp");
  return payload.exp;
}

export function summarizeCliOutput(output, exitCode) {
  return {
    exitCode,
    autoEnabledApi:
      /\benabling\s+(?:required\s+)?(?:api|service)\b|\bapi\b[^\n]*\benabling\b/i.test(output),
  };
}

async function requiredSourceDigests() {
  const checked = [
    ["corpus.json", CORPUS_SHA],
    ["fixtures/index.js", FIXTURE_SHA],
    ["firebase.json", FIREBASE_CONFIG_SHA],
    ["fixtures/package.json", FIXTURE_PACKAGE_SHA],
    ["fixtures/package-lock.json", FIXTURE_LOCK_SHA],
  ];
  for (const [file, expected] of checked) {
    if (digest(await readFile(join(HERE, file))) !== expected)
      throw new Error(`reviewed source changed: ${file}`);
  }
  const cliPackage = JSON.parse(
    await readFile(join(CONFORMANCE, "node_modules/firebase-tools/package.json"), "utf8"),
  );
  if (cliPackage.version !== "15.28.2") throw new Error("pinned Firebase CLI 15.28.2 is required");
  const corpus = JSON.parse(await readFile(join(HERE, "corpus.json"), "utf8"));
  validateCorpus(corpus);
  return corpus;
}

async function assertPrivateApproval() {
  const path = process.env.FIREEMU_FUNCTIONS_HTTP_STAGE3_REVIEW;
  if (!path || !resolve(path).startsWith(`${PRIVATE_ROOT}/`))
    throw new Error("private stage 3 review path is required");
  const content = await readFile(path, "utf8");
  const gitSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
  const dirty = execFileSync(
    "git",
    [
      "status",
      "--porcelain",
      "--",
      "conformance/functions-http",
      "conformance/package.json",
      "conformance/pnpm-lock.yaml",
    ],
    { cwd: ROOT, encoding: "utf8" },
  );
  if (
    dirty ||
    !/^Decision:\s*APPROVE\s*$/im.test(content) ||
    !content.includes(`gitSha: ${gitSha}`) ||
    !content.includes(`corpusDigest: ${CORPUS_SHA}`)
  ) {
    throw new Error("stage 3 pre-send APPROVE must bind a clean reviewed commit and corpus");
  }
}

async function ownerAdc() {
  const path = resolve(
    process.env.FIREEMU_OWNER_ADC ||
      join(homedir(), ".config/gcloud/application_default_credentials.json"),
  );
  const file = JSON.parse(await readFile(path, "utf8"));
  if (
    file.type !== "authorized_user" ||
    !file.refresh_token ||
    !file.client_id ||
    !file.client_secret ||
    (file.token_uri && file.token_uri !== "https://oauth2.googleapis.com/token")
  ) {
    throw new Error("owner authorized_user ADC is required");
  }
  if (
    process.env.GOOGLE_IMPERSONATE_SERVICE_ACCOUNT ||
    process.env.CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT
  ) {
    throw new Error("service-account impersonation is outside this packet");
  }
  return { path, file };
}

async function acquireToken(adc, budget, kind) {
  budget.take(kind);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: adc.refresh_token,
      client_id: adc.client_id,
      client_secret: adc.client_secret,
    }),
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  });
  const text = await response.text();
  if (response.status !== 200 || text.length > MAX_RESPONSE_BYTES)
    throw new Error(`ADC refresh returned ${response.status}`);
  const value = JSON.parse(text);
  if (!value.access_token || !Number.isFinite(value.expires_in))
    throw new Error("ADC refresh had no bounded token");
  return { value: value.access_token, expiresAt: Date.now() + value.expires_in * 1000 - 120_000 };
}

function safeJsonResponse(body) {
  if (body.length > MAX_RESPONSE_BYTES) throw new Error("control response exceeded 1 MiB");
  return body ? JSON.parse(body) : {};
}

function createControl(adc, budget) {
  let token;
  return async function control(method, url, body, kind = "control", allowed = [200]) {
    if (
      ![FUNCTION_HOST, RUN_HOST, ARTIFACT_HOST, AUTH_HOST, SERVICE_USAGE_HOST].some((host) =>
        url.startsWith(`${host}/`),
      )
    ) {
      throw new Error("unreviewed REST host");
    }
    if (!token || Date.now() >= token.expiresAt) token = await acquireToken(adc, budget, kind);
    budget.take(kind);
    const response = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token.value}`,
        "x-goog-user-project": PROJECT,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(60_000),
    });
    const text = await response.text();
    if (!allowed.includes(response.status))
      throw new Error(`bounded ${kind} REST ${method} returned ${response.status}`);
    return { status: response.status, value: safeJsonResponse(text) };
  };
}

async function cli(args, adcPath, budget, kind, runDir) {
  budget.take(kind);
  const isolatedConfig = join(runDir, "firebase-cli-config");
  await mkdir(isolatedConfig, { recursive: true, mode: 0o700 });
  const child = spawn(process.execPath, [CLI, ...args, "--project", PROJECT, "--non-interactive"], {
    cwd: HERE,
    detached: true,
    env: {
      ...process.env,
      GOOGLE_APPLICATION_CREDENTIALS: adcPath,
      FIREBASE_TOKEN: "",
      XDG_CONFIG_HOME: isolatedConfig,
      FIREBASE_CLI_DISABLE_UPDATE_CHECK: "1",
      CI: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const stopGroup = (signal) => {
    try {
      process.kill(-child.pid, signal);
    } catch {
      /* already exited */
    }
  };
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (output.length > 1_000_000) stopGroup("SIGTERM");
    });
  const timeout = setTimeout(() => stopGroup("SIGTERM"), 20 * 60 * 1000);
  const force = setTimeout(() => stopGroup("SIGKILL"), 20 * 60 * 1000 + 10_000);
  const code = await new Promise((resolveChild, reject) => {
    child.once("error", reject);
    child.once("close", resolveChild);
  });
  clearTimeout(timeout);
  clearTimeout(force);
  const summary = summarizeCliOutput(output, code);
  if (code !== 0 || summary.autoEnabledApi) {
    const failure = new Error(`${kind} failed or attempted API enablement (exit ${code})`);
    failure.indeterminate = kind === "cliDeploy";
    throw failure;
  }
  return summary;
}

const functionUrl = (target) =>
  `${FUNCTION_HOST}/v2/${RESOURCE}/functions/${expectedFunctionName(target)}`;
const serviceName = (target) =>
  `${RESOURCE}/services/${expectedFunctionName(target).toLowerCase()}`;
const serviceUrl = (target) => `${RUN_HOST}/v2/${serviceName(target)}`;
const policyUrl = (target, operation) => `${serviceUrl(target)}:${operation}`;
const packageName = (target) => `${REPOSITORY}/packages/${packageId(target)}`;

export async function preflightCliSideEffects(control) {
  const services = await control(
    "GET",
    `${SERVICE_USAGE_HOST}/v1/projects/${PROJECT}/services?filter=state%3AENABLED&pageSize=200`,
    undefined,
    "control",
  );
  if (services.value.nextPageToken) throw new Error("enabled service list is incomplete");
  const enabled = new Set(
    (services.value.services ?? []).map(
      (service) => service.config?.name ?? service.name?.split("/").at(-1),
    ),
  );
  const required = [
    "cloudfunctions",
    "cloudbuild",
    "artifactregistry",
    "run",
    "eventarc",
    "pubsub",
    "storage",
  ].map((name) => `${name}.googleapis.com`);
  if (required.some((name) => !enabled.has(name))) {
    throw new Error("Firebase CLI would encounter a disabled required API");
  }
  const repo = await control(
    "GET",
    `${ARTIFACT_HOST}/v1/${REPOSITORY}`,
    undefined,
    "control",
    [200, 404],
  );
  if (repo.status !== 200 || repo.value.name !== REPOSITORY) {
    throw new Error(
      "gcf-artifacts repository is absent; cleanup-policy setup needs separate review",
    );
  }
  const policies = repo.value.cleanupPolicies ?? {};
  const hasPolicy =
    Object.keys(policies).length > 0 ||
    repo.value.labels?.["firebase-functions-cleanup-opted-out"] === "true";
  if (!hasPolicy) throw new Error("gcf-artifacts has no cleanup policy or reviewed opt-out");
}

async function inspectAbsence(control, target, kind) {
  const f = await control("GET", functionUrl(target), undefined, kind, [200, 404]);
  const s = await control("GET", serviceUrl(target), undefined, kind, [200, 404]);
  return { functionAbsent: f.status === 404, serviceAbsent: s.status === 404 };
}

async function inspectOwnedPackage(control, target, kind) {
  const response = await control(
    "GET",
    `${ARTIFACT_HOST}/v1/${packageName(target)}`,
    undefined,
    kind,
    [200, 404],
  );
  if (response.status === 200 && response.value.name !== packageName(target))
    throw new Error("Artifact Registry package name changed");
  return response.status === 200;
}

async function listOwnedVersions(control, target, kind) {
  const response = await control(
    "GET",
    `${ARTIFACT_HOST}/v1/${packageName(target)}/versions?pageSize=1000`,
    undefined,
    kind,
  );
  if (response.value.nextPageToken)
    throw new Error("owned Artifact Registry version list is incomplete");
  const versions = response.value.versions ?? [];
  if (versions.some((version) => !version.name?.startsWith(`${packageName(target)}/versions/`))) {
    throw new Error("Artifact Registry returned an unowned version");
  }
  return versions;
}

async function assertOwnedTag(control, target, tag, versionName) {
  const response = await control(
    "GET",
    `${ARTIFACT_HOST}/v1/${packageName(target)}/tags?pageSize=1000`,
    undefined,
    "control",
  );
  if (response.value.nextPageToken)
    throw new Error("owned Artifact Registry tag list is incomplete");
  const matches = (response.value.tags ?? []).filter(
    (entry) =>
      entry.name?.startsWith(`${packageName(target)}/tags/`) &&
      decodeURIComponent(entry.name.split("/").at(-1)) === tag,
  );
  if (matches.length !== 1 || matches[0].version !== versionName) {
    throw new Error("Cloud Run image tag does not match the owned Artifact Registry version");
  }
}

async function policy(control, target, kind) {
  const response = await control("GET", policyUrl(target, "getIamPolicy"), undefined, kind);
  if (!Array.isArray(response.value.bindings)) response.value.bindings = [];
  return response.value;
}

async function publicInvoker(control, target, enabled, kind) {
  const current = await policy(control, target, kind);
  if (
    enabled &&
    current.bindings.some(
      ({ members, role }) => members?.includes("allUsers") && role !== "roles/run.invoker",
    )
  ) {
    throw new Error("unreviewed allUsers role");
  }
  const updated = enabled ? withPublicInvoker(current) : withoutPublicInvoker(current);
  if (JSON.stringify(updated) !== JSON.stringify(current)) {
    await control("POST", policyUrl(target, "setIamPolicy"), { policy: updated }, kind);
  }
  const readback = await policy(control, target, kind);
  assertPublicReadback(readback, enabled);
  await logChange(
    enabled ? "public-invoker-granted" : "public-invoker-revoked",
    `${serviceName(target)}; service-level policy read back`,
  );
}

async function createUser(key, budget, runDir, programId) {
  const email = `fireemu-fh-${randomBytes(8).toString("hex")}@example.com`;
  await appendFile(
    join(runDir, "owned-users.jsonl"),
    `${JSON.stringify({ ts: now(), programId, email, state: "signup-attempted" })}\n`,
    { mode: 0o600 },
  );
  budget.take("auth");
  const response = await fetch(`${AUTH_HOST}/v1/accounts:signUp?key=${encodeURIComponent(key)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email,
      password: randomBytes(20).toString("base64url"),
      returnSecureToken: true,
    }),
    redirect: "manual",
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status !== 200) throw new Error(`Auth signUp returned ${response.status}`);
  const user = safeJsonResponse(await response.text());
  await appendFile(
    join(runDir, "owned-users.jsonl"),
    `${JSON.stringify({ ts: now(), programId, email, localId: user.localId ?? null, state: "signup-accepted" })}\n`,
    { mode: 0o600 },
  );
  if (!user.localId || !user.idToken || !user.email || !user.email.endsWith("@example.com")) {
    throw new Error("Auth signUp did not return an owned user");
  }
  expiredAt(user.idToken);
  await logChange("auth-user-created", `${programId}; owned user journaled privately`);
  return user;
}

async function deleteUser(control, user, runDir, programId) {
  if (!user?.localId) return;
  await control(
    "POST",
    `${AUTH_HOST}/v1/projects/${PROJECT}/accounts:delete`,
    { localId: user.localId },
    "auth",
  );
  const readback = await control(
    "POST",
    `${AUTH_HOST}/v1/projects/${PROJECT}/accounts:lookup`,
    { localId: [user.localId] },
    "auth",
  );
  if ((readback.value.users ?? []).length)
    throw new Error("owned Auth user remains after deletion");
  await appendFile(
    join(runDir, "owned-users.jsonl"),
    `${JSON.stringify({ ts: now(), programId, email: user.email, localId: user.localId, state: "deleted-readback-empty" })}\n`,
    { mode: 0o600 },
  );
  await logChange("auth-user-deleted", `${programId}; absence read back`);
}

async function waitForExpiry(token, abort) {
  const expires = expiredAt(token) * 1000 + 5_000;
  if (expires - Date.now() > 75 * 60 * 1000)
    throw new Error("ID token expiry exceeds the approved wait");
  while (Date.now() < expires) {
    if (abort.stopped) throw new Error("signal interrupted the expired-token wait");
    await sleep(Math.min(10_000, expires - Date.now()));
  }
}

async function cleanupTarget(control, target, adcPath, budget, runDir, state) {
  if (!state.started) return;
  try {
    const current = await inspectAbsence(control, target, "cleanup");
    if (!current.serviceAbsent) {
      try {
        await publicInvoker(control, target, false, "cleanup");
      } catch (error) {
        state.iamRevocationError = error.message;
      }
    }
    if (!current.functionAbsent || !current.serviceAbsent) {
      await cli(
        ["functions:delete", expectedFunctionName(target), "--region", REGION, "--force"],
        adcPath,
        budget,
        "cliDelete",
        runDir,
      );
      await logChange("function-deleted", `${functionUrl(target)}; Firebase CLI completed`);
    }
    const absent = await inspectAbsence(control, target, "cleanup");
    if (!absent.functionAbsent || !absent.serviceAbsent)
      throw new Error("function or Cloud Run service remains after delete");
    const packageExists = await inspectOwnedPackage(control, target, "cleanup");
    if (packageExists) {
      const versions = await listOwnedVersions(control, target, "cleanup");
      if (versions.length !== 1 || versions[0].name !== state.versionName) {
        throw new Error("owned image version cannot be distinguished for cleanup");
      }
      const deleted = await control(
        "DELETE",
        `${ARTIFACT_HOST}/v1/${state.versionName}?force=true`,
        undefined,
        "cleanup",
        [200, 204],
      );
      if (
        deleted.value.name &&
        !new RegExp(`^projects/${PROJECT}/locations/${REGION}/operations/[A-Za-z0-9_-]+$`).test(
          deleted.value.name,
        )
      ) {
        throw new Error("Artifact Registry returned an unreviewed delete operation");
      }
      if (deleted.value.name && !deleted.value.done) {
        let done = false;
        for (let poll = 0; poll < 10; poll += 1) {
          await sleep(10_000);
          const operation = await control(
            "GET",
            `${ARTIFACT_HOST}/v1/${deleted.value.name}`,
            undefined,
            "cleanup",
          );
          if (operation.value.error) throw new Error("owned image deletion operation failed");
          if (operation.value.done) {
            done = true;
            break;
          }
        }
        if (!done)
          throw new Error("owned image deletion operation did not complete within 10 polls");
      }
      const after = await control(
        "GET",
        `${ARTIFACT_HOST}/v1/${state.versionName}`,
        undefined,
        "cleanup",
        [404],
      );
      if (after.status !== 404) throw new Error("owned image version remains");
      await logChange("image-version-deleted", `${state.versionName}; absence read back`);
    }
    state.cleaned = true;
  } catch (error) {
    state.cleanupError = error.message;
  }
}

async function observeProgram(program, control, adcPath, budget, runDir, recordings, abort) {
  const targets = [...new Set(program.cases.map((step) => step.target))];
  const states = Object.fromEntries(
    targets.map((target) => [target, { started: false, cleaned: false }]),
  );
  let user;
  let error;
  let userAttempted = false;
  try {
    if (program.id.endsWith("auth-context") || program.id.endsWith("auth-refusal")) {
      const key = JSON.parse(await readFile(KEY_FILE, "utf8")).keyString;
      if (typeof key !== "string" || key.length < 20)
        throw new Error("restricted Auth key is missing");
      userAttempted = true;
      user = await createUser(key, budget, runDir, program.id);
      if (program.id.endsWith("auth-refusal")) await waitForExpiry(user.idToken, abort);
    }
    for (const target of targets) {
      if (abort.stopped) throw new Error("signal stopped observation before deploy");
      const absence = await inspectAbsence(control, target, "control");
      if (
        !absence.functionAbsent ||
        !absence.serviceAbsent ||
        (await inspectOwnedPackage(control, target, "control"))
      ) {
        throw new Error("reserved function, service or image package already exists");
      }
      states[target].started = true;
      states[target].exposureStart = Date.now();
      await cli(
        ["deploy", "--only", `functions:functions-http-oracle:${expectedFunctionName(target)}`],
        adcPath,
        budget,
        "cliDeploy",
        runDir,
      );
      await logChange("function-deployed", `${functionUrl(target)}; Firebase CLI completed`);
      const functionRecord = (await control("GET", functionUrl(target), undefined, "control"))
        .value;
      states[target].url = validateFunctionRecord(functionRecord, target);
      const service = (await control("GET", serviceUrl(target), undefined, "control")).value;
      if (
        service.name?.toLowerCase() !== serviceName(target).toLowerCase() ||
        !service.template?.containers?.[0]?.image
      ) {
        throw new Error("Cloud Run service does not identify the deployed image");
      }
      const image = service.template.containers[0].image;
      const ownedImage = assertOwnedImage(image, target);
      const versions = await listOwnedVersions(control, target, "control");
      if (versions.length !== 1)
        throw new Error("deployed function did not create exactly one owned image version");
      if (
        ownedImage.digest &&
        decodeURIComponent(versions[0].name.split("/").at(-1)) !== ownedImage.digest
      ) {
        throw new Error(
          "Cloud Run image digest does not match the owned Artifact Registry version",
        );
      }
      if (ownedImage.tag) await assertOwnedTag(control, target, ownedImage.tag, versions[0].name);
      states[target].versionName = versions[0].name;
      await publicInvoker(control, target, true, "control");
      states[target].publicSince = Date.now();
    }
    const endpoints = Object.fromEntries(targets.map((target) => [target, states[target].url]));
    const replacements = user ? { [user.localId]: "{{uid}}", [user.email]: "{{email}}" } : {};
    const tokens = user
      ? {
          idToken: user.idToken,
          invalidSignatureIdToken: invalidSignatureToken(user.idToken),
          expiredIdToken: user.idToken,
        }
      : {};
    const deadline = Math.min(
      ...targets.map((target) => states[target].exposureStart + EXPOSURE_MS),
    );
    for (const pass of [0, 1]) {
      if (abort.stopped || Date.now() >= deadline) {
        throw new Error("signal or public exposure limit stopped observation");
      }
      recordings[pass][program.id] = await runCases(program, endpoints, tokens, budget, {
        replacements,
        deadline,
      });
      const raw = JSON.stringify(recordings[pass]);
      if (user && [user.idToken, user.localId, user.email].some((value) => raw.includes(value))) {
        throw new Error("recording retained a private Auth value");
      }
      await writeFile(
        join(runDir, `recording-${pass + 1}.json`),
        `${JSON.stringify(recordings[pass], null, 2)}\n`,
        { mode: 0o600 },
      );
    }
  } catch (caught) {
    error = caught;
  } finally {
    for (const target of targets.toReversed())
      await cleanupTarget(control, target, adcPath, budget, runDir, states[target]);
    if (user) {
      try {
        await deleteUser(control, user, runDir, program.id);
      } catch (caught) {
        states.userCleanupError = caught.message;
      }
    }
  }
  const incomplete =
    targets.some((target) => states[target].started && !states[target].cleaned) ||
    states.userCleanupError ||
    (userAttempted && !user) ||
    error?.indeterminate;
  if (incomplete) {
    const failure = new Error(
      `${program.id}: cleanup requires review; ${JSON.stringify(states, (key, value) => (key === "url" ? undefined : value))}`,
    );
    failure.residual = true;
    throw failure;
  }
  if (error) throw error;
}

export async function recordProduction() {
  await assertPrivateApproval();
  const corpus = await requiredSourceDigests();
  const adc = await ownerAdc();
  const ledgerLines = (await readFile(LEDGER, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assertAdmission(ledgerLines);
  const budget = createBudget();
  const runDir = join(PRIVATE_ROOT, "runs", `functions-http-stage3-${now().replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const lock = await open(LOCK, "wx", 0o600);
  let terminal = false;
  const abort = { stopped: false };
  const stop = () => {
    abort.stopped = true;
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, stop);
  try {
    // Repeat admission after the exclusive lock. The lock remains until ledger closure.
    const lines = (await readFile(LEDGER, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assertAdmission(lines);
    const git = await new Promise((resolveGit, reject) => {
      const child = spawn("git", ["rev-parse", "HEAD"], { cwd: ROOT });
      let result = "";
      child.stdout.on("data", (chunk) => {
        result += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) =>
        code === 0 ? resolveGit(result.trim()) : reject(new Error("git rev-parse failed")),
      );
    });
    const base = {
      ts: now(),
      project: PROJECT,
      database: null,
      taskId: TASK,
      stage: 3,
      gitSha: git,
      corpusDigest: CORPUS_SHA,
      runDir,
      maxEstimatedUsd: 9,
    };
    await appendFile(
      LEDGER,
      `${JSON.stringify({ ...base, event: "started", requests: null, estimatedUsd: 9 })}\n`,
    );
    const control = createControl(adc.file, budget);
    const recordings = [{}, {}];
    let outcome = "recorded";
    let reason;
    let residual = false;
    try {
      await preflightCliSideEffects(control);
      for (const program of corpus.programs) {
        if (abort.stopped) throw new Error("signal stopped the observation");
        await observeProgram(program, control, adc.path, budget, runDir, recordings, abort);
      }
      await writeFile(
        join(runDir, "recording-1.json"),
        `${JSON.stringify(recordings[0], null, 2)}\n`,
        { mode: 0o600 },
      );
      await writeFile(
        join(runDir, "recording-2.json"),
        `${JSON.stringify(recordings[1], null, 2)}\n`,
        { mode: 0o600 },
      );
      await writeFile(
        join(runDir, "comparison.json"),
        `${JSON.stringify({ identical: JSON.stringify(recordings[0]) === JSON.stringify(recordings[1]), requests: budget.snapshot() }, null, 2)}\n`,
        { mode: 0o600 },
      );
    } catch (error) {
      outcome = "stopped-needs-review";
      reason = error.message;
      residual = Boolean(error.residual);
    }
    await appendFile(
      LEDGER,
      `${JSON.stringify({
        ...base,
        ts: now(),
        ...(residual ? { event: "needs-recovery" } : { outcome }),
        reason,
        requests: budget.snapshot(),
        estimatedUsd: estimatedUsd(budget.snapshot()),
      })}\n`,
    );
    terminal = !residual;
    if (reason) throw new Error(`observation stopped: ${reason}; private evidence: ${runDir}`);
    console.log(JSON.stringify({ outcome, requests: budget.snapshot(), runDir }));
  } finally {
    if (!terminal) {
      // A crash before a terminal line leaves the exclusive lock for a reviewed recovery.
      await writeFile(
        join(runDir, "nonterminal.txt"),
        "The shared lock remains. Review the ledger and owned resources before recovery.\n",
        { mode: 0o600 },
      );
    } else {
      await lock.close();
      const { unlink } = await import("node:fs/promises");
      await unlink(LOCK);
    }
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, stop);
  }
}
