// Fakes shared by the FUNCTIONS-HTTP recorder tests: a fake Cloud Storage and REST world, a harmless
// deploy CLI child, and the recorded Gen2 function record shape.
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as production from "./production.mjs";

export const UPLOAD_NUMBER = "123456789012";
export const UPLOAD_OBJECT = "9be229fd-1507-4797-ab4b-69f2fda6e54a.zip";

// A deployed Gen2 function record in the recorded shape (FE v4 lists.functions-v2, masked): its
// source is the copy Cloud Functions made in the sources bucket, not the upload.
export function recordedGen2Record() {
  const recorded = JSON.parse(
    readFileSync(
      new URL(
        "../src/functions-events/record/recorded/v4-run/0029-lists.functions-v2.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const record = structuredClone(recorded.body.functions.find((f) => f.environment === "GEN_2"));
  record.name = "projects/fireemu-oracle-query/locations/us-central1/functions/fireemuHttpProbe";
  record.buildConfig.entryPoint = "fireemuHttpProbe";
  record.serviceConfig.service =
    "projects/fireemu-oracle-query/locations/us-central1/services/fireemuhttpprobe";
  record.serviceConfig.uri = "https://fireemuhttpprobe-abc-uc.a.run.app";
  return record;
}

export async function uploadWorld(overrides = {}) {
  const { createFakeGcs, FAKE_BUCKET, SECRET_MARKER, answer } =
    await import("../src/shared/gen2-source-uploads.fake.mjs");
  const { openSourceUploads } = await import("../src/shared/gen2-source-uploads.mjs");
  const { createBudget } = await import("./harness.mjs");
  const dir = await mkdtemp(join(tmpdir(), "functions-http-uploads-"));
  const gcs = createFakeGcs();
  const budget = createBudget(overrides.caps);
  const functions = {
    present: overrides.functionPresent ?? false,
    record: recordedGen2Record(),
  };
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
    requestsLeft: () => 240 - budget.snapshot().upload,
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

export async function runFakeCli(body, kind, track) {
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

export const FAKE_RECEIPT_SCRIPT = (tail, put) => `
const body = JSON.stringify({
  uploadUrl: "https://storage.googleapis.com/gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com/${UPLOAD_OBJECT}?X-Goog-Signature=SECRET-MARKER-9f3a",
  storageSource: { bucket: "gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com", object: "${UPLOAD_OBJECT}" },
});
console.log("i  functions: deploying");
console.log("[2026-10-26T01:02:03.456Z] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions:generateUploadUrl " + body);
${
  put
    ? `console.log("[2026-10-26T01:02:04.000Z] <<< [apiv2][status] PUT https://storage.googleapis.com/gcf-v2-uploads-123456789012.us-central1.cloudfunctions.appspot.com/${UPLOAD_OBJECT} ${put}");`
    : ""
}
console.log("ARGV " + JSON.stringify(process.argv.slice(2)));
${tail}
`;

export const FH_FUNCTION =
  "projects/fireemu-oracle-query/locations/us-central1/functions/fireemuHttpProbe";
export const FH_SERVICE =
  "projects/fireemu-oracle-query/locations/us-central1/services/fireemuhttpprobe";
export const FH_PACKAGE =
  "projects/fireemu-oracle-query/locations/us-central1/repositories/gcf-artifacts/packages/fireemu--oracle--query__us--central1__fireemu_http_probe";
export const FH_DIGEST = `sha256:${"ab".repeat(32)}`;
export const FH_VERSION = `${FH_PACKAGE}/versions/${FH_DIGEST}`;

/** The fake REST world, the harmless deploy child and the upload helper, without running a program. */
export async function deployWorld({ deployScript, deleteStatus, caps }) {
  const base = await uploadWorld({ caps });
  const deployed = { present: false, versionExists: false, bindings: [] };
  const control = async (method, url, body, kind = "control", allowed = [200]) => {
    base.budget.take(kind);
    const reply = (status, value = {}) => ({ status, value, bytes: 10 });
    let result;
    if (url.startsWith("https://storage.googleapis.com/")) {
      result = await base.gcs.send(method, url);
    } else if (
      url.startsWith(
        "https://serviceusage.googleapis.com/v1/projects/fireemu-oracle-query/services?",
      )
    ) {
      result = reply(200, {
        services: [
          "cloudfunctions",
          "cloudbuild",
          "artifactregistry",
          "run",
          "eventarc",
          "pubsub",
          "storage",
          "firebaseextensions",
        ].map((name) => ({ config: { name: `${name}.googleapis.com` } })),
      });
    } else if (
      url ===
      "https://serviceusage.googleapis.com/v1/projects/fireemu-oracle-query/services/logging.googleapis.com"
    ) {
      result = reply(200, { state: deployed.loggingState ?? "ENABLED" });
    } else if (
      url ===
      `https://artifactregistry.googleapis.com/v1/projects/fireemu-oracle-query/locations/us-central1/repositories/gcf-artifacts`
    ) {
      result = reply(200, {
        name: "projects/fireemu-oracle-query/locations/us-central1/repositories/gcf-artifacts",
        format: "DOCKER",
        mode: "STANDARD_REPOSITORY",
        cleanupPolicies: {
          "firebase-functions-cleanup": {
            id: "firebase-functions-cleanup",
            action: "DELETE",
            condition: { tagState: "ANY", olderThan: "86400s" },
          },
        },
      });
    } else if (
      url === "https://firebase.googleapis.com/v1beta1/projects/fireemu-oracle-query/adminSdkConfig"
    ) {
      result = reply(200, { projectId: "fireemu-oracle-query" });
    } else if (url === `https://cloudfunctions.googleapis.com/v2/${FH_FUNCTION}`) {
      result = deployed.present ? reply(200, recordedGen2Record()) : reply(404);
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
  const argv = [];
  const run = async (args, adc, budget, kind, runDir, track) => {
    calls.push(kind);
    argv.push(args);
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
  return { ...base, uploads, control, run, calls, argv, deployed };
}

export async function observeWorld({ deployScript, deleteStatus }) {
  const base = await deployWorld({ deployScript, deleteStatus });
  const { uploads, control, run, calls, argv } = base;
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
  return { ...base, uploads, error, recordings, program, calls, argv };
}
