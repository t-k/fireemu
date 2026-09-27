import { createHash } from "node:crypto";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");

const projectId = "example-project";
const bucket = "example.appspot.com";
const recipeIds = [
  "storage-object/firebase/simple-upload",
  "storage-object/firebase/download",
  "storage-object/gcs/download",
];
const directory = await mkdtemp(join(tmpdir(), "storage-object-basic-"));
const results = [];

for (const [index, recipeId] of recipeIds.entries()) {
  const runId = `localbasic${String(index + 1).padStart(4, "0")}`;
  const plan = buildStage3DraftPlan({
    projectId,
    bucket,
    runIds: [runId, `unusedbasic${index + 1}`],
  });
  const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
    (item) => item.id === recipeId,
  );
  const eventPath = join(directory, `${runId}.jsonl`);
  await writeFile(eventPath, "", { flag: "wx", mode: 0o600 });
  const record = async (event) =>
    appendFile(eventPath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  const sender = createLocalStorageSender({
    plan,
    origin: `http://${host}`,
    fetchImpl: globalThis.fetch,
    credentials: { admin: "Bearer owner" },
    onStart: async (event) => record({ type: "started", ...event }),
    onReserve: async (event) => record({ type: "reserved", ...event }),
    onJournal: async (event) => record({ type: "ownership", ...event }),
  });
  await sender.start();
  await sender.admitNamespace();
  if (recipe.objects.length !== 1) throw new Error("basic local recipe must have one object");
  const name = recipe.objects[0];
  sender.admitObject(name);
  const responses = new Map();
  for (const step of recipe.preflight) {
    const response = await sender.sendStep(step, { operationId: step.id });
    responses.set(step.id, {
      status: response.status,
      bodyBase64: response.raw.toString("base64"),
    });
    if (response.status !== 404)
      throw new Error(`${recipeId}: preflight ${step.id} was not absent`);
  }
  let uploadId = null;
  let expectedBytesSha256 = null;
  let confirmed = false;
  let currentMetadataId = null;
  let currentMediaId = null;
  for (const [stepIndex, declared] of recipe.steps.entries()) {
    const query = resolveDeclaredQuery({ recipe, stepIndex, responses, bucket });
    const step = { ...declared, query };
    const response = await sender.sendStep(step, { operationId: declared.id });
    responses.set(declared.id, {
      status: response.status,
      bodyBase64: response.raw.toString("base64"),
    });
    if (step.method !== "GET") {
      if (uploadId !== null || typeof step.body?.base64 !== "string")
        throw new Error(`${recipeId}: unexpected second mutation or upload body`);
      uploadId = declared.id;
      expectedBytesSha256 = createHash("sha256")
        .update(Buffer.from(step.body.base64, "base64"))
        .digest("hex");
    } else if (Object.keys(query).length === 0) {
      currentMetadataId = declared.id;
    } else if (
      Object.keys(query).length === 1 &&
      query.alt === "media" &&
      !Object.keys(step.headers ?? {}).some((header) => header.toLowerCase() === "range")
    ) {
      currentMediaId = declared.id;
      if (!confirmed && uploadId && currentMetadataId) {
        sender.confirmOwned({
          name,
          uploadOperationId: uploadId,
          metadataOperationId: currentMetadataId,
          mediaOperationId: currentMediaId,
          expectedBytesSha256,
        });
        confirmed = true;
      }
    }
  }
  if (!confirmed || !currentMetadataId || !currentMediaId)
    throw new Error(`${recipeId}: owned bytes were not confirmed`);
  sender.beginCleanup();
  const deleted = await sender.cleanupOwned({
    name,
    metadataOperationId: currentMetadataId,
    mediaOperationId: currentMediaId,
    operationId: recipe.cleanup[0].id,
  });
  if (deleted.status !== 204) throw new Error(`${recipeId}: cleanup delete was not confirmed`);
  for (const step of recipe.cleanup.slice(1)) {
    const response = await sender.sendStep(step, { operationId: step.id });
    if (response.status !== 404) throw new Error(`${recipeId}: cleanup ${step.id} was not absent`);
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length > 0) throw new Error(`${recipeId}: unresolved owned object`);
  results.push({ recipeId, status: "LOCAL_COMPLETE", requests: sender.snapshot().total });
}

process.stdout.write(`${JSON.stringify({ results, eventDirectory: directory })}\n`);
