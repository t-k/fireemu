import { createHash } from "node:crypto";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");

const projectId = "example-project";
const bucket = "example.appspot.com";
const recipeIds = [
  "storage-object/firebase/multipart-upload",
  "storage-object/gcs/simple-multipart-upload",
  "storage-object/gcs/checksums",
];
const directory = await mkdtemp(join(tmpdir(), "storage-object-independent-"));
const results = [];

function expectedMediaSha256(step) {
  const bytes = Buffer.from(step.body.base64, "base64");
  if (step.query.uploadType === "media") return createHash("sha256").update(bytes).digest("hex");
  const marker = Buffer.from(
    "\r\n--fireemu-object-multipart-v1\r\nContent-Type: application/octet-stream\r\n\r\n",
  );
  const endMarker = Buffer.from("\r\n--fireemu-object-multipart-v1--\r\n");
  const start = bytes.indexOf(marker);
  const end = bytes.lastIndexOf(endMarker);
  if (start < 0 || end < start + marker.length) return null;
  return createHash("sha256")
    .update(bytes.subarray(start + marker.length, end))
    .digest("hex");
}

for (const [index, recipeId] of recipeIds.entries()) {
  const runId = `localindependent${String(index + 1).padStart(2, "0")}`;
  const plan = buildStage3DraftPlan({
    projectId,
    bucket,
    runIds: [runId, `unusedindependent${index + 1}`],
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
  for (const name of recipe.objects) sender.admitObject(name);
  for (const step of recipe.preflight) {
    const response = await sender.sendStep(step);
    if (response.status !== 404)
      throw new Error(`${recipeId}: preflight ${step.id} was not absent`);
  }

  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        mutationId: null,
        mutationStatus: null,
        expectedBytesSha256: null,
        metadataId: null,
        mediaId: null,
        confirmed: false,
        owned: false,
      },
    ]),
  );
  const mutationStatuses = [];
  for (const step of recipe.steps) {
    const state = states.get(step.objectName);
    if (!state) throw new Error(`${recipeId}: undeclared object`);
    const response = await sender.sendStep(step);
    if (step.method !== "GET") {
      if (state.mutationId !== null)
        throw new Error(`${recipeId}: object has more than one mutation`);
      state.mutationId = step.id;
      state.mutationStatus = response.status;
      state.expectedBytesSha256 = expectedMediaSha256(step);
      mutationStatuses.push({ id: step.id, status: response.status });
    } else if (Object.keys(step.query).length === 0) {
      state.metadataId = step.id;
    } else if (Object.keys(step.query).length === 1 && step.query.alt === "media") {
      state.mediaId = step.id;
      if (!state.confirmed && state.mutationId !== null) {
        if (state.mutationStatus >= 400) {
          if (response.status !== 404)
            throw new Error(`${recipeId}: refused ${state.mutationId} left media`);
          await sender.confirmAbsent({
            name: step.objectName,
            mutationOperationId: state.mutationId,
            metadataOperationId: state.metadataId,
            mediaOperationId: state.mediaId,
          });
        } else {
          if (!state.expectedBytesSha256)
            throw new Error(`${recipeId}: successful ${state.mutationId} lacks expected bytes`);
          sender.confirmOwned({
            name: step.objectName,
            uploadOperationId: state.mutationId,
            metadataOperationId: state.metadataId,
            mediaOperationId: state.mediaId,
            expectedBytesSha256: state.expectedBytesSha256,
          });
          state.owned = true;
        }
        state.confirmed = true;
      }
    }
  }
  if ([...states.values()].some((state) => !state.confirmed || !state.metadataId || !state.mediaId))
    throw new Error(`${recipeId}: unconfirmed object mutation`);
  sender.beginCleanup();
  for (const [name, state] of states) {
    const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
    if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
      throw new Error(`${recipeId}: invalid object cleanup declaration`);
    if (state.owned) {
      const deletion = await sender.cleanupOwned({
        name,
        metadataOperationId: state.metadataId,
        mediaOperationId: state.mediaId,
        operationId: cleanup[0].id,
      });
      if (deletion.status !== 204) throw new Error(`${recipeId}: conditional cleanup failed`);
    }
    for (const step of cleanup.slice(1)) {
      const response = await sender.sendStep(step);
      if (response.status !== 404)
        throw new Error(`${recipeId}: cleanup ${step.id} was not absent`);
    }
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error(`${recipeId}: unresolved owned objects`);
  results.push({
    recipeId,
    status: "LOCAL_COMPLETE",
    requests: sender.snapshot().total,
    mutationStatuses,
  });
}

process.stdout.write(`${JSON.stringify({ results, eventDirectory: directory })}\n`);
