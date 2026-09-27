import { createHash } from "node:crypto";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { evaluateListPages } from "./list-pages.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");

const projectId = "example-project";
const bucket = "example.appspot.com";
const recipeIds = ["storage-object/firebase/list", "storage-object/gcs/list"];
const directory = await mkdtemp(join(tmpdir(), "storage-object-list-"));
const results = [];

function listBody(response) {
  if (response.status !== 200) throw new Error("list response was not 200");
  let parsed;
  try {
    parsed = JSON.parse(response.raw.toString("utf8"));
  } catch {
    throw new Error("list response was not JSON");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    (parsed.items !== undefined && !Array.isArray(parsed.items)) ||
    (parsed.prefixes !== undefined && !Array.isArray(parsed.prefixes))
  )
    throw new Error("list response has invalid collection data");
  return parsed;
}

function nextToken(body, cap) {
  const token = body.nextPageToken;
  if (token === undefined) return null;
  if (
    typeof token !== "string" ||
    !token ||
    Buffer.byteLength(token) > cap ||
    [...token].some((character) => {
      const code = character.codePointAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("list nextPageToken is invalid or exceeds the declared bound");
  return token;
}

for (const [index, recipeId] of recipeIds.entries()) {
  const runId = `locallist${String(index + 1).padStart(4, "0")}`;
  const plan = buildStage3DraftPlan({
    projectId,
    bucket,
    runIds: [runId, `unusedlist${index + 1}`],
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
    if (step.collection) {
      const body = listBody(response);
      if (
        body.nextPageToken ||
        (body.items?.length ?? 0) !== 0 ||
        (body.prefixes?.length ?? 0) !== 0
      )
        throw new Error(`${recipeId}: baseline list was not empty`);
    } else if (response.status !== 404) {
      throw new Error(`${recipeId}: preflight ${step.id} was not absent`);
    }
  }

  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        uploadId: null,
        expectedBytesSha256: null,
        metadataId: null,
        mediaId: null,
        confirmed: false,
      },
    ]),
  );
  const pageRecords = [];
  const pageSummaries = [];
  let pageToken = null;
  let pageFinished = false;
  for (const step of recipe.steps) {
    if (step.collection) {
      if (step.continuation && pageFinished) continue;
      if (step.continuation && pageToken === null)
        throw new Error(`${recipeId}: page continuation has no token`);
      const query = step.continuation
        ? { ...step.query, [step.continuation.targetQuery]: pageToken }
        : step.query;
      const response = await sender.sendStep({ ...step, query });
      const body = listBody(response);
      if (step.id.startsWith("page-")) {
        pageRecords.push({
          stepId: step.id,
          query,
          status: response.status,
          bodyBase64: response.raw.toString("base64"),
        });
        pageToken = nextToken(body, step.continuation?.maxTokenBytes ?? 4096);
        pageSummaries.push({
          stepId: step.id,
          items: body.items?.length ?? 0,
          prefixes: body.prefixes?.length ?? 0,
          hasNextPageToken: pageToken !== null,
        });
        pageFinished = pageToken === null;
      }
      continue;
    }
    const state = states.get(step.objectName);
    if (!state) throw new Error(`${recipeId}: undeclared seed object`);
    const response = await sender.sendStep(step);
    if (step.method === "POST") {
      if (response.status !== 200 || state.uploadId !== null || !step.body?.base64)
        throw new Error(`${recipeId}: seed upload failed or repeated`);
      state.uploadId = step.id;
      state.expectedBytesSha256 = createHash("sha256")
        .update(Buffer.from(step.body.base64, "base64"))
        .digest("hex");
    } else if (Object.keys(step.query).length === 0) {
      state.metadataId = step.id;
    } else if (step.query.alt === "media") {
      state.mediaId = step.id;
      sender.confirmOwned({
        name: step.objectName,
        uploadOperationId: state.uploadId,
        metadataOperationId: state.metadataId,
        mediaOperationId: state.mediaId,
        expectedBytesSha256: state.expectedBytesSha256,
      });
      state.confirmed = true;
    }
  }
  if ([...states.values()].some((state) => !state.confirmed) || !pageFinished)
    throw new Error(`${recipeId}: seed or list traversal is incomplete`);
  let pageEvaluation;
  try {
    pageEvaluation = evaluateListPages({ recipe, pages: pageRecords, bucket });
  } catch (error) {
    if (!error.message.startsWith("list pages:")) throw error;
    pageEvaluation = { status: "LOCAL_MISMATCH", reason: error.message };
  }
  sender.beginCleanup();
  for (const [name, state] of states) {
    const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
    if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
      throw new Error(`${recipeId}: invalid seed cleanup declaration`);
    const deletion = await sender.cleanupOwned({
      name,
      metadataOperationId: state.metadataId,
      mediaOperationId: state.mediaId,
      operationId: cleanup[0].id,
    });
    if (deletion.status !== 204) throw new Error(`${recipeId}: seed cleanup failed`);
    for (const step of cleanup.slice(1)) {
      const response = await sender.sendStep(step);
      if (response.status !== 404)
        throw new Error(`${recipeId}: cleanup ${step.id} was not absent`);
    }
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error(`${recipeId}: unresolved seed objects`);
  results.push({
    recipeId,
    status: "LOCAL_COMPLETE",
    requests: sender.snapshot().total,
    pageEvaluation,
    pageSummaries,
  });
}

process.stdout.write(`${JSON.stringify({ results, eventDirectory: directory })}\n`);
