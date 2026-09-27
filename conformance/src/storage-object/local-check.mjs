import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { createLocalStorageSender } from "./sender.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");

const projectId = "example-project";
const bucket = "example.appspot.com";
const runId = "localonlycheck01";
const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, "localonlycheck02"] });
const directory = await mkdtemp(join(tmpdir(), "storage-object-local-"));
const eventPath = join(directory, "events.jsonl");
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
const corpus = buildCorpus({ bucket, prefix: plan.recordings[0].prefix });
const recipe = corpus.recipes.find((item) => item.id === "storage-object/firebase/simple-upload");
sender.admitObject(recipe.objects[0]);
const response = await sender.sendStep(recipe.preflight[0], {
  operationId: "simple-baseline-firebase",
});
if (response.status !== 404)
  throw new Error(`unexpected initial Storage status ${response.status}`);
const baselineGcs = await sender.sendStep(recipe.preflight[1], {
  operationId: "simple-baseline-gcs",
});
if (baselineGcs.status !== 404)
  throw new Error(`unexpected initial GCS status ${baselineGcs.status}`);
const upload = await sender.sendStep(recipe.steps[0], { operationId: "simple-upload" });
const metadata = await sender.sendStep(recipe.steps[1], { operationId: "simple-metadata" });
const media = await sender.sendStep(recipe.steps[2], { operationId: "simple-media" });
const expectedBytesSha256 = createHash("sha256")
  .update(Buffer.from(recipe.steps[0].body.base64, "base64"))
  .digest("hex");
sender.confirmOwned({
  name: recipe.objects[0],
  uploadOperationId: "simple-upload",
  metadataOperationId: "simple-metadata",
  mediaOperationId: "simple-media",
  expectedBytesSha256,
});
sender.beginCleanup();
const deleted = await sender.cleanupOwned({
  name: recipe.objects[0],
  metadataOperationId: "simple-metadata",
  mediaOperationId: "simple-media",
  operationId: "simple-cleanup",
});
await sender.verifyRunEmpty();
sender.close();
process.stdout.write(
  `${JSON.stringify({
    status: "LOCAL_SIMPLE_RECIPE_COMPLETE",
    statuses: [
      response.status,
      baselineGcs.status,
      upload.status,
      metadata.status,
      media.status,
      deleted.status,
    ],
    mediaBytes: media.raw.length,
    requests: sender.snapshot().total,
    unresolved: sender.unresolved().length,
    eventPath,
  })}\n`,
);
