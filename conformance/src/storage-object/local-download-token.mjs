import { replayLocalDownloadTokens } from "./download-token-replay.mjs";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");

const bucket = "example.appspot.com";
const runId = "localtoken01";
const plan = buildStage3DraftPlan({
  projectId: "example-project",
  bucket,
  runIds: [runId, "unusedtoken01"],
});
const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
  (item) => item.id === "storage-object/firebase/download-tokens",
);
const directory = await mkdtemp(join(tmpdir(), "storage-object-token-"));
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
const result = await replayLocalDownloadTokens({ sender, recipe, bucket });
process.stdout.write(`${JSON.stringify({ ...result, eventDirectory: directory })}\n`);
