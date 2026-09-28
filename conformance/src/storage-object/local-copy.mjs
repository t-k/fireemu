import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCorpus } from "./corpus.mjs";
import { replayLocalCopyRewrite } from "./copy-replay.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

const host = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
if (!host || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(host))
  throw new Error("a local Storage emulator host is required");
const bucket = "example.appspot.com";
const plan = buildStage3DraftPlan({
  projectId: "example-project",
  bucket,
  runIds: ["localcopyrewrite", "unusedcopyrewrite"],
});
const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
  (row) => row.id === "storage-object/gcs/copy-rewrite",
);
const directory = await mkdtemp(join(tmpdir(), "storage-object-copy-"));
const eventPath = join(directory, "requests.jsonl");
await writeFile(eventPath, "", { flag: "wx", mode: 0o600 });
const record = (event) => appendFile(eventPath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
const sender = createLocalStorageSender({
  plan,
  origin: `http://${host}`,
  fetchImpl: globalThis.fetch,
  credentials: { admin: "Bearer owner" },
  onStart: async (event) => record({ type: "started", ...event }),
  onReserve: async (event) => record({ type: "reserved", ...event }),
  onJournal: async (event) => record({ type: "ownership", ...event }),
});
const result = await replayLocalCopyRewrite({
  sender,
  recipe,
  bucket,
  onCapture: async (event) => record({ type: "response", ...event }),
});
process.stdout.write(`${JSON.stringify({ ...result, eventDirectory: directory })}\n`);
if (result.status !== "LOCAL_COMPLETE") process.exitCode = 2;
