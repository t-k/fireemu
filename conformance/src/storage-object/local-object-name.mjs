import { replayLocalObjectNames } from "./object-name-replay.mjs";
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
const runId = "localobjectname01";
const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, "unusedobjectname01"] });
const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
  (item) => item.id === "storage-object/errors/object-name",
);
const directory = await mkdtemp(join(tmpdir(), "storage-object-name-"));
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
const result = await replayLocalObjectNames({ sender, recipe, bucket });
process.stdout.write(`${JSON.stringify({ ...result, eventDirectory: directory })}\n`);
