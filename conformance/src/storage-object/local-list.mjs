import { replayLocalList } from "./list-replay.mjs";
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
const recipeIds = ["storage-object/firebase/list", "storage-object/gcs/list"];
const directory = await mkdtemp(join(tmpdir(), "storage-object-list-"));
const results = [];
const gapOption = process.env.STORAGE_OBJECT_LOCAL_KNOWN_LIST_GAPS;
if (gapOption !== undefined && !["0", "1"].includes(gapOption))
  throw new Error("explicit local list gap option must be 0 or 1");

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
  results.push(
    await replayLocalList({
      sender,
      recipe,
      bucket,
      allowKnownLocalListGaps: gapOption === "1",
      onCapture: (event) => record({ type: "response", ...event }),
    }),
  );
}

process.stdout.write(`${JSON.stringify({ results, eventDirectory: directory })}\n`);
