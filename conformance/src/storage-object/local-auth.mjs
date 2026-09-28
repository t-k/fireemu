import { randomBytes, createHash } from "node:crypto";
import { appendFile, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { replayLocalAuth } from "./auth-replay.mjs";
import { createLocalStorageSender } from "./sender.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

function host(name) {
  const value = process.env[name];
  if (!value || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(value))
    throw new Error("local Auth and Storage hosts are required");
  return `http://${value}`;
}
const storageOrigin = host("FIREBASE_STORAGE_EMULATOR_HOST"),
  authOrigin = host("FIREBASE_AUTH_EMULATOR_HOST");
const control = new URL(process.env.FIREEMU_CONTROL_URL);
if (
  control.pathname !== "/v1/" ||
  control.search ||
  control.hash ||
  control.username ||
  control.password
)
  throw new Error("local control URL is invalid");
const source = await readFile(process.env.STORAGE_OBJECT_RULES_SOURCE);
if (createHash("sha256").update(source).digest("hex") !== FIXED_PRODUCTION_RULES_SHA256)
  throw new Error("the fixed stage2 Rules source is required");
const projectId = "example-project",
  bucket = "example.appspot.com",
  directory = await mkdtemp(join(tmpdir(), "storage-object-auth-")),
  results = [];
for (let index = 0; index < 2; index++) {
  const runId = `localauth${index + 1}`,
    plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, `unusedauth${index + 1}`] });
  const recipe = buildAuthCorpus({ projectId, bucket, runId }).recipes[index];
  const eventPath = join(directory, `${runId}.jsonl`);
  await writeFile(eventPath, "", { flag: "wx", mode: 0o600 });
  const record = (event) => appendFile(eventPath, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  const sender = createLocalStorageSender({
    plan,
    origin: storageOrigin,
    authOrigin,
    localAuth: {
      apiKey: "storage-object-local-key",
      password: randomBytes(24).toString("base64url"),
    },
    localControl: { origin: control.origin, token: process.env.FIREEMU_CONTROL_TOKEN },
    credentials: { admin: "Bearer owner" },
    fetchImpl: globalThis.fetch,
    onStart: (event) => record({ type: "started", ...event }),
    onReserve: (event) => record({ type: "reserved", ...event }),
    onJournal: (event) => record({ type: "ownership", ...event }),
  });
  const result = await replayLocalAuth({
    sender,
    recipe,
    bucket,
    prefix: plan.recordings[0].prefix,
    onCapture: (event) => record({ type: "response", ...event }),
  });
  results.push(result);
  if (result.status !== "LOCAL_COMPLETE") break;
}
process.stdout.write(
  `${JSON.stringify({ results, eventDirectory: directory, rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256 })}\n`,
);
if (results.length !== 2 || results.some((result) => result.status !== "LOCAL_COMPLETE"))
  process.exitCode = 2;
