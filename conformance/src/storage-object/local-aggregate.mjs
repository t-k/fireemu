import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdtemp, open, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { replayLocalAggregate } from "./aggregate-replay.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { loopbackHttpOrigin } from "./wire-serialization.mjs";

function host(name) {
  const value = process.env[name];
  if (!value || !/^(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}$/.test(value))
    throw new Error("explicit local emulator hosts are required");
  return loopbackHttpOrigin(`http://${value}`);
}

const storageOrigin = host("FIREBASE_STORAGE_EMULATOR_HOST"),
  authOrigin = host("FIREBASE_AUTH_EMULATOR_HOST"),
  control = new URL(process.env.FIREEMU_CONTROL_URL);
if (
  control.pathname !== "/v1/" ||
  control.search ||
  control.hash ||
  control.username ||
  control.password ||
  loopbackHttpOrigin(control.origin) !== control.origin ||
  !control.origin.startsWith("http:")
)
  throw new Error("explicit loopback control URL is required");
const rulesSource = await readFile(process.env.STORAGE_OBJECT_RULES_SOURCE);
if (createHash("sha256").update(rulesSource).digest("hex") !== FIXED_PRODUCTION_RULES_SHA256)
  throw new Error("the fixed stage2 Rules source is required");

const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: [randomBytes(10).toString("hex"), randomBytes(10).toString("hex")],
  }),
  directory = await mkdtemp(join(tmpdir(), "storage-object-aggregate-"));
await chmod(directory, 0o700);
const journal = await open(join(directory, "aggregate-events.jsonl"), "wx", 0o600);
let writing = false,
  failed = false,
  eventSequence = 0;
async function record(event) {
  if (failed || writing) throw new Error("local aggregate journal is unavailable");
  writing = true;
  try {
    const bytes = Buffer.from(`${JSON.stringify({ ...event, eventSequence: ++eventSequence })}\n`);
    const { bytesWritten } = await journal.write(bytes);
    if (bytesWritten !== bytes.length) throw new Error("incomplete local journal write");
    await journal.sync();
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    writing = false;
  }
}

let result;
try {
  const sourceDirectory = dirname(fileURLToPath(import.meta.url)),
    sourceFiles = [];
  for (const name of (await readdir(sourceDirectory))
    .filter((entry) => entry.endsWith(".mjs"))
    .toSorted())
    sourceFiles.push({
      file: `src/storage-object/${name}`,
      sha256: createHash("sha256")
        .update(await readFile(join(sourceDirectory, name)))
        .digest("hex"),
    });
  await record({
    type: "aggregate-source",
    nodeVersion: process.version,
    rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
    sourceFiles,
    plan,
    productionSendAuthorized: false,
  });
  result = await replayLocalAggregate({
    plan,
    storageOrigin,
    authOrigin,
    localControl: { origin: control.origin, token: process.env.FIREEMU_CONTROL_TOKEN },
    localAuth: {
      apiKey: "storage-object-local-key",
      password: randomBytes(24).toString("base64url"),
    },
    credentials: { admin: "Bearer owner" },
    captureDirectory: directory,
    onStart: (event) => record({ ...event, type: "started" }),
    onReserve: (event) => record({ ...event, type: "reserved" }),
    onRecipeBegin: (event) => record({ ...event, type: "recipe-begin" }),
    onRecipeFinish: (event) => record({ ...event, type: "recipe-finish" }),
    onJournal: record,
    onCapture: (event) => record({ ...event, type: "response" }),
    onByteReserve: (event) => record({ ...event, type: "wire-budget" }),
  });
  await record({ type: "aggregate-ended", result });
  const manifest = await open(join(directory, "manifest.json"), "wx", 0o600);
  try {
    await manifest.writeFile(`${JSON.stringify({ plan, sourceFiles, result }, null, 2)}\n`);
    await manifest.sync();
  } finally {
    await manifest.close();
  }
} finally {
  await journal.close();
}
process.stdout.write(
  `${JSON.stringify({
    status: result.status,
    completedRecipes: result.counter.completedRecipes,
    requests: result.counter.total,
    recordings: result.counter.recordings,
    wire: result.wire,
    eventDirectory: directory,
    productionParityProved: false,
    responseCompatibilityProved: false,
  })}\n`,
);
if (result.status !== "LOCAL_COMPLETE") process.exitCode = 2;
