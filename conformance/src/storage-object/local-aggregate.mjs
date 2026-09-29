import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdtemp, open, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { replayLocalAggregate } from "./aggregate-replay.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { loopbackHttpOrigin } from "./wire-serialization.mjs";
import { createLeanWire } from "./lean-wire.mjs";
import { createLocalFetchForLeanWire } from "./local-lean-wire.mjs";
import { createObjectMutationPacer } from "./production-pacing.mjs";

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
  // STORAGE_OBJECT_LOCAL_WIRE=lean sends every request through lean-wire.mjs itself, with the four
  // real hosts mapped onto the local server, as a production run does.
  const leanWire = process.env.STORAGE_OBJECT_LOCAL_WIRE === "lean";
  const ownerToken = "rehearsal-owner-token-0000000000";
  const stopAfterRecipes = Number(process.env.STORAGE_OBJECT_LOCAL_STOP_AFTER_RECIPES ?? "0");
  let recipesBegun = 0;
  const placeholders = {
    storage: "http://127.0.0.1:19199",
    auth: "http://127.0.0.1:19099",
    control: "http://127.0.0.1:19198",
  };
  result = await replayLocalAggregate({
    plan,
    ...(leanWire
      ? {
          wireFactory: ({ origins }) => {
            const prefix = plan.recordings[0].prefix;
            // `origins` are the placeholders the senders were given; the local servers are the
            // real ones the mapping fetch reaches (Auth and the control API share one origin).
            const localFetch = createLocalFetchForLeanWire({
              local: { storage: storageOrigin, auth: authOrigin, control: control.origin },
              ownerToken,
              fetchImpl: globalThis.fetch,
            });
            return createLeanWire({
              bucket: plan.bucket,
              projectId: plan.projectId,
              prefix,
              origins: { storage: origins[0], auth: origins[1], control: origins[2] },
              adminToken: async () => ownerToken,
              authApiKey: "storage-object-local-key",
              readRules: async ({ countRequest }) => {
                countRequest();
                const response = await globalThis.fetch(
                  new URL("/v1/storage/rules", control.origin),
                  {
                    headers: { authorization: `Bearer ${process.env.FIREEMU_CONTROL_TOKEN}` },
                  },
                );
                return { source: (await response.json()).source };
              },
              fetchImpl: localFetch,
              capture: (entry) =>
                journal.write(`${JSON.stringify({ type: "lean-capture", ...entry })}\n`),
              pacer: createObjectMutationPacer({ ownedPrefixes: [prefix] }),
            });
          },
        }
      : {}),
    stopAfter: () => stopAfterRecipes > 0 && recipesBegun >= stopAfterRecipes,
    recordings: Number(process.env.STORAGE_OBJECT_LOCAL_RECORDINGS ?? "2"),
    storageOrigin: leanWire ? placeholders.storage : storageOrigin,
    authOrigin: leanWire ? placeholders.auth : authOrigin,
    localControl: {
      origin: leanWire ? placeholders.control : control.origin,
      token: process.env.FIREEMU_CONTROL_TOKEN,
    },
    localAuth: {
      apiKey: "storage-object-local-key",
      password: randomBytes(24).toString("base64url"),
    },
    credentials: { admin: "Bearer owner" },
    captureDirectory: directory,
    onStart: (event) => record({ ...event, type: "started" }),
    onReserve: (event) => record({ ...event, type: "reserved" }),
    onRecipeBegin: (event) => {
      recipesBegun++;
      return record({ ...event, type: "recipe-begin" });
    },
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
