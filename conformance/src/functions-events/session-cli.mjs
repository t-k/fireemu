import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { CaptureSink, exportPublicFrames } from "./capture.mjs";
import { validateCorpus } from "./corpus.mjs";
import { createLiveDriver } from "./live-driver.mjs";
import { validatePrograms } from "./programs.mjs";
import { runPrograms } from "./session.mjs";

const readJson = async (url) =>
  JSON.parse(await readFile(fileURLToPath(new URL(url, import.meta.url))));
const privateDir = process.env.FE_EVENTS_PRIVATE_DIR;
const projectId = process.env.GCLOUD_PROJECT;
if (!privateDir || !projectId) throw new Error("local event session environment is incomplete");
const [closure, corpus, manifest] = await Promise.all([
  readJson("../../../spec/compatibility/closure/FUNCTIONS-EVENTS.json"),
  readJson("../../functions-events/corpus.json"),
  readJson("../../functions-events/programs.json"),
]);
validateCorpus(corpus, closure);
validatePrograms(manifest, corpus, closure);
const onlyRecipeIds = process.env.FE_EVENTS_ONLY
  ? process.env.FE_EVENTS_ONLY.split(",").filter(Boolean)
  : undefined;
const windowMs = Number(process.env.FE_EVENTS_WINDOW_MS ?? "5000");
const allowedHandlers = [
  ...new Set(manifest.programs.flatMap((program) => Object.values(program.handlerExports))),
];
const capture = await CaptureSink.open({ privateDir, allowedHandlers });
let driver;
try {
  driver = await createLiveDriver({ projectId });
  const result = await runPrograms({ manifest, corpus, capture, driver, onlyRecipeIds, windowMs });
  await capture.barrier();
  await writeFile(`${privateDir}/session.json`, `${JSON.stringify(result, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  await writeFile(
    `${privateDir}/public.json`,
    `${JSON.stringify({ authority: "LOCAL_ONLY", frames: exportPublicFrames(capture.since(0)) }, null, 2)}\n`,
    { flag: "wx", mode: 0o600 },
  );
  console.log(
    `FUNCTIONS_EVENTS_LOCAL ${JSON.stringify({ status: result.status, programs: result.programs.length })}`,
  );
} finally {
  await driver?.close();
  await capture.close();
}
