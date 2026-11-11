// The local dry run of the Hosting observation: every corpus version is served by a real fireemu
// process (strict or emulator profile) from its own temporary public tree, the same requests the
// recorder sends to production are sent to it with the same client, and the answers are shaped
// into the same rows. Nothing here reaches a network except loopback.
//
//   FIREEMU_BIN=<fireemu binary> node local.mjs --profile strict|emulator --out <new file>
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { edgeRequest } from "./client.mjs";
import { buildCorpus, corpusManifest } from "./corpus.mjs";
import { shapeRow } from "./rows.mjs";

const LOCAL_PROJECT = "demo-hosting";
const READY_DEADLINE_MS = 15_000;

/** Request headers for a spec, filling `headersFrom` from earlier answers of the same version. */
export function requestHeaders(spec, answers) {
  const headers = { ...spec.headers };
  for (const dep of spec.headersFrom ?? []) {
    const source = answers.get(dep.fromRequest);
    const value =
      source?.outcome === "answered"
        ? source.headers.find(([n]) => n.toLowerCase() === dep.fromHeader)?.[1]
        : undefined;
    if (value === undefined) return undefined;
    headers[dep.header] = value;
  }
  return headers;
}

/** Writes the version's tree and firebase.json under `root`. */
export async function materialize(version, root) {
  const publicDir = join(root, "public");
  for (const [path, bytes] of Object.entries(version.files)) {
    const target = join(publicDir, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
  }
  await writeFile(
    join(root, "firebase.json"),
    JSON.stringify({
      hosting: { ...version.hosting, public: publicDir },
      emulators: {
        hosting: { port: 0 },
        ui: { enabled: false },
        logging: { port: 0 },
        hub: { port: 0 },
      },
    }),
  );
  return join(root, "firebase.json");
}

async function startFireemu(binary, profile, root, firebaseJson) {
  const ready = join(root, "ready.json");
  // The strict replay answers as production: `productionExact` turns the development defaults of the
  // default profile off (`hosting.cacheControl` and `hosting.clientCountry`).
  const config = ["--config", join(root, "profile.json")];
  await writeFile(
    join(root, "profile.json"),
    JSON.stringify(
      profile === "emulator"
        ? { schemaVersion: 1, profile: "emulator" }
        : { schemaVersion: 1, profile: "strict", productionExact: true },
    ),
  );
  await mkdir(join(root, "home"), { recursive: true });
  const child = spawn(
    binary,
    [
      "up",
      ...config,
      "--only",
      "hosting",
      "--project",
      LOCAL_PROJECT,
      "--firebase-json",
      firebaseJson,
      "--ready-file",
      ready,
      "--owner-stdin",
      "--log-verbosity",
      "quiet",
    ],
    { env: { PATH: process.env.PATH, HOME: join(root, "home") }, stdio: ["pipe", "pipe", "pipe"] },
  );
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  child.stdout.resume();
  const deadline = Date.now() + READY_DEADLINE_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`fireemu exited ${child.exitCode}: ${stderr}`);
    try {
      const descriptor = JSON.parse(await readFile(ready, "utf8"));
      return { child, port: Number(new URL(descriptor.hostingUrl).port) };
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  child.kill("SIGTERM");
  throw new Error("fireemu readiness deadline");
}

async function stop(child) {
  child.stdin.end();
  await Promise.race([
    new Promise((r) => child.once("exit", r)),
    new Promise((r) => setTimeout(r, 5000)),
  ]);
  if (child.exitCode === null) {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
}

/** Serves one version and returns its rows in request order. */
export async function runVersion(version, { binary, profile, send = edgeRequest }) {
  const root = await mkdtemp(join(tmpdir(), "hosting-prod-local-"));
  let process_;
  try {
    const firebaseJson = await materialize(version, root);
    process_ = await startFireemu(binary, profile, root, firebaseJson);
    const origin = `http://127.0.0.1:${process_.port}`;
    const answers = new Map();
    const rows = [];
    for (const spec of version.requests) {
      const headers = requestHeaders(spec, answers);
      const answer =
        headers === undefined
          ? { outcome: "unknown", reason: "dependency" }
          : await send({
              host: "127.0.0.1",
              port: process_.port,
              secure: false,
              method: spec.method,
              target: spec.target,
              headers: { host: `127.0.0.1:${process_.port}`, ...headers },
              body: spec.body,
            });
      answers.set(spec.id, answer);
      rows.push(shapeRow(spec, answer, { origin, secrets: [], version: version.id }));
    }
    return rows;
  } finally {
    if (process_) await stop(process_.child);
    await rm(root, { recursive: true, force: true });
  }
}

export async function runLocal({ binary, profile }) {
  const corpus = buildCorpus();
  const rows = [];
  for (const version of corpus.versions)
    rows.push(...(await runVersion(version, { binary, profile })));
  return { schema: 1, profile, corpusSha256: corpusManifest(corpus).corpusSha256, rows };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const option = (name) => process.argv[process.argv.indexOf(name) + 1];
  const profile = option("--profile");
  const out = option("--out");
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile strict|emulator");
  if (!out || !process.env.FIREEMU_BIN)
    throw new Error("--out <new file> and FIREEMU_BIN are required");
  const result = await runLocal({ binary: resolve(process.env.FIREEMU_BIN), profile });
  await writeFile(resolve(out), `${JSON.stringify(result, null, 2)}\n`, { flag: "wx" });
  console.log(
    JSON.stringify({
      profile,
      rows: result.rows.length,
      unknown: result.rows.filter((r) => r.outcome !== "answered").length,
    }),
  );
}
