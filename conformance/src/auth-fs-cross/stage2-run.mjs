// AUTH-FS-CROSS stage-2 runner (the listener and SDK conditions).
//
//   node src/auth-fs-cross/stage2-run.mjs admission          the checks made before any request,
//                                                         printed; nothing is sent
//   node src/auth-fs-cross/stage2-run.mjs record-production  one recording (AFC2_RECORDING=1 or 2)
//                                                         against the idp sandbox, under the
//                                                         packet's approval (see stage2-record.mjs)
//   node src/auth-fs-cross/stage2-run.mjs build-fixture <dir1> <dir2>
//                                                         the fixture from the private run
//                                                         directories of recordings 1 and 2
//   node src/auth-fs-cross/stage2-run.mjs export-comparison <comparison.json> <out.json>
//                                                         --artifact <binary> --harness-commit <sha>
//                                                         --fireemu-commit <sha>
//                                                         the committed evidence of a comparison
//   node src/auth-fs-cross/stage2-run.mjs check [--rows <fireemu.json>]
//                                                         run the window against fireemu (or
//                                                         read a saved local run) and compare
//   node src/auth-fs-cross/stage2-run.mjs local [--smoke [--with-browser] [--skip-clients a,b]
//                                                         [--cap-client name=n,...]]
//                                                         run the window against fireemu only
//
// A local run keeps production's timeline in real time (decision D3): about 65 minutes. The
// `--smoke` form drops the browser clients and the waits for the tokens' expiry, so the rest of
// the program can be tried in a few minutes; its rows are never compared.

import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { createContext, SANDBOX_PROJECT } from "../fs-rules/harness.mjs";
import { STAGE2_PRINCIPALS, STAGE2_PROGRAM } from "./programs-stage2.mjs";
import { closureTransports, validateStage2 } from "./stage2-corpus.mjs";
import { scanFixture } from "../auth-account/fixture-scan.mjs";
import { buildFixture, classifyStage2, comparable, stage2Evidence } from "./stage2-compare.mjs";
import { runStage2Window } from "./stage2-orchestrator.mjs";
import { browserKeyProbe, guardHarnessConnections } from "./stage2-record.mjs";

const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-fs-cross-stage2");
const FIXTURE = join(CONFORMANCE_DIR, "auth-fs-cross-stage2-production.json");
const CLOSURE = join(
  CONFORMANCE_DIR,
  "..",
  "spec",
  "compatibility",
  "closure",
  "AUTH-FS-CROSS.json",
);
/** The synthetic project number fireemu is configured with. */
const LOCAL_PROJECT_NUMBER = "123456789012";
const HARNESS_CEILING = 1_000;
const CLEANUP_CEILING = 1_100;

/** The program, checked against the frozen closure's transports. */
export async function checkedProgram() {
  const closure = closureTransports(JSON.parse(await readFile(CLOSURE, "utf8")));
  const cost = validateStage2(STAGE2_PROGRAM, { closure });
  return { program: STAGE2_PROGRAM, cost };
}

/**
 * The smoke form of a program: no browser clients (and none of their steps or references), no
 * waits for the tokens' expiry, and none of the clients named in `skip`. Only for trying the
 * rest locally; its rows are never compared.
 */
export function smokeProgram(program, skip = [], { browser = false, caps = {} } = {}) {
  const dropped = new Set([
    ...program.steps
      .filter((s) => !browser && s.do === "client" && s.transport === "browser")
      .map((s) => s.client),
    ...skip,
  ]);
  const kept = (ref) => !dropped.has(ref.split("/")[0]);
  const steps = [];
  for (const step of program.steps) {
    if (step.do === "expiry-probes" || step.do === "expiry-groups" || step.do === "sleep") continue;
    if (dropped.has(step.client)) continue;
    if (!browser && step.id?.startsWith("b-")) continue;
    const trimmed = { ...step };
    // A lowered cap shows, in a real run, how rows of a client refused by its cap are marked.
    if (step.do === "client" && caps[step.client] !== undefined)
      trimmed.wireCap = caps[step.client];
    if (step.observe) trimmed.observe = step.observe.filter(kept);
    if (step.clients) trimmed.clients = step.clients.filter(kept);
    const watches = (trimmed.observe?.length ?? 0) + (trimmed.clients?.length ?? 0);
    if ((step.do === "probe" || step.do === "observe") && watches === 0) continue;
    steps.push(trimmed);
  }
  return { ...program, steps };
}

/** fireemu's configuration for a local run. */
export function localConfig(profile = "strict") {
  return {
    schemaVersion: 1,
    profile,
    daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
    auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
  };
}

/** The Web SDK configuration of a local client: the same app, pointed at fireemu. */
export function localSdkConfig({ authOrigin, grpcHost, grpcPort }) {
  return {
    mode: "local",
    web: { apiKey: "fake-api-key", projectId: SANDBOX_PROJECT, authDomain: "localhost" },
    authEmulator: authOrigin,
    firestoreEmulator: { host: grpcHost, port: grpcPort },
  };
}

async function sessionLocal() {
  const program = JSON.parse(await readFile(process.env.AFC2_IN, "utf8"));
  const firestore = new URL(`http://${process.env.FIRESTORE_EMULATOR_HOST}`);
  const auth = new URL(`http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`);
  const target = {
    kind: "local",
    firestoreOrigin: firestore.origin,
    authOrigin: auth.origin,
    grpcHost: firestore.hostname,
    grpcPort: Number(firestore.port),
    projectNumber: LOCAL_PROJECT_NUMBER,
    control: {
      url: String(process.env.FIREEMU_CONTROL_URL).replace(/\/v1\/?$/, ""),
      token: process.env.FIREEMU_CONTROL_TOKEN,
    },
  };
  const ctx = createContext({ run: process.env.AFC2_RUN, target });
  const verbose = Boolean(process.env.AFC_VERBOSE);
  const log = (line) => {
    if (verbose) console.error(`${new Date().toISOString()} ${line}`);
  };
  const connections = guardHarnessConnections();
  let out;
  try {
    // As in production: the browser's first request with the key is a read, before any write.
    const keyProbe = await browserKeyProbe(localSdkConfig(target));
    if (!keyProbe.ok) throw new Error(`browser key probe refused: ${keyProbe.code}`);
    out = await runStage2Window(program, ctx, {
      principals: STAGE2_PRINCIPALS,
      sdkConfig: localSdkConfig(target),
      sessionOptions: {
        maxHarnessRequests: HARNESS_CEILING,
        maxCleanupRequests: CLEANUP_CEILING,
        log,
      },
      log,
    });
  } catch (error) {
    await writeFile(
      process.env.AFC2_OUT,
      JSON.stringify({ error: String(error.message ?? error), ...error.partial }),
    );
    throw error;
  }
  await writeFile(
    process.env.AFC2_OUT,
    JSON.stringify({ ...out, harnessConnections: connections.connections() }),
  );
}

/** A new private directory under `root` named by `now` (and a count when the name is taken). */
export async function newRunDir({ root = RUN_DIR, now = new Date() } = {}) {
  await mkdir(root, { recursive: true, mode: 0o700 });
  const stamp = now.toISOString().replaceAll(":", "-");
  for (let n = 1; ; n += 1) {
    const dir = join(root, n === 1 ? stamp : `${stamp}-${n}`);
    try {
      await mkdir(dir, { mode: 0o700 });
      return dir;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
  }
}

/** Where a comparison is written: next to the fresh run's rows, or a new directory for saved rows. */
export async function comparisonDir(local, { root = RUN_DIR, now = new Date() } = {}) {
  return local.runDir ?? (await newRunDir({ root, now }));
}

/**
 * A new private directory under `root` for one local run, named by its start time, with the
 * run's inputs written. An earlier run's directory (its rows, its comparison) is never touched:
 * a run that is stopped early leaves the earlier results as they were.
 */
export async function prepareRunDir({ root = RUN_DIR, now = new Date(), program, config }) {
  const dir = await newRunDir({ root, now });
  const paths = {
    in: join(dir, "program.json"),
    out: join(dir, "fireemu.json"),
    config: join(dir, "fireemu.config.json"),
    firebase: join(dir, "firebase.json"),
  };
  await writeFile(paths.firebase, JSON.stringify({ firestore: [{ database: "(default)" }] }));
  await writeFile(paths.config, JSON.stringify(config));
  await writeFile(paths.in, JSON.stringify(program));
  return { dir, paths };
}

export async function runLocal(program, { profile = "strict" } = {}) {
  const { dir, paths } = await prepareRunDir({ program, config: localConfig(profile) });
  console.log(JSON.stringify({ runDir: dir }));
  const binary = resolveFireemuBinary();
  const ports = [
    "--http-port",
    "--firestore-port",
    "--storage-port",
    "--ui-port",
    "--hub-port",
    "--logging-port",
  ].flatMap((flag) => [flag, "0"]);
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      paths.config,
      "--firebase-json",
      paths.firebase,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth,firestore",
      ...ports,
      "--",
      process.execPath,
      join(CONFORMANCE_DIR, "src/auth-fs-cross/stage2-run.mjs"),
      "session-local",
    ],
    {
      cwd: dir,
      stdio: ["ignore", "inherit", "inherit"],
      env: { ...process.env, AFC2_IN: paths.in, AFC2_OUT: paths.out, AFC2_RUN: String(Date.now()) },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  const out = JSON.parse(await readFile(paths.out, "utf8").catch(() => "{}"));
  if (code !== 0) throw Object.assign(new Error(`fireemu session exited ${code}`), { out });
  return { binary, runDir: dir, ...out };
}

/** Builds the fixture from the private run directories of recordings 1 and 2. */
async function writeStage2Fixture(dirs) {
  if (dirs.length !== 2)
    throw new Error("usage: build-fixture <recording-1 dir> <recording-2 dir>");
  const { stage2HarnessDigest, stage2ProgramDigest } = await import("./stage2-record.mjs");
  const loaded = await Promise.all(
    dirs.map(async (dir) => ({
      meta: JSON.parse(await readFile(join(dir, "meta.json"), "utf8")),
      recording: JSON.parse(await readFile(join(dir, "recording.json"), "utf8")),
    })),
  );
  const metas = loaded.map(({ meta }) => meta);
  if (metas.map((m) => m.recording).join() !== "1,2")
    throw new Error("the directories are not recordings 1 and 2");
  if (metas.some((m) => m.outcome !== "recorded"))
    throw new Error("both recordings must be recorded");
  const fixture = buildFixture({
    recordings: loaded.map(({ recording }) => recording),
    metas,
    programDigest: stage2ProgramDigest(),
    harnessDigest: await stage2HarnessDigest(),
  });
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  const web = JSON.parse(await readFile(process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG, "utf8"));
  scanFixture(text, [web.apiKey, SANDBOX_PROJECT, web.projectNumber, web.appId]);
  await writeFile(FIXTURE, text);
  const differing = Object.entries(fixture.rows)
    .filter(([, row]) => "second" in row)
    .map(([id]) => id);
  console.log(JSON.stringify({ rows: Object.keys(fixture.rows).length, differing }, null, 2));
}

/**
 * Writes the committed evidence of a saved comparison: `<comparison.json> <out.json>
 * --artifact <fireemu binary> --harness-commit <sha> --fireemu-commit <sha>`. The fixture is
 * the one in this checkout; the artifact is hashed here.
 */
async function exportStage2Comparison(args) {
  const [comparisonPath, out] = args;
  const flag = (name) => {
    const at = args.indexOf(name);
    return at >= 0 ? args[at + 1] : undefined;
  };
  const artifact = flag("--artifact");
  if (!comparisonPath || !out || !artifact)
    throw new Error(
      "usage: export-comparison <comparison.json> <out.json> --artifact <binary> --harness-commit <sha> --fireemu-commit <sha>",
    );
  const { createHash } = await import("node:crypto");
  const evidence = stage2Evidence({
    comparison: JSON.parse(await readFile(comparisonPath, "utf8")),
    fixtureText: await readFile(FIXTURE, "utf8"),
    artifactSha256: createHash("sha256").update(await readFile(artifact)).digest("hex"),
    harnessCommit: flag("--harness-commit"),
    fireemuCommit: flag("--fireemu-commit"),
  });
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fireemu: evidence.fireemu }, null, 2));
}

/** Compares fireemu's rows (a fresh window, or a saved local run) with the fixture. */
async function check(args) {
  const { stage2HarnessDigest, stage2ProgramDigest } = await import("./stage2-record.mjs");
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
  const stale =
    fixture.programDigest !== stage2ProgramDigest() ||
    fixture.harnessDigest !== (await stage2HarnessDigest());
  const rowsAt = args.indexOf("--rows");
  const local =
    rowsAt >= 0
      ? JSON.parse(await readFile(args[rowsAt + 1], "utf8"))
      : await runLocal((await checkedProgram()).program);
  const ids = [
    ...new Set([...Object.keys(fixture.rows), ...Object.keys(local.rows ?? {})]),
  ].toSorted();
  const rows = ids.map((id) => {
    const saved = fixture.rows[id];
    const fireemu = local.rows?.[id] === undefined ? undefined : comparable(local.rows[id]);
    const alternative = saved === undefined || !("second" in saved) ? undefined : saved.second;
    const status = classifyStage2({
      row: id,
      stale,
      production: saved?.production,
      alternative,
      fireemu,
    });
    const out = { row: id, status, production: saved?.production, fireemu };
    if (alternative !== undefined) out.alternative = alternative;
    return out;
  });
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const dir = await comparisonDir(local);
  const compared = rowsAt >= 0 ? args[rowsAt + 1] : join(dir, "fireemu.json");
  await writeFile(
    join(dir, "comparison.json"),
    `${JSON.stringify({ summary, compared, cleanupErrors: local.cleanupErrors ?? [], rows }, null, 2)}\n`,
  );
  console.log(JSON.stringify({ comparison: join(dir, "comparison.json") }));
  // A row whose varying part stayed inside its allowed set passes; the output shows both
  // production recordings and fireemu for it all the same.
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
  for (const row of rows.filter((r) => r.status !== "MATCH")) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 400)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 400)}`);
  }
  console.log(JSON.stringify({ summary, cleanupErrors: local.cleanupErrors ?? [] }, null, 2));
  if (rows.some((r) => !passing.has(r.status)) || (local.cleanupErrors ?? []).length)
    process.exitCode = 1;
}

async function main([command, ...args]) {
  switch (command) {
    case "session-local":
      return sessionLocal();
    case "build-fixture":
      return writeStage2Fixture(args);
    case "export-comparison":
      return exportStage2Comparison(args);
    case "check":
      return check(args);
    case "admission": {
      const { stage2Admission, runnerLimits } = await import("./stage2-record.mjs");
      const result = await stage2Admission();
      console.log(
        JSON.stringify(
          {
            sha: result.sha,
            harness: result.harness,
            programDigest: result.programDigest,
            packetSha256: result.packetSha256,
            recording: result.recording,
            runner: result.cost ? runnerLimits(result.cost) : null,
            problems: result.problems,
          },
          null,
          2,
        ),
      );
      if (result.problems.length) process.exitCode = 1;
      return undefined;
    }
    case "record-production": {
      const { recordProduction } = await import("./stage2-record.mjs");
      return recordProduction();
    }
    case "local": {
      const { program, cost } = await checkedProgram();
      const smoke = args.includes("--smoke");
      const skipAt = args.indexOf("--skip-clients");
      const skip =
        skipAt >= 0
          ? String(args[skipAt + 1] ?? "")
              .split(",")
              .filter(Boolean)
          : [];
      if (skip.length && !smoke) throw new Error("--skip-clients is a smoke option");
      console.log(JSON.stringify({ smoke, skip, cost }));
      const browser = args.includes("--with-browser");
      const capAt = args.indexOf("--cap-client");
      const caps = Object.fromEntries(
        (capAt >= 0
          ? String(args[capAt + 1] ?? "")
              .split(",")
              .filter(Boolean)
          : []
        ).map((pair) => {
          const [name, value] = pair.split("=");
          return [name, Number(value)];
        }),
      );
      if (Object.keys(caps).length && !smoke) throw new Error("--cap-client is a smoke option");
      if (browser && !smoke) throw new Error("--with-browser is a smoke option");
      const out = await runLocal(smoke ? smokeProgram(program, skip, { browser, caps }) : program);
      const path = join(out.runDir, "rows.json");
      await writeFile(path, JSON.stringify(out, null, 2));
      console.log(JSON.stringify({ rows: Object.keys(out.rows ?? {}).length, path }));
      return undefined;
    }
    default:
      throw new Error(`unknown command ${command}`);
  }
}

/**
 * A console whose reader is gone (a stopped `tee`) must not end the run mid-cleanup: the ledger
 * and the private files are files, and the run finishes them without the console.
 */
export function keepRunningWithoutConsole(streams = [process.stdout, process.stderr]) {
  for (const stream of streams) stream.on("error", () => {});
}

if (import.meta.url === `file://${process.argv[1]}`) {
  keepRunningWithoutConsole();
  main(process.argv.slice(2)).catch((error) => {
    console.error(error?.stack ?? error);
    process.exitCode = 1;
  });
}
