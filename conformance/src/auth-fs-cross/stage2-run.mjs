// AUTH-FS-CROSS stage-2 runner (the listener and SDK conditions).
//
//   node src/auth-fs-cross/stage2-run.mjs local [--smoke [--skip-clients a,b]]
//                                                         run the window against fireemu only
//
// A local run keeps production's timeline in real time (decision D3): about 65 minutes. The
// `--smoke` form drops the browser clients and the waits for the tokens' expiry, so the rest of
// the program can be tried in a few minutes; its rows are never compared.

import { spawn } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { createContext, SANDBOX_PROJECT } from "../fs-rules/harness.mjs";
import { STAGE2_PRINCIPALS, STAGE2_PROGRAM } from "./programs-stage2.mjs";
import { closureTransports, validateStage2 } from "./stage2-corpus.mjs";
import { runStage2Window } from "./stage2-orchestrator.mjs";

const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-fs-cross-stage2");
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
/** Requests one SDK client may make in a window (its own guard refuses the next one). */
export const WIRE_CAP = 400;

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
export function smokeProgram(program, skip = []) {
  const dropped = new Set([
    ...program.steps
      .filter((s) => s.do === "client" && s.transport === "browser")
      .map((s) => s.client),
    ...skip,
  ]);
  const kept = (ref) => !dropped.has(ref.split("/")[0]);
  const steps = [];
  for (const step of program.steps) {
    if (step.do === "expiry-probes" || step.do === "sleep") continue;
    if (dropped.has(step.client)) continue;
    if (step.id?.startsWith("b-")) continue;
    const trimmed = { ...step };
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
    wireCap: WIRE_CAP,
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
  let out;
  try {
    out = await runStage2Window(program, ctx, {
      principals: STAGE2_PRINCIPALS,
      sdkConfig: localSdkConfig(target),
      sessionOptions: { maxHarnessRequests: HARNESS_CEILING, log },
      log,
    });
  } catch (error) {
    await writeFile(
      process.env.AFC2_OUT,
      JSON.stringify({ error: String(error.message ?? error), ...error.partial }),
    );
    throw error;
  }
  await writeFile(process.env.AFC2_OUT, JSON.stringify(out));
}

export async function runLocal(program, { profile = "strict" } = {}) {
  await rm(RUN_DIR, { recursive: true, force: true });
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const paths = {
    in: join(RUN_DIR, "program.json"),
    out: join(RUN_DIR, "fireemu.json"),
    config: join(RUN_DIR, "fireemu.config.json"),
    firebase: join(RUN_DIR, "firebase.json"),
  };
  await writeFile(paths.firebase, JSON.stringify({ firestore: [{ database: "(default)" }] }));
  await writeFile(paths.config, JSON.stringify(localConfig(profile)));
  await writeFile(paths.in, JSON.stringify(program));
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
      cwd: RUN_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: { ...process.env, AFC2_IN: paths.in, AFC2_OUT: paths.out, AFC2_RUN: String(Date.now()) },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  const out = JSON.parse(await readFile(paths.out, "utf8").catch(() => "{}"));
  if (code !== 0) throw Object.assign(new Error(`fireemu session exited ${code}`), { out });
  return { binary, ...out };
}

async function main([command, ...args]) {
  switch (command) {
    case "session-local":
      return sessionLocal();
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
      const out = await runLocal(smoke ? smokeProgram(program, skip) : program);
      const path = join(RUN_DIR, "rows.json");
      await writeFile(path, JSON.stringify(out, null, 2));
      console.log(JSON.stringify({ rows: Object.keys(out.rows ?? {}).length, path }));
      return undefined;
    }
    default:
      throw new Error(`unknown command ${command}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error?.stack ?? error);
    process.exitCode = 1;
  });
}
