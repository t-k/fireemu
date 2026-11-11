// One bounded production observation, in two runs: what a Gen2 HTTPS function whose code is the callable
// wrapper answers to six Authorization shapes, when it is deployed
//
//   wrapper   as a plain onRequest function (the callable's code served as onRequest: no callable trigger,
//             no callable label), and
//   callable  as a real callable (the control run),
//
// next to the same request without Authorization. The first run answers the question of the issue
// "strict callable served as onRequest 401 body": FUNCTIONS-HTTP-BEARER recorded that a public onRequest
// function receives `Bearer malformed` unchanged, so a callable's wrapper refuses it itself, and its refusal
// has not been recorded. Each run is one deploy, two passes of six requests, cleanup with read-back.
//
//   node functions-http/callable-ingress/observation.mjs local --variant wrapper|callable --profile strict|emulator --out <file>
//   node functions-http/callable-ingress/observation.mjs record-production --variant wrapper|callable
//   node functions-http/callable-ingress/observation.mjs judge <captures.json>
//
// `record-production` is run by the coordinator only, from a launch script that takes the
// fireemu-oracle-query project lock. The deploy, the public invoker, the cleanup, the source upload
// ownership, admission, the Cloud Build read and the two ledger lines are those of bearer-observation.mjs
// (recordObservation); this file adds the corpus, the judge, the fixtures of the two variants and the
// directory the CLI deploys from.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BEARER_SPEC,
  CAPS as BEARER_CAPS,
  KEPT_HEADERS,
  MAX_ATTEMPTS,
  captureFetch,
  productionDeps as bearerProductionDeps,
  recordObservation,
} from "../bearer-observation.mjs";
import {
  FUNCTION_NAMES,
  PROJECT,
  REGION,
  createBudget,
  expectedFunctionName,
} from "../harness.mjs";
import { cli } from "../production.mjs";
import { runCases } from "../session.mjs";
import { CASES, CASE_IDS, judgeObservation } from "./judge.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = resolve(HERE, "../..");

export { MAX_ATTEMPTS };
export const TASK_ID = "FUNCTIONS-HTTP-CALLABLE-INGRESS";
export const PROGRAM_ID = "functions-http/http/callable-ingress";

/** The two runs. The function keeps the reviewed name `fireemuHttpProbe` in both (target `http`). */
export const VARIANTS = Object.freeze({
  wrapper: Object.freeze({ directory: "wrapper" }),
  callable: Object.freeze({ directory: "callable" }),
});

// One attempt: twelve invocations (six cases, two passes); everything else is bearer-observation's bound.
export const CAPS = Object.freeze({ ...BEARER_CAPS, invocation: CASES.length * 2 });

// Response headers kept by value in the capture (every header name is kept besides). The wrapper's own
// CORS and Express headers are what a callable's refusal can carry; no credential or cookie header is kept.
export const captureHeaders = Object.freeze([
  ...KEPT_HEADERS,
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-expose-headers",
  "vary",
  "x-powered-by",
  "etag",
]);

// The reviewed bytes the run depends on, relative to this directory.
const SHARED_PINS = Object.freeze({
  "corpus.json": "ad3da40df55b9aad6c0e086dee3bf42fb4cb92323f00877c2da1bdc554fd232d",
  "baseline.json": "a08a6eed25cab76f5bf4491eec9572009fd5331ff849561eefc12cd8e8d5b34d",
  "../bearer-observation.baseline.json":
    "aff8b2cc9354df595900730de8e0517a17adff9630a971885bc8b4bbd4801ce0",
});
const VARIANT_PINS = Object.freeze({
  wrapper: Object.freeze({
    "wrapper/firebase.json": "0b76734c83f808f8842ee093177fc9ecc2fda2ec9f9d06e025436a0d7f9f7197",
    "wrapper/fixtures/index.js": "07fa7aec41354a4988c8732827097d72c7b277812faf8fd3ad7ce16a851fa313",
    "wrapper/fixtures/package.json":
      "5a2a9739e294a24104b837a940a65dd38746140dd64fd5744ac85f1d13c4043c",
    "wrapper/fixtures/package-lock.json":
      "bcec0509ef824246fc0773859a02561ef178cfd59ede9aab5d39fbcfc178485d",
  }),
  callable: Object.freeze({
    "callable/firebase.json": "0b76734c83f808f8842ee093177fc9ecc2fda2ec9f9d06e025436a0d7f9f7197",
    "callable/fixtures/index.js":
      "f250d2051a51a628712553079e3cc44a999bed4dfbcb19191d0642202cbe0e89",
    "callable/fixtures/package.json":
      "5a2a9739e294a24104b837a940a65dd38746140dd64fd5744ac85f1d13c4043c",
    "callable/fixtures/package-lock.json":
      "bcec0509ef824246fc0773859a02561ef178cfd59ede9aab5d39fbcfc178485d",
  }),
});

export function sourcePins(variant) {
  if (!Object.hasOwn(VARIANTS, variant)) throw new Error(`unknown variant ${String(variant)}`);
  return { ...SHARED_PINS, ...VARIANT_PINS[variant] };
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// ---- corpus ---------------------------------------------------------------------------------------

/** The one program of the frozen corpus; anything else in the file is refused. */
export function validateIngressCorpus(corpus) {
  const fail = (what) => {
    throw new Error(`callable-ingress corpus: ${what}`);
  };
  if (corpus?.schemaVersion !== 1 || corpus.project !== PROJECT || corpus.region !== REGION)
    fail("project or region");
  if (JSON.stringify(corpus.functions) !== JSON.stringify(FUNCTION_NAMES)) fail("functions");
  if (!Array.isArray(corpus.programs) || corpus.programs.length !== 1) fail("one program");
  const [program] = corpus.programs;
  if (program.id !== PROGRAM_ID) fail("program id");
  if (!Array.isArray(program.cases) || program.cases.length !== CASES.length) fail("six cases");
  const expectedBody = JSON.stringify({ data: { op: "auth" } });
  program.cases.forEach((step, index) => {
    const wanted = CASES[index];
    if (step.id !== wanted.id) fail(`case ${index + 1} id`);
    if (step.target !== "http" || expectedFunctionName(step.target) !== "fireemuHttpProbe")
      fail(`${step.id} target`);
    if (step.capture !== "complete") fail(`${step.id} capture`);
    const { method, path, headers, body, ...rest } = step.request ?? {};
    if (Object.keys(rest).length || method !== "POST" || path !== "/") fail(`${step.id} request`);
    if (JSON.stringify(body) !== expectedBody) fail(`${step.id} body`);
    const expected = {
      "content-type": "application/json",
      ...(wanted.authorization ? { authorization: wanted.authorization } : {}),
    };
    if (JSON.stringify(headers) !== JSON.stringify(expected)) fail(`${step.id} headers`);
  });
  return program;
}

// ---- the recording ------------------------------------------------------------------------------

/** What recordObservation needs to know about this observation (see BEARER_SPEC). */
export function ingressSpec(variant) {
  if (!Object.hasOwn(VARIANTS, variant)) throw new Error(`unknown variant ${String(variant)}`);
  return Object.freeze({
    ...BEARER_SPEC,
    taskId: TASK_ID,
    runPrefix: `callable-ingress-obs-${variant}`,
    validateCorpus: validateIngressCorpus,
    judge: judgeObservation,
    caseIds: CASE_IDS,
    keptHeaders: captureHeaders,
    startFields: () => ({ variant }),
    terminalFields: (judgement) => ({
      answers: judgement.answers.map((a) => [a.caseId, a.class, a.status, a.bodyBytes]),
      newShapes: judgement.newShapes,
    }),
  });
}

export const recordCallableIngress = (env, deps, variant) =>
  recordObservation(env, deps, ingressSpec(variant));

// ---- production effects -------------------------------------------------------------------------

export async function readSources(variant, { directory = HERE, conformance = CONFORMANCE } = {}) {
  const files = {};
  for (const [file, expected] of Object.entries(sourcePins(variant))) {
    const bytes = await readFile(join(directory, file));
    if (sha256(bytes) !== expected) throw new Error(`reviewed source changed: ${file}`);
    files[file] = bytes;
  }
  const firebaseTools = JSON.parse(
    await readFile(join(conformance, "node_modules/firebase-tools/package.json"), "utf8"),
  );
  if (firebaseTools.version !== "15.28.2")
    throw new Error("pinned Firebase CLI 15.28.2 is required");
  return {
    corpus: JSON.parse(files["corpus.json"]),
    baseline: {
      frontEndPage: JSON.parse(files["../bearer-observation.baseline.json"]).provisional,
      ...JSON.parse(files["baseline.json"]),
    },
    digests: { corpus: sourcePins(variant)["corpus.json"] },
  };
}

/**
 * The deploy CLI run from `cwd`, the directory that holds this variant's firebase.json (cli() would
 * otherwise deploy the stage 3 fixture). `command` replaces the real CLI in tests.
 */
export const makeCliRunner = (cwd, command) => (args, adcPath, budget, kind, runDir, deployTrack) =>
  cli(args, adcPath, budget, kind, runDir, deployTrack, command, { cwd });

/** The real effects of bearer-observation.mjs, with this observation's sources, caps and deploy directory. */
export function productionDeps({ variant, ledger, privateRoot, command } = {}) {
  if (!Object.hasOwn(VARIANTS, variant)) throw new Error(`unknown variant ${String(variant)}`);
  return {
    ...bearerProductionDeps({ ledger, privateRoot }),
    readSources: () => readSources(variant),
    createBudget: () => createBudget(CAPS),
    run: makeCliRunner(join(HERE, VARIANTS[variant].directory), command),
  };
}

// ---- local dry run --------------------------------------------------------------------------------

const LOCAL_PROJECT = "demo-functions-http";

async function localChild() {
  const host = process.env.FIREEMU_FUNCTIONS_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? ""))
    throw new Error("local Functions host is not loopback");
  const { corpus, baseline } = await readSources(process.env.INGRESS_LOCAL_VARIANT);
  const program = validateIngressCorpus(corpus);
  const endpoint = `http://${host}/${LOCAL_PROJECT}/${REGION}/${FUNCTION_NAMES.http}`;
  const budget = createBudget(CAPS);
  const captures = [];
  const fetchImpl = captureFetch({
    onCapture: (capture) => captures.push(capture),
    caseIds: CASE_IDS,
    keptHeaders: captureHeaders,
  });
  const recordings = [];
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      recordings.push(await runCases(program, { http: endpoint }, {}, budget, { fetchImpl }));
    } catch (error) {
      recordings.push({ error: error.message });
    }
  }
  const judgement = judgeObservation(captures, baseline);
  await writeFile(
    process.env.INGRESS_LOCAL_OUTPUT,
    `${JSON.stringify({ profile: process.env.INGRESS_LOCAL_PROFILE, captures, recordings, judgement }, null, 2)}\n`,
    { mode: 0o600, flag: "wx" },
  );
}

async function local(variant, profile, out) {
  if (!Object.hasOwn(VARIANTS, variant)) throw new Error("--variant wrapper|callable");
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile strict|emulator");
  if (!out) throw new Error("--out <new file> is required");
  const binary = process.env.FIREEMU_BIN;
  if (!binary) throw new Error("FIREEMU_BIN is required");
  const config =
    profile === "emulator"
      ? ["--config", join(HERE, "emulator.fireemu.json")]
      : ["--no-config-discovery"];
  const ports = [
    "http",
    "functions",
    "firestore",
    "storage",
    "eventarc",
    "tasks",
    "pubsub",
    "ui",
    "hub",
    "logging",
  ].flatMap((name) => [`--${name}-port`, "0"]);
  const args = [
    "exec",
    ...config,
    "--project",
    LOCAL_PROJECT,
    "--only",
    "functions",
    "--functions",
    join(HERE, VARIANTS[variant].directory, "fixtures"),
    ...ports,
    "--",
    process.execPath,
    fileURLToPath(import.meta.url),
    "local-child",
  ];
  const child = spawn(binary, args, {
    cwd: CONFORMANCE,
    stdio: "inherit",
    env: {
      ...process.env,
      INGRESS_LOCAL_OUTPUT: resolve(out),
      INGRESS_LOCAL_PROFILE: profile,
      INGRESS_LOCAL_VARIANT: variant,
    },
  });
  const code = await new Promise((resolveChild, reject) => {
    child.once("error", reject);
    child.once("exit", resolveChild);
  });
  if (code !== 0) throw new Error(`local fireemu session exited ${code}`);
  const { judgement, captures } = JSON.parse(await readFile(out, "utf8"));
  console.log(
    JSON.stringify({
      variant,
      profile,
      verdict: judgement.verdict,
      answers: captures.map((c) => [c.pass, c.caseId, c.status, c.bodyBytes]),
    }),
  );
}

// ---- entry ----------------------------------------------------------------------------------------

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  const option = (name) => rest[rest.indexOf(name) + 1];
  if (mode === "local") await local(option("--variant"), option("--profile"), option("--out"));
  else if (mode === "local-child") await localChild();
  else if (mode === "judge") {
    const { baseline } = await readSources(option("--variant") ?? "wrapper");
    const captures = JSON.parse(await readFile(rest[0], "utf8"));
    console.log(JSON.stringify(judgeObservation(captures, baseline), null, 2));
  } else if (mode === "record-production") {
    const variant = option("--variant");
    const result = await recordCallableIngress(process.env, productionDeps({ variant }), variant);
    console.log(JSON.stringify(result));
    process.exitCode = result.exitCode;
  } else
    throw new Error(
      "usage: observation.mjs local|judge|record-production --variant wrapper|callable",
    );
}
