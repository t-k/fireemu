// One bounded production re-recording of the stage 3 callable Authorization rows, with what stage 3 did not
// keep. Stage 3 (2026-09-27) recorded the Google front end's 401 page for `Bearer malformed`, a bad
// signature and an expired token sent to a real callable; FUNCTIONS-HTTP-CALLABLE-INGRESS (2026-11-11)
// recorded the callable wrapper's own 401 envelope for `Bearer malformed` sent to the same kind of function.
// Nothing in the two setups explained it (docs.local/runs/callable-401/stage3-vs-run2.md), so this run
// answers it again, on the stage 3 fixture and with the stage 3 recorder's own deploy, invoker, user and
// cleanup helpers:
//
//   - auth-context: no Authorization, a valid ID token of the project;
//   - auth-refusal: no Authorization (a leading control), `Bearer malformed`, a bad signature, an expired
//     token (the token is made first and the run waits until it has expired, as stage 3 did);
//   - each program twice on one deployment: right after the public invoker is granted, and 60 s later.
//
// New this time: every request records the URL host (the project number masked), the HTTP version, the ALPN
// protocol and TLS version, the exact request head, the response headers in order, `server`,
// `www-authenticate` and whether `x-cloud-trace-context` is present (never its value), and the function's,
// the Cloud Run service's and the invoker policy's identifying fields (facts.json).
//
//   node functions-http/callable-ingress/rerecord.mjs local --profile strict|emulator --out <file>
//   node functions-http/callable-ingress/rerecord.mjs record-production
//   node functions-http/callable-ingress/rerecord.mjs judge <captures.json>
//
// `record-production` is run by the coordinator only, from a launch script that takes the
// fireemu-oracle-query project lock. Admission, the two deployments, the public invoker, the user, the
// cleanup with read-back, the source upload ownership, the Cloud Build read and the two ledger lines are
// those of bearer-observation.mjs (recordObservation).

import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, inflateSync } from "node:zlib";

import {
  BEARER_SPEC,
  CAPS as BEARER_CAPS,
  KEPT_HEADERS,
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
import { invalidSignatureToken, localExpiredToken } from "../harness.mjs";
import { runCases } from "../session.mjs";
import { MASKED_TOKEN, PROGRAMS, SLOTS, judgeRerecord } from "./rerecord-judge.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = resolve(HERE, "../..");

export const TASK_ID = "FUNCTIONS-HTTP-CALLABLE-RERECORD";
/** The ledger reservation of one attempt (two deployments, one of them after the token wait). */
export const RESERVED_USD_PER_ATTEMPT = 2;
/** The pause before the second pass of each program: the "60 s later" pass. */
export const PASS_DELAY_MS = 60_000;

const DEPLOYMENTS = PROGRAMS.length;

// Ceilings of one attempt: the bounds of bearer-observation.mjs for one deployment, once per program.
export const CAPS = Object.freeze({
  invocation: SLOTS.length,
  control: BEARER_CAPS.control * DEPLOYMENTS,
  cleanup: BEARER_CAPS.cleanup * DEPLOYMENTS,
  auth: 3 * DEPLOYMENTS,
  cliDeploy: DEPLOYMENTS,
  cliDelete: DEPLOYMENTS,
  token: BEARER_CAPS.token * DEPLOYMENTS,
  upload: BEARER_CAPS.upload * DEPLOYMENTS,
});

// The reviewed bytes the run depends on, relative to this directory: the stage 3 fixture and its firebase.json
// are the very files stage 3 deployed (the lock is the patch-level successor listed in
// release-strict-regression.mjs FUNCTIONS_HTTP_LOCK_SUCCESSORS).
export const SOURCE_PINS = Object.freeze({
  "rerecord.corpus.json": "665bd73ae2144f2035840835eff00a447fee33139c65a83b718978cbb5d3c167",
  "rerecord.baseline.json": "472c51238bba95a25ce903eb5f3addb07ae5470ab22744b7ce013b6039840367",
  "baseline.json": "a08a6eed25cab76f5bf4491eec9572009fd5331ff849561eefc12cd8e8d5b34d",
  "../bearer-observation.baseline.json":
    "aff8b2cc9354df595900730de8e0517a17adff9630a971885bc8b4bbd4801ce0",
  "../firebase.json": "0b76734c83f808f8842ee093177fc9ecc2fda2ec9f9d06e025436a0d7f9f7197",
  "../fixtures/index.js": "0c481ec6b6ec87db71a2f90550238ce69ec2b923c7a92b7ea5171cb7909886a5",
  "../fixtures/package.json": "5a2a9739e294a24104b837a940a65dd38746140dd64fd5744ac85f1d13c4043c",
  "../fixtures/package-lock.json":
    "bcec0509ef824246fc0773859a02561ef178cfd59ede9aab5d39fbcfc178485d",
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Response headers kept by value in the capture. `server` and `www-authenticate` are in the default list;
// the trace header is only counted, never kept (see the transport).
export const captureHeaders = Object.freeze([
  ...KEPT_HEADERS,
  "access-control-allow-origin",
  "vary",
  "x-powered-by",
  "etag",
]);

// ---- corpus ---------------------------------------------------------------------------------------

const TOKEN_PLACEHOLDER = {
  "valid-project-id-token": "idToken",
  "invalid-signature": "invalidSignatureIdToken",
  "expired-id-token": "expiredIdToken",
};

/** The frozen request of one case. */
function expectedRequest(step) {
  const headers = { "content-type": "application/json" };
  if (step.authorization === "token") {
    headers.authorization = `Bearer {{${TOKEN_PLACEHOLDER[step.id]}}}`;
  } else if (step.authorization !== "none") {
    headers.authorization = step.authorization;
  }
  return { method: "POST", path: "/", headers, body: { data: { op: "auth" } } };
}

/** The two programs of the frozen corpus, in order; anything else in the file is refused. */
export function validateRerecordCorpus(corpus) {
  const fail = (what) => {
    throw new Error(`rerecord corpus: ${what}`);
  };
  if (corpus?.schemaVersion !== 1 || corpus.project !== PROJECT || corpus.region !== REGION)
    fail("project or region");
  if (JSON.stringify(corpus.functions) !== JSON.stringify(FUNCTION_NAMES)) fail("functions");
  if (
    JSON.stringify(corpus.placeholders) !==
    JSON.stringify(["idToken", "invalidSignatureIdToken", "expiredIdToken"])
  )
    fail("placeholders");
  if (!Array.isArray(corpus.programs) || corpus.programs.length !== PROGRAMS.length)
    fail("programs");
  return corpus.programs.map((program, index) => {
    const wanted = PROGRAMS[index];
    if (program?.id !== wanted.id) fail(`program ${index + 1} id`);
    if (!Array.isArray(program.cases) || program.cases.length !== wanted.cases.length)
      fail(`${wanted.id} cases`);
    program.cases.forEach((step, position) => {
      const expected = wanted.cases[position];
      if (step.id !== expected.id) fail(`${wanted.id} case ${position + 1} id`);
      if (
        step.target !== "callable" ||
        expectedFunctionName(step.target) !== "fireemuCallableProbe"
      )
        fail(`${step.id} target`);
      if (step.capture !== "complete") fail(`${step.id} capture`);
      if (JSON.stringify(step.request) !== JSON.stringify(expectedRequest(expected)))
        fail(`${step.id} request`);
      if (Object.keys(step).length !== 4) fail(`${step.id} fields`);
    });
    return program;
  });
}

// ---- the transport ----------------------------------------------------------------------------------

/**
 * The headers Node's `fetch` (undici 6/7) sends for a request with a body, in its order: the previous
 * recorders sent exactly these, so a different client does not change the request.
 */
export function requestHeaders({ host, headers, bodyBytes }) {
  const ordered = [
    ["host", host],
    ["connection", "keep-alive"],
    ["content-type", headers["content-type"]],
    ["authorization", headers.authorization],
    ["accept", "*/*"],
    ["accept-language", "*"],
    ["sec-fetch-mode", "cors"],
    ["user-agent", "node"],
    ["accept-encoding", "gzip, deflate"],
    ["content-length", String(bodyBytes)],
  ];
  return ordered.filter(([, value]) => value !== undefined);
}

const MAX_RESPONSE_BYTES = 64 * 1024;

function readBody(response) {
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    let size = 0;
    response.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_RESPONSE_BYTES) {
        response.destroy(new Error("response body exceeded 64 KiB"));
        return;
      }
      chunks.push(chunk);
    });
    response.once("end", () => resolveBody(Buffer.concat(chunks)));
    response.once("error", reject);
    response.once("aborted", () => reject(new Error("response aborted")));
  });
}

/** The head of the request as it went on the wire, with a credential replaced by its shape. */
function headText(method, path, ordered) {
  const lines = ordered.map(([name, value]) =>
    name === "authorization" && value !== "Bearer malformed"
      ? `${name}: ${MASKED_TOKEN}`
      : `${name}: ${value}`,
  );
  return `${method} ${path} HTTP/1.1\r\n${lines.join("\r\n")}\r\n\r\n`;
}

/**
 * A `fetch` over node:http(s) that keeps what `fetch` hides (the HTTP version, the negotiated protocol, the
 * response headers in order) and pauses before the second pass of each program. Its answer is a real
 * `Response` carrying a `fireemuExtra` property for captureFetch's `enrich`.
 *
 * @param {object} options
 * @param {(ms: number) => Promise<void>} options.sleep
 * @param {() => number} options.now
 * @param {number} options.delayMs pause before the first request of every second pass
 * @param {readonly object[]} options.slots the frozen order of the requests
 * @param {object} options.modules the `http` and `https` modules (a test replaces them)
 */
export function createTransport({
  sleep = (ms) => new Promise((done) => setTimeout(done, ms)),
  now = Date.now,
  delayMs = PASS_DELAY_MS,
  slots = SLOTS,
  modules = { "https:": https, "http:": http },
} = {}) {
  const agents = {
    "https:": new modules["https:"].Agent({ keepAlive: true, maxSockets: 1 }),
    "http:": new modules["http:"].Agent({ keepAlive: true, maxSockets: 1 }),
  };
  let index = 0;
  const fetchImpl = async (url, init) => {
    const slot = slots[index];
    const previous = slots[index - 1];
    index += 1;
    if (slot?.pass === 2 && previous?.pass !== 2) {
      await sleep(delayMs);
    }
    const target = new URL(url);
    const body = Buffer.from(init.body ?? "");
    const ordered = requestHeaders({
      host: target.host,
      headers: init.headers ?? {},
      bodyBytes: body.length,
    });
    const sentAt = new Date(now()).toISOString();
    const transport = modules[target.protocol];
    if (!transport) throw new Error(`unsupported protocol ${target.protocol}`);
    const options = {
      method: init.method,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      headers: Object.fromEntries(ordered),
      agent: agents[target.protocol],
      signal: init.signal,
      ...(target.protocol === "https:" ? { ALPNProtocols: ["http/1.1"] } : {}),
    };
    const { response, bytes } = await new Promise((resolveRequest, reject) => {
      const request = transport.request(options, (res) => {
        readBody(res).then((data) => resolveRequest({ response: res, bytes: data }), reject);
      });
      request.once("error", reject);
      request.end(body);
    });
    const encoding = String(response.headers["content-encoding"] ?? "").toLowerCase();
    const decoded =
      encoding === "gzip" ? gunzipSync(bytes) : encoding === "deflate" ? inflateSync(bytes) : bytes;
    const headers = new Headers();
    for (let i = 0; i + 1 < response.rawHeaders.length; i += 2) {
      const name = response.rawHeaders[i].toLowerCase();
      if (encoding && (name === "content-encoding" || name === "content-length")) continue;
      headers.append(name, response.rawHeaders[i + 1]);
    }
    const answer = new Response(
      [101, 204, 205, 304].includes(response.statusCode) ? null : decoded,
      {
        status: response.statusCode,
        headers,
      },
    );
    const names = response.rawHeaders.filter((_, position) => position % 2 === 0);
    answer.fireemuExtra = {
      sentAt,
      host: target.host,
      httpVersion: response.httpVersion,
      alpn: response.socket?.alpnProtocol ?? null,
      tlsProtocol: response.socket?.getProtocol?.() ?? null,
      requestHead: headText(init.method, options.path, ordered),
      responseHeaderNames: names.map((name) => name.toLowerCase()),
      server: response.headers.server ?? null,
      wwwAuthenticate: response.headers["www-authenticate"] ?? null,
      traceContextPresent: response.headers["x-cloud-trace-context"] !== undefined,
      contentEncoding: encoding || null,
    };
    return answer;
  };
  return { fetchImpl, close: () => Object.values(agents).forEach((agent) => agent.destroy()) };
}

/** What a capture records of the Authorization it sent: nothing but a literal, or the shape of a token. */
export const maskAuthorization = (value) =>
  value === null || value === "Bearer malformed" ? value : MASKED_TOKEN;

/** The project number never reaches a file: it stands for itself as `{{projectNumber}}`. */
const maskNumber = (text, projectNumber) =>
  typeof text === "string" && projectNumber
    ? text.replaceAll(projectNumber, "{{projectNumber}}")
    : text;

/** The form of a Cloud Run or Cloud Functions host, with the project number as a placeholder. */
export function hostForm(host) {
  if (/^[a-z0-9-]+-\{\{projectNumber\}\}\.[a-z0-9-]+\.run\.app(:\d+)?$/u.test(host))
    return "service-{{projectNumber}}.region.run.app";
  if (/^[a-z0-9-]+-[a-z0-9]{3,16}-[a-z]{2}\.a\.run\.app(:\d+)?$/u.test(host))
    return "service-hash-region.a.run.app";
  if (/^[a-z0-9-]+\.cloudfunctions\.net(:\d+)?$/u.test(host))
    return "region-project.cloudfunctions.net";
  return "other";
}

export function enrichCapture(record, source, { projectNumber } = {}) {
  const extra = source?.fireemuExtra;
  if (!extra) return;
  const host = maskNumber(extra.host, projectNumber);
  record.transport = {
    sentAt: extra.sentAt,
    host,
    hostForm: hostForm(host),
    httpVersion: extra.httpVersion,
    alpn: extra.alpn,
    tlsProtocol: extra.tlsProtocol,
    requestHead: maskNumber(extra.requestHead, projectNumber),
    responseHeaderNames: extra.responseHeaderNames,
    server: extra.server,
    wwwAuthenticate: extra.wwwAuthenticate,
    traceContextPresent: extra.traceContextPresent,
    contentEncoding: extra.contentEncoding,
  };
}

// ---- the function, service and policy facts ------------------------------------------------------------

const FUNCTION_URL =
  /^https:\/\/cloudfunctions\.googleapis\.com\/v2\/projects\/[^/]+\/locations\/[^/]+\/functions\/[^/?:]+$/u;
const SERVICE_URL =
  /^https:\/\/run\.googleapis\.com\/v2\/projects\/[^/]+\/locations\/[^/]+\/services\/[^/?:]+$/u;
const POLICY_URL =
  /^https:\/\/run\.googleapis\.com\/v2\/projects\/[^/]+\/locations\/[^/]+\/services\/[^/?:]+:getIamPolicy$/u;

const pick = (value, keys) =>
  Object.fromEntries(
    keys.filter((key) => value?.[key] !== undefined).map((key) => [key, value[key]]),
  );

/** The fields of a function record that identify its setup. */
export function functionFacts(record) {
  return {
    ...pick(record, ["environment", "state", "url"]),
    buildConfig: pick(record.buildConfig, ["runtime", "entryPoint"]),
    serviceConfig: pick(record.serviceConfig, [
      "uri",
      "ingressSettings",
      "allTrafficOnLatestRevision",
      "timeoutSeconds",
      "maxInstanceCount",
      "minInstanceCount",
      "availableMemory",
      "securityLevel",
    ]),
    labels: pick(record.labels, [
      "deployment-callable",
      "deployment-tool",
      "firebase-functions-hash",
    ]),
  };
}

/** The fields of a Cloud Run service that identify its setup. */
export function serviceFacts(service) {
  return pick(service, [
    "ingress",
    "invokerIamDisabled",
    "defaultUriDisabled",
    "launchStage",
    "uri",
    "urls",
    "generation",
  ]);
}

/** Collects the three kinds of facts from the replies of the shared helpers' reads, without a request of its own. */
export function createFactsCollector() {
  const facts = { functions: [], services: [], policies: [] };
  const watch =
    (control) =>
    async (method, url, ...rest) => {
      const reply = await control(method, url, ...rest);
      if (reply?.status === 200 && reply.value) {
        if (FUNCTION_URL.test(url)) facts.functions.push(functionFacts(reply.value));
        else if (SERVICE_URL.test(url)) facts.services.push(serviceFacts(reply.value));
        else if (POLICY_URL.test(url))
          facts.policies.push({
            bindings: reply.value.bindings ?? [],
            version: reply.value.version ?? null,
          });
      }
      return reply;
    };
  return { facts, watch };
}

// ---- the recording --------------------------------------------------------------------------------

/** What recordObservation needs to know about this observation (see BEARER_SPEC). */
export function rerecordSpec(collector) {
  return Object.freeze({
    ...BEARER_SPEC,
    taskId: TASK_ID,
    runPrefix: "callable-rerecord",
    validateCorpus: validateRerecordCorpus,
    judge: judgeRerecord,
    caseIds: [],
    slots: SLOTS,
    keptHeaders: captureHeaders,
    reservedUsd: RESERVED_USD_PER_ATTEMPT,
    startFields: () => ({}),
    terminalFields: (judgement) => ({
      rows: judgement.rows.map(({ program, caseId, passes }) => [
        program.split("/").at(-1),
        caseId,
        passes.map((p) => [p.class, p.status, p.bodyBytes]),
      ]),
      timingDiffers: judgement.timingDiffers,
    }),
    maskAuthorization,
    enrichCapture,
    extraFiles: ({ projectNumber }) =>
      collector
        ? {
            "facts.json": JSON.parse(
              JSON.stringify(collector.facts).replaceAll(projectNumber, "{{projectNumber}}"),
            ),
          }
        : {},
  });
}

export const recordRerecord = (env, deps, collector) =>
  recordObservation(env, deps, rerecordSpec(collector));

// ---- production effects -------------------------------------------------------------------------

export async function readSources({ directory = HERE, conformance = CONFORMANCE } = {}) {
  const files = {};
  for (const [file, expected] of Object.entries(SOURCE_PINS)) {
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
    corpus: JSON.parse(files["rerecord.corpus.json"]),
    baseline: {
      frontEndPage: JSON.parse(files["../bearer-observation.baseline.json"]).provisional,
      control: JSON.parse(files["baseline.json"]).control,
      ...JSON.parse(files["rerecord.baseline.json"]),
    },
    digests: { corpus: SOURCE_PINS["rerecord.corpus.json"] },
  };
}

/** The real effects of bearer-observation.mjs, with this observation's sources, caps, transport and facts. */
export function productionDeps({
  ledger,
  privateRoot,
  base = bearerProductionDeps({ ledger, privateRoot, caps: CAPS }),
} = {}) {
  const transport = createTransport();
  const collector = createFactsCollector();
  return {
    deps: {
      ...base,
      readSources: () => readSources(),
      createControl: (adcFile, budget) => collector.watch(base.createControl(adcFile, budget)),
      fetchImpl: transport.fetchImpl,
    },
    collector,
    close: transport.close,
  };
}

// ---- local dry run --------------------------------------------------------------------------------

const LOCAL_PROJECT = "demo-functions-http";

async function localAuth(method, body) {
  const host = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? "")) throw new Error("local Auth host is not loopback");
  const response = await fetch(
    `http://${host}/identitytoolkit.googleapis.com/v1/${method}?key=local-fixture-key`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (response.status !== 200) throw new Error(`local Auth ${method} returned ${response.status}`);
  return response.json();
}

async function localChild() {
  const host = process.env.FIREEMU_FUNCTIONS_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? ""))
    throw new Error("local Functions host is not loopback");
  const { corpus, baseline } = await readSources();
  const programs = validateRerecordCorpus(corpus);
  const endpoint = `http://${host}/${LOCAL_PROJECT}/${REGION}/${FUNCTION_NAMES.callable}`;
  const budget = createBudget(CAPS);
  const captures = [];
  const transport = createTransport({ delayMs: 0 });
  const fetchImpl = captureFetch({
    fetchImpl: transport.fetchImpl,
    onCapture: (capture) => captures.push(capture),
    slots: SLOTS,
    keptHeaders: captureHeaders,
    maskAuthorization,
    enrich: (record, source) => enrichCapture(record, source, {}),
  });
  const user = await localAuth("accounts:signUp", {
    email: `fireemu-fh-${Date.now().toString(36)}@example.com`,
    password: "local-password-1",
    returnSecureToken: true,
  });
  const tokens = {
    idToken: user.idToken,
    invalidSignatureIdToken: invalidSignatureToken(user.idToken),
    expiredIdToken: localExpiredToken(user.idToken),
  };
  try {
    for (const program of programs) {
      for (let pass = 0; pass < 2; pass += 1) {
        await runCases(program, { callable: endpoint }, tokens, budget, { fetchImpl });
      }
    }
  } finally {
    transport.close();
    await localAuth("accounts:delete", { idToken: user.idToken });
  }
  const judgement = judgeRerecord(captures, baseline);
  await writeFile(
    process.env.RERECORD_LOCAL_OUTPUT,
    `${JSON.stringify({ profile: process.env.RERECORD_LOCAL_PROFILE, captures, judgement }, null, 2)}\n`,
    { mode: 0o600, flag: "wx" },
  );
}

async function local(profile, out) {
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
    "auth,functions",
    "--functions",
    join(HERE, "../fixtures"),
    ...ports,
    "--",
    process.execPath,
    fileURLToPath(import.meta.url),
    "local-child",
  ];
  const child = spawn(binary, args, {
    cwd: CONFORMANCE,
    stdio: "inherit",
    env: { ...process.env, RERECORD_LOCAL_OUTPUT: resolve(out), RERECORD_LOCAL_PROFILE: profile },
  });
  const code = await new Promise((resolveChild, reject) => {
    child.once("error", reject);
    child.once("exit", resolveChild);
  });
  if (code !== 0) throw new Error(`local fireemu session exited ${code}`);
  const { judgement } = JSON.parse(await readFile(out, "utf8"));
  console.log(
    JSON.stringify({
      profile,
      verdict: judgement.verdict,
      rows: judgement.rows?.map((row) => [row.caseId, row.passes.map((p) => [p.class, p.status])]),
    }),
  );
}

// ---- entry ----------------------------------------------------------------------------------------

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  const option = (name) => rest[rest.indexOf(name) + 1];
  if (mode === "local") await local(option("--profile"), option("--out"));
  else if (mode === "local-child") await localChild();
  else if (mode === "judge") {
    const { baseline } = await readSources();
    const captures = JSON.parse(await readFile(rest[0], "utf8"));
    console.log(JSON.stringify(judgeRerecord(captures, baseline), null, 2));
  } else if (mode === "record-production") {
    const { deps, collector, close } = productionDeps();
    try {
      const result = await recordRerecord(process.env, deps, collector);
      console.log(JSON.stringify(result));
      process.exitCode = result.exitCode;
    } finally {
      close();
    }
  } else throw new Error("usage: rerecord.mjs local|judge|record-production");
}
