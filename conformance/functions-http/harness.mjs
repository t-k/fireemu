// Pure bounds and normalization for the FUNCTIONS-HTTP observation runner.

import { createHash } from "node:crypto";

import { REQUESTS_PER_DEPLOY } from "../src/shared/gen2-source-uploads.mjs";

export const PROJECT = "fireemu-oracle-query";
export const REGION = "us-central1";
export const FUNCTION_NAMES = Object.freeze({
  http: "fireemuHttpProbe",
  callable: "fireemuCallableProbe",
});
// Worst cases of one deployment, counted from the code: a 2nd gen target given as a spec adds the
// complete function list of its region (at most 5 pages) to the control reads and the exact delete with
// its polls to the cleanup. Cleanup: absence 2, IAM removal 3, exact delete 1 + 10 polls, absence 2,
// package 1, versions 1, image delete 1 + 10 polls, read-back 1, residue 2 packages + 2 version lists.
const CONTROL_PER_DEPLOYMENT = 17;
const CLEANUP_PER_DEPLOYMENT = 36;
export const BOUNDS = Object.freeze({
  invocations: 136,
  control: 16 * CONTROL_PER_DEPLOYMENT,
  cleanup: 16 * CLEANUP_PER_DEPLOYMENT,
  auth: 12,
  cliDeploy: 16,
  cliDelete: 16,
  // Access token refreshes, counted apart from the request that happened to need one.
  token: 12,
  // Source upload bucket requests: the bound of one deploy for each of the 16 deployments.
  upload: 16 * REQUESTS_PER_DEPLOY,
});

const ALLOWED_HEADERS = new Set([
  "content-type",
  "accept",
  "origin",
  "access-control-request-method",
  "access-control-request-headers",
  "x-fireemu-probe",
  "authorization",
]);
const AUTH_HEADERS = new Set([
  "Bearer {{idToken}}",
  "Bearer {{invalidSignatureIdToken}}",
  "Bearer {{expiredIdToken}}",
  "Bearer malformed",
]);
const RESPONSE_HEADERS = [
  "content-type",
  "x-fireemu-probe",
  "access-control-allow-origin",
  "access-control-allow-methods",
  "access-control-allow-headers",
];
const SECRET_KEYS = new Set([
  "token",
  "idtoken",
  "refreshtoken",
  "apikey",
  "keystring",
  "authorization",
  "password",
  "clientsecret",
]);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function expectedFunctionName(target) {
  const name =
    typeof target === "string" && Object.hasOwn(FUNCTION_NAMES, target)
      ? FUNCTION_NAMES[target]
      : undefined;
  if (!name) throw new Error(`unreviewed target ${String(target)}`);
  return name;
}

const SPEC_KEYS = new Set([
  "functionName",
  "region",
  "codebase",
  "generation",
  "project",
  "runtime",
  "entryPoint",
]);

/** Codebase names a spec's function name may never equal: firebase-tools' own default and this recorder's. */
const RESERVED_CODEBASES = new Set(["default", "functions-http-oracle"]);

/** The frozen results of `resolveTarget`: resolving one again returns it unchanged. */
const RESOLVED = new WeakSet();

function ownData(target, field) {
  const descriptor = Object.getOwnPropertyDescriptor(target, field);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor))
    throw new Error(`invalid target spec: ${field} is not a data field`);
  return descriptor.value;
}

/**
 * A target is a named fixture function (`http`, `callable`) or a spec object for another reviewed 2nd gen
 * function of this project: a plain object with own data fields `{ functionName, region, codebase,
 * generation: "gcfv2" }` and optional `project` (this project only), `runtime` (default nodejs22) and
 * `entryPoint` (default the function name). The result is frozen, complete and read exactly once: resolving
 * it again returns it. `named` tells the CLI-deleted fixture functions from specs (which are deleted by
 * their exact resource, never by a selector); `resourceId` is the identity of the function itself.
 */
export function resolveTarget(target) {
  if (RESOLVED.has(target)) return target;
  if (typeof target === "string" || typeof target !== "object") {
    const functionName = expectedFunctionName(target);
    const resolved = Object.freeze({
      key: target,
      resourceId: `${REGION}/${functionName}`,
      named: true,
      project: PROJECT,
      region: REGION,
      codebase: "functions-http-oracle",
      generation: "gcfv2",
      functionName,
      entryPoint: functionName,
      runtime: "nodejs22",
    });
    RESOLVED.add(resolved);
    return resolved;
  }
  if (target === null || Array.isArray(target)) throw new Error("invalid target spec");
  if (Object.getPrototypeOf(target) !== Object.prototype) {
    throw new Error("invalid target spec: a plain object is required");
  }
  for (const key of Reflect.ownKeys(target)) {
    if (!SPEC_KEYS.has(key)) {
      throw new Error(`invalid target spec: unknown field ${String(key)}`);
    }
  }
  const field = (name) => ownData(target, name);
  const generation = field("generation");
  if (generation === "gcfv1") throw new Error("1st gen targets are not supported by this recorder");
  if (generation !== "gcfv2") throw new Error("invalid target spec: generation");
  const functionName = field("functionName");
  const region = field("region");
  const codebase = field("codebase");
  const project = field("project") ?? PROJECT;
  const runtime = field("runtime") ?? "nodejs22";
  const entryPoint = field("entryPoint") ?? functionName;
  const bad = (name) => new Error(`invalid target spec: ${name}`);
  if (project !== PROJECT) throw new Error("unreviewed target project");
  if (typeof functionName !== "string" || !/^[A-Za-z][A-Za-z0-9_-]{0,62}$/u.test(functionName))
    throw bad("functionName");
  if (typeof region !== "string" || !/^[a-z]+-[a-z]+\d+$/u.test(region)) throw bad("region");
  if (typeof codebase !== "string" || !/^[a-z][a-z0-9-]{0,62}$/u.test(codebase))
    throw bad("codebase");
  if (typeof runtime !== "string" || !/^[a-z]+\d+$/u.test(runtime)) throw bad("runtime");
  if (typeof entryPoint !== "string" || !/^[A-Za-z][A-Za-z0-9_.-]{0,126}$/u.test(entryPoint))
    throw bad("entryPoint");
  if (functionName === codebase || RESERVED_CODEBASES.has(functionName)) {
    throw bad("functionName equals a codebase name");
  }
  // The named targets are deleted by the CLI, whose `functions:delete <name>` also removes every
  // `<name>-*` function of the region: a spec named like that would be deleted with them.
  for (const named of Object.values(FUNCTION_NAMES)) {
    if (functionName.startsWith(`${named}-`))
      throw bad("functionName extends a named target's name");
  }
  const resolved = Object.freeze({
    key: functionName,
    resourceId: `${region}/${functionName}`,
    named: false,
    project,
    region,
    codebase,
    generation: "gcfv2",
    functionName,
    entryPoint,
    runtime,
  });
  RESOLVED.add(resolved);
  return resolved;
}

/** The canonical key of a target, as used for states, endpoints and ledger keys. */
export const targetKey = (target) => resolveTarget(target).key;

export function validateCorpus(corpus) {
  if (corpus.project !== PROJECT) throw new Error("corpus project changed");
  if (corpus.region !== REGION) throw new Error("corpus region changed");
  if (JSON.stringify(corpus.functions) !== JSON.stringify(FUNCTION_NAMES)) {
    throw new Error("corpus function names changed");
  }
  if (!Array.isArray(corpus.programs) || corpus.programs.length !== 15) {
    throw new Error("corpus must have exactly 15 programs");
  }
  const programIds = new Set();
  let cases = 0;
  let deployments = 0;
  for (const program of corpus.programs) {
    if (!/^functions-http\/[a-z0-9-]+\/[a-z0-9-]+$/.test(program.id)) {
      throw new Error(`unreviewed program ${program.id}`);
    }
    if (programIds.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    programIds.add(program.id);
    if (!Array.isArray(program.cases) || program.cases.length === 0) {
      throw new Error(`${program.id}: no cases`);
    }
    const caseIds = new Set();
    const targets = new Set();
    for (const step of program.cases) {
      if (!/^[a-zA-Z0-9-]+$/.test(step.id) || caseIds.has(step.id)) {
        throw new Error(`${program.id}: duplicate or invalid case id`);
      }
      caseIds.add(step.id);
      targets.add(step.target);
      expectedFunctionName(step.target);
      if (!new Set(["GET", "POST", "HEAD", "OPTIONS"]).has(step.request?.method)) {
        throw new Error(`${program.id}#${step.id}: method`);
      }
      const path = step.request.path;
      if (
        typeof path !== "string" ||
        !path.startsWith("/") ||
        path.startsWith("//") ||
        path.includes("..") ||
        path.length > 512
      ) {
        throw new Error(`${program.id}#${step.id}: path`);
      }
      if (!["complete", "first-chunk-then-abort"].includes(step.capture)) {
        throw new Error(`${program.id}#${step.id}: capture`);
      }
      for (const [key, value] of Object.entries(step.request.headers ?? {})) {
        if (!ALLOWED_HEADERS.has(key) || typeof value !== "string" || value.length > 512) {
          throw new Error(`${program.id}#${step.id}: header ${key}`);
        }
        if (key === "authorization" && !AUTH_HEADERS.has(value)) {
          throw new Error(`${program.id}#${step.id}: authorization`);
        }
      }
      if (JSON.stringify(step.request.body ?? "").length > 4096) {
        throw new Error(`${program.id}#${step.id}: body limit`);
      }
      cases += 1;
    }
    deployments += targets.size;
  }
  if (cases !== 68 || deployments !== 16)
    throw new Error("corpus must have 68 cases and 16 deployments");
  return { programs: programIds.size, cases, deployments, invocations: cases * 2 };
}

// `caps` lowers ceilings for one run (a packet's own request lists); it can never raise one.
// `extraKinds` names request kinds a second recorder adds, each with its own ceiling.
export function createBudget(caps = {}, extraKinds = {}) {
  const used = {
    invocation: 0,
    control: 0,
    cleanup: 0,
    auth: 0,
    cliDeploy: 0,
    cliDelete: 0,
    token: 0,
    upload: 0,
  };
  const limits = {
    invocation: BOUNDS.invocations,
    control: BOUNDS.control,
    cleanup: BOUNDS.cleanup,
    auth: BOUNDS.auth,
    cliDeploy: BOUNDS.cliDeploy,
    cliDelete: BOUNDS.cliDelete,
    token: BOUNDS.token,
    upload: BOUNDS.upload,
  };
  for (const [kind, ceiling] of Object.entries(extraKinds)) {
    if (kind in limits) throw new Error(`${kind} is already a request kind`);
    if (!Number.isInteger(ceiling) || ceiling < 0) {
      throw new Error(`invalid request ceiling for ${kind}`);
    }
    used[kind] = 0;
    limits[kind] = ceiling;
  }
  for (const [kind, cap] of Object.entries(caps)) {
    if (!(kind in limits) || !Number.isInteger(cap) || cap < 0) {
      throw new Error(`invalid request cap for ${kind}`);
    }
    limits[kind] = Math.min(limits[kind], cap);
  }
  return {
    take(kind) {
      if (!(kind in limits)) throw new Error(`unknown request kind ${kind}`);
      if (used[kind] >= limits[kind]) throw new Error(`${kind} ceiling ${limits[kind]} reached`);
      used[kind] += 1;
      return used[kind];
    },
    snapshot: () => ({ ...used }),
  };
}

export function validateFunctionRecord(record, target) {
  const { functionName: name, project, region, runtime, entryPoint } = resolveTarget(target);
  const resource = `projects/${project}/locations/${region}/functions/${name}`;
  if (record?.name !== resource)
    throw new Error("function name differs from the reviewed resource");
  if (record.environment !== "GEN_2") throw new Error("function generation is not GEN_2");
  if (record.buildConfig?.runtime !== runtime || record.buildConfig?.entryPoint !== entryPoint) {
    throw new Error("function runtime or entry point differs from the fixture");
  }
  const service = `projects/${project}/locations/${region}/services/${name.toLowerCase()}`;
  if (record.serviceConfig?.service?.toLowerCase() !== service.toLowerCase()) {
    throw new Error("Cloud Run service differs from the reviewed resource");
  }
  let uri;
  try {
    uri = new URL(record.serviceConfig.uri);
  } catch {
    throw new Error("function URL is invalid");
  }
  const host = uri.hostname.toLowerCase();
  const runHost = host.startsWith(`${name.toLowerCase()}-`) && host.endsWith(".run.app");
  const functionsHost =
    host === `${region}-${project}.cloudfunctions.net` && uri.pathname === `/${name}`;
  if (
    uri.protocol !== "https:" ||
    uri.username ||
    uri.password ||
    uri.port ||
    uri.search ||
    uri.hash ||
    (!runHost && !functionsHost)
  ) {
    throw new Error("function URL differs from the reviewed destination");
  }
  return uri.href.replace(/\/$/, "");
}

export function withPublicInvoker(policy) {
  if (!policy || !Array.isArray(policy.bindings)) throw new Error("IAM policy has no bindings");
  if (
    policy.bindings.some(
      ({ role, members }) => role !== "roles/run.invoker" && members?.includes("allUsers"),
    )
  ) {
    throw new Error("allUsers has an unreviewed role");
  }
  const copy = structuredClone(policy);
  let binding = copy.bindings.find(({ role }) => role === "roles/run.invoker");
  if (!binding) {
    binding = { role: "roles/run.invoker", members: [] };
    copy.bindings.push(binding);
  }
  if (!binding.members.includes("allUsers")) binding.members.push("allUsers");
  return copy;
}

export function withoutPublicInvoker(policy) {
  if (!policy || !Array.isArray(policy.bindings)) throw new Error("IAM policy has no bindings");
  const copy = structuredClone(policy);
  copy.bindings = copy.bindings
    .map((binding) =>
      binding.role === "roles/run.invoker"
        ? { ...binding, members: binding.members.filter((member) => member !== "allUsers") }
        : binding,
    )
    .filter((binding) => binding.members.length > 0);
  return copy;
}

function sanitize(value, replacements) {
  if (Array.isArray(value)) return value.map((item) => sanitize(item, replacements));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !SECRET_KEYS.has(key.toLowerCase()))
        .map(([key, item]) => [key, sanitize(item, replacements)]),
    );
  }
  if (typeof value === "string") {
    let result = value;
    for (const [literal, placeholder] of Object.entries(replacements)) {
      if (literal) result = result.replaceAll(literal, placeholder);
    }
    return result;
  }
  return value;
}

export function normalizeInvocation(status, headers, bodyBytes, replacements = {}) {
  const body = Buffer.from(bodyBytes);
  const stableHeaders = {};
  for (const key of RESPONSE_HEADERS) {
    const value = headers[key] ?? headers[key.toLowerCase()];
    if (value !== undefined) stableHeaders[key] = String(value);
  }
  let normalizedBody;
  if (body.length > 64 * 1024) {
    normalizedBody = { byteLength: body.length, sha256: sha256(body) };
  } else {
    const raw = body.toString("utf8");
    try {
      normalizedBody = sanitize(JSON.parse(raw), replacements);
    } catch {
      normalizedBody = sanitize(raw, replacements);
    }
  }
  return { status, headers: stableHeaders, body: normalizedBody };
}

export function buildInvocation(step, baseUrl, tokens) {
  const base = new URL(baseUrl);
  if (
    !["http:", "https:"].includes(base.protocol) ||
    base.username ||
    base.password ||
    base.search ||
    base.hash
  ) {
    throw new Error("invalid function base URL");
  }
  const prefix = base.pathname === "/" ? "" : base.pathname.replace(/\/$/, "");
  const url = new URL(`${prefix}${step.request.path}`, base.origin);
  if (url.origin !== base.origin) throw new Error("function path escaped its destination");
  const headers = { ...step.request.headers };
  const bearer = headers.authorization;
  if (bearer?.includes("{{")) {
    const match = /^Bearer \{\{(idToken|invalidSignatureIdToken|expiredIdToken)\}\}$/.exec(bearer);
    if (!match || !tokens[match[1]]) throw new Error(`missing token for ${step.id}`);
    headers.authorization = `Bearer ${tokens[match[1]]}`;
  }
  const init = { method: step.request.method, headers, redirect: "manual" };
  if (step.request.body !== undefined) {
    init.body =
      typeof step.request.body === "string" ? step.request.body : JSON.stringify(step.request.body);
  }
  return { url: url.href, init };
}

export function invalidSignatureToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("token is not a JWT");
  if (!parts[2]) {
    const header = {
      ...JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")),
      alg: "RS256",
    };
    return `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${parts[1]}.invalid`;
  }
  const first = parts[2][0] === "A" ? "B" : "A";
  return `${parts[0]}.${parts[1]}.${first}${parts[2].slice(1)}`;
}

export function localExpiredToken(token, nowSeconds = Math.floor(Date.now() / 1000)) {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[2]) throw new Error("local expiry requires an unsigned token");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header.alg !== "none") throw new Error("local expiry requires an unsigned token");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  payload.exp = nowSeconds - 1;
  return `${parts[0]}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.`;
}
