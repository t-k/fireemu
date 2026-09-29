// AUTH-FEDERATION harness runner. The local mode runs the corpus against fireemu (strict
// profile) and writes the recorded rows under `.runs/`; the production recording
// (`record.mjs`) runs the same programs through `runPrograms` against the sandbox.
//
//   node src/auth-federation/run.mjs local [record-saml|record-followup|record-strict-safety]

import { execFile, spawn } from "node:child_process";
import { createHash, createPrivateKey, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { PROGRAMS, resolveCorpus } from "./corpus.mjs";
import { SAML_PROGRAMS } from "./corpus-saml.mjs";
import { FOLLOWUP_DISCOVERY_SCOPES, FOLLOWUP_PROGRAMS } from "./corpus-followup.mjs";
import { STRICT_SAFETY_PROGRAMS } from "./corpus-strict-safety.mjs";
import { guardHttp, validateFederationCorpus } from "./guard.mjs";
import { normalizeHttp } from "./harness.mjs";
import {
  certificateBase64,
  readAuthnRequest,
  signedSamlResponse,
  tamperSignature,
} from "./saml.mjs";
import {
  discoveryDocument,
  generateSigningKey,
  jwksDocument,
  saveSigningKey,
  signIdToken,
} from "./idp.mjs";

const execFileAsync = promisify(execFile);
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-federation");
const LOCAL_PROJECT_NUMBER = "123456789012";
const OWNER = "Bearer owner";

/**
 * A self-signed certificate of a fresh key, made with the system `openssl`, in a private
 * temporary directory. Only the certificate (public) leaves it. `expired`: its validity
 * ended in 2024 (a signing certificate out of date).
 */
export async function makeCertificate(dir, name, { expired = false } = {}) {
  const key = join(dir, `${name}.key.pem`);
  const cert = join(dir, `${name}.cert.pem`);
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    key,
    "-out",
    cert,
    ...(expired
      ? ["-not_before", "20240101000000Z", "-not_after", "20240102000000Z"]
      : ["-days", "2"]),
    "-subj",
    `/CN=fireemu-${name}`,
  ]);
  return readFile(cert, "utf8");
}

/**
 * The run's SAML signers: a current certificate (`saml-a`, key `run`) and an expired one
 * (`saml-expired`, key `expired`), made in `dir` and read into memory, the files removed.
 * `keyPems` is for a local session in another process only; `runCertificates` are the
 * certificates as a SAMLResponse carries them.
 */
export async function prepareSamlSigners(dir) {
  const certificates = {};
  const keys = {};
  const keyPems = {};
  for (const [name, key, expired] of [
    ["saml-a", "run", false],
    ["saml-expired", "expired", true],
  ]) {
    const certificatePem = await makeCertificate(dir, name, { expired });
    const keyPath = join(dir, `${name}.key.pem`);
    keyPems[key] = await readFile(keyPath, "utf8");
    await rm(keyPath);
    await rm(join(dir, `${name}.cert.pem`));
    certificates[name] = certificatePem;
    keys[key] = { privateKey: createPrivateKey(keyPems[key]), certificatePem };
  }
  return {
    certificates,
    keys,
    keyPems,
    runCertificates: Object.values(certificates).map(certificateBase64),
  };
}

/** A claim value of a token spec: `{$now: s}` relative to `now`, `{$sha256: raw}` hashed. */
function claimValue(value, now) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if (typeof value.$now === "number") return now + value.$now;
    if (typeof value.$sha256 === "string") {
      return createHash("sha256").update(value.$sha256).digest("hex");
    }
  }
  return value;
}

/** The ID tokens a program's `tokens` spec describes, signed with the run's keys. */
export function mintTokens(program, { issuer, keys, now }) {
  const minted = {};
  for (const [name, spec] of Object.entries(program.tokens ?? {})) {
    const claims = {
      iss: issuer,
      aud: program.client,
      sub: `sub-${name}`,
      iat: now,
      exp: now + 3600,
      ...Object.fromEntries(
        Object.entries(spec.claims ?? {}).map(([k, v]) => [k, claimValue(v, now)]),
      ),
    };
    for (const dropped of spec.drop ?? []) delete claims[dropped];
    minted[name] = signIdToken(keys.run, claims, {
      header: spec.header,
      signWith: spec.signWith === "other" ? keys.other.privateKey : undefined,
    });
  }
  return minted;
}

/** The run's signing key and another key its issuer does not publish (negative rows). */
export function prepareKeys() {
  return { run: generateSigningKey(), other: generateSigningKey() };
}

/**
 * The corpus resolved for a run: placeholders filled with the run, its issuer host (the
 * run's preview channel) and certificate, and every program's ID tokens minted at `now`.
 */
/** The corpora a recording can run, by packet. */
export const CORPORA = {
  "record-oidc": PROGRAMS,
  "record-saml": SAML_PROGRAMS,
  "record-followup": FOLLOWUP_PROGRAMS,
  "record-strict-safety": STRICT_SAFETY_PROGRAMS,
};

/** The scopes_supported a corpus's run issuer lists in its discovery document, if any. */
export const DISCOVERY_SCOPES = { "record-followup": FOLLOWUP_DISCOVERY_SCOPES };

/**
 * The tag of pass number `pass` made at `now` (unix seconds): what `PASSTAG` in the corpus
 * becomes. The pass number keeps two passes that start in the same second apart.
 */
export const passTagOf = (now, pass = 1) => `p${now.toString(36)}${pass}`;

/**
 * The hash of each raw nonce a tagged corpus's tokens carry, labelled by that raw nonce with the
 * tag as `<pass>` (`<sha256:fireemu-nonce-a-<pass>>`): the hashes differ per pass, the labels do
 * not, and two credentials of one program stay told apart in a recorded row.
 */
function nonceLabelsOf(programs, passTag) {
  const labels = {};
  for (const program of programs) {
    for (const spec of Object.values(program.tokens ?? {})) {
      const raw = spec.claims?.nonce?.$sha256;
      if (typeof raw !== "string") continue;
      labels[createHash("sha256").update(raw).digest("hex")] =
        `<sha256:${raw.split(passTag).join("<pass>")}>`;
    }
  }
  return labels;
}

export function resolveRun({
  project,
  run,
  issuerHost,
  keys,
  certificatePem,
  certificates = { "saml-a": certificatePem },
  now,
  pass = 1,
  programs: corpus = PROGRAMS,
}) {
  const issuer = `https://${issuerHost}/oidc/${run}`;
  const legacy = (subject) =>
    signIdToken(keys.run, {
      iss: issuer,
      aud: "client-off",
      sub: subject,
      iat: now,
      exp: now + 3600,
    });
  const programs = resolveCorpus(corpus, {
    project,
    run,
    issuerHost,
    certificates,
    tokens: { missing: legacy("missing"), off: legacy("off") },
    passTag: passTagOf(now, pass),
  });
  for (const program of programs) program.minted = mintTokens(program, { issuer, keys, now });
  validateFederationCorpus(programs, { run });
  // Only a corpus that tags its passes has a tag to mask; the others' rows are recorded as before.
  const tagged = JSON.stringify(corpus).includes("PASSTAG");
  const passTag = tagged ? passTagOf(now, pass) : undefined;
  return { issuer, programs, passTag, nonceLabels: passTag ? nonceLabelsOf(programs, passTag) : undefined };
}

/**
 * This run's key material and the corpus resolved with it. `issuerHost` is the run's preview
 * channel (the local mode names one that is never deployed).
 */
async function prepareRun(project, run, issuerHost, corpus = PROGRAMS) {
  const secretDir = await mkdtemp(join(tmpdir(), "fireemu-auth-federation-"));
  const keys = prepareKeys();
  await saveSigningKey(join(secretDir, "oidc.pem"), keys.run);
  const signers = await prepareSamlSigners(secretDir);
  // The SAML keys for the local session in another process, beside the OIDC key (mode 600).
  const samlKeysPath = join(secretDir, "saml-keys.json");
  await writeFile(
    samlKeysPath,
    JSON.stringify({ keyPems: signers.keyPems, certificates: signers.certificates }),
    { mode: 0o600 },
  );
  const { issuer, programs, passTag, nonceLabels } = resolveRun({
    project,
    run,
    issuerHost,
    keys,
    certificates: signers.certificates,
    now: Math.floor(Date.now() / 1000),
    programs: corpus,
  });
  return {
    run,
    issuerHost,
    issuer,
    secretDir,
    samlKeysPath,
    runKids: [keys.run.jwk.kid],
    runCertificates: signers.runCertificates,
    passTag,
    nonceLabels,
    programs,
    jwks: [keys.run.jwk],
  };
}

/** The SAML signers a local session reads from `path` (written by `prepareRun`). */
async function loadSamlSigners(path) {
  const { keyPems, certificates } = JSON.parse(await readFile(path, "utf8"));
  return {
    run: { privateKey: createPrivateKey(keyPems.run), certificatePem: certificates["saml-a"] },
    expired: {
      privateKey: createPrivateKey(keyPems.expired),
      certificatePem: certificates["saml-expired"],
    },
  };
}

/** `step:a.b` → the value at `a.b` in the raw answer of `step`. */
function fromRaw(raw, reference) {
  const [stepId, path] = reference.split(":");
  const found = path.split(".").reduce((value, key) => value?.[key], raw.get(stepId));
  if (found === undefined) throw new Error(`step ${stepId} recorded nothing at ${path}`);
  return found;
}

/**
 * A SAMLResponse signed now with one of the run's SAML keys (`saml.keys[key]`), answering the
 * AuthnRequest of the step `request` unless `inResponseTo` names another ID (or `null`: an
 * unsolicited response). Times are relative to `saml.now()`: `conditions.notBefore` (-60),
 * `conditions.notOnOrAfter` (300), `confirmationNotOnOrAfter` (300); `null` leaves the
 * attribute out. `algorithm: "sha1"` signs and digests with SHA-1. `remember: name` keeps the
 * value for the program's later `{ reuse: name }`, which sends the same response again.
 */
function samlValue(spec, raw, saml) {
  // A response remembered by an earlier step of the program is sent again unchanged.
  if (spec.reuse !== undefined) {
    const remembered = raw.get(`$saml:${spec.reuse}`);
    if (remembered === undefined) throw new Error(`no SAML response ${spec.reuse} was remembered`);
    return remembered;
  }
  const signer = saml?.keys?.[spec.key ?? "run"];
  if (!signer) throw new Error(`the run made no SAML key ${spec.key ?? "run"}`);
  const now = saml.now();
  const authUri = spec.request === undefined ? undefined : fromRaw(raw, `${spec.request}:authUri`);
  const inResponseTo =
    spec.inResponseTo !== undefined ? spec.inResponseTo : readAuthnRequest(authUri).id;
  const suffix = randomBytes(8).toString("hex");
  // A time is relative to now; an explicit null leaves the attribute out.
  const at = (offset, fallback) => (offset === null ? null : now + (offset ?? fallback));
  const { xml } = signedSamlResponse(
    {
      responseId: `_r${suffix}`,
      assertionId: `_a${suffix}`,
      issuer: spec.issuer,
      assertionIssuer: spec.assertionIssuer,
      audience: spec.audience,
      destination: spec.destination,
      recipient: spec.recipient,
      inResponseTo,
      nameId: spec.nameId,
      nameIdFormat: spec.nameIdFormat,
      attributes: spec.attributes,
      statusCode: spec.status,
      now,
      conditionsNotBefore: at(spec.conditions?.notBefore, -60),
      conditionsNotOnOrAfter: at(spec.conditions?.notOnOrAfter, 300),
      confirmationNotOnOrAfter: at(spec.confirmationNotOnOrAfter, 300),
    },
    { ...signer, sign: spec.sign ?? "assertion", algorithm: spec.algorithm ?? "sha256" },
  );
  // `tamper`: the signature no longer verifies (production's refusal, saml-smoke efe0ef).
  const value = Buffer.from(spec.tamper ? tamperSignature(xml) : xml, "utf8").toString("base64");
  if (spec.remember !== undefined) raw.set(`$saml:${spec.remember}`, value);
  return value;
}

/**
 * A request value with `$from`, `$token`, `$form` (URL-encoded postBody), `$saml` (a signed
 * SAMLResponse, see `samlValue`) and `$relayState` (the relay state of a step's AuthnRequest)
 * resolved.
 */
export function materialize(value, raw, minted, saml) {
  if (Array.isArray(value)) return value.map((v) => materialize(v, raw, minted, saml));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") return fromRaw(raw, value.$from);
    if (value.$saml && typeof value.$saml === "object") return samlValue(value.$saml, raw, saml);
    if (typeof value.$relayState === "string") {
      return readAuthnRequest(fromRaw(raw, `${value.$relayState}:authUri`)).relayState;
    }
    if (typeof value.$token === "string") {
      if (minted[value.$token] === undefined) throw new Error(`token ${value.$token} not minted`);
      return minted[value.$token];
    }
    if (value.$form && typeof value.$form === "object") {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(materialize(value.$form, raw, minted, saml))) {
        if (v !== undefined) form.set(k, String(v));
      }
      return form.toString();
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, materialize(v, raw, minted, saml)]),
    );
  }
  return value;
}

/** Every `localId` an answer names: the accounts a program created, to delete after it. */
function localIds(value, into = new Set()) {
  if (Array.isArray(value)) value.forEach((v) => localIds(v, into));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (k === "localId" && typeof v === "string") into.add(v);
      else localIds(v, into);
    }
  }
  return into;
}

/** Whether a step may create an account (a sign-in, a sign-up or an Admin create). */
const mayCreateAccount = (step) =>
  /accounts:(signInWithIdp|signUp)$/.test(step.path) ||
  /^v1\/projects\/[^/]+\/accounts$/.test(step.path);

/**
 * Sends every step of `programs` to `origin` and returns the recorded rows. With
 * `ctx.accountLimit`, the run stops (throws) before a step that may create an account once
 * that many distinct accounts were named: an account costs an MAU even when deleted.
 * `ctx.saml` holds the run's SAML keys and clock for `$saml` values.
 */
export async function runPrograms(programs, ctx) {
  const results = {};
  const failures = [];
  const named = new Set();
  let requests = 0;
  // Every account an answer named (the MAU a production pass costs).
  let accountsDeleted = 0;
  for (const program of programs) {
    const steps = {};
    const stepCtx = { ...ctx, defaultIdpWrites: program.defaultIdpWrites ?? [] };
    const harness = (method, path) => harnessRequest(stepCtx, method, path);
    // A default IdP a program writes must be absent before it, so deleting it restores.
    let refused;
    for (const idp of program.defaultIdpWrites ?? []) {
      const { status } = await harness("GET", `defaultSupportedIdpConfigs/${idp}`);
      if (status !== 404) refused = `${program.id}: default IdP ${idp} exists (${status})`;
    }
    if (refused) {
      failures.push(refused);
      continue;
    }
    const raw = new Map();
    const accounts = new Set();
    const restore = [];
    for (const path of program.touches ?? []) {
      const config = await harnessJson(stepCtx, "GET", "config");
      const value = path.split(".").reduce((v, k) => v?.[k], config) ?? false;
      restore.push({ path, value });
    }
    for (const step of program.steps) {
      const query = new URLSearchParams(step.query ?? {});
      if (step.auth === "key") query.set("key", ctx.apiKey);
      const host = step.path.startsWith("v1/token")
        ? "securetoken.googleapis.com"
        : "identitytoolkit.googleapis.com";
      const url = urlFor(ctx, host, `${step.path}${query.size ? `?${query}` : ""}`);
      const method = step.method ?? "POST";
      if (
        ctx.accountLimit !== undefined &&
        mayCreateAccount(step) &&
        named.size >= ctx.accountLimit
      ) {
        throw new Error(
          `account limit ${ctx.accountLimit} reached before ${program.id}#${step.id}`,
        );
      }
      let body;
      try {
        body =
          step.body === undefined
            ? undefined
            : JSON.stringify(materialize(step.body, raw, program.minted ?? {}, ctx.saml));
      } catch (error) {
        // A value an earlier answer did not give: the row is recorded as not sent.
        steps[step.id] = { status: -1, skipped: error.message };
        continue;
      }
      try {
        guardHttp({ url, method, body }, stepCtx, { role: "step" });
      } catch (error) {
        failures.push(`${program.id}#${step.id}: guard refused: ${error.message}`);
        break;
      }
      const response = await send(ctx, url, {
        method,
        headers: {
          "content-type": "application/json",
          ...(step.auth === "admin" ? adminHeaders(ctx) : {}),
        },
        body,
      });
      requests += 1;
      const text = await response.text();
      try {
        const parsed = JSON.parse(text);
        raw.set(step.id, parsed);
        localIds(parsed, accounts);
        localIds(parsed, named);
      } catch {
        raw.set(step.id, undefined);
      }
      steps[step.id] = normalizeHttp(response.status, text, ctx, step.record);
    }
    results[program.id] = { steps };
    // Every account the program's answers named, and every config path it touched.
    for (const localId of accounts) {
      await harnessAccountDelete(stepCtx, localId);
      accountsDeleted += 1;
    }
    for (const { path, value } of restore) {
      const body = {};
      path.split(".").reduce((target, key, index, keys) => {
        target[key] = index === keys.length - 1 ? value : {};
        return target[key];
      }, body);
      await harnessJson(stepCtx, "PATCH", `config?updateMask=${path}`, body);
    }
    // Whatever the program may have created goes, whether or not a step deleted it.
    for (const provider of program.providers ?? []) {
      const collection = provider.startsWith("oidc.") ? "oauthIdpConfigs" : "inboundSamlConfigs";
      await harness("DELETE", `${collection}/${provider}`);
    }
    for (const idp of program.defaultIdpWrites ?? []) {
      await harness("DELETE", `defaultSupportedIdpConfigs/${idp}`);
    }
  }
  // Read back that none of the run's providers is left, whatever a delete answered.
  for (const leftover of await runProviderLeftovers(ctx)) {
    failures.push(`provider ${leftover} is left after the run`);
  }
  return { results, failures, requests, accountsDeleted };
}

/** The run's providers the project still lists. */
export async function runProviderLeftovers(ctx) {
  // Any provider named for the run, also one whose unprefixed ID the service accepted.
  const own = { test: (id) => String(id).toLowerCase().includes(`fireemu-${ctx.run}-`) };
  const left = [];
  for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
    const listed = await harnessJson(ctx, "GET", `${collection}?pageSize=100`);
    for (const { name } of listed[collection] ?? []) {
      const id = String(name).split("/").at(-1);
      if (own.test(id)) left.push(id);
    }
  }
  return left;
}

/**
 * The URL of `path` on the API `host`: the host itself in production, a path below the
 * local emulator's origin otherwise.
 */
function urlFor(ctx, host, path) {
  return ctx.target.kind === "production"
    ? `https://${host}/${path}`
    : `${ctx.origin}/${host}/${path}`;
}

/** The headers of an administrator's request: the owner's token (and quota project). */
function adminHeaders(ctx) {
  return { authorization: ctx.adminAuthorization, ...ctx.adminHeaders };
}

/** Sends a request through the context's (counted) fetch; harness requests are counted too. */
function send(ctx, url, init) {
  return (ctx.fetch ?? fetch)(url, init);
}

/** A harness config read or write-back through the same guard; the answer's JSON. */
async function harnessJson(ctx, method, path, body) {
  const url = urlFor(
    ctx,
    "identitytoolkit.googleapis.com",
    `admin/v2/projects/${ctx.project}/${path}`,
  );
  const text = body === undefined ? undefined : JSON.stringify(body);
  guardHttp({ url, method, body: text }, ctx, { role: "harness" });
  const response = await send(ctx, url, {
    method,
    headers: { ...adminHeaders(ctx), "content-type": "application/json" },
    ...(text === undefined ? {} : { body: text }),
  });
  return response.json().catch(() => ({}));
}

/** Deletes an account a program created, through the same guard. */
async function harnessAccountDelete(ctx, localId) {
  const url = urlFor(
    ctx,
    "identitytoolkit.googleapis.com",
    `v1/projects/${ctx.project}/accounts:delete`,
  );
  const body = JSON.stringify({ localId });
  guardHttp({ url, method: "POST", body }, ctx, { role: "harness" });
  const response = await send(ctx, url, {
    method: "POST",
    headers: { ...adminHeaders(ctx), "content-type": "application/json" },
    body,
  });
  await response.text();
}

/** A harness request (a read before a program, a delete after it) through the same guard. */
async function harnessRequest(ctx, method, path) {
  const url = urlFor(
    ctx,
    "identitytoolkit.googleapis.com",
    `admin/v2/projects/${ctx.project}/${path}`,
  );
  guardHttp({ url, method }, ctx, { role: "harness" });
  const response = await send(ctx, url, { method, headers: adminHeaders(ctx) });
  await response.text();
  return { status: response.status };
}

/** Inside `fireemu exec`: runs the prepared corpus against the local emulator. */
async function sessionLocal() {
  const prepared = JSON.parse(await readFile(process.env.AUTH_FEDERATION_IN, "utf8"));
  const out = await runPrograms(prepared.programs, {
    run: prepared.run,
    issuerHost: prepared.issuerHost,
    project: SANDBOX_PROJECT,
    projectNumber: LOCAL_PROJECT_NUMBER,
    runKids: prepared.runKids,
    runCertificates: prepared.runCertificates,
    passTag: prepared.passTag,
    nonceLabels: prepared.nonceLabels,
    saml: {
      keys: await loadSamlSigners(prepared.samlKeysPath),
      now: () => Math.floor(Date.now() / 1000),
    },
    apiKey: "fake-api-key",
    adminAuthorization: OWNER,
    origin: `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`,
    target: { kind: "local", origin: `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}` },
  });
  await writeFile(process.env.AUTH_FEDERATION_OUT, JSON.stringify(out));
}

async function runLocal(packet = "record-oidc") {
  const corpus = CORPORA[packet];
  if (!corpus) throw new Error(`no corpus for ${packet}`);
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const run = randomBytes(3).toString("hex");
  const prepared = await prepareRun(
    SANDBOX_PROJECT,
    run,
    `${SANDBOX_PROJECT}--fed-${run}-local.web.app`,
    corpus,
  );
  try {
    const inPath = join(RUN_DIR, "programs.json");
    const outPath = join(RUN_DIR, "fireemu.json");
    const configPath = join(RUN_DIR, "fireemu.config.json");
    await writeFile(inPath, JSON.stringify({ ...prepared, secretDir: undefined }), { mode: 0o600 });
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 1,
        profile: "strict",
        daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
        auth: {
          idTokenSigning: "session-rsa",
          apiKeys: ["fake-api-key"],
          // Strict verifies the run's ID tokens with the key its issuer would publish (O4).
          // The authorization endpoint of the discovery document the recording publishes.
          idpSigners: {
            [prepared.issuer]: {
              ...jwksDocument(...prepared.jwks),
              authorization_endpoint: discoveryDocument(prepared.issuer).authorization_endpoint,
              ...(DISCOVERY_SCOPES[packet] ? { scopes_supported: DISCOVERY_SCOPES[packet] } : {}),
            },
          },
        },
      }),
    );
    const binary = resolveFireemuBinary();
    const ports = ["--firestore-port", "0", "--ui-port", "0", "--hub-port", "0"];
    const child = spawn(
      binary,
      [
        "exec",
        "--config",
        configPath,
        "--project",
        SANDBOX_PROJECT,
        "--only",
        "auth",
        "--http-port",
        "0",
        ...ports,
        "--logging-port",
        "0",
        "--",
        process.execPath,
        "src/auth-federation/run.mjs",
        "session-local",
      ],
      {
        cwd: CONFORMANCE_DIR,
        stdio: ["ignore", "inherit", "inherit"],
        env: { ...process.env, AUTH_FEDERATION_IN: inPath, AUTH_FEDERATION_OUT: outPath },
      },
    );
    const code = await new Promise((resolve) => child.once("exit", resolve));
    if (code !== 0) throw new Error(`fireemu session exited ${code}`);
    const out = JSON.parse(await readFile(outPath, "utf8"));
    const results =
      packet === "record-oidc" ? "fireemu-results.json" : `fireemu-${packet}-results.json`;
    await writeFile(join(RUN_DIR, results), `${JSON.stringify(out, null, 2)}\n`);
    console.log(
      JSON.stringify({ binary, requests: out.requests, failures: out.failures }, null, 2),
    );
  } finally {
    await rm(prepared.secretDir, { recursive: true, force: true });
  }
}

const mode = process.argv[1] === fileURLToPath(import.meta.url) ? process.argv[2] : undefined;
if (mode === "local") await runLocal(process.argv[3]);
else if (mode === "session-local") await sessionLocal();
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
