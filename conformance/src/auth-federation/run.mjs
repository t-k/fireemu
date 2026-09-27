// AUTH-FEDERATION harness runner (draft). Only the local mode exists: it runs the corpus
// against fireemu (strict profile) and writes the recorded rows under `.runs/`. The
// production mode is added after the closure conditions are frozen, the owner decisions
// O1 to O6 are recorded and a pre-send review passes; it will hold the shared
// `<ledger>.lock` and write the started and terminal ledger lines as the other lanes do.
//
//   node src/auth-federation/run.mjs local

import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { PROGRAMS, resolveCorpus } from "./corpus.mjs";
import { guardHttp, validateFederationCorpus } from "./guard.mjs";
import { normalizeHttp } from "./harness.mjs";
import { generateSigningKey, saveSigningKey, signIdToken } from "./idp.mjs";

const execFileAsync = promisify(execFile);
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-federation");
const LOCAL_PROJECT_NUMBER = "123456789012";
const OWNER = "Bearer owner";

/**
 * A self-signed certificate of a fresh key, made with the system `openssl`, in a private
 * temporary directory. Only the certificate (public) leaves it.
 */
async function makeCertificate(dir, name) {
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
    "-days",
    "2",
    "-subj",
    `/CN=fireemu-${name}`,
  ]);
  return readFile(cert, "utf8");
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

/** This run's key material and the corpus resolved with it. */
async function prepareRun(project) {
  const run = randomBytes(3).toString("hex");
  const secretDir = await mkdtemp(join(tmpdir(), "fireemu-auth-federation-"));
  const keys = { run: generateSigningKey(), other: generateSigningKey() };
  await saveSigningKey(join(secretDir, "oidc.pem"), keys.run);
  const now = Math.floor(Date.now() / 1000);
  const issuer = `https://${project}.web.app/oidc/${run}`;
  const legacy = (subject) =>
    signIdToken(keys.run, { iss: issuer, aud: "client-off", sub: subject, iat: now, exp: now + 3600 });
  const programs = resolveCorpus(PROGRAMS, {
    project,
    run,
    certificates: { "saml-a": await makeCertificate(secretDir, "saml-a") },
    tokens: { missing: legacy("missing"), off: legacy("off") },
  });
  for (const program of programs) program.minted = mintTokens(program, { issuer, keys, now });
  validateFederationCorpus(programs);
  return { run, secretDir, runKids: [keys.run.jwk.kid], programs, jwks: [keys.run.jwk] };
}

/** `step:a.b` → the value at `a.b` in the raw answer of `step`. */
function fromRaw(raw, reference) {
  const [stepId, path] = reference.split(":");
  const found = path.split(".").reduce((value, key) => value?.[key], raw.get(stepId));
  if (found === undefined) throw new Error(`step ${stepId} recorded nothing at ${path}`);
  return found;
}

/** A request value with `$from`, `$token` and `$form` (URL-encoded postBody) resolved. */
export function materialize(value, raw, minted) {
  if (Array.isArray(value)) return value.map((v) => materialize(v, raw, minted));
  if (value && typeof value === "object") {
    if (typeof value.$from === "string") return fromRaw(raw, value.$from);
    if (typeof value.$token === "string") {
      if (minted[value.$token] === undefined) throw new Error(`token ${value.$token} not minted`);
      return minted[value.$token];
    }
    if (value.$form && typeof value.$form === "object") {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(materialize(value.$form, raw, minted))) {
        if (v !== undefined) form.set(k, String(v));
      }
      return form.toString();
    }
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, materialize(v, raw, minted)]),
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

/** Sends every step of `programs` to `origin` and returns the recorded rows. */
export async function runPrograms(programs, ctx) {
  const results = {};
  const failures = [];
  let requests = 0;
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
      const url = `${ctx.origin}/${host}/${step.path}${query.size ? `?${query}` : ""}`;
      const method = step.method ?? "POST";
      let body;
      try {
        body =
          step.body === undefined
            ? undefined
            : JSON.stringify(materialize(step.body, raw, program.minted ?? {}));
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
      const response = await fetch(url, {
        method,
        headers: {
          "content-type": "application/json",
          ...(step.auth === "admin" ? { authorization: ctx.adminAuthorization } : {}),
        },
        body,
      });
      requests += 1;
      const text = await response.text();
      try {
        const parsed = JSON.parse(text);
        raw.set(step.id, parsed);
        localIds(parsed, accounts);
      } catch {
        raw.set(step.id, undefined);
      }
      steps[step.id] = normalizeHttp(response.status, text, ctx);
    }
    results[program.id] = { steps };
    // Every account the program's answers named, and every config path it touched.
    for (const localId of accounts) {
      await harnessAccountDelete(stepCtx, localId);
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
  return { results, failures, requests };
}

/** A harness config read or write-back through the same guard; the answer's JSON. */
async function harnessJson(ctx, method, path, body) {
  const url = `${ctx.origin}/identitytoolkit.googleapis.com/admin/v2/projects/${ctx.project}/${path}`;
  const text = body === undefined ? undefined : JSON.stringify(body);
  guardHttp({ url, method, body: text }, ctx, { role: "harness" });
  const response = await fetch(url, {
    method,
    headers: { authorization: ctx.adminAuthorization, "content-type": "application/json" },
    ...(text === undefined ? {} : { body: text }),
  });
  return response.json().catch(() => ({}));
}

/** Deletes an account a program created, through the same guard. */
async function harnessAccountDelete(ctx, localId) {
  const url = `${ctx.origin}/identitytoolkit.googleapis.com/v1/projects/${ctx.project}/accounts:delete`;
  const body = JSON.stringify({ localId });
  guardHttp({ url, method: "POST", body }, ctx, { role: "harness" });
  const response = await fetch(url, {
    method: "POST",
    headers: { authorization: ctx.adminAuthorization, "content-type": "application/json" },
    body,
  });
  await response.text();
}

/** A harness request (a read before a program, a delete after it) through the same guard. */
async function harnessRequest(ctx, method, path) {
  const url = `${ctx.origin}/identitytoolkit.googleapis.com/admin/v2/projects/${ctx.project}/${path}`;
  guardHttp({ url, method }, ctx, { role: "harness" });
  const response = await fetch(url, { method, headers: { authorization: ctx.adminAuthorization } });
  await response.text();
  return { status: response.status };
}

/** Inside `fireemu exec`: runs the prepared corpus against the local emulator. */
async function sessionLocal() {
  const prepared = JSON.parse(await readFile(process.env.AUTH_FEDERATION_IN, "utf8"));
  const out = await runPrograms(prepared.programs, {
    run: prepared.run,
    project: SANDBOX_PROJECT,
    projectNumber: LOCAL_PROJECT_NUMBER,
    runKids: prepared.runKids,
    apiKey: "fake-api-key",
    adminAuthorization: OWNER,
    origin: `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`,
    target: { kind: "local", origin: `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}` },
  });
  await writeFile(process.env.AUTH_FEDERATION_OUT, JSON.stringify(out));
}

async function runLocal() {
  await mkdir(RUN_DIR, { recursive: true, mode: 0o700 });
  const prepared = await prepareRun(SANDBOX_PROJECT);
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
        auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
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
    await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(out, null, 2)}\n`);
    console.log(JSON.stringify({ binary, requests: out.requests, failures: out.failures }, null, 2));
  } finally {
    await rm(prepared.secretDir, { recursive: true, force: true });
  }
}

const mode = process.argv[2];
if (mode === "local") await runLocal();
else if (mode === "session-local") await sessionLocal();
else if (mode !== undefined) throw new Error(`unknown mode ${mode}`);
