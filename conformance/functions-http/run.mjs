// FUNCTIONS-HTTP task runner. Production mode is gated by its separate pre-send review.
//
//   node conformance/functions-http/run.mjs check-local
//   node conformance/functions-http/run.mjs record-production

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createBudget,
  expectedFunctionName,
  invalidSignatureToken,
  localExpiredToken,
  validateCorpus,
} from "./harness.mjs";
import { runCases } from "./session.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = resolve(HERE, "..");
const REPO = resolve(CONFORMANCE, "..");
const CORPUS_PATH = join(HERE, "corpus.json");
const FIXTURE_SOURCE = join(HERE, "fixtures");
const LOCAL_PROJECT = "demo-functions-http";

async function loadCorpus() {
  const corpus = JSON.parse(await readFile(CORPUS_PATH, "utf8"));
  validateCorpus(corpus);
  return corpus;
}

const localAuthUrl = (path) => {
  const host = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? "")) throw new Error("local Auth host is not loopback");
  return `http://${host}/identitytoolkit.googleapis.com/v1/${path}?key=local-fixture-key`;
};

async function localAuth(method, body) {
  const response = await fetch(localAuthUrl(method), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
  });
  const result = await response.json();
  if (response.status !== 200) throw new Error(`local Auth ${method} returned ${response.status}`);
  return result;
}

async function localTokens(program, budget) {
  if (!program.id.endsWith("auth-context") && !program.id.endsWith("auth-refusal")) {
    return { tokens: {}, user: null };
  }
  const suffix = randomBytes(6).toString("hex");
  budget.take("auth");
  const user = await localAuth("accounts:signUp", {
    email: `fireemu-fh-${suffix}@example.com`,
    password: randomBytes(18).toString("base64url"),
    returnSecureToken: true,
  });
  if (!user.idToken || !user.localId) throw new Error("local Auth returned no user token");
  return {
    user,
    tokens: {
      idToken: user.idToken,
      invalidSignatureIdToken: invalidSignatureToken(user.idToken),
      expiredIdToken: localExpiredToken(user.idToken),
    },
  };
}

async function deleteLocalUser(user, budget) {
  if (!user) return;
  budget.take("auth");
  await localAuth("accounts:delete", { idToken: user.idToken });
}

async function localChild() {
  const host = process.env.FIREEMU_FUNCTIONS_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? ""))
    throw new Error("local Functions host is not loopback");
  const corpus = await loadCorpus();
  const budget = createBudget();
  const recordings = [{}, {}];
  for (const program of corpus.programs) {
    const endpoints = Object.fromEntries(
      [...new Set(program.cases.map((step) => step.target))].map((target) => [
        target,
        `http://${host}/${LOCAL_PROJECT}/us-central1/${expectedFunctionName(target)}`,
      ]),
    );
    const { tokens, user } = await localTokens(program, budget);
    try {
      const replacements = user ? { [user.localId]: "{{uid}}", [user.email]: "{{email}}" } : {};
      for (const [pass, output] of recordings.entries()) {
        output[program.id] = await runCases(program, endpoints, tokens, budget, { replacements });
        console.log(`local pass ${pass + 1}: ${program.id}`);
      }
    } finally {
      await deleteLocalUser(user, budget);
    }
  }
  const output = process.env.FUNCTIONS_HTTP_LOCAL_OUTPUT;
  if (!output) throw new Error("local output path is missing");
  await writeFile(
    output,
    `${JSON.stringify({ recordings, requests: budget.snapshot() }, null, 2)}\n`,
    { mode: 0o600 },
  );
}

async function checkLocal() {
  await loadCorpus();
  const binary = process.env.FIREEMU_BIN || join(REPO, "target/debug/fireemu");
  const runDir = join(CONFORMANCE, ".runs/functions-http");
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const output = join(runDir, `local-${new Date().toISOString().replaceAll(":", "")}.json`);
  const args = [
    "exec",
    "--project",
    LOCAL_PROJECT,
    "--only",
    "auth,functions",
    "--functions",
    FIXTURE_SOURCE,
    "--http-port",
    "0",
    "--functions-port",
    "0",
    "--firestore-port",
    "0",
    "--storage-port",
    "0",
    "--eventarc-port",
    "0",
    "--tasks-port",
    "0",
    "--pubsub-port",
    "0",
    "--ui-port",
    "0",
    "--hub-port",
    "0",
    "--logging-port",
    "0",
    "--",
    process.execPath,
    fileURLToPath(import.meta.url),
    "local-child",
  ];
  const child = spawn(binary, args, {
    cwd: CONFORMANCE,
    stdio: "inherit",
    env: { ...process.env, FUNCTIONS_HTTP_LOCAL_OUTPUT: output },
  });
  const code = await new Promise((resolveChild, reject) => {
    child.once("error", reject);
    child.once("exit", resolveChild);
  });
  if (code !== 0) throw new Error(`local fireemu session exited ${code}`);
  const result = JSON.parse(await readFile(output, "utf8"));
  console.log(
    JSON.stringify({
      programs: Object.keys(result.recordings[0]).length,
      requests: result.requests,
      output,
    }),
  );
}

async function recordProduction() {
  const { recordProduction: record } = await import("./production.mjs");
  await record();
}

const mode = process.argv[2];
if (mode === "check-local") await checkLocal();
else if (mode === "local-child") await localChild();
else if (mode === "record-production") await recordProduction();
else throw new Error("usage: run.mjs check-local|record-production");
