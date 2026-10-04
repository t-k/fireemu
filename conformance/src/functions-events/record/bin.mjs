#!/usr/bin/env node
// The command line of the formal recording. Run by the coordinator only: `record` reads the owner's
// authorized-user credential and the browser API key file, and sends to the events sandbox project.
//   node bin.mjs check  --packet <file> --source-commit <sha> --api-key-file <file>
//   node bin.mjs record --packet <file> --source-commit <sha> --api-key-file <file>
// Run it inside tmux (or with stdout and stderr redirected to a file) so a closed terminal cannot cut
// the cleanup short. A first SIGINT, SIGTERM or SIGHUP stops at the next step and runs the cleanup.

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { runCli } from "./deploy.mjs";
import { main } from "./main.mjs";

const root = resolve(fileURLToPath(new URL("../../../..", import.meta.url)));
const shared = process.env.FIREEMU_SHARED_ROOT ?? root;
if (!existsSync(join(shared, "docs.local/runs/sandbox-ledger.jsonl"))) {
  console.error(
    "set FIREEMU_SHARED_ROOT to the checkout that holds docs.local (the ledger, the owner decisions and the run directories live there)",
  );
  process.exit(2);
}

// The access token comes from the command the sandbox notes name, never from the credential file.
function printAccessToken() {
  return execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
    encoding: "utf8",
    timeout: 30_000,
    env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });
}

const deps = {
  root,
  env: process.env,
  fetch,
  printAccessToken,
  runCli,
  sleep: (seconds) => delay(seconds * 1000),
  now: () => Date.now(),
  ledgerPath: join(shared, "docs.local/runs/sandbox-ledger.jsonl"),
  ownerPath: join(shared, "docs.local/instructions/owner-decisions.md"),
  lockDir: join(shared, "docs.local/runs/sandbox-locks"),
  legacyLock: join(shared, "docs.local/runs/sandbox-ledger.jsonl.lock"),
  runsDir: join(shared, "docs.local/runs"),
  signals: (handler) => {
    for (const name of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(name, () => handler(name));
  },
};

try {
  const result = await main(process.argv.slice(2), deps);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.ok ? 0 : 1;
} catch (error) {
  console.error(error.stack ?? String(error));
  process.exitCode = 2;
}
