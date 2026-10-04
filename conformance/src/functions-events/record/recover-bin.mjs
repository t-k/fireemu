#!/usr/bin/env node
// The command line of the v4 recovery. Run by the coordinator only; `recover` reads the owner's authorized-user
// credential (through gcloud) and sends to the events sandbox project.
//   node recover-bin.mjs check   --packet <file> --source-commit <sha>
//   node recover-bin.mjs recover --packet <file> --source-commit <sha> > <log> 2>&1

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import { main } from "./recover-main.mjs";

const root = resolve(fileURLToPath(new URL("../../../..", import.meta.url)));
const shared = process.env.FIREEMU_SHARED_ROOT ?? root;
if (!existsSync(join(shared, "docs.local/runs/sandbox-ledger.jsonl"))) {
  console.error("set FIREEMU_SHARED_ROOT to the checkout that holds docs.local");
  process.exit(2);
}

const deps = {
  root,
  env: process.env,
  fetch,
  printAccessToken: () =>
    execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
      encoding: "utf8",
      timeout: 30_000,
      env: { PATH: process.env.PATH, HOME: process.env.HOME },
    }),
  sleep: (seconds) => delay(seconds * 1000),
  now: () => Date.now(),
  ledgerPath: join(shared, "docs.local/runs/sandbox-ledger.jsonl"),
  ownerPath: join(shared, "docs.local/instructions/owner-decisions.md"),
  lockDir: join(shared, "docs.local/runs/sandbox-locks"),
  legacyLock: join(shared, "docs.local/runs/sandbox-ledger.jsonl.lock"),
  runsDir: join(shared, "docs.local/runs"),
};

try {
  const result = await main(process.argv.slice(2), deps);
  console.log(JSON.stringify(result, null, 2));
  process.exitCode = result.ok ? 0 : 1;
} catch (error) {
  console.error(error.stack ?? String(error));
  process.exitCode = 2;
}
