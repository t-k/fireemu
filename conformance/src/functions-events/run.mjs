import { spawn, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createWriteStream, existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve as resolvePath } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { identityEnv, identityOf } from "./binary-identity.mjs";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const fixtureDir = join(repoRoot, "conformance/functions-events/fixtures");
const envPath = join(fixtureDir, ".env");
const projectId = "demo-conformance";

export function buildFireemuArgs(profile) {
  if (!["emulator", "strict"].includes(profile)) throw new Error("unknown local profile");
  return [
    "exec",
    "--config",
    `conformance/functions-events/${profile}.json`,
    "--project",
    projectId,
    "--only",
    "auth,firestore,storage,functions,pubsub",
    "--firestore-port",
    "0",
    "--http-port",
    "0",
    "--storage-port",
    "0",
    "--functions-port",
    "0",
    "--pubsub-port",
    "0",
    "--eventarc-port",
    "0",
    "--tasks-port",
    "0",
    "--hub-port",
    "0",
    "--logging-port",
    "0",
    "--ui-port",
    "0",
    "--functions",
    "conformance/functions-events/fixtures",
    "--log-verbosity",
    "quiet",
    "--",
    process.execPath,
    "conformance/src/functions-events/session-cli.mjs",
  ];
}

function mainCheckoutRoot() {
  const common = execFileSync("git", ["rev-parse", "--git-common-dir"], {
    cwd: repoRoot,
    encoding: "utf8",
  }).trim();
  return dirname(resolvePath(repoRoot, common));
}

function signalGroup(child, signal) {
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

async function stopGroup(child) {
  if (!child.pid) return;
  signalGroup(child, "SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 500));
  try {
    process.kill(-child.pid, 0);
    signalGroup(child, "SIGKILL");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

async function runProfile({ profile, binary, identity, privateRoot, onlyRecipeIds, windowMs }) {
  const privateDir = join(privateRoot, profile);
  await mkdir(privateDir, { recursive: true, mode: 0o700 });
  const shortRoot = await mkdtemp(join(tmpdir(), "fe-"));
  const shortDir = join(shortRoot, "run");
  await symlink(privateDir, shortDir, "dir");
  const socketPath = join(shortDir, "events.sock");
  await writeFile(
    envPath,
    `FE_EVENTS_MODE=local\nFE_EVENTS_CAPTURE_MODE=socket\nFE_EVENTS_CAPTURE_SOCKET=${socketPath}\n`,
    {
      flag: "wx",
      mode: 0o600,
    },
  );
  const logPath = join(privateDir, "supervisor.log");
  const log = createWriteStream(logPath, { flags: "wx", mode: 0o600 });
  const env = {
    ...process.env,
    GOOGLE_APPLICATION_CREDENTIALS: "",
    FE_EVENTS_PRIVATE_DIR: shortDir,
    FE_EVENTS_ONLY: onlyRecipeIds ?? "",
    FE_EVENTS_WINDOW_MS: String(windowMs),
    FE_EVENTS_MODE: "local",
    FE_EVENTS_CAPTURE_MODE: "socket",
    FE_EVENTS_CAPTURE_SOCKET: socketPath,
    ...identityEnv(identity),
    // the daemon would otherwise walk up from the binary to whichever checkout holds it: pin the runner of this checkout
    FIREEMU_RUNNER_NODE: identity.runnerPath,
  };
  delete env.FE_EVENTS_ALLOW_PRODUCTION_ADMIN;
  let child;
  let logBytes = 0;
  let exceeded = false;
  try {
    child = spawn(binary, buildFireemuArgs(profile), {
      cwd: repoRoot,
      env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        logBytes += chunk.length;
        if (logBytes > 32 * 1024 * 1024) {
          exceeded = true;
          signalGroup(child, "SIGTERM");
          return;
        }
        log.write(chunk);
      });
    }
    let timer;
    const result = await Promise.race([
      new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => resolve({ code, signal }));
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("local profile timed out")), 20 * 60_000);
      }),
    ]).finally(() => clearTimeout(timer));
    if (exceeded) throw new Error("local profile log limit exceeded");
    if (result.code !== 0)
      throw new Error(`${profile} exited ${result.code ?? result.signal}; see ${logPath}`);
    const sessionPath = join(privateDir, "session.json");
    if (!existsSync(sessionPath))
      throw new Error(`${profile} produced no session record; see ${logPath}`);
    return JSON.parse(await readFile(sessionPath, "utf8"));
  } finally {
    if (child) await stopGroup(child);
    await new Promise((resolve) => log.end(resolve));
    await rm(envPath, { force: true });
    await rm(shortRoot, { recursive: true, force: true });
  }
}

async function main() {
  const privateRoot = join(
    mainCheckoutRoot(),
    "docs.local/runs/functions-events-local",
    `${new Date().toISOString().replaceAll(/[:.]/g, "-")}-${randomUUID()}`,
  );
  await mkdir(privateRoot, { recursive: true, mode: 0o700 });
  const binary = process.env.FIREEMU_BIN ?? join(repoRoot, "target/debug/fireemu");
  if (!existsSync(binary)) throw new Error("build fireemu in this worktree before the local run");
  // The binary that runs is the one the sessions will name: hashed from the file here, not typed in later.
  const identity = identityOf({ binary, repoRoot });
  const onlyRecipeIds = process.env.FE_EVENTS_ONLY ?? "";
  const windowMs = Number(process.env.FE_EVENTS_WINDOW_MS ?? "5000");
  const runs = {};
  for (const profile of ["emulator", "strict"]) {
    runs[profile] = await runProfile({
      profile,
      binary,
      identity,
      privateRoot,
      onlyRecipeIds,
      windowMs,
    });
  }
  const summary = {
    authority: "LOCAL_ONLY",
    productionEvidence: null,
    fireemu: identity,
    profiles: Object.fromEntries(
      Object.entries(runs).map(([profile, result]) => [
        profile,
        {
          status: result.status,
          programs: result.programs.length,
          cases: result.programs.flatMap((program) => program.cases).length,
        },
      ]),
    ),
  };
  await writeFile(join(privateRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  console.log(`Local event run: ${privateRoot}`);
  console.log(JSON.stringify(summary));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
