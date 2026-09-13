import { spawn } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ownedProcessCommand, stopOwnedProcess } from "../src/lib/processTarget";

// Starts a real daemon (release binary when built, debug otherwise) with the smoke
// functions project and a pinned clock, and retains its child handle for teardown.
const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const candidates = [
  process.env.FIREEMU_BIN,
  resolve(repo, "target/release/fireemu"),
  resolve(repo, "target/debug/fireemu"),
].filter((p): p is string => Boolean(p));

const port = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`${name} must be a TCP port`);
  }
  return parsed;
};

export const PORTS = {
  firestore: port("FIREEMU_E2E_FIRESTORE_PORT", 18080),
  http: port("FIREEMU_E2E_HTTP_PORT", 19099),
  storage: port("FIREEMU_E2E_STORAGE_PORT", 19199),
  functions: port("FIREEMU_E2E_FUNCTIONS_PORT", 15001),
  ui: port("FIREEMU_E2E_UI_PORT", 14000),
};
export const STATE_FILE = resolve(here, "../test-results/daemon.json");

type ChildStatus = {
  error?: Error;
  exit?: { code: number | null; signal: NodeJS.Signals | null };
};

const waitFor = async (
  url: string,
  attempts: number,
  status: ChildStatus,
  output: () => string,
): Promise<void> => {
  for (let i = 0; i < attempts; i += 1) {
    if (status.error) {
      throw new Error(`daemon failed to start: ${status.error.message}\n${output()}`);
    }
    if (status.exit) {
      throw new Error(
        `daemon exited before answering at ${url} (code=${status.exit.code}, signal=${status.exit.signal})\n${output()}`,
      );
    }
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(1_000) });
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`daemon did not answer at ${url}\n${output()}`);
};

export default async function globalSetup(): Promise<() => Promise<void>> {
  const bin = candidates.find((p) => existsSync(p));
  if (!bin) {
    throw new Error("no fireemu binary: cargo build -p fireemu first");
  }
  const args = [
    "up",
    "--config",
    resolve(repo, "tools/sdk-smoke/fireemu.smoke.json"),
    "--firestore-port",
    String(PORTS.firestore),
    "--http-port",
    String(PORTS.http),
    "--storage-port",
    String(PORTS.storage),
    "--functions",
    resolve(repo, "tools/sdk-smoke/functions-project"),
    "--functions-port",
    String(PORTS.functions),
    "--ui-port",
    String(PORTS.ui),
  ];
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  rmSync(STATE_FILE, { force: true });
  const processCommand = ownedProcessCommand(
    bin,
    args,
    process.platform,
    resolve(repo, "verification/quint/bin/process-group"),
  );
  const child = spawn(processCommand.command, processCommand.args, {
    cwd: repo,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let banner = "";
  const status: ChildStatus = {};
  child.stdout?.on("data", (d: Buffer) => {
    banner += d.toString();
  });
  child.stderr?.on("data", (d: Buffer) => {
    banner += d.toString();
  });
  child.once("error", (error) => {
    status.error = error;
  });
  child.once("exit", (code, signal) => {
    status.exit = { code, signal };
  });
  try {
    // A release daemon normally starts immediately. Keep the CI readiness budget bounded while
    // allowing a cold, contended hosted runner enough time to schedule the process.
    await waitFor(`http://127.0.0.1:${PORTS.http}/health/live`, 240, status, () => banner);
    await waitFor(`http://127.0.0.1:${PORTS.ui}/ui/`, 40, status, () => banner);
    const html = await (
      await fetch(`http://127.0.0.1:${PORTS.ui}/ui/`, { signal: AbortSignal.timeout(1_000) })
    ).text();
    const config = /window\.__FIREEMU__ = (\{.*?\});<\/script>/.exec(html)?.[1];
    const token = config
      ? ((JSON.parse(config) as { controlToken?: string }).controlToken ?? "")
      : "";
    if (!token) throw new Error(`the served UI page carries no control token\n${banner}`);
    writeFileSync(STATE_FILE, JSON.stringify({ pid: child.pid, banner, token }));
    // Playwright retains this closure until global teardown, including the captured process group.
    return async () => {
      await stopOwnedProcess(child);
      rmSync(STATE_FILE, { force: true });
    };
  } catch (error) {
    await stopOwnedProcess(child);
    throw error;
  }
}
