import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Starts a real daemon (release binary when built, debug otherwise) with the smoke
// functions project and a pinned clock, and records its PID for the teardown.
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

const waitFor = async (url: string, attempts: number): Promise<void> => {
  for (let i = 0; i < attempts; i += 1) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`daemon did not answer at ${url}`);
};

export default async function globalSetup(): Promise<void> {
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
  const child = spawn(bin, args, { cwd: repo, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  let banner = "";
  child.stdout?.on("data", (d: Buffer) => {
    banner += d.toString();
  });
  child.stderr?.on("data", (d: Buffer) => {
    banner += d.toString();
  });
  await waitFor(`http://127.0.0.1:${PORTS.http}/health/live`, 120);
  await waitFor(`http://127.0.0.1:${PORTS.ui}/ui/`, 40);
  const html = await (await fetch(`http://127.0.0.1:${PORTS.ui}/ui/`)).text();
  const config = /window\.__FIREEMU__ = (\{.*?\});<\/script>/.exec(html)?.[1];
  const token = config
    ? ((JSON.parse(config) as { controlToken?: string }).controlToken ?? "")
    : "";
  if (!token) throw new Error("the served UI page carries no control token");
  writeFileSync(STATE_FILE, JSON.stringify({ pid: child.pid, banner, token }));
  child.unref();
}
