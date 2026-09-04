import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "@playwright/test";

import { STATE_FILE } from "./global-setup";

const UI_SHA256 = "97d8c4c574e3f20c4d690a2ce8373eef76ab024da73279a062dba8517f88cf9a";
const uiArchive =
  process.env.FIREBASE_UI_ZIP ?? join(homedir(), ".cache/firebase/emulators/ui-v1.15.0.zip");
const canRun = process.platform !== "win32" && existsSync(uiArchive) && existsSync(STATE_FILE);

const addressFromBanner = (banner: string, label: string): string => {
  const address = new RegExp(`^  ${label}:\\s+([^\\s]+)`, "m").exec(banner)?.[1];
  if (!address) throw new Error(`daemon banner has no ${label} address`);
  return address;
};

const freePort = async (): Promise<number> =>
  await new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("temporary listener has no TCP address"));
        return;
      }
      server.close((error) => (error ? reject(error) : resolve(address.port)));
    });
  });

const waitForUi = async (url: string, child: ChildProcess, output: () => string): Promise<void> => {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    if (child.exitCode !== null) {
      throw new Error(`official UI exited with ${child.exitCode}:\n${output()}`);
    }
    try {
      if ((await fetch(`${url}/api/config`)).ok) return;
    } catch {
      // The listener is not ready yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`official UI did not become ready:\n${output()}`);
};

const stopChild = async (child: ChildProcess): Promise<void> => {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  child.kill("SIGKILL");
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("official UI did not exit after SIGKILL");
};

test("the pinned official Emulator UI renders a live fireemu Functions log", async ({
  page,
  request,
}) => {
  test.skip(!canRun, "requires the pinned Firebase Emulator UI archive and managed daemon");
  const digest = createHash("sha256").update(readFileSync(uiArchive)).digest("hex");
  expect(digest, "the UI archive must be the oracle-pinned artifact").toBe(UI_SHA256);

  const { banner } = JSON.parse(readFileSync(STATE_FILE, "utf8")) as { banner: string };
  const hub = addressFromBanner(banner, "emulator hub");
  const firestore = addressFromBanner(banner, "firestore \\(gRPC \\+ REST\\)");
  const scratch = mkdtempSync(join(tmpdir(), "fireemu-official-ui-"));
  execFileSync("unzip", ["-q", uiArchive, "-d", scratch]);
  const port = await freePort();
  const output: string[] = [];
  const child = spawn(process.execPath, [join(scratch, "server/server.mjs")], {
    env: {
      ...process.env,
      GCLOUD_PROJECT: "demo-app",
      FIREBASE_EMULATOR_HUB: hub,
      HOST: "127.0.0.1",
      PORT: String(port),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (chunk: Buffer) => output.push(chunk.toString()));
  child.stderr?.on("data", (chunk: Buffer) => output.push(chunk.toString()));

  try {
    const origin = `http://127.0.0.1:${port}`;
    await waitForUi(origin, child, () => output.join(""));
    const configResponse = await request.get(`${origin}/api/config`);
    expect(configResponse.ok()).toBeTruthy();
    const config = (await configResponse.json()) as {
      logging?: { host?: string; port?: number };
    };
    expect(config.logging).toEqual({
      host: "127.0.0.1",
      listen: expect.any(Array),
      name: "logging",
      pid: expect.any(Number),
      port: expect.any(Number),
    });

    await page.goto(`${origin}/logs`);
    await expect(page.getByRole("textbox", { name: "Filter or search logs..." })).toBeVisible();
    const id = `official-ui-log-${Date.now()}`;
    const write = await request.patch(
      `http://${firestore}/v1/projects/demo-app/databases/(default)/documents/todos/${id}`,
      { data: { fields: { title: { stringValue: "official-ui-live-log" } } } },
    );
    expect(write.ok(), await write.text()).toBeTruthy();

    await expect(page.getByText("function[mirrorTodo]", { exact: true })).toBeVisible();
    await expect(page.getByText("mirrorTodo", { exact: true })).toBeVisible();
  } finally {
    await stopChild(child);
    rmSync(scratch, { recursive: true, force: true });
  }
});
