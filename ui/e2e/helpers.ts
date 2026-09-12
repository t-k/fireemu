import { readFileSync } from "node:fs";

import { expect, type APIRequestContext, type Page } from "@playwright/test";

import { STATE_FILE } from "./global-setup";

/** The control token embedded in the same-origin UI page. */
export const controlToken = (): string => {
  const state = JSON.parse(readFileSync(STATE_FILE, "utf8")) as { token?: string };
  const token = state.token;
  if (!token) {
    throw new Error("the UI test state carries no control token");
  }
  return token;
};

/** The API of the daemon under test, as the app calls it (token in the header). */
export const api = async (
  request: APIRequestContext,
  method: string,
  path: string,
  data?: unknown,
): Promise<unknown> => {
  const r = await request.fetch(`/ui/api/${path}`, {
    method,
    headers: { authorization: `Bearer ${controlToken()}` },
    ...(data === undefined ? {} : { data }),
  });
  expect(r.ok(), `${method} ${path}: ${r.status()} ${await r.text()}`).toBeTruthy();
  const text = await r.text();
  return text ? (JSON.parse(text) as unknown) : null;
};

/** Wipes the default session before a scenario. */
export const resetSession = (request: APIRequestContext): Promise<unknown> =>
  api(request, "POST", "control/v1/sessions/default/reset", {});

/**
 * Waits until the Functions runner's HTTP server accepts a connection again. A session reset
 * restarts the runner, and there is a brief window afterwards where the Functions port (and so
 * an invoke or a task dispatch) is refused with a 502 -- the port's own behaviour, which the
 * console mirrors. Tests that invoke or enqueue call this after resetting.
 */
export const waitForFunctionsRunner = async (request: APIRequestContext): Promise<void> => {
  await expect(async () => {
    const r = (await api(request, "POST", "functions/echo:invoke", { method: "GET" })) as {
      status: number;
    };
    expect(r.status).toBe(200);
  }).toPass({ timeout: 15000 });
};

export const gotoApp = async (page: Page, path: string): Promise<void> => {
  await page.goto(`/ui${path}`);
  await expect(page.getByRole("navigation").first()).toBeVisible();
};
