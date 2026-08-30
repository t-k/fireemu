import { readFileSync } from "node:fs";

import { expect, type APIRequestContext, type Page } from "@playwright/test";

import { STATE_FILE } from "./global-setup";

/** The control token the daemon printed at start (every UI API request presents it). */
export const controlToken = (): string => {
  const state = JSON.parse(readFileSync(STATE_FILE, "utf8")) as { banner?: string };
  const match = /FTD_CONTROL_TOKEN=([0-9a-f]+)/.exec(state.banner ?? "");
  if (!match) {
    throw new Error("the daemon banner carries no FTD_CONTROL_TOKEN");
  }
  return match[1];
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

export const gotoApp = async (page: Page, path: string): Promise<void> => {
  await page.goto(`/ui${path}`);
  await expect(page.getByRole("navigation").first()).toBeVisible();
};
