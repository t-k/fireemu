import { expect, type APIRequestContext, type Page } from "@playwright/test";

/** The API of the daemon under test (no Origin: the control token is not needed). */
export const api = async (
  request: APIRequestContext,
  method: string,
  path: string,
  data?: unknown,
): Promise<unknown> => {
  const r = await request.fetch(`/ui/api/${path}`, {
    method,
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
