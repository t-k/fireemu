import { expect, test } from "@playwright/test";
import { t } from "../src/i18n";

/** Requires root's integrated RTDB listener; this file never substitutes mocked transport. */
test("Realtime Database keyboard edits deliver real SSE changes and Rules cancellation", async ({
  page,
}, info) => {
  const rawPort = process.env.FIREEMU_E2E_DATABASE_PORT;
  test.skip(!rawPort, "Root must provide the integrated RTDB port for the final CV15 gate");
  const port = Number(rawPort);
  expect(Number.isInteger(port) && port > 0 && port <= 65535).toBe(true);
  const origin = `http://127.0.0.1:${port}`;
  await page.goto("/ui/database");
  const instance = page.getByLabel(t("database.instance"));
  await expect(instance).toBeVisible();
  const namespace = await instance.inputValue();
  expect(namespace).not.toBe("");
  const query = `ns=${encodeURIComponent(namespace)}`;
  const path = `/ui-cv15-${process.pid}-${info.workerIndex}`;
  const location = `${origin}${path}.json?${query}`;
  const rulesLocation = `${origin}/.settings/rules.json?${query}`;
  const owner = { authorization: "Bearer owner", "content-type": "application/json" };
  const original = await fetch(rulesLocation, {
    headers: owner,
    signal: AbortSignal.timeout(5000),
  });
  expect(original.status).toBe(200);
  const originalRules = await original.text();
  const controller = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let buffer = "";
  const decoder = new TextDecoder();
  const nextEvent = async (): Promise<{ event: string; data: unknown }> => {
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      for (;;) {
        const boundary = buffer.indexOf("\n\n");
        if (boundary >= 0) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          const event = /^event: (.+)$/m.exec(block)?.[1];
          const data = /^data: (.+)$/m.exec(block)?.[1];
          if (event && data && event !== "keep-alive")
            return { event, data: JSON.parse(data) as unknown };
        } else {
          const chunk = await reader!.read();
          expect(chunk.done).toBe(false);
          buffer += decoder.decode(chunk.value, { stream: true });
        }
      }
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    expect(
      (
        await fetch(rulesLocation, {
          method: "PUT",
          headers: owner,
          body: '{"rules":{".read":true,".write":false}}',
          signal: AbortSignal.timeout(5000),
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await fetch(location, {
          method: "DELETE",
          headers: owner,
          signal: AbortSignal.timeout(5000),
        })
      ).status,
    ).toBe(200);
    await page.reload();
    await page.getByLabel(t("database.path")).fill(path);
    await page.getByLabel(t("database.path")).press("Enter");
    await expect(page.getByLabel(t("database.json"), { exact: true })).toHaveValue("null");
    const stream = await fetch(location, {
      headers: { accept: "text/event-stream" },
      signal: controller.signal,
    });
    expect(stream.status).toBe(200);
    reader = stream.body!.getReader();
    expect(await nextEvent()).toEqual({ event: "put", data: { path: "/", data: null } });
    const source = page.getByLabel(t("database.json"), { exact: true });
    await source.fill('{"written":1}');
    await source.press("Tab");
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("database-save")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: t("database.saved") })).toHaveText(
      t("database.saved"),
    );
    const committed = await fetch(location, { headers: owner, signal: AbortSignal.timeout(5000) });
    expect(committed.status).toBe(200);
    expect(await committed.json()).toEqual({ written: 1 });
    expect(await nextEvent()).toEqual({ event: "put", data: { path: "/", data: { written: 1 } } });
    const rules = page.getByLabel(t("database.rulesSource"));
    await rules.fill('{"rules":{".read":false,".write":false}}');
    await rules.press("Tab");
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("database-rules-save")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("status").filter({ hasText: t("database.rulesSaved") })).toHaveText(
      t("database.rulesSaved"),
    );
    expect(await nextEvent()).toEqual({ event: "cancel", data: "Permission denied" });
    await page.getByLabel(t("database.requestBody")).focus();
    await page.keyboard.press("Tab");
    await expect(page.getByTestId("database-request-run")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("database-response")).toContainText("HTTP 401");
    const unchanged = await fetch(location, { headers: owner, signal: AbortSignal.timeout(5000) });
    expect(unchanged.status).toBe(200);
    expect(await unchanged.json()).toEqual({ written: 1 });
    await source.fill('{"patched":true}');
    await page.getByTestId("database-patch").press("Enter");
    await expect
      .poll(async () =>
        (await fetch(location, { headers: owner, signal: AbortSignal.timeout(5000) })).json(),
      )
      .toEqual({ written: 1, patched: true });
    await page.getByTestId("database-delete").press("Enter");
    await page.getByTestId("database-delete-confirm").press("Enter");
    await expect(source).toHaveValue("null");
    await page.screenshot({
      path: info.outputPath("database-keyboard-and-real-delivery.png"),
      fullPage: true,
    });
  } finally {
    controller.abort();
    await reader?.cancel().catch(() => {});
    expect(
      (
        await fetch(location, {
          method: "DELETE",
          headers: owner,
          signal: AbortSignal.timeout(5000),
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await fetch(rulesLocation, {
          method: "PUT",
          headers: owner,
          body: originalRules,
          signal: AbortSignal.timeout(5000),
        })
      ).status,
    ).toBe(200);
  }
});
