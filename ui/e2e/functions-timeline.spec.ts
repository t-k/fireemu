import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession, waitForFunctionsRunner } from "./helpers";
import type { FunctionsOverview } from "../src/api/functions";
const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.beforeEach(async ({ request }) => {
  await resetSession(request);
  await waitForFunctionsRunner(request);
});
test("follows a real event with the keyboard and shows only its trusted logs", async ({
  page,
  request,
}, info) => {
  await gotoApp(page, "/functions");
  for (const id of ["timeline-first", "timeline-second"]) {
    await api(request, "PATCH", `${DOCS}/todos/${id}`, { fields: { title: { stringValue: id } } });
  }
  await page.getByTestId("await-idle").click();
  const rows = page
    .getByTestId("event-timeline")
    .locator("tbody tr")
    .filter({ hasText: "mirrorTodo" });
  await expect(rows).toHaveCount(2);
  const first = rows.first().getByRole("button");
  const event = (await first.innerText()).trim();
  await first.focus();
  await page.keyboard.press("Enter");
  await expect(first).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("timeline-phases")).toContainText("registered");
  await expect(page.getByTestId("timeline-phases")).toContainText("completed");
  const snapshot = (await api(request, "GET", "functions")) as FunctionsOverview;
  const matching = snapshot.logRecords!.filter(
    (r) => r.invocationId === `${event}-1` && r.function === "mirrorTodo",
  );
  expect(matching.length).toBeGreaterThan(0);
  const other = snapshot.logRecords!.filter(
    (r) => r.invocationId !== `${event}-1` && r.function === "mirrorTodo",
  );
  for (const log of matching)
    await expect(page.getByTestId("timeline-logs")).toContainText(log.line);
  for (const log of other)
    await expect(page.getByTestId("timeline-logs")).not.toContainText(log.line);
  await page.getByLabel("Filter by event source").selectOption("firestore");
  await expect(first).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("timeline-outcomes").locator("li")).toHaveCount(1);
  await page.getByTestId("timeline-detail").scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("functions-timeline.png"), fullPage: true });
});
test("keeps two interleaved retry histories separate and filters the selected attempt", async ({
  page,
  request,
}) => {
  await gotoApp(page, "/functions");
  for (const id of ["timeline-retry-a", "timeline-retry-b"]) {
    await api(request, "PATCH", `${DOCS}/flaky/${id}`, {
      fields: { value: { integerValue: "1" } },
    });
  }
  await expect(async () => {
    const o = (await api(request, "GET", "functions")) as FunctionsOverview;
    expect(o.status?.retryWaiting).toBe(2);
  }).toPass();
  for (const [seconds, attempt] of [
    [10, 2],
    [20, 3],
  ]) {
    await api(request, "POST", "control/v1/sessions/default/clock:advance", { seconds });
    await expect(async () => {
      const o = (await api(request, "GET", "functions")) as FunctionsOverview;
      expect(o.history.filter((r) => r.function === "flaky" && r.attempt === attempt)).toHaveLength(
        2,
      );
    }).toPass();
  }
  await page.getByTestId("await-idle").click();
  const rows = page.getByTestId("event-timeline").locator("tbody tr").filter({ hasText: "flaky" });
  await expect(rows).toHaveCount(2);
  await rows.first().getByRole("button").click();
  await expect(page.getByTestId("timeline-outcomes").locator("li")).toHaveCount(3);
  await page.getByLabel("Filter by attempt").selectOption("2");
  await expect(page.getByTestId("timeline-outcomes").locator("li")).toHaveCount(1);
  await expect(page.getByTestId("timeline-outcomes")).toContainText("attempt 2 fails on purpose");
  await expect(page.getByTestId("timeline-phases")).not.toContainText("Attempt 3");
});
