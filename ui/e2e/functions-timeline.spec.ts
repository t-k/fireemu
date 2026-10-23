import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession, waitForFunctionsRunner } from "./helpers";
import type { FunctionsOverview } from "../src/api/functions";
const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

const currentEventIds = (overview: FunctionsOverview, name: string): string[] => {
  const causality = overview.status?.causality;
  expect(causality).toBeDefined();
  return causality!.events
    .filter((event) => event.function === name && event.epoch === causality!.epoch)
    .map((event) => event.eventId);
};

test.beforeEach(async ({ request }) => {
  await resetSession(request);
  await waitForFunctionsRunner(request);
});
test("follows a real event with the keyboard and shows only its trusted logs", async ({
  page,
  request,
}, info) => {
  // Reset preserves invocation history: make that precondition independent of suite order.
  await api(request, "PATCH", `${DOCS}/todos/timeline-retained`, {
    fields: { title: { stringValue: "retained from the previous epoch" } },
  });
  const settled = (await api(request, "POST", "control/v1/sessions/default:awaitIdle", {
    timeoutSeconds: 30,
  })) as { idle: boolean };
  expect(settled.idle).toBe(true);
  const retained = (await api(request, "GET", "functions")) as FunctionsOverview;
  const retainedIds = currentEventIds(retained, "mirrorTodo");
  expect(retainedIds).toHaveLength(1);
  await resetSession(request);
  await waitForFunctionsRunner(request);
  const reset = (await api(request, "GET", "functions")) as FunctionsOverview;
  expect(reset.history.some((record) => retainedIds.includes(record.eventId))).toBe(true);

  await gotoApp(page, "/functions");
  for (const id of ["timeline-first", "timeline-second"]) {
    await api(request, "PATCH", `${DOCS}/todos/${id}`, { fields: { title: { stringValue: id } } });
  }
  await page.getByTestId("await-idle").click();
  const completed = (await api(request, "GET", "functions")) as FunctionsOverview;
  const events = currentEventIds(completed, "mirrorTodo");
  expect(events).toHaveLength(2);
  expect(events.some((event) => retainedIds.includes(event))).toBe(false);
  const timeline = page.getByTestId("event-timeline");
  await expect(
    timeline.getByRole("button", {
      name: `Select event ${retainedIds[0]!} / mirrorTodo`,
      exact: true,
    }),
  ).toHaveCount(1);
  for (const event of events)
    await expect(
      timeline.getByRole("button", { name: `Select event ${event} / mirrorTodo`, exact: true }),
    ).toHaveCount(1);
  const event = events[0]!;
  const first = timeline.getByRole("button", {
    name: `Select event ${event} / mirrorTodo`,
    exact: true,
  });
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
  expect(other.length).toBeGreaterThan(0);
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
  const pending = (await api(request, "GET", "functions")) as FunctionsOverview;
  const events = currentEventIds(pending, "flaky");
  expect(events).toHaveLength(2);
  for (const [seconds, attempt] of [
    [10, 2],
    [20, 3],
  ]) {
    await api(request, "POST", "control/v1/sessions/default/clock:advance", { seconds });
    await expect(async () => {
      const o = (await api(request, "GET", "functions")) as FunctionsOverview;
      expect(
        o.history.filter(
          (r) => events.includes(r.eventId) && r.function === "flaky" && r.attempt === attempt,
        ),
      ).toHaveLength(2);
    }).toPass();
  }
  await page.getByTestId("await-idle").click();
  const timeline = page.getByTestId("event-timeline");
  for (const event of events)
    await expect(
      timeline.getByRole("button", { name: `Select event ${event} / flaky`, exact: true }),
    ).toHaveCount(1);
  await timeline
    .getByRole("button", { name: `Select event ${events[0]!} / flaky`, exact: true })
    .click();
  await expect(page.getByTestId("timeline-outcomes").locator("li")).toHaveCount(3);
  await page.getByLabel("Filter by attempt").selectOption("2");
  await expect(page.getByTestId("timeline-outcomes").locator("li")).toHaveCount(1);
  await expect(page.getByTestId("timeline-outcomes")).toContainText("attempt 2 fails on purpose");
  await expect(page.getByTestId("timeline-phases")).not.toContainText("Attempt 3");
});
