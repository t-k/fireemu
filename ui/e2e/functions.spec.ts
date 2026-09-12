import { expect, test } from "@playwright/test";
import { api, gotoApp, resetSession, waitForFunctionsRunner } from "./helpers";

const DOCS = "firestore/v1/projects/demo-app/databases/(default)/documents";

test.describe("Functions", () => {
  test.beforeEach(async ({ request }) => {
    await resetSession(request);
  });

  test("lists the registered functions with their triggers", async ({ page }) => {
    await gotoApp(page, "/functions");
    const table = page.getByTestId("function-table");
    await expect(table).toContainText("mirrorTodo");
    await expect(table).toContainText("Firestore created on todos/{todoId}");
    await expect(table).toContainText("Pub/Sub topic jobs");
    await expect(table).toContainText("Schedule every 5 minutes (Asia/Tokyo)");
    await expect(table).toContainText("HTTP request");
    await expect(table).toContainText("HTTP callable");
  });

  test("runs a schedule now and publishes a Pub/Sub message, showing invocations and logs", async ({
    page,
    request,
  }) => {
    await gotoApp(page, "/functions");
    await page.getByTestId("run-tick").click();
    await page.getByTestId("await-idle").click();
    await expect(page.getByTestId("invocation-table")).toContainText("tick");
    await page.getByTestId("publish-onJob").click();
    const message = page.getByLabel("Message (JSON or text)");
    await message.fill('{"draft": "survives refresh"}');
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(message).toHaveValue('{"draft": "survives refresh"}');
    await page.getByTestId("publish-jobs-send").click();
    await expect(page.getByRole("status").filter({ hasText: "Published 1 message" })).toBeVisible();
    await page.getByTestId("await-idle").click();
    await expect(page.getByTestId("invocation-table")).toContainText("onJob");
    // mirrorTodo logs through firebase-functions/logger: the line reaches the log stream.
    await api(request, "PATCH", `${DOCS}/todos/t1`, {
      fields: { title: { stringValue: "Log me" } },
    });
    await page.getByTestId("await-idle").click();
    await expect(page.getByTestId("invocation-table")).toContainText("mirrorTodo");
    await expect(page.getByTestId("function-logs")).toContainText("mirrorTodo");
  });

  test("invokes an onRequest function and shows its response", async ({ page, request }) => {
    await waitForFunctionsRunner(request);
    await gotoApp(page, "/functions");
    await page.getByTestId("invoke-echo-toggle").click();
    // The onRequest form: a header and a JSON body are echoed back by the function.
    await page.getByLabel("Headers (one per line, Name: value)").fill("x-smoke: hello");
    await page.getByLabel("Body (optional)").fill('{"ping":1}');
    await page.getByTestId("invoke-echo-send").click();
    await expect(page.getByTestId("invoke-result")).toContainText("Status 200");
    const body = page.getByTestId("invoke-response-body");
    await expect(body).toContainText('"method":"POST"');
    await expect(body).toContainText('"header":"hello"');
    await expect(body).toContainText('"ping":1');
  });

  test("invokes a callable and shows its result envelope", async ({ page, request }) => {
    await waitForFunctionsRunner(request);
    await gotoApp(page, "/functions");
    await page.getByTestId("invoke-add-toggle").click();
    await page.getByTestId("invoke-add-data").fill('{"a":2,"b":3}');
    await page.getByTestId("invoke-add-send").click();
    await expect(page.getByTestId("invoke-result")).toContainText("Status 200");
    // A callable's return travels in the `{ "result": ... }` envelope.
    await expect(page.getByTestId("invoke-response-body")).toContainText('"sum":5');
  });

  test("enqueues a task that reaches its onTaskDispatched handler", async ({ page, request }) => {
    await waitForFunctionsRunner(request);
    await gotoApp(page, "/functions");
    await page.getByTestId("enqueue-countJob-toggle").click();
    await page.getByTestId("enqueue-countJob-data").fill('{"id":"ui-task-1","n":42}');
    await page.getByTestId("enqueue-countJob-send").click();
    await expect(
      page.getByRole("status").filter({ hasText: "Enqueued a task onto countJob" }),
    ).toBeVisible();
    // The handler writes tasks/{data.id} with the task's payload; poll until it lands.
    await expect(async () => {
      const doc = (await api(request, "GET", `${DOCS}/tasks/ui-task-1`)) as {
        fields?: { n?: { integerValue?: string } };
      };
      expect(doc.fields?.n?.integerValue).toBe("42");
    }).toPass({ timeout: 10000 });
  });

  test("shows a schedule's next run and advances the clock to it", async ({ page }) => {
    await gotoApp(page, "/functions");
    await expect(page.getByTestId("next-run-tick")).toContainText("Next run");
    await page.getByTestId("advance-to-next-tick").click();
    await expect(page.getByRole("status").filter({ hasText: "Advanced the clock" })).toBeVisible();
    // Advancing to the next run makes it due; the catch-up policy runs it.
    await page.getByTestId("await-idle").click();
    await expect(page.getByTestId("invocation-table")).toContainText("tick");
  });

  test("filters invocations by function and logs by text", async ({ page, request }) => {
    await gotoApp(page, "/functions");
    await page.getByTestId("run-tick").click();
    await page.getByTestId("await-idle").click();
    await api(request, "PATCH", `${DOCS}/todos/t9`, {
      fields: { title: { stringValue: "Filter me" } },
    });
    await page.getByTestId("await-idle").click();
    const invocations = page.getByTestId("invocation-table");
    await expect(invocations).toContainText("tick");
    await expect(invocations).toContainText("mirrorTodo");

    // The invocation filter narrows the table to one function.
    await page.getByTestId("invocation-function-filter").selectOption("tick");
    await expect(invocations).toContainText("tick");
    await expect(invocations).not.toContainText("mirrorTodo");
    await page.getByTestId("invocation-function-filter").selectOption("");
    await expect(invocations).toContainText("mirrorTodo");

    // The log text filter is a live substring; a query that matches nothing says so.
    const logs = page.getByTestId("function-logs");
    await page.getByTestId("log-text-filter").fill("mirrorTodo");
    await expect(logs).toContainText("mirrorTodo");
    await page.getByTestId("log-text-filter").fill("zzz-no-such-line-zzz");
    await expect(logs).toContainText("No log lines match the filter");
  });
});
