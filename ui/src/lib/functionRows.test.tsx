import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { appState } from "../state";
import { FunctionRows } from "../pages/Functions";
import type { FunctionInfo } from "../api/functions";

afterEach(cleanup);
it("preserves a publish draft and focus on refresh but resets it when its target changes", () => {
  appState.setSession("default");
  const initial: FunctionInfo = {
    name: "consume",
    region: "us-central1",
    entryPoint: "consume",
    trigger: { kind: "pubsub", topic: "events" },
    timeoutSeconds: 60,
    retry: false,
    concurrency: 1,
  };
  const [functions, setFunctions] = createSignal([initial]);
  const [project, setProject] = createSignal("demo-a");
  const ui = render(() => (
    <table>
      <tbody>
        <FunctionRows
          functions={functions()}
          project={project()}
          onNotice={() => {}}
          onError={() => {}}
        />
      </tbody>
    </table>
  ));
  fireEvent.click(ui.getByTestId("publish-consume"));
  const message = ui.getByLabelText("Message (JSON or text)") as HTMLTextAreaElement;
  message.focus();
  fireEvent.input(message, { target: { value: "unsaved message" } });
  setFunctions([{ ...initial, timeoutSeconds: 90 }]);
  expect(ui.getByLabelText("Message (JSON or text)")).toBe(message);
  expect(message.value).toBe("unsaved message");
  expect(document.activeElement).toBe(message);
  expect(ui.container.textContent).toContain("90s");
  setFunctions([{ ...initial, trigger: { kind: "pubsub", topic: "other" } }]);
  expect(ui.queryByTestId("publish-events")).toBeNull();
  fireEvent.click(ui.getByTestId("publish-consume"));
  expect(ui.getByTestId("publish-other")).toBeTruthy();
  appState.setSession("other");
  expect(ui.queryByTestId("publish-other")).toBeNull();
  fireEvent.click(ui.getByTestId("publish-consume"));
  setProject("demo-b");
  expect(ui.queryByTestId("publish-other")).toBeNull();
  setFunctions([]);
  expect(ui.queryByTestId("function-row-consume")).toBeNull();
});

it.each([
  [{ kind: "tasks", maxAttempts: 3, maxConcurrentDispatches: 5 }, "Task queue"],
  [
    {
      kind: "eventarc",
      event: "custom.done",
      channel: "projects/demo/locations/us/channels/custom",
      filters: { region: "emea" },
    },
    "emea",
  ],
  [
    {
      kind: "eventarc",
      event: "google.firebase.firebasealerts.alerts.v1.published",
      channel: null,
      filters: {},
    },
    "firebasealerts",
  ],
  [
    {
      kind: "blockingAuth",
      event: "beforeCreate",
      tokenPolicy: { accessToken: false, idToken: false, refreshToken: false },
    },
    "beforeCreate",
  ],
  [{ kind: "future", target: "<script>bad()</script>" }, "Unknown trigger"],
])("renders trigger metadata and safe unknown details for %j", (trigger, expected) => {
  const ui = render(() => (
    <table>
      <tbody>
        <FunctionRows
          functions={[
            {
              name: "test",
              region: "us-central1",
              entryPoint: "test",
              trigger: trigger as FunctionInfo["trigger"],
              timeoutSeconds: 60,
              retry: false,
              concurrency: 1,
            },
          ]}
          project="demo"
          onNotice={() => {}}
          onError={() => {}}
        />
      </tbody>
    </table>
  ));
  expect(ui.getByTestId("function-row-test").textContent).toContain(expected);
  if (trigger.kind === "future") {
    expect(ui.container.querySelector("details")?.textContent).toContain("<script>bad()</script>");
    expect(ui.container.querySelector("script")).toBeNull();
  }
});

it("disables every action when the functions do not belong to the selected session", () => {
  const functions: FunctionInfo[] = [
    {
      name: "echo",
      region: "us-central1",
      entryPoint: "echo",
      trigger: { kind: "http", callable: false },
      timeoutSeconds: 60,
      retry: false,
      concurrency: 1,
    },
    {
      name: "countJob",
      region: "us-central1",
      entryPoint: "countJob",
      trigger: { kind: "tasks", maxAttempts: 3, maxConcurrentDispatches: 1 },
      timeoutSeconds: 60,
      retry: false,
      concurrency: 1,
    },
    {
      name: "tick",
      region: "us-central1",
      entryPoint: "tick",
      trigger: { kind: "schedule", schedule: "every 5 minutes", timeZone: null },
      timeoutSeconds: 60,
      retry: false,
      concurrency: 1,
      nextRun: "2026-08-29T12:05:00Z",
    },
  ];
  const [active, setActive] = createSignal(false);
  const ui = render(() => (
    <table>
      <tbody>
        <FunctionRows
          functions={functions}
          project="demo"
          functionsAddr="127.0.0.1:5001"
          active={active()}
          onNotice={() => {}}
          onError={() => {}}
        />
      </tbody>
    </table>
  ));
  const button = (id: string) => ui.getByTestId(id) as HTMLButtonElement;
  // A session that does not own the functions: no invoke, enqueue, run, or advance is possible,
  // so switching the top bar can never fire an action against the functions' project.
  for (const id of [
    "invoke-echo-toggle",
    "enqueue-countJob-toggle",
    "run-tick",
    "advance-to-next-tick",
  ]) {
    expect(button(id).disabled).toBe(true);
  }
  // Selecting the functions' own session re-enables them.
  setActive(true);
  for (const id of [
    "invoke-echo-toggle",
    "enqueue-countJob-toggle",
    "run-tick",
    "advance-to-next-tick",
  ]) {
    expect(button(id).disabled).toBe(false);
  }
});
