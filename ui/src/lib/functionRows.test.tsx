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
