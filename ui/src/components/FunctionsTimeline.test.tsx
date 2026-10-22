import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { t } from "../i18n";
import { FunctionsTimeline } from "./FunctionsTimeline";
import type { FunctionsCausality } from "../api/functions";

afterEach(cleanup);
const causal: FunctionsCausality = {
  epoch: 4,
  retained: 1,
  retention: 512,
  evicted: 3,
  resetGaps: 1,
  truncated: true,
  events: [
    {
      eventId: "17",
      epoch: 4,
      function: "consume",
      source: "pubsub",
      eventType: "messagePublished",
      parent: "publish:jobs",
      terminal: false,
      phasesDropped: 1,
      phases: [
        { phase: "registered", attempt: 0, at: null },
        { phase: "retry", attempt: 1, at: "2026-01-01T00:00:00Z" },
        { phase: "future-phase", attempt: 2, at: null },
      ],
    },
  ],
};
it("preserves event selection and keyboard focus across polling and filtering; reports eviction", () => {
  const [snapshot, setSnapshot] = createSignal(causal);
  const ui = render(() => (
    <FunctionsTimeline
      project="demo"
      session="owner"
      causality={snapshot()}
      codebases={[]}
      invocations={[]}
      logs={[]}
      logGaps={true}
      stale={false}
    />
  ));
  const button = ui.getByTestId("event-timeline").querySelector("button")!;
  button.focus();
  fireEvent.click(button);
  expect(button.getAttribute("aria-pressed")).toBe("true");
  expect(ui.getByTestId("timeline-no-outcomes")).toBeTruthy();
  expect(ui.getByTestId("timeline-phases").textContent).toContain("future-phase");
  setSnapshot({ ...causal, events: causal.events.map((e) => ({ ...e, phases: [...e.phases] })) });
  expect(document.activeElement).toBe(button);
  expect(ui.getByTestId("event-timeline").querySelector("button")).toBe(button);
  fireEvent.input(ui.container.querySelector("input")!, { target: { value: "unmatched" } });
  expect(ui.getByTestId("timeline-detail").textContent).toContain("17");
  setSnapshot({ ...causal, events: [] });
  expect(ui.getByTestId("timeline-detail").textContent).toContain(
    t("functions.timelineMissingSelection"),
  );
});
it("filters attempts and keeps unrelated concurrent logs out of the detail", () => {
  const ui = render(() => (
    <FunctionsTimeline
      project="demo"
      session="owner"
      causality={causal}
      codebases={[{ codebase: "a", functions: ["consume"], runnerAlive: true }]}
      invocations={[
        { eventId: "17", function: "consume", attempt: 1, outcome: "failed" },
        { eventId: "17", function: "consume", attempt: 2, outcome: "success" },
      ]}
      logs={[
        {
          project: "demo",
          codebase: "a",
          runner: "r",
          cursor: "0",
          line: "first-attempt",
          invocationId: "17-1",
          function: "consume",
          truncated: false,
        },
        {
          project: "demo",
          codebase: "a",
          runner: "r",
          cursor: "1",
          line: "other-event",
          invocationId: "18-1",
          function: "consume",
          truncated: false,
        },
      ]}
      logGaps={false}
      stale={false}
    />
  ));
  fireEvent.click(ui.getByTestId("event-timeline").querySelector("button")!);
  expect(ui.getByTestId("timeline-logs").textContent).toContain("first-attempt");
  expect(ui.getByTestId("timeline-logs").textContent).not.toContain("other-event");
  const detail = ui.getByTestId("timeline-detail");
  fireEvent.input(detail.querySelector("select")!, { target: { value: "2" } });
  expect(ui.getByTestId("timeline-outcomes").textContent).not.toContain("failed");
  expect(ui.getByTestId("timeline-outcomes").textContent).toContain("success");
  expect(ui.getByTestId("timeline-logs").textContent).not.toContain("first-attempt");
});
