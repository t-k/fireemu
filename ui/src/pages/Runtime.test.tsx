import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { okAsync } from "neverthrow";
import { FaultPlanPanel } from "./Runtime";
import * as control from "../api/control";

vi.mock("../api/control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/control")>()),
  getFaultPlan: vi.fn(),
}));
beforeEach(() => {
  vi.mocked(control.getFaultPlan).mockReturnValue(
    okAsync({ session: "default", plan: null, fired: [], counters: {} }),
  );
});
afterEach(cleanup);

describe("Fault plan recipes", () => {
  it("fills the draft with a retry plan", () => {
    const ui = render(() => <FaultPlanPanel />);
    fireEvent.change(ui.getByTestId("fault-recipe"), { target: { value: "retryEvent" } });
    fireEvent.input(ui.getByTestId("fault-recipe-function"), { target: { value: "worker" } });
    fireEvent.input(ui.getByTestId("fault-recipe-count"), { target: { value: "2" } });
    fireEvent.click(ui.getByTestId("fault-recipe-fill"));
    expect(
      JSON.parse((ui.container.querySelector("#fault-plan") as HTMLTextAreaElement).value),
    ).toEqual({
      seed: 1,
      rules: [1, 2].map((nth) => ({
        match: { operation: "functions.invoke", function: "worker", nth },
        action: { type: "returnError", code: "UNAVAILABLE" },
      })),
    });
  });
  it("shows invalid input without changing the draft", () => {
    const ui = render(() => <FaultPlanPanel />);
    const draft = ui.container.querySelector("#fault-plan") as HTMLTextAreaElement;
    const before = draft.value;
    fireEvent.click(ui.getByTestId("fault-recipe-fill"));
    expect(ui.getByRole("alert").textContent).toContain("function");
    expect(draft.value).toBe(before);
  });
  it("shows snippets only for a parseable plan", () => {
    const ui = render(() => <FaultPlanPanel />);
    const draft = ui.container.querySelector("#fault-plan") as HTMLTextAreaElement;
    expect(ui.getByTestId("fault-snippet-testing")).toBeTruthy();
    expect(ui.getByTestId("fault-snippet-control")).toBeTruthy();
    fireEvent.input(draft, { target: { value: "{" } });
    expect(ui.queryByTestId("fault-snippet-testing")).toBeNull();
    fireEvent.input(draft, { target: { value: '{"seed":1,"rules":[]}' } });
    expect(ui.getByTestId("fault-snippet-control")).toBeTruthy();
  });
});
