import { describe, expect, it } from "vitest";
import { fireEvent, render } from "@solidjs/testing-library";
import {
  MemoryRouter,
  Route,
  useNavigate,
  type MemoryHistory,
  createMemoryHistory,
} from "@solidjs/router";
import { createSignal, type Component } from "solid-js";
import { createLeaveGuard, LeavePrompt } from "./unsaved";

/** A page with a draft flag, a guarded in-page action and a route link away. */
const harness = () => {
  const [dirty, setDirty] = createSignal(false);
  const [acted, setActed] = createSignal(0);
  const Page: Component = () => {
    const guard = createLeaveGuard(dirty);
    const navigate = useNavigate();
    return (
      <div>
        <LeavePrompt guard={guard} subject="The draft" />
        <button data-testid="act" onClick={() => guard.request(() => setActed((n) => n + 1))}>
          act
        </button>
        <button data-testid="leave" onClick={() => navigate("/away")}>
          leave
        </button>
        <button data-testid="discard-direct" onClick={guard.discard}>
          discard
        </button>
      </div>
    );
  };
  const history: MemoryHistory = createMemoryHistory();
  const ui = render(() => (
    <MemoryRouter history={history}>
      <Route path="/" component={Page} />
      <Route path="/away" component={() => <p data-testid="away">away</p>} />
    </MemoryRouter>
  ));
  return { ...ui, setDirty, acted, history };
};

describe("createLeaveGuard", () => {
  it("runs a request at once while nothing is unsaved", () => {
    const h = harness();
    fireEvent.click(h.getByTestId("act"));
    expect(h.acted()).toBe(1);
    expect(h.queryByTestId("unsaved-prompt")).toBeNull();
    h.unmount();
  });

  it("parks a request behind the prompt while dirty; keep forgets it, discard runs it", () => {
    const h = harness();
    h.setDirty(true);
    fireEvent.click(h.getByTestId("act"));
    expect(h.acted()).toBe(0);
    expect(h.getByTestId("unsaved-prompt").textContent).toContain("The draft");
    expect(h.getByTestId("unsaved-discard").textContent).toBe("Discard changes");
    expect(h.getByTestId("unsaved-keep").textContent).toBe("Keep editing");
    fireEvent.click(h.getByTestId("unsaved-keep"));
    expect(h.queryByTestId("unsaved-prompt")).toBeNull();
    expect(h.acted()).toBe(0);
    fireEvent.click(h.getByTestId("act"));
    fireEvent.click(h.getByTestId("unsaved-discard"));
    expect(h.acted()).toBe(1);
    expect(h.queryByTestId("unsaved-prompt")).toBeNull();
    h.unmount();
  });

  it("holds a route change while dirty and retries it on discard", async () => {
    const h = harness();
    h.setDirty(true);
    fireEvent.click(h.getByTestId("leave"));
    await new Promise((r) => setTimeout(r, 0));
    expect(h.queryByTestId("away")).toBeNull();
    expect(h.getByTestId("unsaved-prompt")).toBeTruthy();
    fireEvent.click(h.getByTestId("unsaved-discard"));
    await new Promise((r) => setTimeout(r, 0));
    expect(h.getByTestId("away")).toBeTruthy();
    h.unmount();
  });

  it("discarding with nothing parked is harmless", () => {
    const h = harness();
    fireEvent.click(h.getByTestId("discard-direct"));
    expect(h.acted()).toBe(0);
    h.unmount();
  });

  it("lets a route change through while clean", async () => {
    const h = harness();
    fireEvent.click(h.getByTestId("leave"));
    await new Promise((r) => setTimeout(r, 0));
    expect(h.getByTestId("away")).toBeTruthy();
    h.unmount();
  });

  it("asks the browser to confirm an unload only while dirty, and stops after unmount", () => {
    const h = harness();
    const fire = () => {
      const event = new Event("beforeunload", { cancelable: true });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    };
    expect(fire()).toBe(false);
    h.setDirty(true);
    expect(fire()).toBe(true);
    h.unmount();
    expect(fire()).toBe(false);
  });
});
