import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, waitFor } from "@solidjs/testing-library";
import { okAsync } from "neverthrow";
import Overview from "./Overview";
import { appState } from "../state";
import * as control from "../api/control";

vi.mock("../api/control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/control")>()),
  getRules: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(control.getRules).mockImplementation(() => okAsync({ loaded: true, source: "" }));
  appState.setSessions([{ name: "default", project: "demo-a" }]);
  appState.setSession("default");
});
afterEach(cleanup);

describe("Overview", () => {
  it("shows the project, the services, the rules, the sessions and the SDK environment", async () => {
    const view = render(() => <Overview />);
    await waitFor(() => expect(view.getAllByText("Loaded").length).toBeGreaterThan(0));
    for (const heading of [
      "Project",
      "Services",
      "Security Rules",
      "Sessions",
      "Environment for SDKs",
    ]) {
      expect(view.getAllByText(heading).length, heading).toBeGreaterThan(0);
    }
    expect(view.getByTestId("env-dotenv").textContent).toContain("GOOGLE_CLOUD_PROJECT=demo-a");
    expect(view.getByTestId("env-shell").textContent).toContain(
      "export GOOGLE_CLOUD_PROJECT=demo-a",
    );
  });

  it("carries no product scope table and no compatibility or scope label", async () => {
    const view = render(() => <Overview />);
    await waitFor(() => expect(view.getAllByText("Loaded").length).toBeGreaterThan(0));
    expect(view.queryByTestId("product-scope")).toBeNull();
    expect(view.container.querySelectorAll("[data-testid^='scope-']").length).toBe(0);
    expect(view.container.querySelectorAll("[data-status]").length).toBe(0);
    const text = view.container.textContent ?? "";
    for (const word of [
      "Product scope",
      "supported",
      "deferred",
      "not planned",
      "Realtime Database",
      "Extensions",
    ]) {
      expect(text, word).not.toContain(word);
    }
  });
});
