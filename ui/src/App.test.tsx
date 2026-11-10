import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render } from "@solidjs/testing-library";
import { Router } from "@solidjs/router";
import { okAsync } from "neverthrow";
import { App } from "./App";
import { appState } from "./state";
import { routes } from "./routes";
import * as control from "./api/control";

vi.mock("./api/control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./api/control")>()),
  sessionInfo: vi.fn(),
  listSessions: vi.fn(),
}));

beforeEach(() => {
  vi.mocked(control.sessionInfo).mockImplementation(() =>
    okAsync({
      session: "default",
      edition: "standard",
      requireDemoPrefix: true,
      clock: { clock: "2026-08-29T12:00:00Z", backwardsSets: 0 },
    }),
  );
  vi.mocked(control.listSessions).mockImplementation(() =>
    okAsync({ sessions: [{ name: "default", project: "demo-a" }] }),
  );
  appState.setSessions([{ name: "default", project: "demo-a" }]);
  appState.setSession("default");
});
afterEach(cleanup);

it("links the Hosting page in the products navigation, after Functions", () => {
  const ui = render(() => <Router root={App}>{routes}</Router>);
  const links = [...ui.getByLabelText("Emulator products").querySelectorAll("a")];
  const names = links.map((a) => a.textContent);
  expect(names.indexOf("Hosting")).toBe(names.indexOf("Functions") + 1);
  expect(links[names.indexOf("Hosting")]!.getAttribute("href")).toBe("/hosting");
});

it("says in the header whether the clock is frozen or follows real time", () => {
  appState.setConfig({ ...appState.config(), clockMode: "frozen" });
  const frozen = render(() => <Router root={App}>{routes}</Router>);
  expect(frozen.getByTestId("context-bar").textContent).toContain("frozen");
  cleanup();
  appState.setConfig({ ...appState.config(), clockMode: "realtime" });
  const live = render(() => <Router root={App}>{routes}</Router>);
  expect(live.getByTestId("context-bar").textContent).toContain("real time");
  expect(live.getByTestId("context-bar").textContent).not.toContain("frozen");
});
