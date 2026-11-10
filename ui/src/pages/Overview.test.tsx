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
  it("lists the Host names the emulators answer: the built-in names, the configured ones and the flag", async () => {
    appState.setConfig({
      ...appState.config(),
      clockMode: "realtime",
      hosts: {
        allowed: ["ci.example", ".svc.cluster.local"],
        allowNonLoopbackHosts: true,
        defaultNames: ["localhost"],
        defaultSuffixes: [".localhost", ".internal"],
      },
    });
    const view = render(() => <Overview />);
    await waitFor(() => expect(view.getAllByText("Loaded").length).toBeGreaterThan(0));
    const hosts = view.getByTestId("host-names").textContent ?? "";
    for (const name of [
      "ci.example",
      ".svc.cluster.local",
      "localhost",
      ".localhost",
      ".internal",
    ]) {
      expect(hosts, name).toContain(name);
    }
    expect(hosts).toContain("IP address");
    expect(view.getByTestId("host-names-single-label").textContent).toBe("yes");
    expect(view.queryByTestId("host-names-open")).toBeNull();
  });

  it("warns when every Host is answered and says so when nothing was added", async () => {
    appState.setConfig({
      ...appState.config(),
      hosts: {
        allowed: ["*"],
        allowNonLoopbackHosts: false,
        defaultNames: ["localhost"],
        defaultSuffixes: [],
      },
    });
    const open = render(() => <Overview />);
    await waitFor(() => expect(open.getAllByText("Loaded").length).toBeGreaterThan(0));
    expect(open.getByTestId("host-names-open")).toBeTruthy();
    expect(open.getByTestId("host-names-single-label").textContent).toBe("no");
    cleanup();
    appState.setConfig({
      ...appState.config(),
      hosts: {
        allowed: [],
        allowNonLoopbackHosts: false,
        defaultNames: ["localhost"],
        defaultSuffixes: [],
      },
    });
    const none = render(() => <Overview />);
    await waitFor(() => expect(none.getAllByText("Loaded").length).toBeGreaterThan(0));
    expect(none.queryByTestId("host-names-open")).toBeNull();
    expect(none.getByTestId("host-names-none").textContent).toContain("none");
  });

  it("says whether the virtual clock stands still or follows real time", async () => {
    appState.setConfig({ ...appState.config(), clockMode: "frozen" });
    const frozen = render(() => <Overview />);
    await waitFor(() => expect(frozen.getAllByText("Loaded").length).toBeGreaterThan(0));
    expect(frozen.getByTestId("overview-clock-mode").textContent).toContain("frozen");
    cleanup();
    appState.setConfig({ ...appState.config(), clockMode: "realtime" });
    const live = render(() => <Overview />);
    await waitFor(() => expect(live.getAllByText("Loaded").length).toBeGreaterThan(0));
    expect(live.getByTestId("overview-clock-mode").textContent).toContain("real time");
  });

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
