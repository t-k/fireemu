import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, waitFor, cleanup } from "@solidjs/testing-library";
import { MemoryRouter, Route } from "@solidjs/router";
import { okAsync, errAsync, ResultAsync } from "neverthrow";
import Rules from "./Rules";
import Overview from "./Overview";
import { appState } from "../state";
import * as api from "../api/control";
vi.mock("../api/control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/control")>()),
  getRules: vi.fn(),
  putRules: vi.fn(),
  dropRules: vi.fn(),
  rulesRequests: vi.fn(),
  ruleCoverage: vi.fn(),
}));
const source = "// 日😀\r\nallow get: if false;";
const start = new TextEncoder().encode(source.slice(0, source.indexOf("false"))).length;
const trace = (generation = "1", recorded = source) => ({
  capacity: 100,
  loaded: true,
  generation,
  source: recorded,
  requests: [
    {
      sequence: 1,
      service: "firestore",
      method: "get",
      path: "notes/a",
      uid: null,
      allowed: false,
      reason: "evaluation error",
      expressions: [
        {
          line: 2,
          column: 15,
          currentOffset: start,
          endOffset: start + 5,
          values: [{ value: { kind: "bool" as const, bool: false }, count: 1 }],
        },
        { line: 2, column: 1, currentOffset: 0, endOffset: 0, values: [] },
      ],
    },
  ],
});
const coverage = {
  rules: { files: [{ name: "firestore.rules", content: source }] },
  report: [
    {
      sourcePosition: { line: 2, column: 15, currentOffset: start, endOffset: start + 5 },
      values: [],
    },
  ],
};
const mount = (component = Rules) =>
  render(() => (
    <MemoryRouter>
      <Route path="/" component={component} />
    </MemoryRouter>
  ));
afterEach(cleanup);
beforeEach(() => {
  vi.resetAllMocks();
  appState.setSessions([
    { name: "default", project: "demo-a" },
    { name: "other", project: "demo-a" },
  ]);
  appState.setSession("default");
  vi.mocked(api.getRules).mockImplementation(() =>
    okAsync({ loaded: true, source: "current loaded source" }),
  );
  vi.mocked(api.rulesRequests).mockImplementation(() => okAsync(trace()));
  vi.mocked(api.ruleCoverage).mockImplementation(() => okAsync(coverage));
  vi.mocked(api.putRules).mockImplementation(() => okAsync({}));
  vi.mocked(api.dropRules).mockImplementation(() => okAsync({}));
});

describe("rules diagnostic state and provenance", () => {
  for (const status of [401, 500, 0])
    it(`shows ${status} failure rather than empty/unconfigured`, async () => {
      const fail = () => errAsync({ status, message: "injected failure" });
      vi.mocked(api.getRules).mockImplementation(fail);
      vi.mocked(api.rulesRequests).mockImplementation(fail);
      vi.mocked(api.ruleCoverage).mockImplementation(fail);
      const h = mount();
      await waitFor(() => expect(h.getAllByTestId("fetch-error").length).toBe(4));
      expect(h.queryByTestId("rules-requests")).toBeNull();
      expect(h.queryByText("No request has been decided against the loaded rules yet.")).toBeNull();
      expect(h.queryByText("Not loaded: every request is allowed")).toBeNull();
    });
  it("preserves a draft and successful source on refresh failure and recovers", async () => {
    const h = mount();
    const editor = await h.findByLabelText("Currently loaded source", {
      selector: "#rules-firestore",
    });
    fireEvent.input(editor, { target: { value: "unsaved draft" } });
    vi.mocked(api.getRules).mockImplementation(() =>
      errAsync({ status: 500, message: "refresh failed" }),
    );
    fireEvent.click(h.getByTestId("rules-firestore-refresh"));
    await waitFor(() => expect(h.getAllByTestId("fetch-stale").length).toBe(1));
    expect((editor as HTMLTextAreaElement).value).toBe("unsaved draft");
    vi.mocked(api.getRules).mockImplementation(() =>
      okAsync({ loaded: true, source: "new loaded" }),
    );
    fireEvent.click(h.getAllByText("Retry")[0]!);
    await waitFor(() => expect(h.queryByTestId("fetch-stale")).toBeNull());
    expect((editor as HTMLTextAreaElement).value).toBe("unsaved draft");
  });
  it("keeps a newer draft after a save resolves and ignores old-scope save completion", async () => {
    let resolve!: () => void;
    vi.mocked(api.putRules).mockImplementation(() =>
      ResultAsync.fromSafePromise(new Promise<null>((r) => (resolve = () => r(null)))),
    );
    const h = mount();
    const editor = await h.findByLabelText("Currently loaded source", {
      selector: "#rules-firestore",
    });
    fireEvent.input(editor, { target: { value: "submitted" } });
    fireEvent.click(h.getByTestId("rules-firestore-save"));
    fireEvent.input(editor, { target: { value: "newer draft" } });
    resolve();
    await waitFor(() => expect(h.getByText("Rules replaced")).toBeTruthy());
    expect((editor as HTMLTextAreaElement).value).toBe("newer draft");
    fireEvent.click(h.getByTestId("rules-firestore-save"));
    appState.setSession("other");
    await waitFor(() =>
      expect(
        (
          h.getByLabelText("Currently loaded source", {
            selector: "#rules-firestore",
          }) as HTMLTextAreaElement
        ).value,
      ).toBe("current loaded source"),
    );
    resolve();
    await Promise.resolve();
    expect(h.queryByText("Rules replaced")).toBeNull();
  });
  it("navigates the recorded source, not a draft; separates request denial from expression false/unreached", async () => {
    const h = mount();
    await h.findByTestId("rules-requests");
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    fireEvent.click(h.getByTestId("rules-request-expression-0"));
    expect(h.getByTestId("rules-request-highlight").textContent).toBe("false");
    expect(h.getByTestId("rules-request-source").textContent).toBe(source);
    expect(h.getByTestId("rules-request-expressions").textContent).toContain("false");
    expect(h.getByTestId("rules-request-expressions").textContent).toContain("not reached");
    expect(h.getByText(/evaluation error/)).toBeTruthy();
    vi.mocked(api.rulesRequests).mockImplementation(() =>
      okAsync(trace("2", "same line different source")),
    );
    fireEvent.click(h.getByTestId("rules-requests-refresh"));
    await waitFor(() => expect(h.queryByTestId("rules-request-expressions")).toBeNull());
  });
  it("disables navigation for legacy responses and Storage rows instead of guessing current source", async () => {
    const value = trace();
    delete (value as Partial<typeof value>).generation;
    vi.mocked(api.rulesRequests).mockImplementation(() => okAsync(value));
    const h = mount();
    await h.findByTestId("rules-requests");
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    expect((h.getByTestId("rules-request-expression-0") as HTMLButtonElement).disabled).toBe(true);
    expect(
      h.getByText("Recorded source identity is unavailable; source navigation is disabled."),
    ).toBeTruthy();
  });
  it("uses embedded coverage source and clears selection on a same-project session switch", async () => {
    const h = mount();
    await h.findByTestId("rules-coverage");
    fireEvent.click(h.getByTestId("rules-coverage-expression-0"));
    expect(h.getByTestId("rules-coverage-highlight").textContent).toBe("false");
    expect(h.getByTestId("rules-coverage-source").textContent).toBe(source);
    appState.setSession("other");
    await waitFor(() => expect(h.queryByTestId("rules-coverage-highlight")).toBeNull());
  });
  it("Overview reports failed rules reads as errors rather than no", async () => {
    vi.mocked(api.getRules).mockImplementation(() =>
      errAsync({ status: 401, message: "not authorized" }),
    );
    const h = mount(Overview);
    await waitFor(() => expect(h.getAllByTestId("fetch-error").length).toBe(2));
  });
  it("distinguishes loaded-empty requests and coverage from unconfigured responses", async () => {
    vi.mocked(api.rulesRequests).mockImplementation(() => okAsync({ ...trace(), requests: [] }));
    vi.mocked(api.ruleCoverage).mockImplementation(() => okAsync({ ...coverage, report: [] }));
    const h = mount();
    await waitFor(() =>
      expect(h.getByText("No request has been decided against the loaded rules yet.")).toBeTruthy(),
    );
    expect(
      h.getByText("No coverage yet: load a ruleset and let a request evaluate against it."),
    ).toBeTruthy();
    vi.mocked(api.rulesRequests).mockImplementation(() =>
      okAsync({ capacity: 100, loaded: false, source: null, generation: "3", requests: [] }),
    );
    vi.mocked(api.ruleCoverage).mockImplementation(() =>
      okAsync({ rules: { files: [] }, report: [] }),
    );
    fireEvent.click(h.getByTestId("rules-requests-refresh"));
    fireEvent.click(h.getByTestId("rules-coverage-refresh"));
    await waitFor(() =>
      expect(h.getByText("No rules source is configured in this coverage report.")).toBeTruthy(),
    );
    expect(h.queryByText("No request has been decided against the loaded rules yet.")).toBeNull();
    expect(h.getByText("Not loaded: every request is allowed")).toBeTruthy();
  });
  it("retains request/coverage source and selections on refresh failure, then retries", async () => {
    const h = mount();
    await h.findByTestId("rules-requests");
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    fireEvent.click(h.getByTestId("rules-request-expression-0"));
    fireEvent.click(h.getByTestId("rules-coverage-expression-0"));
    vi.mocked(api.rulesRequests).mockImplementation(() =>
      errAsync({ status: 500, message: "trace offline" }),
    );
    vi.mocked(api.ruleCoverage).mockImplementation(() =>
      errAsync({ status: 0, message: "coverage disconnected" }),
    );
    fireEvent.click(h.getByTestId("rules-requests-refresh"));
    fireEvent.click(h.getByTestId("rules-coverage-refresh"));
    await waitFor(() => expect(h.getAllByTestId("fetch-stale").length).toBe(2));
    expect(h.getByTestId("rules-request-highlight").textContent).toBe("false");
    expect(h.getByTestId("rules-coverage-highlight").textContent).toBe("false");
    vi.mocked(api.rulesRequests).mockImplementation(() => okAsync(trace()));
    vi.mocked(api.ruleCoverage).mockImplementation(() => okAsync(coverage));
    for (const b of h.getAllByText("Retry")) fireEvent.click(b);
    await waitFor(() => expect(h.queryByTestId("fetch-stale")).toBeNull());
    await waitFor(() =>
      expect(h.queryByText("Refreshing; showing the last successful snapshot.")).toBeNull(),
    );
    expect(h.getByTestId("rules-request-expression-0").getAttribute("aria-pressed")).toBe("true");
  });
  it("does not reuse a selected sequence across identical-source reload generations", async () => {
    const h = mount();
    await h.findByTestId("rules-requests");
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    vi.mocked(api.rulesRequests).mockImplementation(() => okAsync(trace("2")));
    fireEvent.click(h.getByTestId("rules-requests-refresh"));
    await waitFor(() => expect(h.queryByTestId("rules-request-expressions")).toBeNull());
  });
  it("rejects Storage trace source associations and multi-file coverage ambiguity", async () => {
    const value = trace();
    value.requests[0]!.service = "storage";
    vi.mocked(api.rulesRequests).mockImplementation(() => okAsync(value));
    vi.mocked(api.ruleCoverage).mockImplementation(() =>
      okAsync({
        ...coverage,
        rules: { files: [...coverage.rules.files, { name: "other", content: source }] },
      }),
    );
    const h = mount();
    await h.findByTestId("rules-requests");
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    expect((h.getByTestId("rules-request-expression-0") as HTMLButtonElement).disabled).toBe(true);
    expect((h.getByTestId("rules-coverage-expression-0") as HTMLButtonElement).disabled).toBe(true);
    expect(h.queryByTestId("rules-request-source")).toBeNull();
    expect(h.queryByTestId("rules-coverage-source")).toBeNull();
  });
  it("drops draft and diagnostics on project replacement even if session name is unchanged", async () => {
    const h = mount();
    const editor = await h.findByLabelText("Currently loaded source", {
      selector: "#rules-firestore",
    });
    fireEvent.input(editor, { target: { value: "old project draft" } });
    fireEvent.click(h.getByTestId("rules-request-trace-1"));
    appState.setSessions([{ name: "default", project: "demo-b" }]);
    await waitFor(() =>
      expect(
        (
          h.getByLabelText("Currently loaded source", {
            selector: "#rules-firestore",
          }) as HTMLTextAreaElement
        ).value,
      ).toBe("current loaded source"),
    );
    expect(h.queryByTestId("rules-request-expressions")).toBeNull();
  });
  it("preserves a newer draft while a confirmed drop finishes", async () => {
    let resolve!: () => void;
    vi.mocked(api.dropRules).mockImplementation(() =>
      ResultAsync.fromSafePromise(new Promise<null>((r) => (resolve = () => r(null)))),
    );
    const h = mount();
    const editor = await h.findByLabelText("Currently loaded source", {
      selector: "#rules-firestore",
    });
    fireEvent.click(h.getByTestId("rules-firestore-drop"));
    fireEvent.click(h.getByTestId("rules-firestore-drop-confirm"));
    expect(api.dropRules).toHaveBeenCalledWith("firestore");
    fireEvent.input(editor, { target: { value: "draft entered during drop" } });
    vi.mocked(api.getRules).mockImplementation((which) =>
      okAsync({ loaded: which !== "firestore", source: which === "firestore" ? "" : "storage" }),
    );
    resolve();
    await waitFor(() => expect(h.getByText("Not loaded: every request is allowed")).toBeTruthy());
    expect((editor as HTMLTextAreaElement).value).toBe("draft entered during drop");
  });

  it("retains unsaved content when save or confirmed drop fails", async () => {
    const h = mount();
    const editor = await h.findByLabelText("Currently loaded source", {
      selector: "#rules-firestore",
    });
    fireEvent.input(editor, { target: { value: "unsaved invalid source" } });
    vi.mocked(api.putRules).mockImplementation(() =>
      errAsync({ status: 400, message: "rules do not parse" }),
    );
    fireEvent.click(h.getByTestId("rules-firestore-save"));
    await waitFor(() => expect(h.getByRole("alert").textContent).toContain("rules do not parse"));
    expect((editor as HTMLTextAreaElement).value).toBe("unsaved invalid source");
    vi.mocked(api.dropRules).mockImplementation(() =>
      errAsync({ status: 500, message: "drop failed" }),
    );
    fireEvent.click(h.getByTestId("rules-firestore-drop"));
    fireEvent.click(h.getByTestId("rules-firestore-drop-confirm"));
    await waitFor(() => expect(h.getByRole("alert").textContent).toContain("drop failed"));
    expect((editor as HTMLTextAreaElement).value).toBe("unsaved invalid source");
  });
  it("never reuses an old coverage selection for another embedded source at the same position", async () => {
    const h = mount();
    await h.findByTestId("rules-coverage");
    fireEvent.click(h.getByTestId("rules-coverage-expression-0"));
    expect(h.getByTestId("rules-coverage-highlight").textContent).toBe("false");
    const nextSource = source.replace("false", "true ");
    vi.mocked(api.ruleCoverage).mockImplementation(() =>
      okAsync({
        rules: { files: [{ name: "reloaded.rules", content: nextSource }] },
        report: coverage.report,
      }),
    );
    fireEvent.click(h.getByTestId("rules-coverage-refresh"));
    await waitFor(() =>
      expect(h.getByTestId("rules-coverage-source").textContent).toBe(nextSource),
    );
    expect(h.queryByTestId("rules-coverage-highlight")).toBeNull();
  });
});
