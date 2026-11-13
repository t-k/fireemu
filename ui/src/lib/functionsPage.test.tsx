import { Router, Route } from "@solidjs/router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { errAsync, okAsync, ResultAsync } from "neverthrow";
import Functions from "../pages/Functions";
import { appState } from "../state";
import type { FunctionsOverview, LogEvent } from "../api/functions";
import { t } from "../i18n";
const mocks = vi.hoisted(() => ({
  overview: vi.fn(),
  selectedStatus: vi.fn(),
  idle: vi.fn(),
  stop: vi.fn(),
  filter: vi.fn(),
  event: undefined as ((event: LogEvent) => void) | undefined,
  close: undefined as (() => void) | undefined,
}));
vi.mock("../api/functions", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/functions")>()),
  functionsOverview: () => mocks.overview(),
  subscribeLogs: (callback: (event: LogEvent) => void, close: () => void) => {
    mocks.close = close;
    mocks.event = callback;
    return mocks.stop;
  },
}));
vi.mock("../api/control", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/control")>()),
  functionsStatus: mocks.selectedStatus,
  awaitIdle: mocks.idle,
}));
vi.mock("../lib/logFilter", async (importOriginal) => {
  const original = await importOriginal<typeof import("../lib/logFilter")>();
  return {
    ...original,
    matchesLog: (...args: Parameters<typeof original.matchesLog>) => {
      mocks.filter();
      return original.matchesLog(...args);
    },
  };
});
const owner: FunctionsOverview = {
  configured: true,
  project: "demo-owner",
  session: "owner",
  functions: [],
  history: [],
  deadLetters: [],
  status: {
    pending: 0,
    running: 0,
    retryWaiting: 0,
    succeeded: 11,
    deadLettered: 0,
    runnerAlive: true,
    epoch: 1,
    functions: [],
    catchUpPending: false,
    overlapRejected: 0,
    causality: {
      epoch: 1,
      retained: 0,
      retention: 512,
      evicted: 0,
      resetGaps: 0,
      truncated: false,
      events: [],
    },
  },
};
beforeEach(() => {
  history.replaceState(null, "", "/functions");
  sessionStorage.clear();
  mocks.overview.mockReset();
  mocks.selectedStatus.mockReset();
  mocks.idle.mockReset();
  mocks.idle.mockReturnValue(okAsync({ idle: true }));
  mocks.stop.mockReset();
  mocks.overview.mockReturnValue(okAsync(owner));
  appState.setSessions([
    { name: "owner", project: "demo-owner" },
    { name: "other", project: "demo-other" },
  ]);
  appState.setSession("other");
});
afterEach(cleanup);
it("shows owner status with another session selected and rejects wrong-owner stream records", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() =>
    expect(ui.getByTestId("timeline-owner").textContent).toContain("owner / demo-owner"),
  );
  expect(ui.getByTestId("succeeded-count").textContent).toBe("11");
  expect(mocks.selectedStatus).not.toHaveBeenCalled();
  fireEvent.click(ui.getByTestId("await-idle"));
  await waitFor(() => expect(mocks.idle).toHaveBeenCalledWith("owner", 30));
  mocks.event?.({
    kind: "snapshot",
    project: "demo-other",
    generation: 9,
    logs: ["wrong-owner"],
    invocations: [{ eventId: "9", function: "other", attempt: 1, outcome: "wrong-owner" }],
    logRecords: [],
    logScopes: [],
  });
  expect(ui.getByTestId("function-logs").textContent).not.toContain("wrong-owner");
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 9,
    logs: [],
    invocations: [{ eventId: "7", function: "consume", attempt: 1, outcome: "success" }],
    logRecords: [],
    logScopes: [],
  });
  expect(ui.getByTestId("event-timeline").textContent).toContain("7");
  cleanup();
  expect(mocks.stop).toHaveBeenCalledTimes(1);
  mocks.event?.({ kind: "log", project: "demo-owner", line: "late after cleanup" });
});
it("keeps the last successful owner snapshot visible with a refresh error and recovers", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner")).toBeTruthy());
  mocks.overview.mockReturnValue(errAsync({ status: 503, message: "refresh unavailable" }));
  fireEvent.click(ui.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(ui.getByRole("alert").textContent).toContain("refresh unavailable"));
  expect(ui.getByTestId("timeline-owner").textContent).toContain("demo-owner");
  expect(ui.container.textContent).toContain(t("functions.timelineStale"));
  await waitFor(() =>
    expect((ui.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(false),
  );
  mocks.overview.mockReturnValue(
    okAsync({ ...owner, status: { ...owner.status!, succeeded: 12 } }),
  );
  fireEvent.click(ui.getByRole("button", { name: "Refresh" }));
  await waitFor(() => expect(ui.getByTestId("succeeded-count").textContent).toBe("12"));
  expect(ui.queryByRole("alert")).toBeNull();
});
it("distinguishes loading, initial failure, empty and not-configured responses", async () => {
  let resolve!: (value: FunctionsOverview) => void;
  mocks.overview.mockReturnValue(
    ResultAsync.fromPromise(
      new Promise<FunctionsOverview>((done) => {
        resolve = done;
      }),
      () => ({ status: 500, message: "failed" }),
    ),
  );
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  expect(ui.queryByTestId("timeline-empty")).toBeNull();
  resolve(owner);
  await waitFor(() => expect(ui.getByTestId("timeline-empty")).toBeTruthy());
  cleanup();
  mocks.overview.mockReturnValue(errAsync({ status: 500, message: "initial failure" }));
  const failed = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(failed.getByRole("alert").textContent).toContain("initial failure"));
  expect(failed.queryByTestId("timeline-empty")).toBeNull();
  cleanup();
  mocks.overview.mockReturnValue(okAsync({ ...owner, configured: false }));
  const absent = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(absent.container.textContent).toContain(t("functions.notConfigured")));
  expect(absent.queryByTestId("timeline-empty")).toBeNull();
});

it("filters the capped log window once per change even when multiple views consume it", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner")).toBeTruthy());
  mocks.filter.mockClear();
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 1,
    logs: Array.from({ length: 2500 }, (_, i) => `info line-${i}`),
    invocations: [],
    logRecords: [],
    logScopes: [],
  });
  expect(mocks.filter).toHaveBeenCalledTimes(2000);
  expect(ui.getByTestId("function-logs").textContent).not.toContain("info line-499\n");
  fireEvent.input(ui.getByTestId("log-text-filter"), { target: { value: "line-2499" } });
  expect(mocks.filter).toHaveBeenCalledTimes(4000);
  expect(ui.getByTestId("function-logs").textContent).toBe("info line-2499");
  fireEvent.input(ui.getByTestId("invocation-function-filter"), { target: { value: "" } });
  expect(mocks.filter).toHaveBeenCalledTimes(4000);
});

it("discards a late overview and old stream callback after the owner project changes", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner").textContent).toContain("demo-owner"));
  const oldEvent = mocks.event!;
  let resolve!: (value: FunctionsOverview) => void;
  mocks.overview
    .mockReturnValueOnce(
      ResultAsync.fromPromise(
        new Promise<FunctionsOverview>((done) => {
          resolve = done;
        }),
        () => ({ status: 500, message: "failed" }),
      ),
    )
    .mockReturnValue(okAsync({ ...owner, project: "demo-new", session: "new" }));
  fireEvent.click(ui.getByRole("button", { name: "Refresh" }));
  await Promise.resolve();
  await Promise.resolve();
  oldEvent({
    kind: "invocation",
    project: "demo-owner",
    record: { eventId: "7", function: "consume", attempt: 1, outcome: "success" },
  });
  await waitFor(() => expect(ui.getByTestId("timeline-owner").textContent).toContain("demo-new"));
  expect(mocks.stop).toHaveBeenCalledTimes(1);
  resolve(owner);
  await Promise.resolve();
  await Promise.resolve();
  oldEvent({ kind: "log", project: "demo-owner", line: "late old owner" });
  expect(ui.getByTestId("timeline-owner").textContent).toContain("demo-new");
  expect(ui.getByTestId("function-logs").textContent).not.toContain("late old owner");
  expect(ui.queryByTestId("invocation-table")).toBeNull();
});

it("reconnects explicitly without dropping retained attributed logs or accepting late callbacks", async () => {
  mocks.overview.mockReturnValue(
    okAsync({
      ...owner,
      status: {
        ...owner.status!,
        codebases: [{ codebase: "a", functions: ["consume"], runnerAlive: true }],
      },
    }),
  );
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner")).toBeTruthy());
  const first = {
    project: "demo-owner",
    codebase: "a",
    runner: "r1",
    cursor: "0",
    line: "before replacement",
    invocationId: "7-1",
    function: "consume",
    truncated: false,
  };
  const second = { ...first, runner: "r2", line: "after replacement", invocationId: "7-2" };
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 1,
    logs: [first.line],
    invocations: [{ eventId: "7", function: "consume", attempt: 1, outcome: "failed" }],
    logRecords: [first],
    logScopes: [],
  });
  fireEvent.click(ui.getByTestId("event-timeline").querySelector("a")!);
  const oldEvent = mocks.event!;
  expect(ui.queryByTestId("logs-reconnect")).toBeNull();
  mocks.close?.();
  fireEvent.click(ui.getByTestId("logs-reconnect"));
  expect(mocks.stop).toHaveBeenCalledTimes(1);
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 1,
    logs: [second.line],
    invocations: [
      { eventId: "7", function: "consume", attempt: 1, outcome: "failed" },
      { eventId: "7", function: "consume", attempt: 2, outcome: "success" },
    ],
    logRecords: [second, second],
    logScopes: [],
  });
  expect(ui.getByTestId("timeline-logs").textContent).toContain(first.line);
  expect(ui.getByTestId("timeline-logs").textContent).toContain(second.line);
  expect(ui.getByTestId("timeline-logs").textContent!.split(second.line)).toHaveLength(2);
  expect(ui.getByTestId("timeline-log-gaps")).toBeTruthy();
  oldEvent({ kind: "log", project: "demo-owner", line: "late callback" });
  expect(ui.getByTestId("function-logs").textContent).not.toContain("late callback");
});

it("does not show a late idle result from a previous Functions owner", async () => {
  let resolve!: (value: { idle: boolean }) => void;
  mocks.idle.mockReturnValue(
    ResultAsync.fromPromise(
      new Promise<{ idle: boolean }>((done) => {
        resolve = done;
      }),
      () => ({ status: 500, message: "failed" }),
    ),
  );
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner")).toBeTruthy());
  fireEvent.click(ui.getByTestId("await-idle"));
  mocks.overview.mockReturnValue(okAsync({ ...owner, project: "demo-new", session: "new" }));
  mocks.event?.({
    kind: "invocation",
    project: "demo-owner",
    record: { eventId: "7", function: "consume", attempt: 1, outcome: "success" },
  });
  await waitFor(() => expect(ui.getByTestId("timeline-owner").textContent).toContain("demo-new"));
  resolve({ idle: true });
  await waitFor(() =>
    expect((ui.getByTestId("await-idle") as HTMLButtonElement).disabled).toBe(false),
  );
  expect(ui.queryByText(t("functions.idle"), { exact: true })).toBeNull();
});

it("shows the held Auth events, the queue and schedule counters, each codebase's runtime and the ignored exports", async () => {
  mocks.overview.mockReturnValue(
    okAsync({
      ...owner,
      functions: [
        {
          name: "py",
          region: "us-central1",
          entryPoint: "py",
          trigger: { kind: "http", callable: false },
          timeoutSeconds: 60,
          retry: false,
          concurrency: 1,
          codebase: "py-app",
          runtime: { language: "python", declared: "python312" },
        },
        {
          name: "js",
          region: "us-central1",
          entryPoint: "js",
          trigger: { kind: "http", callable: false },
          timeoutSeconds: 60,
          retry: false,
          concurrency: 1,
          codebase: "default",
          runtime: { language: "node", declared: null },
        },
      ],
      codebases: [
        { codebase: "py-app", language: "python", declared: "python312" },
        { codebase: "default", language: "node", declared: null },
        { codebase: "ignored-only", language: "python", declared: null },
      ],
      status: {
        ...owner.status!,
        authEventsPending: 3,
        tasksInFlight: 2,
        catchUpPending: true,
        overlapRejected: 4,
        codebases: [
          { codebase: "py-app", functions: ["py"], runnerAlive: true },
          { codebase: "default", functions: ["js"], runnerAlive: false },
          { codebase: "ignored-only", functions: [], runnerAlive: true },
        ],
        ignored: [
          {
            name: "legacy",
            region: "us-central1",
            triggerType: "scheduled",
            scope: "gcfv1",
            reason: "unsupported trigger",
          },
        ],
      },
    }),
  );
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("function-status")).toBeTruthy());
  const status = ui.getByTestId("function-status").textContent ?? "";
  expect(ui.getByTestId("status-auth-events-pending").textContent).toBe("3");
  expect(ui.getByTestId("status-tasks-in-flight").textContent).toBe("2");
  expect(ui.getByTestId("status-catch-up-pending").textContent).toBe("yes");
  expect(ui.getByTestId("status-overlap-rejected").textContent).toBe("4");
  expect(status).toContain("Auth events held");
  const py = ui.getByTestId("codebase-status-py-app").textContent ?? "";
  expect(py).toContain("Python (python312)");
  expect(py).toContain("running");
  const js = ui.getByTestId("codebase-status-default").textContent ?? "";
  expect(js).toContain("Node.js");
  expect(js).toContain("stopped");
  // A codebase that registered no function still shows its runtime, from the codebase list.
  const only = ui.getByTestId("codebase-status-ignored-only").textContent ?? "";
  expect(only).toContain("Python");
  expect(only).not.toContain("Python (");
  expect(only).toContain("running");
  const ignored = ui.getByTestId("ignored-exports").textContent ?? "";
  expect(ignored).toContain("legacy");
  expect(ignored).toContain("unsupported trigger");
});

it("shows zero for counters an older daemon does not send and hides the empty sections", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("function-status")).toBeTruthy());
  expect(ui.getByTestId("status-auth-events-pending").textContent).toBe("0");
  expect(ui.getByTestId("status-tasks-in-flight").textContent).toBe("0");
  expect(ui.getByTestId("status-catch-up-pending").textContent).toBe("no");
  expect(ui.queryByTestId("ignored-exports")).toBeNull();
  expect(ui.container.querySelector("[data-testid^='codebase-status-']")).toBeNull();
  expect(ui.queryByTestId("codebase-list")).toBeNull();
});

it("restores filters, excludes private text by default and shares it only on request", async () => {
  history.replaceState(null, "", "/functions?function=unknown&level=error&q=shared");
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("log-text-filter")).toBeTruthy());
  expect((ui.getByTestId("log-level-filter") as HTMLSelectElement).value).toBe("error");
  expect((ui.getByTestId("log-text-filter") as HTMLInputElement).value).toBe("shared");
  expect(ui.getByText(/not registered or retained/)).toBeTruthy();
  fireEvent.input(ui.getByTestId("log-text-filter"), { target: { value: "private" } });
  expect(location.search).not.toContain("private");
  fireEvent.click(ui.getByText("Copy filter link"));
  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(writeText.mock.calls[0]![0]).not.toContain("q=");
  await waitFor(() =>
    expect((ui.getByText("Copy filter link") as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.input(ui.getByTestId("log-level-filter"), { target: { value: "warn" } });
  expect((ui.getByTestId("log-text-filter") as HTMLInputElement).value).toBe("private");
  fireEvent.click(ui.getByLabelText("Include search text in the shared link"));
  fireEvent.click(ui.getByText("Copy filter link"));
  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(2));
  expect(new URL(writeText.mock.calls[1]![0]).searchParams.get("q")).toBe("private");
});

it("keeps URL filters reactive after changing sessions and restores private text on remount", async () => {
  let ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("log-text-filter")).toBeTruthy());
  fireEvent.input(ui.getByTestId("log-text-filter"), { target: { value: "private" } });
  cleanup();
  ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() =>
    expect((ui.getByTestId("log-text-filter") as HTMLInputElement).value).toBe("private"),
  );
  appState.setSession("owner");
  expect((ui.getByTestId("log-text-filter") as HTMLInputElement).value).toBe("");
  fireEvent.input(ui.getByTestId("log-level-filter"), { target: { value: "error" } });
  expect((ui.getByTestId("log-level-filter") as HTMLSelectElement).value).toBe("error");
  await waitFor(() => expect(location.search).toContain("level=error"));
});

it("keeps private text across filter changes when browser storage is blocked", async () => {
  const get = vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
    throw new Error("blocked");
  });
  const set = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
    throw new Error("blocked");
  });
  try {
    const ui = render(() => (
      <Router>
        <Route path="*" component={Functions} />
      </Router>
    ));
    await waitFor(() => expect(ui.getByTestId("log-text-filter")).toBeTruthy());
    fireEvent.input(ui.getByTestId("log-text-filter"), { target: { value: "private" } });
    fireEvent.input(ui.getByTestId("log-level-filter"), { target: { value: "error" } });
    await waitFor(() => expect(location.search).toContain("level=error"));
    expect((ui.getByTestId("log-text-filter") as HTMLInputElement).value).toBe("private");
  } finally {
    get.mockRestore();
    set.mockRestore();
  }
});

it("restores an event link, reports eviction, and clears it on session change", async () => {
  history.replaceState(
    null,
    "",
    "/functions?event=7&eventFunction=consume&eventSession=owner&eventProject=demo-owner",
  );
  appState.setSession("default");
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  expect(appState.session()).toBe("owner");
  await waitFor(() =>
    expect(ui.getByTestId("timeline-detail").textContent).toContain(
      t("functions.timelineMissingSelection"),
    ),
  );
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 1,
    logs: [],
    invocations: [{ eventId: "7", function: "consume", attempt: 1, outcome: "success" }],
    logRecords: [],
    logScopes: [],
  });
  await waitFor(() =>
    expect(ui.getByTestId("timeline-detail").textContent).toContain("7 / consume"),
  );
  expect(ui.getByRole("link", { name: /Select event 7/ }).getAttribute("href")).toContain(
    "event=7",
  );
  appState.setSession("other");
  await waitFor(() => expect(ui.queryByTestId("timeline-detail")).toBeNull());
});

it("opens a synthetic invocation after selecting a linked event", async () => {
  const ui = render(() => (
    <Router>
      <Route path="*" component={Functions} />
    </Router>
  ));
  await waitFor(() => expect(ui.getByTestId("timeline-owner")).toBeTruthy());
  mocks.event?.({
    kind: "snapshot",
    project: "demo-owner",
    generation: 1,
    logs: [],
    invocations: [
      { eventId: "7", function: "consume", attempt: 1, outcome: "success" },
      { eventId: "0", function: "synthetic", attempt: 1, outcome: "success" },
    ],
    logRecords: [],
    logScopes: [],
  });
  fireEvent.click(ui.getByRole("link", { name: /Select event 7/ }));
  await waitFor(() =>
    expect(ui.getByTestId("timeline-detail").textContent).toContain("7 / consume"),
  );
  fireEvent.click(ui.getByRole("button", { name: "0" }));
  await waitFor(() =>
    expect(ui.getByTestId("timeline-detail").textContent).toContain("0 / synthetic"),
  );
});
