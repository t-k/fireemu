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
  const ui = render(() => <Functions />);
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
  const ui = render(() => <Functions />);
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
  const ui = render(() => <Functions />);
  expect(ui.queryByTestId("timeline-empty")).toBeNull();
  resolve(owner);
  await waitFor(() => expect(ui.getByTestId("timeline-empty")).toBeTruthy());
  cleanup();
  mocks.overview.mockReturnValue(errAsync({ status: 500, message: "initial failure" }));
  const failed = render(() => <Functions />);
  await waitFor(() => expect(failed.getByRole("alert").textContent).toContain("initial failure"));
  expect(failed.queryByTestId("timeline-empty")).toBeNull();
  cleanup();
  mocks.overview.mockReturnValue(okAsync({ ...owner, configured: false }));
  const absent = render(() => <Functions />);
  await waitFor(() => expect(absent.container.textContent).toContain(t("functions.notConfigured")));
  expect(absent.queryByTestId("timeline-empty")).toBeNull();
});

it("filters the capped log window once per change even when multiple views consume it", async () => {
  const ui = render(() => <Functions />);
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
  const ui = render(() => <Functions />);
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
  const ui = render(() => <Functions />);
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
  fireEvent.click(ui.getByTestId("event-timeline").querySelector("button")!);
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
  const ui = render(() => <Functions />);
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
