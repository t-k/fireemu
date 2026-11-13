import { afterEach, expect, it, vi } from "vitest";
import { okAsync, errAsync, ResultAsync } from "neverthrow";
import { appState } from "./state";
import * as control from "./api/control";
vi.mock("./api/control", () => ({ sessionInfo: vi.fn(), listSessions: vi.fn() }));
afterEach(() => vi.restoreAllMocks());
const info = (clock: string) => ({
  session: "default",
  edition: "standard",
  requireDemoPrefix: true,
  clock: { clock, backwardsSets: 0 },
});
it("keeps the last successful real check when a subsequent poll fails", async () => {
  vi.mocked(control.sessionInfo).mockReturnValue(okAsync(info("virtual")));
  vi.mocked(control.listSessions).mockReturnValue(okAsync({ sessions: [] }));
  await appState.refreshClock();
  const success = appState.lastConnectedAt();
  expect(success).not.toBeNull();
  vi.mocked(control.sessionInfo).mockReturnValue(errAsync({ status: 0, message: "offline" }));
  await appState.refreshClock();
  expect(appState.connected()).toBe(false);
  expect(appState.lastConnectedAt()).toBe(success);
});
it("ignores a superseded poll and a reply for a replaced session", async () => {
  let resolve!: (value: ReturnType<typeof info>) => void;
  vi.mocked(control.sessionInfo).mockReturnValueOnce(
    ResultAsync.fromSafePromise(
      new Promise((r) => {
        resolve = r;
      }),
    ),
  );
  vi.mocked(control.listSessions).mockReturnValue(okAsync({ sessions: [] }));
  const old = appState.refreshClock();
  vi.mocked(control.sessionInfo).mockReturnValue(okAsync(info("new")));
  await appState.refreshClock();
  resolve(info("old"));
  await old;
  expect(appState.clock()).toBe("new");
  vi.mocked(control.sessionInfo).mockReturnValueOnce(
    ResultAsync.fromSafePromise(
      new Promise((r) => {
        resolve = r;
      }),
    ),
  );
  const replaced = appState.refreshClock();
  appState.setSession("different");
  resolve(info("wrong"));
  await replaced;
  expect(appState.clock()).not.toBe("wrong");
  expect(appState.connected()).toBeNull();
});

it("publishes slow polls in completion order without starvation from newer starts", async () => {
  const resolvers: ((value: ReturnType<typeof info>) => void)[] = [];
  vi.mocked(control.sessionInfo).mockImplementation(() =>
    ResultAsync.fromSafePromise(new Promise((resolve) => resolvers.push(resolve))),
  );
  vi.mocked(control.listSessions).mockReturnValue(okAsync({ sessions: [] }));
  const first = appState.refreshClock();
  const second = appState.refreshClock();
  resolvers[0]!(info("first"));
  await first;
  expect(appState.clock()).toBe("first");
  const third = appState.refreshClock();
  resolvers[1]!(info("second"));
  await second;
  expect(appState.clock()).toBe("second");
  resolvers[2]!(info("third"));
  await third;
  expect(appState.clock()).toBe("third");
});

it("does not let a superseded response restore an old session catalog", async () => {
  appState.setSessions([{ name: "default", project: "demo-before" }]);
  appState.setSession("default");
  let resolve!: (value: ReturnType<typeof info>) => void;
  vi.mocked(control.sessionInfo)
    .mockReturnValueOnce(
      ResultAsync.fromSafePromise(
        new Promise((r) => {
          resolve = r;
        }),
      ),
    )
    .mockReturnValue(okAsync(info("new")));
  vi.mocked(control.listSessions)
    .mockReturnValueOnce(okAsync({ sessions: [{ name: "default", project: "demo-before" }] }))
    .mockReturnValue(okAsync({ sessions: [{ name: "default", project: "demo-after" }] }));
  const old = appState.refreshClock();
  await appState.refreshClock();
  resolve(info("old"));
  await old;
  expect(appState.project()).toBe("demo-after");
  expect(appState.clock()).not.toBe("old");
});
