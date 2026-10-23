import { describe, expect, it } from "vitest";
import { routes } from "../routes";

describe("Realtime Database route", () => {
  it("exposes the data, Rules and request workflow", () => {
    expect(routes.some((route) => route.path === "/database/*path")).toBe(true);
  });
});

import { afterEach, beforeEach, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { MemoryRouter, Route } from "@solidjs/router";
import { errAsync, okAsync, ResultAsync } from "neverthrow";
import Database from "./Database";
import { appState } from "../state";
import * as api from "../api/database";
import type { TextReply } from "../api/client";
vi.mock("../api/database", () => ({
  databaseInstances: vi.fn(),
  databaseRead: vi.fn(),
  databaseRules: vi.fn(),
  databaseWrite: vi.fn(),
  databaseSaveRules: vi.fn(),
  databaseProbe: vi.fn(),
}));
const reply = (body: string): TextReply => ({ status: 200, body, etag: '"v1"' });
const mount = () =>
  render(() => (
    <MemoryRouter>
      <Route path="/" component={Database} />
    </MemoryRouter>
  ));
afterEach(cleanup);
beforeEach(() => {
  vi.resetAllMocks();
  appState.setSessions([
    { name: "default", project: "demo-a" },
    { name: "other", project: "demo-b" },
  ]);
  appState.setSession("default");
  vi.mocked(api.databaseInstances).mockImplementation((_session, project) =>
    okAsync({ instances: [{ name: `${project}-default-rtdb`, project }] }),
  );
  vi.mocked(api.databaseRead).mockImplementation(() => okAsync(reply("null")));
  vi.mocked(api.databaseRules).mockImplementation(() =>
    okAsync(reply('{"rules":{ ".read":false }}')),
  );
  vi.mocked(api.databaseWrite).mockImplementation(() => okAsync(reply("-0")));
  vi.mocked(api.databaseSaveRules).mockImplementation(() => okAsync(reply('{"status":"ok"}')));
  vi.mocked(api.databaseProbe).mockImplementation(() =>
    okAsync({ ...reply('{"error":"Permission denied"}'), status: 401 }),
  );
});

describe("database scoped editor", () => {
  it("distinguishes initial read error from genuine null and recovers", async () => {
    vi.mocked(api.databaseRead).mockImplementation(() =>
      errAsync({ status: 500, message: "initial failure" }),
    );
    const h = mount();
    await h.findByText("initial failure");
    expect(h.queryByLabelText("JSON source")).toBeNull();
    vi.mocked(api.databaseRead).mockImplementation(() => okAsync(reply("null")));
    fireEvent.click(h.getByTestId("fetch-retry"));
    await waitFor(() =>
      expect((h.getByLabelText("JSON source") as HTMLTextAreaElement).value).toBe("null"),
    );
  });
  it("retains the draft and snapshot across refresh failure", async () => {
    const h = mount();
    const editor = await h.findByLabelText("JSON source");
    fireEvent.input(editor, { target: { value: ' {"local":-0} ' } });
    vi.mocked(api.databaseRead).mockImplementation(() =>
      errAsync({ status: 503, message: "refresh offline" }),
    );
    fireEvent.click(h.getByTestId("database-data-refresh"));
    await h.findByText("refresh offline");
    expect((editor as HTMLTextAreaElement).value).toBe(' {"local":-0} ');
    expect(h.getByTestId("fetch-stale")).toBeTruthy();
  });
  it("does not clear a newer draft after a save acknowledgement", async () => {
    let complete!: (value: TextReply) => void;
    vi.mocked(api.databaseWrite).mockImplementation(() =>
      ResultAsync.fromSafePromise(
        new Promise<TextReply>((resolve) => {
          complete = resolve;
        }),
      ),
    );
    const h = mount();
    const editor = await h.findByLabelText("JSON source");
    fireEvent.input(editor, { target: { value: " -0 " } });
    fireEvent.click(h.getByTestId("database-save"));
    await waitFor(() => expect(api.databaseWrite).toHaveBeenCalled());
    fireEvent.input(editor, { target: { value: '{"newer":true}' } });
    complete(reply("-0"));
    await h.findByText("Database data saved");
    expect((editor as HTMLTextAreaElement).value).toBe('{"newer":true}');
    expect(api.databaseWrite).toHaveBeenCalledWith(
      expect.objectContaining({ project: "demo-a" }),
      "/",
      "PUT",
      " -0 ",
    );
  });
  it("keeps edits on unknown write outcome without retrying", async () => {
    vi.mocked(api.databaseWrite).mockImplementation(() =>
      errAsync({ status: 0, message: "connection lost" }),
    );
    const h = mount();
    const editor = await h.findByLabelText("JSON source");
    fireEvent.input(editor, { target: { value: "12" } });
    fireEvent.click(h.getByTestId("database-save"));
    await h.findByText(/outcome is unknown/);
    expect((editor as HTMLTextAreaElement).value).toBe("12");
    expect(h.queryByText("Database data saved")).toBeNull();
    expect(api.databaseWrite).toHaveBeenCalledTimes(1);
  });
  it("ignores old-scope mutation completion and disables a deleted session", async () => {
    let complete!: (value: TextReply) => void;
    vi.mocked(api.databaseWrite).mockImplementation(() =>
      ResultAsync.fromSafePromise(
        new Promise<TextReply>((resolve) => {
          complete = resolve;
        }),
      ),
    );
    const h = mount();
    fireEvent.input(await h.findByLabelText("JSON source"), { target: { value: "42" } });
    fireEvent.click(h.getByTestId("database-save"));
    await waitFor(() => expect(api.databaseWrite).toHaveBeenCalled());
    appState.setSession("other");
    await waitFor(() =>
      expect(api.databaseRead).toHaveBeenCalledWith(
        expect.objectContaining({ project: "demo-b" }),
        "/",
      ),
    );
    const readsBeforeOldCompletion = vi.mocked(api.databaseRead).mock.calls.length;
    complete(reply("42"));
    // Drain the already registered ResultAsync/await continuation, without a timer or retry.
    for (let tick = 0; tick < 6; tick++) await Promise.resolve();
    expect(api.databaseRead).toHaveBeenCalledTimes(readsBeforeOldCompletion);
    expect(h.queryByText("Database data saved")).toBeNull();
    appState.setSessions([{ name: "default", project: "demo-a" }]);
    await h.findByText(/selected session no longer exists/);
    expect(h.queryByTestId("database-save")).toBeNull();
  });
  it("guards path changes and keeps focus/draft when the reader keeps editing", async () => {
    const h = mount();
    const editor = await h.findByLabelText("JSON source");
    fireEvent.input(editor, { target: { value: "42" } });
    fireEvent.input(h.getByLabelText("Data path"), { target: { value: "/other" } });
    fireEvent.click(h.getByText("Open path"));
    await h.findByTestId("unsaved-prompt");
    fireEvent.click(h.getByTestId("unsaved-keep"));
    expect((editor as HTMLTextAreaElement).value).toBe("42");
    expect(api.databaseRead).not.toHaveBeenCalledWith(expect.anything(), "/other");
    fireEvent.click(h.getByText("Open path"));
    fireEvent.click(await h.findByTestId("unsaved-discard"));
    await waitFor(() => expect(api.databaseRead).toHaveBeenCalledWith(expect.anything(), "/other"));
  });
  it("shows the denied anonymous request without presenting it as a successful save", async () => {
    const h = mount();
    await h.findByLabelText("JSON source");
    fireEvent.click(h.getByTestId("database-request-run"));
    await h.findByText("HTTP 401");
    expect(h.getByTestId("database-response").textContent).toContain("Permission denied");
    expect(h.queryByText("Database data saved")).toBeNull();
  });
});

it("keeps the acknowledged data visible while its follow-up read is held", async () => {
  const h = mount();
  const editor = await h.findByLabelText("JSON source");
  vi.mocked(api.databaseRead).mockImplementation(() =>
    ResultAsync.fromSafePromise(new Promise<TextReply>(() => {})),
  );
  fireEvent.input(editor, { target: { value: " -0 " } });
  fireEvent.click(h.getByTestId("database-save"));
  await h.findByText("Database data saved");
  expect((editor as HTMLTextAreaElement).value.trim()).toBe("-0");
});

it("never sends invalid JSON or clears the Rules draft on refresh failure", async () => {
  const h = mount();
  fireEvent.input(await h.findByLabelText("JSON source"), { target: { value: "{" } });
  fireEvent.click(h.getByTestId("database-save"));
  await h.findByText("Enter valid JSON. The source has not been sent.");
  expect(api.databaseWrite).not.toHaveBeenCalled();
  const editor = h.getByLabelText("Rules JSON source");
  fireEvent.input(editor, { target: { value: '{"rules":{ ".read":true }}' } });
  vi.mocked(api.databaseRules).mockImplementation(() =>
    errAsync({ status: 500, message: "rules refresh failed" }),
  );
  fireEvent.click(h.getByTestId("database-rules-refresh"));
  await h.findByText("rules refresh failed");
  expect((editor as HTMLTextAreaElement).value).toBe('{"rules":{ ".read":true }}');
});
