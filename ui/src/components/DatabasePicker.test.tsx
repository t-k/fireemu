import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { okAsync, errAsync, ResultAsync } from "neverthrow";
import DatabasePicker from "./DatabasePicker";
import * as api from "../api/firestore";
vi.mock("../api/firestore", () => ({ listDatabases: vi.fn() }));
afterEach(() => {
  cleanup();
  sessionStorage.clear();
});
it("offers known databases, keeps arbitrary input, and synchronizes navigation", async () => {
  vi.mocked(api.listDatabases).mockReturnValue(okAsync(["(default)", "catalog"]));
  const [db, setDb] = createSignal("(default)");
  const view = render(() => (
    <DatabasePicker project="p" session="default" database={db()} onSelect={setDb} />
  ));
  await waitFor(() =>
    expect(view.getByTestId("database-options").textContent).toContain("catalog"),
  );
  fireEvent.input(view.getByTestId("database-input"), { target: { value: "catalog" } });
  fireEvent.click(view.getByText("Open database"));
  expect(db()).toBe("catalog");
  setDb("(default)");
  expect((view.getByTestId("database-input") as HTMLInputElement).value).toBe("(default)");
  setDb("missing");
  await waitFor(() => expect(view.getByRole("status").textContent).toContain("does not exist"));
});
it("does not present a failed list as an absent database", async () => {
  vi.mocked(api.listDatabases).mockReturnValue(errAsync({ status: 500, message: "unavailable" }));
  const view = render(() => (
    <DatabasePicker project="p" session="default" database="x" onSelect={() => {}} />
  ));
  await waitFor(() => expect(view.getByText(/Database list unavailable/)).toBeTruthy());
  expect(view.queryByText(/does not exist/)).toBeNull();
});
it("ignores a late database list from another project", async () => {
  let resolve!: (value: string[]) => void;
  vi.mocked(api.listDatabases)
    .mockReturnValueOnce(
      ResultAsync.fromSafePromise(
        new Promise((r) => {
          resolve = r;
        }),
      ),
    )
    .mockReturnValue(okAsync(["new-db"]));
  const [project, setProject] = createSignal("old");
  const view = render(() => (
    <DatabasePicker project={project()} session="default" database="new-db" onSelect={() => {}} />
  ));
  setProject("new");
  await waitFor(() => expect(view.getByTestId("database-options").textContent).toContain("new-db"));
  resolve(["old-db"]);
  await Promise.resolve();
  expect(view.getByTestId("database-options").textContent).not.toContain("old-db");
});

it("refreshes the catalog when selecting a database created externally", async () => {
  vi.mocked(api.listDatabases)
    .mockReturnValueOnce(okAsync(["(default)"]))
    .mockReturnValue(okAsync(["(default)", "created"]));
  const [db, setDb] = createSignal("(default)");
  const view = render(() => (
    <DatabasePicker project="p" session="default" database={db()} onSelect={setDb} />
  ));
  await waitFor(() =>
    expect(view.getByTestId("database-options").textContent).toContain("(default)"),
  );
  setDb("created");
  await waitFor(() => expect(api.listDatabases).toHaveBeenLastCalledWith("p"));
  await waitFor(() =>
    expect(view.getByTestId("database-options").textContent).toContain("created"),
  );
  expect(view.queryByText(/does not exist/)).toBeNull();
});

it("does not assert absence from a stale catalog after refresh fails", async () => {
  vi.mocked(api.listDatabases)
    .mockReturnValueOnce(okAsync(["(default)"]))
    .mockReturnValue(errAsync({ status: 500, message: "offline" }));
  const view = render(() => (
    <DatabasePicker project="p" session="default" database="missing" onSelect={() => {}} />
  ));
  await waitFor(() => expect(view.getByText(/does not exist/)).toBeTruthy());
  fireEvent.click(view.getByText("Refresh"));
  await waitFor(() => expect(view.getByText(/Database list unavailable/)).toBeTruthy());
  expect(view.queryByText(/does not exist/)).toBeNull();
});
