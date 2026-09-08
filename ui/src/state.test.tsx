import { afterEach, describe, expect, it } from "vitest";
import { render, fireEvent, cleanup } from "@solidjs/testing-library";
import { createEffect, For } from "solid-js";
import { appState } from "./state";
import { ConfirmButton } from "./components/common";

afterEach(cleanup);

describe("session snapshot identity", () => {
  it("does not reset project consumers for unchanged snapshots but propagates actual changes", () => {
    appState.setSession("default");
    appState.setSessions([{ name: "default", project: "demo-a" }]);
    const observed: string[] = [];
    render(() => {
      createEffect(() => {
        observed.push(appState.project());
      });
      return <div />;
    });
    appState.setSessions([{ name: "default", project: "demo-a" }]);
    expect(observed).toEqual(["demo-a"]);
    appState.setSessions([{ name: "default", project: "demo-b" }]);
    expect(observed).toEqual(["demo-a", "demo-b"]);
    appState.setSessions([
      { name: "default", project: "demo-b" },
      { name: "other", project: "demo-c" },
    ]);
    appState.setSession("other");
    expect(observed).toEqual(["demo-a", "demo-b", "demo-c"]);
  });

  it("discards a confirmation when the same session name now targets another project", () => {
    appState.setSessions([{ name: "default", project: "demo-a" }]);
    const ui = render(() => (
      <For each={appState.sessions()}>
        {(s) => <ConfirmButton label="Reset" question={s.project} onConfirm={async () => {}} />}
      </For>
    ));
    fireEvent.click(ui.getByText("Reset"));
    expect(ui.getByText("Confirm")).toBeTruthy();
    appState.setSessions([{ name: "default", project: "demo-b" }]);
    expect(ui.queryByText("Confirm")).toBeNull();
  });

  it("matches the project transition model for every pair of bounded snapshots and selections", () => {
    const snapshots = [
      [],
      [{ name: "default", project: "demo-a" }],
      [{ name: "default", project: "demo-b" }],
      [
        { name: "default", project: "demo-a" },
        { name: "other", project: "demo-a" },
      ],
      [{ name: "other", project: "demo-c" }],
    ];
    const selections = ["default", "other", "missing"];
    const fallback = appState.config().project;
    const states = snapshots.flatMap((snapshot) =>
      selections.map((selection) => ({ snapshot, selection })),
    );
    for (const before of states)
      for (const after of states) {
        appState.setSessions(before.snapshot);
        appState.setSession(before.selection);
        const observed: string[] = [];
        const ui = render(() => {
          createEffect(() => {
            observed.push(appState.project());
          });
          return <div />;
        });
        const expected = [
          before.snapshot.find((s) => s.name === before.selection)?.project ?? fallback,
        ];
        for (const value of [
          after.snapshot.find((s) => s.name === before.selection)?.project ?? fallback,
          after.snapshot.find((s) => s.name === after.selection)?.project ?? fallback,
        ]) {
          if (value !== expected.at(-1)) expected.push(value);
        }
        appState.setSessions(after.snapshot.map((s) => ({ ...s })));
        appState.setSession(after.selection);
        expect(observed).toEqual(expected);
        ui.unmount();
      }
  });

  it("keeps confirmation state across snapshots and reordering, and removes deleted sessions", () => {
    appState.setSessions([
      { name: "default", project: "demo-a" },
      { name: "other", project: "demo-b" },
    ]);
    const ui = render(() => (
      <For each={appState.sessions()}>
        {(s) => (
          <div data-testid={s.name}>
            <span>{s.project}</span>
            <ConfirmButton label="Reset" question="Reset session?" onConfirm={async () => {}} />
          </div>
        )}
      </For>
    ));
    fireEvent.click(ui.getAllByText("Reset")[0]!);
    const confirm = ui.getByText("Confirm");
    appState.setSessions([
      { name: "other", project: "demo-b" },
      { name: "default", project: "demo-a" },
    ]);
    expect(ui.getByText("Confirm")).toBe(confirm);
    appState.setSessions([{ name: "other", project: "demo-c" }]);
    expect(ui.queryByTestId("default")).toBeNull();
    expect(ui.getByTestId("other").textContent).toContain("demo-c");
  });
});
