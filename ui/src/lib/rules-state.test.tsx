import { describe, expect, it } from "vitest";
import { render, waitFor } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { ok, err, type Result } from "neverthrow";
import { createScopedFetch } from "./rules-state";
import type { ApiError } from "../api/client";

const deferred = () => {
  let resolve!: (r: Result<string, ApiError>) => void;
  const promise = new Promise<Result<string, ApiError>>((r) => (resolve = r));
  return { promise, resolve };
};

describe("scope-owned diagnostics reads", () => {
  it("retains success through refreshing and errors, then recovers on retry", async () => {
    const calls = [deferred(), deferred(), deferred()];
    let n = 0;
    let resource!: ReturnType<typeof createScopedFetch<string>>;
    const ui = render(() => {
      resource = createScopedFetch(
        () => "a",
        () => calls[n++]!.promise,
      );
      return <span>{resource.data()}</span>;
    });
    expect(resource.loading()).toBe(true);
    calls[0]!.resolve(ok("recorded"));
    await waitFor(() => expect(resource.data()).toBe("recorded"));
    const refresh = resource.refetch();
    expect(resource.data()).toBe("recorded");
    expect(resource.loading()).toBe(true);
    calls[1]!.resolve(err({ status: 500, message: "offline" }));
    await refresh;
    expect(resource.data()).toBe("recorded");
    expect(resource.error()).toBe("offline");
    const retry = resource.refetch();
    calls[2]!.resolve(ok("new"));
    await retry;
    expect(resource.data()).toBe("new");
    expect(resource.error()).toBeNull();
    ui.unmount();
  });
  it("rejects late old-scope and superseded reads, including A/B/A and disposal", async () => {
    const [scope, setScope] = createSignal("a");
    const calls: ReturnType<typeof deferred>[] = [];
    let resource!: ReturnType<typeof createScopedFetch<string>>;
    const ui = render(() => {
      resource = createScopedFetch(scope, () => {
        const d = deferred();
        calls.push(d);
        return d.promise;
      });
      return <span>{resource.data()}</span>;
    });
    calls[0]!.resolve(ok("a old"));
    await waitFor(() => expect(resource.data()).toBe("a old"));
    const old = resource.refetch();
    setScope("b");
    await waitFor(() => expect(calls.length).toBe(3));
    expect(resource.data()).toBeUndefined();
    setScope("a");
    await waitFor(() => expect(calls.length).toBe(4));
    calls[1]!.resolve(ok("stale a"));
    calls[2]!.resolve(ok("late b"));
    await old;
    expect(resource.data()).toBeUndefined();
    calls[3]!.resolve(ok("fresh a"));
    await waitFor(() => expect(resource.data()).toBe("fresh a"));
    const late = resource.refetch();
    ui.unmount();
    calls[4]!.resolve(ok("disposed"));
    await late;
    expect(resource.data()).toBe("fresh a");
  });
});
