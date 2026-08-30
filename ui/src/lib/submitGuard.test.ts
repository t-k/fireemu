import { describe, expect, it } from "vitest";
import { createRoot } from "solid-js";
import { createSubmitGuard } from "./submitGuard";

describe("submit guard", () => {
  it("runs one action at a time and refuses re-entry synchronously", async () => {
    await createRoot(async (dispose) => {
      const guard = createSubmitGuard();
      let runs = 0;
      let release: () => void = () => {};
      const first = guard.run(
        () =>
          new Promise<string>((resolve) => {
            runs += 1;
            release = () => resolve("first");
          }),
      );
      expect(guard.pending()).toBe(true);
      const second = await guard.run(async () => {
        runs += 1;
        return "second";
      });
      expect(second).toBeUndefined();
      release();
      expect(await first).toBe("first");
      expect(guard.pending()).toBe(false);
      expect(runs).toBe(1);
      const third = await guard.run(async () => "third");
      expect(third).toBe("third");
      dispose();
    });
  });
});
