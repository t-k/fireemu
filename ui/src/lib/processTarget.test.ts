import { describe, expect, it } from "vitest";

import { ownedProcessTarget } from "./processTarget";

describe("ownedProcessTarget", () => {
  it("uses the owned child PID on Windows", () => {
    expect(ownedProcessTarget(47, "win32")).toBe(47);
  });

  it("uses the owned process group on POSIX", () => {
    expect(ownedProcessTarget(47, "linux")).toBe(-47);
    expect(ownedProcessTarget(47, "darwin")).toBe(-47);
  });
});
