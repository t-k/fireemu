import { describe, expect, it } from "vitest";
import { runtimeLabel } from "./functionRuntime";

describe("runtimeLabel", () => {
  it.each([
    [{ language: "python", declared: "python312" }, "Python (python312)"],
    [{ language: "node", declared: "nodejs22" }, "Node.js (nodejs22)"],
    [{ language: "node", declared: null }, "Node.js"],
    [{ language: "python", declared: null }, "Python"],
  ] as const)("%j", (runtime, label) => {
    expect(runtimeLabel(runtime)).toBe(label);
  });
});
