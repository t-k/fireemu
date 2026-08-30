import { describe, expect, it } from "vitest";
import { productScope, statusLabelKey } from "./products";

describe("product scope", () => {
  it("labels Realtime Database as deferred and Extensions as not planned", () => {
    const scope = productScope();
    expect(scope.find((r) => r.id === "rtdb")?.status).toBe("deferred");
    expect(scope.find((r) => r.id === "extensions")?.status).toBe("notPlanned");
  });

  it("marks the still-unserved diagnostics as pending backend, never as supported", () => {
    const scope = productScope();
    expect(scope.find((r) => r.id === "requests")?.status).toBe("pendingBackend");
    expect(scope.find((r) => r.id === "alerts")?.status).toBe("pendingBackend");
  });

  it("marks the official Logging emulator as substituted by the SSE stream", () => {
    expect(productScope().find((r) => r.id === "logging")?.status).toBe("substituted");
  });

  it("keeps the four active parity products supported", () => {
    const supported = productScope()
      .filter((r) => r.status === "supported")
      .map((r) => r.id);
    for (const id of ["auth", "firestore", "functions", "storage"]) {
      expect(supported).toContain(id);
    }
  });

  it("derives a status label key for every status it uses", () => {
    for (const row of productScope()) {
      expect(statusLabelKey(row.status)).toBe(`scope.status.${row.status}`);
    }
  });
});
