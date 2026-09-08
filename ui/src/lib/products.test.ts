import { describe, expect, it } from "vitest";
import { productScope, statusLabelKey } from "./products";

describe("product scope", () => {
  it("labels Realtime Database as deferred and Extensions as not planned", () => {
    const scope = productScope();
    expect(scope.find((r) => r.id === "rtdb")?.status).toBe("deferred");
    expect(scope.find((r) => r.id === "extensions")?.status).toBe("notPlanned");
  });

  it("marks the Firestore Requests trace supported (its panel is on the Rules page)", () => {
    expect(productScope().find((r) => r.id === "requests")?.status).toBe("supported");
  });

  it("marks the Rules coverage view supported (its panel is on the Rules page)", () => {
    expect(productScope().find((r) => r.id === "coverage")?.status).toBe("supported");
  });

  it("marks the Firebase alerts workflow supported (it publishes through the official path)", () => {
    expect(productScope().find((r) => r.id === "alerts")?.status).toBe("supported");
  });

  it("marks the official Logging emulator supported (the daemon serves its WebSocket)", () => {
    expect(productScope().find((r) => r.id === "logging")?.status).toBe("supported");
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

describe("product scope inventory", () => {
  it("is exactly the documented list, in Overview order", () => {
    expect(productScope()).toEqual([
      { id: "auth", nameKey: "scope.auth", status: "supported", noteKey: "scope.authNote" },
      {
        id: "firestore",
        nameKey: "scope.firestore",
        status: "supported",
        noteKey: "scope.firestoreNote",
      },
      {
        id: "functions",
        nameKey: "scope.functions",
        status: "supported",
        noteKey: "scope.functionsNote",
      },
      {
        id: "storage",
        nameKey: "scope.storage",
        status: "supported",
        noteKey: "scope.storageNote",
      },
      { id: "rules", nameKey: "scope.rules", status: "supported", noteKey: "scope.rulesNote" },
      {
        id: "appCheck",
        nameKey: "scope.appCheck",
        status: "supported",
        noteKey: "scope.appCheckNote",
      },
      { id: "rtdb", nameKey: "scope.rtdb", status: "deferred", noteKey: "scope.rtdbNote" },
      {
        id: "extensions",
        nameKey: "scope.extensions",
        status: "notPlanned",
        noteKey: "scope.extensionsNote",
      },
      {
        id: "requests",
        nameKey: "scope.requests",
        status: "supported",
        noteKey: "scope.requestsNote",
      },
      {
        id: "coverage",
        nameKey: "scope.coverage",
        status: "supported",
        noteKey: "scope.coverageNote",
      },
      { id: "alerts", nameKey: "scope.alerts", status: "supported", noteKey: "scope.alertsNote" },
      {
        id: "logging",
        nameKey: "scope.logging",
        status: "supported",
        noteKey: "scope.loggingNote",
      },
    ]);
  });
});
