import { describe, expect, it } from "vitest";
import {
  retryEvent,
  duplicateDelivery,
  delayAttempt,
  timeoutAttempt,
  failFirstAttempts,
  testingSnippet,
  controlSnippet,
  type FaultPlan,
} from "./faultRecipes";

const allowed: Record<string, string[]> = {
  "functions.invoke": [
    "returnError",
    "delay",
    "timeout",
    "deadLetter",
    "crashRunner",
    "dropConnection",
  ],
  "functions.deliver": ["duplicate"],
  "firestore.commit": ["returnError", "delay", "timeout", "transactionConflict", "dropConnection"],
  "firestore.read": ["returnError", "delay", "timeout", "dropConnection"],
  "firestore.beginTransaction": ["returnError", "delay", "timeout", "dropConnection"],
  "storage.upload": ["returnError", "delay", "timeout", "transactionConflict", "dropConnection"],
  "storage.read": ["returnError", "delay", "timeout", "dropConnection"],
  "storage.delete": ["returnError", "delay", "timeout", "dropConnection"],
  "storage.list": ["returnError", "delay", "timeout", "dropConnection"],
  "storage.request": ["returnError", "delay", "timeout", "dropConnection"],
};

function check(plan: FaultPlan, count: number) {
  expect(plan.seed).toBe(1);
  expect(plan.rules).toHaveLength(count);
  for (const rule of plan.rules) {
    expect(allowed[rule.match.operation]).toContain(rule.action.type);
    if (rule.match.nth !== undefined) expect(rule.match.nth).toBeGreaterThanOrEqual(1);
    if (rule.action.type === "delay") {
      expect(rule.action.seconds).toBeGreaterThanOrEqual(0);
      expect(rule.action.seconds).toBeLessThanOrEqual(31622400);
    }
    if (rule.action.type === "duplicate") {
      expect(rule.action.count).toBeGreaterThanOrEqual(1);
      expect(rule.action.count).toBeLessThanOrEqual(100);
    }
    if (rule.action.type === "returnError") expect(rule.action.code.length).toBeGreaterThan(0);
  }
}

describe("fault recipes", () => {
  it("builds plans with supported wire rules and counts", () => {
    const plans = [
      retryEvent("worker", 3),
      duplicateDelivery("worker", 2, "created"),
      delayAttempt("worker", 2, 4),
      timeoutAttempt("worker", 1),
      failFirstAttempts("firestore.commit", 3, "ABORTED"),
    ];
    plans.forEach((result, i) => {
      expect(result.isOk()).toBe(true);
      if (result.isOk()) check(result.value, [3, 1, 1, 1, 3][i]!);
    });
    const duplicate = duplicateDelivery("worker", 1, "")._unsafeUnwrap();
    expect(duplicate.rules[0]!.match).not.toHaveProperty("eventType");
    expect(
      retryEvent("worker", 2)
        ._unsafeUnwrap()
        .rules.map((r) => r.match.nth),
    ).toEqual([1, 2]);
  });
  it("rejects invalid inputs with messages", () => {
    const invalid = [
      retryEvent("", 1),
      retryEvent("bad name", 1),
      retryEvent("x", 0),
      retryEvent("x", 21),
      duplicateDelivery("x", 0),
      duplicateDelivery("x", 101),
      delayAttempt("x", 1, -1),
      delayAttempt("x", 1, 31622401),
      timeoutAttempt("x", 0),
      failFirstAttempts("unknown", 1, "ABORTED"),
      failFirstAttempts("firestore.read", 1, ""),
      failFirstAttempts("firestore.read", 1, "   "),
    ];
    for (const result of invalid) {
      expect(result.isErr()).toBe(true);
      if (result.isErr()) expect(result.error.length).toBeGreaterThan(0);
    }
  });
  it("keeps the event type of a duplicate rule when one is named", () => {
    const named = duplicateDelivery(
      "orders",
      2,
      "google.cloud.firestore.document.v1.written",
    )._unsafeUnwrap();
    expect(named.rules[0]?.match).toEqual({
      operation: "functions.deliver",
      function: "orders",
      eventType: "google.cloud.firestore.document.v1.written",
    });
    const unnamed = duplicateDelivery("orders", 2)._unsafeUnwrap();
    expect(unnamed.rules[0]?.match).not.toHaveProperty("eventType");
  });
  it("embeds the same plan in both snippets", () => {
    const plan = failFirstAttempts("storage.upload", 2, "ABOR'TED")._unsafeUnwrap();
    const testing = testingSnippet(plan);
    const json = JSON.stringify(plan, null, 2);
    expect(testing).toContain(json);
    expect(
      JSON.parse(testing.slice(testing.indexOf(json), testing.indexOf(json) + json.length)),
    ).toEqual(plan);
    const shell = controlSnippet(plan);
    const encoded = JSON.stringify(plan).replaceAll("'", "'\\''");
    expect(shell).toContain(`--data '${encoded}'`);
    expect(JSON.parse(encoded.replaceAll("'\\''", "'"))).toEqual(plan);
  });
});
