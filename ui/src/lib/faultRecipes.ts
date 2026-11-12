import { err, ok, type Result } from "neverthrow";
import { t, type MessageKey } from "../i18n";

export type FaultMatch = { operation: string; function?: string; eventType?: string; nth?: number };
export type FaultAction =
  | { type: "returnError"; code: string }
  | { type: "delay"; seconds: number }
  | { type: "timeout" }
  | { type: "duplicate"; count: number };
export type FaultPlan = { seed: number; rules: Array<{ match: FaultMatch; action: FaultAction }> };
export type RecipeId =
  | "retryEvent"
  | "duplicateDelivery"
  | "delayAttempt"
  | "timeoutAttempt"
  | "failFirstAttempts";
export const recipeIds: RecipeId[] = [
  "retryEvent",
  "duplicateDelivery",
  "delayAttempt",
  "timeoutAttempt",
  "failFirstAttempts",
];
export const recipeLabels: Record<RecipeId, MessageKey> = {
  retryEvent: "runtime.recipeRetry",
  duplicateDelivery: "runtime.recipeDuplicate",
  delayAttempt: "runtime.recipeDelay",
  timeoutAttempt: "runtime.recipeTimeout",
  failFirstAttempts: "runtime.recipeFailFirst",
};

const validFunction = (name: string) => /^[A-Za-z0-9_-]{1,100}$/.test(name);
const inRange = (n: number, min: number, max: number) =>
  Number.isSafeInteger(n) && n >= min && n <= max;
const plan = (rules: FaultPlan["rules"]): Result<FaultPlan, string> => ok({ seed: 1, rules });

export function retryEvent(name: string, count: number): Result<FaultPlan, string> {
  if (!validFunction(name)) return err(t("runtime.recipeInvalidFunction"));
  if (!inRange(count, 1, 20)) return err(t("runtime.recipeInvalidCount"));
  return plan(
    Array.from({ length: count }, (_, i) => ({
      match: { operation: "functions.invoke", function: name, nth: i + 1 },
      action: { type: "returnError", code: "UNAVAILABLE" },
    })),
  );
}
export function duplicateDelivery(
  name: string,
  copies: number,
  eventType = "",
): Result<FaultPlan, string> {
  if (!validFunction(name)) return err(t("runtime.recipeInvalidFunction"));
  if (!inRange(copies, 1, 100)) return err(t("runtime.recipeInvalidCopies"));
  return plan([
    {
      match: {
        operation: "functions.deliver",
        function: name,
        ...(eventType ? { eventType } : {}),
      },
      action: { type: "duplicate", count: copies },
    },
  ]);
}
export function delayAttempt(
  name: string,
  attempt: number,
  seconds: number,
): Result<FaultPlan, string> {
  if (!validFunction(name)) return err(t("runtime.recipeInvalidFunction"));
  if (!inRange(attempt, 1, Number.MAX_SAFE_INTEGER)) return err(t("runtime.recipeInvalidAttempt"));
  if (!inRange(seconds, 0, 31622400)) return err(t("runtime.recipeInvalidSeconds"));
  return plan([
    {
      match: { operation: "functions.invoke", function: name, nth: attempt },
      action: { type: "delay", seconds },
    },
  ]);
}
export function timeoutAttempt(name: string, attempt: number): Result<FaultPlan, string> {
  if (!validFunction(name)) return err(t("runtime.recipeInvalidFunction"));
  if (!inRange(attempt, 1, Number.MAX_SAFE_INTEGER)) return err(t("runtime.recipeInvalidAttempt"));
  return plan([
    {
      match: { operation: "functions.invoke", function: name, nth: attempt },
      action: { type: "timeout" },
    },
  ]);
}
export function failFirstAttempts(
  operation = "firestore.commit",
  count = 1,
  code = "ABORTED",
): Result<FaultPlan, string> {
  if (!["firestore.commit", "firestore.read", "storage.upload"].includes(operation))
    return err(t("runtime.recipeInvalidOperation"));
  if (!inRange(count, 1, 20)) return err(t("runtime.recipeInvalidCount"));
  if (!code.trim()) return err(t("runtime.recipeInvalidCode"));
  return plan(
    Array.from({ length: count }, (_, i) => ({
      match: { operation, nth: i + 1 },
      action: { type: "returnError", code },
    })),
  );
}
export function testingSnippet(value: FaultPlan): string {
  return `import { withTestWorld } from "fireemu/testing";\nawait withTestWorld({}, async (world) => {\n  await world.control("PUT", "/v1/sessions/default/faultPlan", ${JSON.stringify(value, null, 2)});\n  // ... run the code under test here\n});`;
}
export function controlSnippet(value: FaultPlan): string {
  const json = JSON.stringify(value).replaceAll("'", "'\\''");
  return `curl -sS -X PUT -H "Authorization: Bearer $FIREEMU_CONTROL_TOKEN" -H "content-type: application/json" --data '${json}' "$FIREEMU_CONTROL_URL/v1/sessions/default/faultPlan"`;
}
