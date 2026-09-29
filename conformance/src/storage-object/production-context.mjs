import { isDeepStrictEqual, types } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";

/** Bounded data-only canonical snapshots carry local identity, never production admission. */
export function copyCanonicalProductionStage3Plan(supplied) {
  let units = 0;
  function copy(value, depth = 0) {
    if (depth > 16 || types.isProxy(value) || ++units > 65536) throw new Error();
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error();
      return value;
    }
    if (typeof value === "string") {
      if (value.length > 8192 || !value.isWellFormed() || (units += value.length) > 65536)
        throw new Error();
      return value;
    }
    if (!value || ![Object.prototype, null, Array.prototype].includes(Object.getPrototypeOf(value)))
      throw new Error();
    const names = Reflect.ownKeys(value),
      descriptors = Object.getOwnPropertyDescriptors(value);
    if (Array.isArray(value)) {
      if (
        Object.getPrototypeOf(value) !== Array.prototype ||
        value.length > 64 ||
        names.length !== value.length + 1
      )
        throw new Error();
      return Object.freeze(
        Array.from({ length: value.length }, (_, i) => {
          const d = descriptors[String(i)];
          if (!d?.enumerable || !Object.hasOwn(d, "value")) throw new Error();
          return copy(d.value, depth + 1);
        }),
      );
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error();
    if (
      names.length > 64 ||
      names.some(
        (name) =>
          typeof name !== "string" ||
          name.length > 128 ||
          !descriptors[name].enumerable ||
          !Object.hasOwn(descriptors[name], "value"),
      )
    )
      throw new Error();
    return Object.freeze(
      Object.fromEntries(names.map((name) => [name, copy(descriptors[name].value, depth + 1)])),
    );
  }
  try {
    const plan = copy(supplied);
    if (
      !isDeepStrictEqual(
        plan,
        buildProductionStage3DraftPlan({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runIds: plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error();
    return plan;
  } catch {
    throw new Error("invalid production canonical plan");
  }
}
