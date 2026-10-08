import { makePlan, validatePlan, categoryCaps } from "./plan.mjs";

export class Limit extends Error {}
const zero = () => ({ requests: 0, rest: 0, grpc: 0, streams: 0 });
export function createMeter({ now = () => performance.now(), a2 = false, plan = makePlan() } = {}) {
  const admittedPlan = structuredClone(validatePlan(plan)), caps = admittedPlan.caps;
  const begun = now();
  const groups = { G2: zero(), G7: zero() };
  const visited = new Set();
  let cell,
    end,
    requests = 0,
    framesOut = 0,
    framesIn = 0,
    largePublishes = 0,
    smallPublishes = 0;
  let lastClock = begun;
  const time = () => {
    const value = now();
    if (!Number.isFinite(value) || value < lastClock) throw new Limit("monotonic time required");
    lastClock = value;
    return value;
  };
  const remaining = (maintenance = false) => {
    if (!cell) throw new Limit("cell required");
    const reserve = maintenance || a2 ? 0 : caps.cleanupReserveMs;
    const left = Math.floor(
      Math.min(end - reserve, begun + (a2 ? 600000 : caps.sourceWallMs)) - time(),
    );
    if (left <= 0) throw new Limit("cell or source time exhausted");
    return left;
  };
  const api = {
    clock: time,
    enter(value) {
      if (cell) remaining(true);
      if (
        a2
          ? value.group !== "G7"
          : !admittedPlan.cells.some((item) => JSON.stringify(item) === JSON.stringify(value))
      )
        throw new Limit("undeclared cell");
      if (visited.has(value.id)) throw new Limit("cell cannot reopen");
      visited.add(value.id);
      cell = {
        ...value,
        categories: Object.fromEntries(
          Object.keys(categoryCaps(value.group)).map((key) => [key, 0]),
        ),
        out: 0,
        in: 0,
      };
      end = time() + (a2 ? 600000 : caps[value.group].cellMs);
      remaining();
    },
    remaining,
    start(category, transport) {
      const maintenance = category.startsWith("cleanup") || a2;
      remaining(maintenance);
      const limit = categoryCaps(cell.group)[category];
      if (!Number.isSafeInteger(limit) || cell.categories[category] >= limit)
        throw new Limit("category cap exhausted");
      if (
        !["rest", "grpc", "streams"].includes(transport) ||
        (a2 && transport !== "rest") ||
        (!a2 && transport !== (category === "stream" ? "streams" : cell.transport))
      )
        throw new Limit("transport outside cell");
      const group = groups[cell.group],
        groupCaps = caps[cell.group];
      if (
        group.requests >= groupCaps.requests ||
        group[transport] >= groupCaps[transport] ||
        requests >= (a2 ? caps.G7.requests : caps.sourceRequests)
      )
        throw new Limit("request cap exhausted");
      cell.categories[category]++;
      group.requests++;
      group[transport]++;
      requests++;
    },
    frame() {
      throw new Limit("frame scope");
    },
    payload(bytes) {
      const large = false;
      if (
        !Number.isSafeInteger(bytes) ||
        bytes < 0 ||
        bytes > caps[large ? "largeEncodedPayloadBytes" : "smallEncodedPayloadBytes"] ||
        (large ? largePublishes >= caps.largePublishes : smallPublishes >= caps.smallPublishes)
      )
        throw new Limit("publish payload cap exhausted");
      if (large) largePublishes++;
      else smallPublishes++;
    },
    snapshot() {
      return structuredClone({
        requests,
        groups,
        cell,
        framesOut,
        framesIn,
        largePublishes,
        smallPublishes,
      });
    },
  };
  return Object.freeze(api);
}
