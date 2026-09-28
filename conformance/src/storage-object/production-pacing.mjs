import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";

const MUTATION_INTERVAL_MS = 1000;

/** Conservatively separate attempts from the previous completion, including failures. */
export function createObjectMutationPacer({
  ownedPrefixes,
  now = () => performance.now(),
  sleep = delay,
}) {
  if (
    !Array.isArray(ownedPrefixes) ||
    ownedPrefixes.length < 1 ||
    ownedPrefixes.length > 2 ||
    ownedPrefixes.some(
      (prefix, index) =>
        typeof prefix !== "string" ||
        prefix.length === 0 ||
        !prefix.endsWith("/") ||
        ownedPrefixes.some((other, otherIndex) => otherIndex !== index && other.startsWith(prefix)),
    ) ||
    typeof now !== "function" ||
    typeof sleep !== "function"
  )
    throw new Error("invalid pacing configuration");
  const prefixes = [...ownedPrefixes];
  const previousAttempts = new Map();
  let active = false;
  let lastClock = -Infinity;
  const clock = () => {
    const value = now();
    if (!Number.isFinite(value) || value < 0 || value < lastClock)
      throw new Error("invalid monotonic clock");
    lastClock = value;
    return value;
  };

  return Object.freeze({
    async dispatch(objectName, attempt) {
      if (
        typeof objectName !== "string" ||
        !prefixes.some(
          (prefix) => objectName.startsWith(prefix) && objectName.length > prefix.length,
        )
      )
        throw new Error("mutation requires an owned object");
      if (typeof attempt !== "function") throw new Error("invalid dispatch callback");
      if (active) throw new Error("mutation dispatch is active");
      active = true;
      try {
        let time = clock();
        const previous = previousAttempts.get(objectName);
        if (previous !== undefined) {
          const deadline = previous + MUTATION_INTERVAL_MS;
          for (let waits = 0; time < deadline && waits < 2; waits++) {
            await sleep(Math.ceil(deadline - time));
            time = clock();
          }
          if (time < deadline) throw new Error("mutation interval not reached");
        }
        previousAttempts.set(objectName, time);
        try {
          return await attempt();
        } finally {
          previousAttempts.set(objectName, clock());
        }
      } finally {
        active = false;
      }
    },
  });
}
