// A boundary search for the limits of the publish API, with a bounded number of requests.

/** The number of halvings that pin a boundary inside an interval of `width` values: ceil(log2(width)). */
export function stepsNeeded(width) {
  let steps = 0;
  for (let size = 1; size < width; size *= 2) steps += 1;
  return steps;
}

/**
 * Searches the largest accepted value of a monotone limit. `low` is known to be accepted and `high` to be
 * refused. `accepts(n)` answers true (accepted), false (refused) or null (an answer that does not say:
 * the search ends and nothing is sent again). At most `maxSteps` values are asked, each strictly between
 * the two known ones and none twice. The result is the interval left: `accepted` and `refused`, adjacent
 * when the boundary is pinned.
 */
export async function bisect({ low, high, accepts, maxSteps }) {
  if (!(Number.isSafeInteger(low) && Number.isSafeInteger(high) && low < high))
    throw new Error("low must be below high");
  if (!Number.isSafeInteger(maxSteps) || maxSteps < 1) throw new Error("maxSteps must be at least 1");
  let accepted = low;
  let refused = high;
  let steps = 0;
  while (refused - accepted > 1 && steps < maxSteps) {
    const middle = accepted + Math.floor((refused - accepted) / 2);
    steps += 1;
    const answer = await accepts(middle);
    if (answer === null) return { accepted, refused, steps, unknown: true };
    if (answer) accepted = middle;
    else refused = middle;
  }
  return { accepted, refused, steps, unknown: false };
}

/**
 * Whether the answer to a publish accepted the value: true for a 2xx, false for a refusal (a 4xx other
 * than a request timeout or a rate limit, which say nothing about the value), null for anything that
 * does not say (an unknown answer, a 3xx, a 5xx, a missing answer).
 */
export function acceptance(reply) {
  if (reply === undefined || reply === null || reply.unknown === true) return null;
  const { status } = reply;
  if (!Number.isInteger(status)) return null;
  if (status >= 200 && status < 300) return true;
  if (status >= 400 && status < 500 && status !== 408 && status !== 429) return false;
  return null;
}

/**
 * Walks a rising ladder of values from `start` (known to be accepted) and stops at the first one that is
 * refused: `low` is the last accepted value, `high` the first refused one (null when every value was
 * accepted). An answer that does not say ends the ladder (`unknown`), and nothing is asked twice.
 */
export async function bracket({ start, values, accepts }) {
  const rises =
    values.length > 0 &&
    values[0] > start &&
    values.every((value, index) => index === 0 || value > values[index - 1]);
  if (!rises) throw new Error("the values must rise above the start");
  let low = start;
  for (const value of values) {
    const answer = await accepts(value);
    if (answer === null) return { low, high: null, unknown: true };
    if (!answer) return { low, high: value, unknown: false };
    low = value;
  }
  return { low, high: null, unknown: false };
}
