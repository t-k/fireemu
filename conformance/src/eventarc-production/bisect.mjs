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
  if (!Number.isSafeInteger(maxSteps) || maxSteps < 1)
    throw new Error("maxSteps must be at least 1");
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

const errorOf = (reply) => reply?.body?.error;

/**
 * The recorded answer that refuses an event count (stage A r2 rows 59 to 61): a 400 `OUT_OF_RANGE`,
 * "Too many events.".
 */
export const isCountRefusal = (reply) =>
  reply?.status === 400 &&
  errorOf(reply)?.status === "OUT_OF_RANGE" &&
  errorOf(reply)?.message === "Too many events.";

/**
 * The recorded answer that refuses an event's size (r2 rows 63 to 65): a 400 `INVALID_ARGUMENT`, "The event
 * size (N bytes) is too large. The maximum size is M bytes.".
 */
export const isSizeRefusal = (reply) =>
  reply?.status === 400 &&
  errorOf(reply)?.status === "INVALID_ARGUMENT" &&
  /^The event size \(\d+ bytes\) is too large\. The maximum size is \d+ bytes\.$/.test(
    errorOf(reply)?.message ?? "",
  );

/**
 * The recorded answer that refuses the number of attributes (stage B, row 148): a 400 `INVALID_ARGUMENT`,
 * "There are too many attributes in the request. The request contains N attributes, but the maximum
 * allowed is M. Refer to ...".
 */
export const isAttributeCountRefusal = (reply) =>
  reply?.unknown !== true &&
  reply?.status === 400 &&
  errorOf(reply)?.status === "INVALID_ARGUMENT" &&
  /^There are too many attributes in the request\. The request contains \d+ attributes, but the maximum allowed is \d+\. /.test(
    errorOf(reply)?.message ?? "",
  );

/**
 * The recorded answer that refuses the size of an attribute's key (stage B, row 149): a 400
 * `INVALID_ARGUMENT`, `The attribute "<key>" in the request has a key that is too large. The size is N
 * bytes, but the maximum allowed is M. Refer to ...`.
 */
export const isAttributeKeyRefusal = (reply) =>
  reply?.unknown !== true &&
  reply?.status === 400 &&
  errorOf(reply)?.status === "INVALID_ARGUMENT" &&
  /^The attribute ".*" in the request has a key that is too large\. The size is \d+ bytes, but the maximum allowed is \d+\. /s.test(
    errorOf(reply)?.message ?? "",
  );

/**
 * Whether the answer to a publish accepted the value: true for a 2xx, false only for `isRefusal`, the
 * recorded answer of the limit under search, and null for anything else (an unknown answer, a 3xx, a 5xx,
 * a missing channel, a permission error, any other 4xx): such an answer says nothing about the value and
 * ends the search.
 */
export function acceptance(reply, isRefusal) {
  if (reply === undefined || reply === null || reply.unknown === true) return null;
  const { status } = reply;
  if (!Number.isInteger(status)) return null;
  if (status >= 200 && status < 300) return true;
  return isRefusal(reply) ? false : null;
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
