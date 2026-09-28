/** Count every network attempt, including seeding and public-API cleanup. */
export function createRequestBudget(limit) {
  if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) {
    throw new Error("request cap must be an integer between 1 and 10000");
  }
  let used = 0;
  return Object.freeze({
    claim() {
      if (used >= limit) throw new Error("request cap reached before network send");
      used += 1;
      return used;
    },
    count: () => used,
  });
}
