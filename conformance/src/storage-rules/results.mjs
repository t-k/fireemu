// The controller's clean terminal results. Only an object the controller itself returned for a run that finished or a recovery
// that was proven is registered here, by identity and together with the controller that returned it, so a result built by a
// caller (an object that merely says `status: "finished"`) or one taken from another controller can never confirm a close and
// release the project locks.
const clean = new WeakMap();

/** Register a controller result as a clean terminal one (finished, or recovered with the owned prefix proven) of `owner`. */
export function markCleanResult(result, owner) {
  if (result === null || typeof result !== "object" || !Object.isFrozen(result) || !["finished", "recovered"].includes(result.status) || owner === null || typeof owner !== "object") throw new Error("not a clean result");
  clean.set(result, owner);
  return result;
}

export const isCleanResult = (result, owner) => result !== null && typeof result === "object" && owner !== null && typeof owner === "object" && clean.get(result) === owner;
