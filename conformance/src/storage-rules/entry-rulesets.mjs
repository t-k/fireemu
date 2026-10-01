// The rulesets production holds on the query project when a recording starts, by name and service: the storage ruleset that stage 2c-pre deliberately kept
// (the bucket release that pointed at it is removed for the recording and published again after it) and the project's Firestore ruleset. The entry list must
// be exactly these two, so an unknown ruleset (or a missing one) stops the run before anything is written, and the final list must be exactly these two again,
// so a ruleset the run leaves behind, or one another party adds meanwhile, is seen. The run deletes only rulesets it created itself; these two are never touched.
export const ENTRY_RULESETS = Object.freeze([
  Object.freeze({ name: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8", services: Object.freeze(["firebase.storage"]) }),
  Object.freeze({ name: "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1", services: Object.freeze(["cloud.firestore"]) }),
]);
const equalLists = (left, right) => Array.isArray(left) && left.length === right.length && left.every((entry, index) => entry === right[index]);

/** Whether the rulesets a list page reported (sorted by name, each with its sorted services) are exactly the known two. */
export const isEntryList = (listed) => Array.isArray(listed) && listed.length === ENTRY_RULESETS.length && listed.every((entry, index) => entry?.name === ENTRY_RULESETS[index].name && equalLists(entry.services, ENTRY_RULESETS[index].services));
