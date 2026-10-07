// How the native client reads two Firestore answers, kept apart from the gRPC binding so a
// recorded production body can be replayed through it.

/**
 * The answers of a BatchGetDocuments for `names`: each result is `{ found: { name } }` or
 * `{ missing: name }`. A requested name that no result mentions is an incomplete answer, which
 * is unknown and stops the read (it must never read as absent).
 */
export function readBack(names, results) {
  const found = new Set();
  const missing = new Set();
  for (const result of results) {
    if (typeof result?.found?.name === "string") found.add(result.found.name);
    else if (typeof result?.missing === "string") missing.add(result.missing);
  }
  return names.map((name) => {
    if (found.has(name)) return { name, exists: true };
    if (missing.has(name)) return { name, exists: false };
    throw new Error("a BatchGetDocuments answer did not mention a requested name");
  });
}

/** The names in one ListDocuments page whose id starts with `prefix`. */
export function listedNames(page, prefix) {
  return (page?.documents ?? [])
    .map((doc) => doc.name)
    .filter((name) => typeof name === "string" && name.split("/").at(-1).startsWith(prefix));
}
