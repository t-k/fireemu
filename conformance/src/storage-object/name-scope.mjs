export function assertNameScopePageExhaustion(step, nextPageToken, policy) {
  if (!step.collection || step.scopePrefix !== policy.scopePrefix) return;
  const match = /-page-(\d+)$/.exec(step.id);
  if (!match) return;
  const index = Number(match[1]);
  if (!Number.isSafeInteger(index) || index >= policy.maxPages)
    throw new Error("name-scope page exceeds the declared limit");
  if (
    policy.exhaustedOnlyWhenNoNextPageToken &&
    index === policy.maxPages - 1 &&
    nextPageToken !== null
  )
    throw new Error("name-scope list is not exhausted within the declared page limit");
}

export function listedNameScopeEntries(body, { bucket, scopePrefix }) {
  const items = body.items ?? [];
  const prefixes = body.prefixes ?? [];
  const names = items.map((item) => {
    if (
      !item ||
      typeof item !== "object" ||
      Array.isArray(item) ||
      (item.bucket !== undefined && item.bucket !== bucket) ||
      typeof item.name !== "string" ||
      !item.name.startsWith(scopePrefix)
    )
      throw new Error("name-scope list contains an invalid object entry");
    return item.name;
  });
  if (prefixes.some((entry) => typeof entry !== "string" || !entry.startsWith(scopePrefix)))
    throw new Error("name-scope list contains an invalid prefix entry");
  return { names, prefixes };
}

export function assertAcceptedNamesListed(listedNames, acceptedNames) {
  const expected = new Set();
  for (const name of acceptedNames) {
    const encoded = encodeURI(name);
    if (!listedNames.has(name) && !listedNames.has(encoded))
      throw new Error("accepted malformed name is missing from the complete name-scope list");
    expected.add(name);
    expected.add(encoded);
  }
  if ([...listedNames].some((name) => !expected.has(name)))
    throw new Error("name-scope list contains an unowned name or alternate representation");
}
