/** Local ownership evidence for one run prefix; this module performs no HTTP requests. */
export function createRunOwnership({ bucket, prefix } = {}) {
  if (
    typeof bucket !== "string" ||
    !/^[a-z0-9][a-z0-9.-]{1,220}[a-z0-9]$/.test(bucket) ||
    typeof prefix !== "string" ||
    !/^storage-object\/[a-z0-9]{8,32}\/$/.test(prefix)
  )
    throw new Error("invalid owned bucket or run prefix");
  let namespaceEmpty = false;
  const objects = new Map();

  function checkName(name) {
    if (
      typeof name !== "string" ||
      !name.startsWith(prefix) ||
      name.length === prefix.length ||
      name.slice(prefix.length).split("/").some((part) => part === "." || part === "..")
    )
      throw new Error("object name is outside the owned run prefix");
  }

  function checkEmptyPages(input) {
    if (input?.bucket !== bucket) throw new Error("wrong bucket for owned run");
    if (input.prefix !== prefix) throw new Error("wrong run prefix");
    const pages = input.pages;
    if (!Array.isArray(pages) || pages.length === 0)
      throw new Error("incomplete prefix traversal");
    for (const [index, page] of pages.entries()) {
      if (!Array.isArray(page?.items)) throw new Error("incomplete prefix traversal");
      if (page.items.length > 0) throw new Error("occupied run prefix");
      const token = page.nextPageToken;
      if (index < pages.length - 1) {
        if (typeof token !== "string" || token.length === 0)
          throw new Error("incomplete prefix traversal");
      } else if (token !== null && token !== undefined && token !== "")
        throw new Error("incomplete prefix traversal");
    }
    return true;
  }

  function validGeneration(value) {
    return (
      typeof value === "string" &&
      /^[1-9]\d{0,19}$/.test(value) &&
      BigInt(value) <= 18_446_744_073_709_551_615n
    );
  }

  return {
    assertInitialEmpty(input) {
      checkEmptyPages(input);
      namespaceEmpty = true;
      return true;
    },
    noteInitialAbsent(name, evidence) {
      checkName(name);
      if (!namespaceEmpty) throw new Error("initial run prefix absence is unproved");
      if (objects.has(name)) throw new Error("initial object absence was already recorded");
      if (
        evidence?.metadataStatus !== 404 ||
        evidence.mediaStatus !== 404 ||
        evidence.prefixPagesComplete !== true ||
        evidence.nameFound !== false
      )
        throw new Error("initial object absence is unproved");
      objects.set(name, { state: "absent", operationId: null, generation: null, bytesSha256: null });
      return true;
    },
    noteInitialAbsentFromNamespace(name) {
      checkName(name);
      if (!namespaceEmpty) throw new Error("initial run prefix absence is unproved");
      if (objects.has(name)) throw new Error("initial object absence was already recorded");
      objects.set(name, { state: "absent", operationId: null, generation: null, bytesSha256: null });
      return true;
    },
    noteMutationAttempt(name, operationId) {
      checkName(name);
      const object = objects.get(name);
      if (!object || object.state === "pending" || object.state === "deleted")
        throw new Error("object mutation has no owned initial state");
      if (typeof operationId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(operationId))
        throw new Error("invalid mutation operation ID");
      object.state = "pending";
      object.operationId = operationId;
    },
    observeOwnedGeneration(name, response, expectedBytesSha256) {
      checkName(name);
      const object = objects.get(name);
      if (!object || object.state !== "pending" || response?.operationId !== object.operationId)
        throw new Error("write response is not bound to a pending owned mutation");
      if (response.bucket !== bucket || response.name !== name || !validGeneration(response.generation))
        throw new Error("write response has wrong owned object or generation");
      if (
        typeof expectedBytesSha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(expectedBytesSha256) ||
        response.bytesSha256 !== expectedBytesSha256
      )
        throw new Error("owned object bytes are unverified");
      object.state = "written";
      object.generation = response.generation;
      object.bytesSha256 = expectedBytesSha256;
    },
    cleanupRequest(name, current) {
      checkName(name);
      const object = objects.get(name);
      if (!object || object.state !== "written")
        throw new Error("object write is uncertain or unverified");
      if (current?.bucket !== bucket || current.name !== name)
        throw new Error("cleanup readback has wrong owned object");
      if (current.generation !== object.generation)
        throw new Error("cleanup generation no longer matches owned generation");
      if (current.bytesSha256 !== object.bytesSha256)
        throw new Error("cleanup bytes no longer match owned bytes");
      object.state = "cleanup-requested";
      return { method: "DELETE", bucket, name, query: { ifGenerationMatch: object.generation } };
    },
    noteDeleted(name, result) {
      checkName(name);
      const object = objects.get(name);
      if (!object || object.state !== "cleanup-requested")
        throw new Error("no owned cleanup request for object");
      if (result?.status !== 204 || result.metadataStatus !== 404 || result.mediaStatus !== 404)
        throw new Error("owned object deletion is unverified");
      object.state = "deleted";
    },
    unresolved() {
      return [...objects.entries()]
        .filter(([, object]) => !["absent", "deleted"].includes(object.state))
        .map(([name]) => name)
        .sort();
    },
    verifyEmpty(input) {
      if ([...objects.values()].some((object) => !["absent", "deleted"].includes(object.state)))
        throw new Error("unresolved owned object responsibility");
      return checkEmptyPages(input);
    },
  };
}
