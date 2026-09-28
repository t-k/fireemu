function plainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

/** Validate a declaration before resolving secrets or admitting any HTTP request. */
export function validateProductionCredentialDeclaration(step, options = {}) {
  try {
    if (!plainObject(options)) throw new Error("invalid credential inventory");
    const { accountRefs = [] } = options;
    if (
      !plainObject(step) ||
      !Array.isArray(accountRefs) ||
      accountRefs.some(
        (ref) =>
          typeof ref !== "string" ||
          !/^owned-account:[a-z0-9]{8,32}:(authorization-errors|firebase-id-token):(valid|competitor)$/.test(
            ref,
          ),
      ) ||
      new Set(accountRefs).size !== accountRefs.length
    )
      throw new Error("invalid declaration");
    const headers = step.headers;
    if (
      headers !== undefined &&
      (!plainObject(headers) ||
        Object.keys(headers).some((name) => name.toLowerCase() === "authorization"))
    )
      throw new Error("prefilled authorization");
    const direct = Object.hasOwn(step, "credential");
    const reference = Object.hasOwn(step, "credentialRef");
    if (direct === reference) throw new Error("missing or ambiguous declaration");
    if (direct) {
      const credential = step.credential;
      if (!["admin", "owner", "none"].includes(credential)) throw new Error("unknown credential");
      return Object.freeze({ credential: credential === "none" ? "none" : "admin" });
    }
    const ref = step.credentialRef;
    if (!plainObject(ref) || !Object.hasOwn(ref, "kind")) throw new Error("unknown reference");
    const kind = ref.kind;
    if (kind === "anonymous" || kind === "malformed") {
      if (Object.keys(ref).length !== 1) throw new Error("ambiguous reference");
      return kind === "anonymous"
        ? Object.freeze({ credential: "none" })
        : Object.freeze({ credentialRef: Object.freeze({ kind: "malformed" }) });
    }
    const accountRef = ref.accountRef;
    if (
      !["valid", "competitor"].includes(kind) ||
      Object.keys(ref).length !== 2 ||
      !Object.hasOwn(ref, "accountRef") ||
      !accountRefs.includes(accountRef) ||
      !accountRef.endsWith(`:${kind}`)
    )
      throw new Error("unbound reference");
    return Object.freeze({
      credentialRef: Object.freeze({ kind, accountRef }),
    });
  } catch {
    throw new Error("explicit production credential is required");
  }
}
