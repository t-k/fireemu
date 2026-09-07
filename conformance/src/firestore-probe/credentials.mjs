// Explicit probe credentials keep privileged setup separate from user requests.
export function selectCredential(spec, { ownerToken, userToken }) {
  const kind = spec.credential ?? (spec.owner === false ? "anonymous" : "owner");
  if (!["owner", "user", "anonymous"].includes(kind)) {
    throw new Error("Unsupported Firestore probe credential");
  }
  if (kind === "anonymous") return { kind, authorization: null };
  const token = kind === "user" ? userToken : ownerToken;
  if (typeof token !== "string" || token.trim() === "") {
    throw new Error(`Missing Firestore probe ${kind} credential`);
  }
  return { kind, authorization: `Bearer ${token}` };
}

// Only the credential class is recorded: no JWT, principal ID or project ID.
export function credentialMetadata(credential) {
  if (!["owner", "user", "anonymous"].includes(credential.kind)) {
    throw new Error("Unsupported Firestore probe credential");
  }
  return { kind: credential.kind };
}

/**
 * Creates exactly one anonymous Auth user, runs the callback, and deletes that user.
 * The callback receives a token in memory only. Cleanup uses that same token rather
 * than project-wide account deletion. No response body is included in errors.
 */
export async function withAnonymousUser({ base, apiKey }, callback) {
  const endpoint = new URL(base);
  if (
    endpoint.protocol !== "https:" &&
    !(
      endpoint.protocol === "http:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
    )
  ) {
    throw new Error("Identity Toolkit requires HTTPS or a local emulator endpoint");
  }
  if (typeof apiKey !== "string" || apiKey.trim() === "") {
    throw new Error("An Identity Toolkit API key is required");
  }
  const request = async (method, body) => {
    const response = await fetch(
      `${base.replace(/\/$/, "")}/v1/accounts:${method}?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
      },
    );
    if (!response.ok)
      throw new Error(`Identity Toolkit ${method} failed (HTTP ${response.status})`);
    return response;
  };
  const created = await (await request("signUp", { returnSecureToken: true })).json();
  if (typeof created.idToken !== "string" || created.idToken.trim() === "") {
    throw new Error("Identity Toolkit signUp returned no ID token");
  }
  try {
    return await callback(created.idToken);
  } finally {
    await request("delete", { idToken: created.idToken });
  }
}
