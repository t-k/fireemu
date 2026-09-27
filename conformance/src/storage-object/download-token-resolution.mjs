function tokenSet(value) {
  const tokens = value === "" ? [] : typeof value === "string" ? value.split(",") : value;
  if (
    !Array.isArray(tokens) ||
    tokens.length > 64 ||
    tokens.some((token) => typeof token !== "string" || !/^[A-Za-z0-9._~-]{1,512}$/.test(token)) ||
    new Set(tokens).size !== tokens.length
  )
    throw new Error("download token response has an invalid token set");
  return new Set(tokens);
}

function tokensFromEvidence(evidence, bucket, name) {
  if (
    evidence?.response?.status !== 200 ||
    !Buffer.isBuffer(evidence.response.raw) ||
    evidence.response.raw.length > 65536
  )
    throw new Error("download token response is missing or exceeds the capture bound");
  let metadata;
  try {
    metadata = JSON.parse(evidence.response.raw.toString("utf8"));
  } catch {
    throw new Error("download token response is not JSON");
  }
  if (metadata?.bucket !== bucket || metadata.name !== name)
    throw new Error("download token response object identity differs");
  return tokenSet(metadata.downloadTokens);
}

export function resolveFirebaseDownloadToken({ reference, prior, created, bucket, name }) {
  if (
    reference?.kind !== "firebase-download-token" ||
    reference.fromStep !== "create-token" ||
    reference.priorStep !== "after-upload-firebase-metadata" ||
    reference.field !== "downloadTokens" ||
    reference.selection !== "exactly-one-new" ||
    reference.secretHandling !== "private-only"
  )
    throw new Error("download token reference is not the declared private reference");
  const path = `/v0/b/${bucket}/o/${encodeURIComponent(name)}`;
  if (
    prior?.step?.id !== reference.priorStep ||
    prior.step.objectName !== name ||
    prior.step.path !== path ||
    prior.step.method !== "GET" ||
    prior.step.credential !== "admin" ||
    Object.keys(prior.step.query).length !== 0 ||
    created?.step?.id !== reference.fromStep ||
    created.step.objectName !== name ||
    created.step.path !== path ||
    created.step.method !== "POST" ||
    created.step.credential !== "admin" ||
    Object.keys(created.step.query).length !== 1 ||
    created.step.query.create_token !== "true"
  )
    throw new Error("download token evidence is not bound to the owner route");
  const before = tokensFromEvidence(prior, bucket, name);
  const after = tokensFromEvidence(created, bucket, name);
  if ([...before].some((token) => !after.has(token)))
    throw new Error("download token creation removed a prior token");
  const added = [...after].filter((token) => !before.has(token));
  if (added.length !== 1) throw new Error("download token creation did not add exactly one token");
  return added[0];
}

export function assertFirebaseTokenState({ evidence, bucket, name, token, present }) {
  const path = `/v0/b/${bucket}/o/${encodeURIComponent(name)}`;
  if (
    evidence?.step?.dialect !== "firebase" ||
    evidence.step.method !== "GET" ||
    evidence.step.objectName !== name ||
    evidence.step.path !== path ||
    evidence.step.credential !== "admin" ||
    Object.keys(evidence.step.query).length !== 0 ||
    typeof token !== "string" ||
    typeof present !== "boolean"
  )
    throw new Error("download token state evidence has the wrong route");
  if (tokensFromEvidence(evidence, bucket, name).has(token) !== present)
    throw new Error("download token state differs from the declared expectation");
}

export function assertDeletedTokenDenied(response, ownedBytes) {
  if (!Buffer.isBuffer(ownedBytes) || ownedBytes.length === 0 || !Buffer.isBuffer(response?.raw))
    throw new Error("deleted token denial evidence is invalid");
  if (response.status !== 403) throw new Error("deleted token download was not denied");
  if (response.raw.includes(ownedBytes))
    throw new Error("deleted token denial returned owned bytes");
}
