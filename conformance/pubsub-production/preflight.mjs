// Capture the fixed read-only preparation requests. The coordinator supplies credentials,
// holds the existing project lock, and owns the private ledger and response persistence.
// Importing this module performs no request and reads no credentials.

const PROJECT = "fireemu-oracle-idp";
const REGION = "us-central1";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ELAPSED_MS = 600000;

export function preflightRequests(projectNumber) {
  if (!/^[0-9]{12,13}$/.test(projectNumber)) throw new Error("invalid project number");
  const services = [
    "pubsub.googleapis.com",
    "eventarc.googleapis.com",
    "eventarcpublishing.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
  ];
  return [
    {
      id: "identity",
      method: "GET",
      url: `https://cloudresourcemanager.googleapis.com/v3/projects/${PROJECT}`,
    },
    ...services.map((service) => ({
      id: `service-${service.split(".")[0]}`,
      method: "GET",
      url: `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services/${service}`,
    })),
    ...["topics", "subscriptions", "snapshots"].map((kind) => ({
      id: kind,
      method: "GET",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/${kind}?pageSize=1000`,
    })),
    {
      id: "channels",
      method: "GET",
      url: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels?pageSize=100`,
    },
    {
      id: "firebase-channel",
      method: "GET",
      url: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels/firebase`,
    },
  ];
}

async function responseBytes(response) {
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error("preflight response byte limit exceeded");
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, size);
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function collectPreflight({
  projectNumber,
  accessToken,
  save,
  clock = Date.now,
  send = (request) => fetch(request.url, request),
}) {
  if (typeof accessToken !== "string" || !accessToken || /[\r\n]/.test(accessToken)) {
    throw new Error("coordinator-supplied access token is required");
  }
  if (typeof save !== "function") throw new Error("private response persistence is required");
  const requests = preflightRequests(projectNumber);
  const started = clock();
  let captured = 0;
  for (const request of requests) {
    if (clock() - started >= MAX_ELAPSED_MS)
      throw new Error("preflight elapsed-time limit exceeded");
    const response = await send({
      ...request,
      redirect: "manual",
      signal: AbortSignal.timeout(30000),
      headers: { authorization: `Bearer ${accessToken}`, "x-goog-user-project": PROJECT },
    });
    const bytes = await responseBytes(response);
    await save({
      ...request,
      status: response.status,
      body: bytes.toString("utf8"),
      bodyBase64: bytes.toString("base64"),
      bodyBytes: bytes.length,
      contentType: response.headers.get("content-type"),
      recordedAt: new Date().toISOString(),
    });
    captured++;
    if (response.status >= 300 && response.status < 400)
      throw new Error("preflight redirect refused");
  }
  return { requests: requests.length, captured };
}
