// Real dependencies of the signed PUT observer: the network, the Admin SDK signer, the credentials.
// Kept apart from observe.mjs so the tests never load the SDK or touch a credential.

import { Buffer } from "node:buffer";
import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { createRequire } from "node:module";

import { cert, deleteApp, initializeApp } from "firebase-admin/app";
import { getStorage } from "firebase-admin/storage";

import { isUnknownStatus } from "./guard.mjs";
import { BUCKET, PROJECT, RANGE_HEADER } from "./plan.mjs";

const requireHere = createRequire(import.meta.url);

/** fetch with no redirect following; status, lower-case headers and the exact body bytes. */
export async function fetchNet({ method, url, headers, body, timeoutMs }) {
  const init = { method, headers, redirect: "manual", signal: AbortSignal.timeout(timeoutMs) };
  if (body !== undefined) init.body = body;
  const response = await fetch(url, init);
  const bytes = Buffer.from(await response.arrayBuffer());
  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body: bytes,
  };
}

function signedUrlOptions(spec) {
  const options = {
    version: "v4",
    action: "write",
    expires: spec.expires,
    ...(spec.accessibleAt === undefined ? {} : { accessibleAt: spec.accessibleAt }),
    ...(spec.contentType ? { contentType: spec.contentType } : {}),
    ...(spec.range ? { extensionHeaders: { [RANGE_HEADER]: spec.range } } : {}),
  };
  return options;
}

/**
 * Throws on any outbound http/https request to a host outside `hosts`. The SDKs open sockets
 * through these modules; fetch (used only by `fetchNet`, after the observer's own guard) does not.
 */
export function installEgressGuard(hosts) {
  const allowed = new Set(hosts);
  for (const module of [http, https]) {
    for (const name of ["request", "get"]) {
      const original = module[name];
      module[name] = function guarded(first, ...rest) {
        const host =
          typeof first === "string" || first instanceof URL
            ? new URL(first).hostname
            : (first.hostname ?? first.host ?? "").replace(/:\d+$/, "");
        if (!allowed.has(host)) throw new Error(`egress refused: ${host}`);
        return original.call(this, first, ...rest);
      };
    }
  }
}

/**
 * Production: the owner's user ADC access token is the source credential; the Admin SDK's
 * `File#getSignedUrl` signs through IAM Credentials signBlob of the signer service account (no
 * key file). Every request the SDKs make goes through the source client's transporter, which
 * reports to the observer's meter, takes the project lock lease and disables SDK retries.
 */
export function createProductionDeps({ accessToken, lease, transport, signer }) {
  const storageDir = createRequire(requireHere.resolve("firebase-admin"));
  const storagePath = storageDir.resolve("@google-cloud/storage");
  const auth = createRequire(storagePath)("google-auth-library");
  const source = new auth.OAuth2Client();
  source.setCredentials({ access_token: accessToken });
  source.quotaProjectId = PROJECT;
  let meter = null;
  let label = "sdk";
  const transporter = source.transporter;
  // `transport` replaces the network in the tests of the SDK paths.
  const original = transport ?? transporter.request.bind(transporter);
  transporter.request = async (options) => {
    if (!meter) throw new Error("an SDK request outside an observer step");
    const request = {
      method: options.method ?? "GET",
      url: String(options.url),
      headers: options.headers,
    };
    meter.request(label, request);
    await lease.verifyHeld();
    // A definitive HTTP error (a 4xx from the signer) is an answer, not a failed
    // dispatch; only a transport failure or an unknown status keeps the lock.
    let outcome;
    try {
      outcome = await lease.dispatch(async () => {
        try {
          return {
            response: await original({ ...options, retry: false, retryConfig: { retry: 0 } }),
          };
        } catch (error) {
          const status = error?.response?.status;
          if (Number.isInteger(status) && !isUnknownStatus(status)) return { error, status };
          throw error;
        }
      });
    } catch (error) {
      meter.after(label, error?.response?.status ?? Number.NaN);
      throw error;
    }
    meter.after(label, outcome.response?.status ?? outcome.status);
    if (outcome.error) throw outcome.error;
    return outcome.response;
  };
  const impersonated = new auth.Impersonated({
    sourceClient: source,
    targetPrincipal: signer,
    targetScopes: ["https://www.googleapis.com/auth/cloud-platform"],
    lifetime: 300,
  });
  const app = initializeApp(
    { projectId: PROJECT, storageBucket: BUCKET },
    `signed-put-${process.pid}`,
  );
  const signing = getStorage(app).bucket(BUCKET);
  signing.storage.authClient = new auth.GoogleAuth({ authClient: impersonated });
  const within = async (name, meterForStep, work) => {
    meter = meterForStep;
    label = name;
    try {
      return await work();
    } finally {
      meter = null;
    }
  };
  return {
    adminHeaders: () => ({
      authorization: `Bearer ${accessToken}`,
      "x-goog-user-project": PROJECT,
    }),
    net: async (request) => {
      await lease.verifyHeld();
      return lease.dispatch(() => fetchNet(request));
    },
    sign: (spec, stepMeter) =>
      within(
        "signBlob",
        stepMeter,
        async () => (await signing.file(spec.name).getSignedUrl(signedUrlOptions(spec)))[0],
      ),
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    close: () => deleteApp(app),
  };
}

/**
 * Local dry run against fireemu: the same SDK call, a synthetic key, the emulator's origin. Run it
 * under `fireemu exec --only storage -- node run.mjs record-local`.
 */
export function createLocalDeps({ origin, bucket, project }) {
  process.env.STORAGE_EMULATOR_HOST ??= origin;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const app = initializeApp(
    {
      credential: cert({
        projectId: project,
        clientEmail: `fixture@${project}.iam.gserviceaccount.com`,
        privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
      }),
      storageBucket: bucket,
    },
    `signed-put-local-${process.pid}`,
  );
  const files = getStorage(app).bucket(bucket);
  return {
    adminHeaders: () => ({}),
    net: fetchNet,
    sign: async (spec) => (await files.file(spec.name).getSignedUrl(signedUrlOptions(spec)))[0],
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    close: () => deleteApp(app),
  };
}
