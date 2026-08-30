// App Check rows for specification sections 17 and 23.
//
// The official Local Emulator Suite has no App Check surface at all: it issues no token, it
// serves no exchange or JWKS route, and it never inspects `X-Firebase-AppCheck`. That is the
// oracle result recorded here, and it is the only App Check fact a local run can establish.
// Everything the rows would need a real project for -- what production denies, which claims a
// production limited-use token carries, which Identity Toolkit methods App Check protects --
// is recorded as `pending` with the reason "needs a real project" and never as an observation.

import { APP_CHECK, VARIANTS } from "../config.mjs";

/** A syntactically well-formed but locally unverifiable token, for the "invalid" column. */
const INVALID_TOKEN = "not-a-token";

/** Obtains a valid App Check token where the side can mint one; null where it cannot. */
async function acquireToken(ctx) {
  if (!ctx.hosts.appCheck) return null;
  const url =
    `http://${ctx.hosts.appCheck}/v1/projects/${ctx.project}` +
    `/apps/${encodeURIComponent(APP_CHECK.appId)}:exchangeDebugToken`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ debugToken: APP_CHECK.debugSecret, limitedUse: false }),
  });
  if (!response.ok) return null;
  const body = await response.json();
  return typeof body.token === "string" ? body.token : null;
}

const readJson = async (response) => {
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { nonJsonBodyLength: text.length };
  }
  return { status: response.status, body };
};

/**
 * The admission decision a matrix row is about: the HTTP status and the canonical error code,
 * never the whole payload. The exact wording of a Firestore, Auth or Storage error belongs to
 * the product's own scenario; recording it again here would turn one message difference into a
 * dozen identical rows and bury the App Check answer.
 */
const admission = async (response) => {
  const { status, body } = await readJson(response);
  return {
    status,
    code: body?.error?.status ?? body?.error?.code ?? null,
    admitted: status >= 200 && status < 400,
  };
};

/** Writes the document the Firestore rows read, through the credential that bypasses App Check. */
async function seedProbeDocument(ctx) {
  const response = await fetch(
    `http://${ctx.hosts.firestore}/v1/projects/${ctx.project}` +
      `/databases/(default)/documents/conf_appcheck?documentId=probe`,
    {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer owner" },
      body: JSON.stringify({ fields: { seeded: { booleanValue: true } } }),
    },
  );
  return { status: response.status };
}

/** Uploads the object the Storage rows read, through the JSON API dialect. */
async function seedProbeObject(ctx) {
  const response = await fetch(
    `http://${ctx.hosts.storage}/upload/storage/v1/b/${ctx.bucket}/o` +
      `?uploadType=media&name=${encodeURIComponent("conf_public/probe.txt")}`,
    {
      method: "POST",
      headers: { "content-type": "text/plain", authorization: "Bearer owner" },
      body: "probe",
    },
  );
  return { status: response.status };
}

/**
 * Runs one request four ways: with no App Check field, with a valid token where the side can
 * mint one, with an unverifiable value, and with two conflicting fields. Each row records the
 * admission decision the product reached, which is what specification section 17 governs.
 */
async function headerMatrix(ctx, label, request) {
  const token = await acquireToken(ctx);
  await ctx.step(`${label}-no-app-check-field`, () => request({}));
  // A side that issues no token cannot present one; the row records that fact next to the
  // result of the same request without the field, which is what the oracle can actually say.
  await ctx.step(`${label}-valid-token`, async () =>
    token === null
      ? { noTokenIssuedBySide: true, ...(await request({})) }
      : request({ "x-firebase-appcheck": token }),
  );
  await ctx.step(`${label}-unverifiable-token`, () =>
    request({ "x-firebase-appcheck": INVALID_TOKEN }),
  );
  await ctx.step(`${label}-duplicate-fields`, () =>
    request({ "x-firebase-appcheck": `${token ?? INVALID_TOKEN}, ${INVALID_TOKEN}` }),
  );
}

const exchangeAndJwks = {
  id: "appcheck/exchange-and-jwks",
  product: "appcheck",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "The debug-token exchange and JWKS routes, and whether the side serves them at all",
  async run(ctx) {
    const base = ctx.hosts.appCheck ?? ctx.hosts.auth;
    const exchangeUrl =
      `http://${base}/v1/projects/${ctx.project}` +
      `/apps/${encodeURIComponent(APP_CHECK.appId)}:exchangeDebugToken`;

    await ctx.step("exchange-a-registered-debug-secret", async () => {
      const { status, body } = await readJson(
        await fetch(exchangeUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ debugToken: APP_CHECK.debugSecret, limitedUse: false }),
        }),
      );
      return { status, keys: Object.keys(body).toSorted(), ttl: body.ttl ?? null };
    });

    await ctx.step("exchange-an-unknown-secret", async () => {
      const { status, body } = await readJson(
        await fetch(exchangeUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ debugToken: "00000000-0000-4000-8000-000000000000" }),
        }),
      );
      return { status, body };
    });

    await ctx.step("exchange-a-limited-use-token", async () => {
      const { status, body } = await readJson(
        await fetch(exchangeUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ debugToken: APP_CHECK.debugSecret, limitedUse: true }),
        }),
      );
      return { status, body };
    });

    await ctx.step("jwks", async () => {
      const { status, body } = await readJson(await fetch(`http://${base}/v1/jwks`));
      return {
        status,
        keyCount: Array.isArray(body.keys) ? body.keys.length : null,
        keyFields:
          Array.isArray(body.keys) && body.keys[0] ? Object.keys(body.keys[0]).toSorted() : null,
      };
    });

    ctx.pending(
      "production-limited-use-token-claims",
      "needs a real project",
      "Section 23 lists the extra claims on a production limited-use token as unresolved debt. " +
        "The official suite issues no App Check token at all, so nothing local can record them.",
    );
  },
};

const unenforcedMatrix = {
  id: "appcheck/unenforced-header-matrix",
  product: "appcheck",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "Every product under a baseline where App Check is present but not enforced",
  async run(ctx) {
    await ctx.step("seed-through-the-owner-credential", () => seedProbeDocument(ctx));
    await ctx.step("seed-a-storage-object-through-the-json-api", () => seedProbeObject(ctx));

    await headerMatrix(ctx, "firestore-rest", (headers) =>
      fetch(
        `http://${ctx.hosts.firestore}/v1/projects/${ctx.project}` +
          `/databases/(default)/documents/conf_appcheck/probe`,
        { headers },
      ).then(admission),
    );

    await headerMatrix(ctx, "auth-signup", (headers) =>
      fetch(
        `http://${ctx.hosts.auth}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`,
        {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ returnSecureToken: true }),
        },
      ).then(admission),
    );

    await headerMatrix(ctx, "storage-metadata", (headers) =>
      fetch(
        `http://${ctx.hosts.storage}/v0/b/${ctx.bucket}/o/${encodeURIComponent(
          "conf_public/probe.txt",
        )}`,
        { headers },
      ).then(admission),
    );

    // A callable that does not enforce still receives whatever app context the side derived.
    await headerMatrix(ctx, "callable-unenforcing", (headers) =>
      fetch(ctx.functionUrl("confWhoAmI"), {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ data: {} }),
      }).then(readJson),
    );

    // A callable declared `enforceAppCheck: true`: the callable option is enforced by the
    // product, not by an emulator-wide switch, so this row is meaningful on both sides.
    await headerMatrix(ctx, "callable-enforcing", (headers) =>
      fetch(ctx.functionUrl("confGuarded"), {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ data: {} }),
      }).then(readJson),
    );

    // An onRequest function owns its own verification and must see the raw field list.
    await headerMatrix(ctx, "on-request", (headers) =>
      fetch(ctx.functionUrl("confEcho"), { headers }).then(readJson),
    );

    ctx.pending(
      "production-enforcement-denials",
      "needs a real project",
      "With enforcement enabled in the console, production denies a missing or invalid token on " +
        "each of these surfaces. The official emulators never enforce App Check, so the exact " +
        "production status, code and message of each denial cannot be recorded locally.",
    );

    ctx.pending(
      "production-protected-identity-toolkit-methods",
      "needs a real project",
      "Section 23 lists the exact set of Identity Toolkit and Secure Token methods App Check " +
        "protects as unresolved debt; the official Auth emulator inspects no App Check field at " +
        "all, so it cannot enumerate that set.",
    );
  },
};

const enforcedMatrix = {
  id: "appcheck/enforced-header-matrix",
  product: "appcheck",
  variant: VARIANTS.appCheckEnforced,
  sdks: ["rest"],
  title:
    "The same matrix with firebase-testd enforcing Firestore, Storage and Auth; the official suite cannot enforce",
  async run(ctx) {
    // Seed through the privileged dialects, which bypass App Check on both sides. Without
    // this the enforced rows could not tell an App Check denial from a plain 404.
    await ctx.step("seed-through-the-owner-credential", () => seedProbeDocument(ctx));
    await ctx.step("seed-a-storage-object-through-the-json-api", () => seedProbeObject(ctx));

    await headerMatrix(ctx, "firestore-rest", (headers) =>
      fetch(
        `http://${ctx.hosts.firestore}/v1/projects/${ctx.project}` +
          `/databases/(default)/documents/conf_appcheck/probe`,
        { headers },
      ).then(admission),
    );

    await headerMatrix(ctx, "auth-signup", (headers) =>
      fetch(
        `http://${ctx.hosts.auth}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`,
        {
          method: "POST",
          headers: { "content-type": "application/json", ...headers },
          body: JSON.stringify({ returnSecureToken: true }),
        },
      ).then(admission),
    );

    await headerMatrix(ctx, "storage-metadata", (headers) =>
      fetch(
        `http://${ctx.hosts.storage}/v0/b/${ctx.bucket}/o/${encodeURIComponent(
          "conf_public/probe.txt",
        )}`,
        { headers },
      ).then(admission),
    );

    await headerMatrix(ctx, "callable-enforcing", (headers) =>
      fetch(ctx.functionUrl("confGuarded"), {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify({ data: {} }),
      }).then(readJson),
    );

    ctx.pending(
      "production-open-stream-when-a-token-expires",
      "needs a real project",
      "Section 23 records the behaviour of an already open Firestore stream whose token expires, " +
        "or whose enforcement changes, as unresolved debt. Neither local side can answer it: the " +
        "official suite never enforces, and firebase-testd's answer is the one under test.",
    );

    ctx.pending(
      "production-storage-download-token-under-enforcement",
      "needs a real project",
      "Whether a public Storage download URL keeps serving while App Check is enforced is listed " +
        "in section 23 as unresolved debt and needs a real bucket to settle.",
    );
  },
};

export const scenarios = [exchangeAndJwks, unenforcedMatrix, enforcedMatrix];
