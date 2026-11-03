// A synthetic Cloud Storage for the tests of the signed PUT observer. It is NOT a production
// recording: the XML error codes and message texts are the ones the public documentation names,
// and the V4 "signature" is a digest, not RSA. What it does reproduce is the request-shape rules
// the observer must satisfy: a PUT must repeat every signed header with its signed value, an
// unsigned x-goog-* header is refused, the content-length range is enforced, a URL past its
// lifetime is expired, and a write needs the same fields the real API requires.

import { createHash } from "node:crypto";

import { ROLE_ID } from "./plan.mjs";

const xmlError = (code, message) =>
  Buffer.from(
    `<?xml version='1.0' encoding='UTF-8'?><Error><Code>${code}</Code><Message>${message}</Message></Error>`,
  );

export const fakeSignature = (canonical) =>
  createHash("sha256").update(canonical).digest("hex").repeat(8);

function parseDate(text) {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(text ?? "");
  return m ? Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : Number.NaN;
}

const formatDate = (ms) =>
  new Date(ms)
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");

/**
 * @param {object} options
 * @param {{now(): number, sleep(ms): Promise<void>}} options.clock a virtual clock
 * @param {object} [options.faults] `{ [label-substring]: answer | "transport" }` overrides the
 *   answer of the first matching request (an `{status, body?}` or the string "transport")
 */
export function createFakeWorld({
  target,
  clock,
  faults = {},
  lenient = false,
  hideFromList = new Set(),
  intercept = () => undefined,
  iam: iamOptions = {},
}) {
  const iamConfig = {
    member: IAM_CONFIG.member,
    propagationMs: 0,
    initialPolicy: { etag: "etag-0" },
    projectBindings: [
      {
        role: "roles/firebase.sdkAdminServiceAgent",
        members: [`serviceAccount:${target.signer}`],
      },
    ],
    bucketBindings: [],
    predefinedRoles: {
      "firebase.sdkAdminServiceAgent": [
        "storage.objects.create",
        "storage.objects.get",
        "storage.objects.delete",
        "storage.objects.list",
      ],
    },
    ...iamOptions,
  };
  const iamState = {
    policy: structuredClone(iamConfig.initialPolicy),
    roles: new Map(),
    appliedAt: 0,
    etagCounter: 0,
  };
  const roleKey = `projects/${target.project}/roles/${ROLE_ID}`;
  const objects = new Map();
  const log = [];
  let generation = 1000;
  const origin = target.name === "production" ? "https://storage.googleapis.com" : target.origin;

  const json = (status, value, extra = {}) => ({
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      date: new Date(clock.now()).toUTCString(),
      ...extra,
    },
    body: Buffer.from(JSON.stringify(value)),
  });
  const notFound = () => json(404, { error: { code: 404, message: "No such object." } });

  function xmlPut(url, request) {
    const params = url.searchParams;
    const signature = params.get("X-Goog-Signature");
    if (!signature && !lenient)
      return {
        status: 403,
        headers: {},
        body: xmlError("MissingSecurityHeader", "Your request was missing a required header."),
      };
    const signedHeaders = (params.get("X-Goog-SignedHeaders") ?? "").split(";");
    const headers = Object.fromEntries(
      Object.entries(request.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
    );
    const issued = parseDate(params.get("X-Goog-Date"));
    const lifetime = Number(params.get("X-Goog-Expires")) * 1000;
    if (!lenient && (!(lifetime >= 1000) || Number.isNaN(issued))) {
      return { status: 400, headers: {}, body: xmlError("InvalidArgument", "Invalid argument.") };
    }
    if (!lenient && clock.now() > issued + lifetime) {
      return { status: 400, headers: {}, body: xmlError("ExpiredToken", "Invalid argument.") };
    }
    const unsignedGoog = Object.keys(headers).filter(
      (h) => h.startsWith("x-goog-") && !signedHeaders.includes(h),
    );
    const stringToSign = JSON.stringify({
      method: "PUT",
      path: url.pathname,
      query: [...params.entries()].filter(([k]) => k !== "X-Goog-Signature").toSorted(),
      headers: signedHeaders.filter((h) => h !== "host").map((h) => [h, headers[h] ?? null]),
    });
    if (!lenient && (signature !== fakeSignature(stringToSign) || unsignedGoog.length)) {
      return {
        status: 403,
        headers: { "content-type": "application/xml; charset=UTF-8" },
        body: xmlError(
          "SignatureDoesNotMatch",
          "The request signature we calculated does not match the signature you provided.",
        ),
      };
    }
    const range = headers["x-goog-content-length-range"];
    if (range !== undefined && !lenient) {
      const [min, max] = range.split(",").map(Number);
      const length = request.body?.length ?? 0;
      if (length > max)
        return {
          status: 400,
          headers: {},
          body: xmlError(
            "EntityTooLarge",
            "Your proposed upload exceeds the maximum allowed object size.",
          ),
        };
      if (length < min)
        return {
          status: 400,
          headers: {},
          body: xmlError(
            "EntityTooSmall",
            "Your proposed upload is smaller than the minimum allowed object size.",
          ),
        };
    }
    const name = decodeURIComponent(url.pathname.split("/").slice(2).join("/"));
    generation += 1;
    objects.set(name, {
      name,
      generation: String(generation),
      body: Buffer.from(request.body ?? []),
      contentType: headers["content-type"] ?? "application/octet-stream",
    });
    return {
      status: 200,
      headers: { etag: '"x"', "x-goog-generation": String(generation), "content-length": "0" },
      body: Buffer.alloc(0),
    };
  }

  async function net(request) {
    const url = new URL(request.url);
    log.push({ method: request.method, url: request.url, headers: request.headers ?? {} });
    const headersIn = Object.fromEntries(
      Object.entries(request.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
    );
    const custom = intercept(request, log);
    if (custom === "transport") throw new Error("socket hang up");
    if (custom) return { headers: {}, body: Buffer.alloc(0), ...custom };
    for (const [needle, fault] of Object.entries(faults)) {
      if (request.url.includes(needle) || `${request.method} ${url.pathname}`.includes(needle)) {
        delete faults[needle];
        if (fault === "transport") throw new Error("socket hang up");
        return { headers: {}, body: Buffer.alloc(0), ...fault };
      }
    }
    const segments = url.pathname.split("/").slice(1);
    const isSigned = url.searchParams.has("X-Goog-Algorithm");
    if (isSigned && headersIn.authorization !== undefined) {
      throw new Error("a signed request must not carry credentials");
    }
    if (!isSigned && target.name === "production" && headersIn.authorization === undefined) {
      return json(401, { error: { code: 401, message: "Invalid Credentials" } });
    }
    const iamAnswer = iamRequest(url, request, segments);
    if (iamAnswer) return iamAnswer;
    if (segments[0] === "storage") {
      if (segments.length === 4) return json(200, { name: target.bucket });
      if (segments.length === 5 && segments[4] === "iam") {
        return json(200, {
          kind: "storage#policy",
          etag: "b-etag",
          bindings: iamConfig.bucketBindings,
        });
      }
      if (segments.length === 5) {
        const prefix = url.searchParams.get("prefix") ?? "";
        const items = [...objects.values()]
          .filter((o) => o.name.startsWith(prefix) && !hideFromList.has(o.name))
          .map((o) => ({ name: o.name, generation: o.generation }));
        return json(
          200,
          items.length ? { kind: "storage#objects", items } : { kind: "storage#objects" },
        );
      }
      const name = decodeURIComponent(segments[5]);
      const object = objects.get(name);
      if (request.method === "DELETE") {
        const precondition = url.searchParams.get("ifGenerationMatch");
        if (!object) return notFound();
        if (precondition && precondition !== object.generation)
          return json(412, { error: { code: 412, message: "Precondition Failed" } });
        objects.delete(name);
        return { status: 204, headers: {}, body: Buffer.alloc(0) };
      }
      if (!object) return notFound();
      if (url.searchParams.get("alt") === "media")
        return { status: 200, headers: { "content-type": object.contentType }, body: object.body };
      return json(200, {
        kind: "storage#object",
        name,
        bucket: target.bucket,
        size: String(object.body.length),
        contentType: object.contentType,
        generation: object.generation,
      });
    }
    if (request.method === "OPTIONS")
      return { status: 403, headers: {}, body: xmlError("AccessDenied", "Access denied.") };
    if (request.method === "PUT") return xmlPut(url, request);
    return { status: 405, headers: {}, body: Buffer.alloc(0) };
  }

  function conditionEnd(condition) {
    const m = /timestamp\("([^"]+)"\)/.exec(condition?.expression ?? "");
    return m ? Date.parse(m[1]) : Number.NaN;
  }

  /** Whether signBlob would succeed now: the run's binding is applied, unexpired and the role exists. */
  function signerEnabled() {
    const role = iamState.roles.get(roleKey);
    if (!role || role.deleted) return false;
    if (clock.now() < iamState.appliedAt + iamConfig.propagationMs) return false;
    return (iamState.policy.bindings ?? []).some(
      (b) =>
        b.role === roleKey &&
        (b.members ?? []).includes(iamConfig.member) &&
        conditionEnd(b.condition) > clock.now(),
    );
  }

  const bodyOf = (request) => JSON.parse(Buffer.from(request.body ?? "{}").toString("utf8"));

  function policyView() {
    const bindings = iamState.policy.bindings ?? [];
    const view = { version: bindings.some((b) => b.condition) ? 3 : 1, etag: iamState.policy.etag };
    if (bindings.length) view.bindings = structuredClone(bindings);
    return view;
  }

  function iamRequest(url, request, segments) {
    const email = target.signer;
    if (url.hostname === "cloudresourcemanager.googleapis.com") {
      return json(200, { version: 1, etag: "p-etag", bindings: iamConfig.projectBindings });
    }
    if (url.hostname !== "iam.googleapis.com") return undefined;
    const path = decodeURIComponent(url.pathname);
    const account = `/v1/projects/${target.project}/serviceAccounts/${email}`;
    if (path === account) return json(200, { email, disabled: false });
    if (path === `${account}:getIamPolicy`) return json(200, policyView());
    if (path === `${account}:setIamPolicy`) {
      const { policy } = bodyOf(request);
      if (!policy || policy.etag !== iamState.policy.etag) {
        return json(409, { error: { code: 409, status: "ABORTED" } });
      }
      if ((policy.bindings ?? []).some((b) => b.condition) && policy.version < 3) {
        return json(400, { error: { code: 400, status: "INVALID_ARGUMENT" } });
      }
      iamState.etagCounter += 1;
      iamState.policy = {
        etag: `etag-${iamState.etagCounter}`,
        bindings: structuredClone(policy.bindings ?? []),
      };
      iamState.appliedAt = clock.now();
      return json(200, policyView());
    }
    if (path === `/v1/projects/${target.project}/roles` && request.method === "POST") {
      const body = bodyOf(request);
      if (!body.roleId || !Array.isArray(body.role?.includedPermissions)) {
        return json(400, { error: { code: 400, status: "INVALID_ARGUMENT" } });
      }
      const key = `projects/${target.project}/roles/${body.roleId}`;
      if (iamState.roles.has(key))
        return json(409, { error: { code: 409, status: "ALREADY_EXISTS" } });
      iamState.roles.set(key, { name: key, ...body.role, deleted: false });
      return json(200, iamState.roles.get(key));
    }
    if (path.startsWith(`/v1/projects/${target.project}/roles/`)) {
      const key = path.slice(4);
      const role = iamState.roles.get(key);
      if (request.method === "DELETE") {
        if (!role) return json(404, { error: { code: 404 } });
        role.deleted = true;
        return json(200, role);
      }
      return role ? json(200, role) : json(404, { error: { code: 404, status: "NOT_FOUND" } });
    }
    if (path.startsWith("/v1/roles/")) {
      const permissions = iamConfig.predefinedRoles[path.slice("/v1/roles/".length)];
      return permissions
        ? json(200, { name: path.slice(4), includedPermissions: permissions })
        : json(404, { error: { code: 404 } });
    }
    void segments;
    return json(404, { error: { code: 404 } });
  }

  /** The SDK signer: one signBlob request (production), then a URL of the SDK's V4 shape. */
  async function sign(spec, meter) {
    if (target.name === "production") {
      meter.request("signBlob", {
        method: "POST",
        url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${target.signer}:signBlob`,
      });
      const answer = faults.signBlob ?? (signerEnabled() ? 200 : 403);
      delete faults.signBlob;
      meter.after("signBlob", answer);
      if (answer !== 200) throw new Error(`signBlob refused with ${answer}`);
    }
    const issued = spec.accessibleAt ?? Math.floor(clock.now() / 1000) * 1000;
    const period = Math.floor(spec.expires / 1000) - Math.floor(issued / 1000);
    const signedHeaders = ["host"];
    const values = {};
    if (spec.contentType) {
      signedHeaders.push("content-type");
      values["content-type"] = spec.contentType;
    }
    if (spec.range) {
      signedHeaders.push("x-goog-content-length-range");
      values["x-goog-content-length-range"] = spec.range;
    }
    signedHeaders.splice(0, signedHeaders.length, ...signedHeaders.toSorted());
    const pathname = `/${target.bucket}/${spec.name}`;
    const query = [
      ["X-Goog-Algorithm", "GOOG4-RSA-SHA256"],
      [
        "X-Goog-Credential",
        `${target.signer ?? "local@example.com"}/${formatDate(issued).slice(0, 8)}/auto/storage/goog4_request`,
      ],
      ["X-Goog-Date", formatDate(issued)],
      ["X-Goog-Expires", String(period)],
      ["X-Goog-SignedHeaders", signedHeaders.join(";")],
    ];
    const canonical = JSON.stringify({
      method: "PUT",
      path: pathname,
      query: query.toSorted(),
      headers: signedHeaders.filter((h) => h !== "host").map((h) => [h, values[h] ?? null]),
    });
    const encode = (value) => encodeURIComponent(value);
    const search = [...query, ["X-Goog-Signature", fakeSignature(canonical)]]
      .map(([k, v]) => `${k}=${encode(v)}`)
      .join("&");
    return `${origin}${pathname}?${search}`;
  }

  return {
    objects,
    log,
    iam: iamState,
    signerEnabled,
    deps: {
      net,
      sign,
      adminHeaders: () => (target.name === "production" ? { authorization: "Bearer fake" } : {}),
      now: () => clock.now(),
      sleep: (ms) => clock.sleep(ms),
    },
  };
}

export function createVirtualClock(start = Date.UTC(2026, 10, 3, 12, 0, 0, 250)) {
  let current = start;
  return {
    now: () => current,
    sleep: async (ms) => {
      current += ms;
    },
  };
}

export function memoryOut() {
  const journal = [];
  const saved = new Map();
  return {
    journal: (entry) => journal.push(entry),
    save: (name, data) => saved.set(name, JSON.parse(JSON.stringify(data))),
    entries: journal,
    saved,
  };
}

export const PRODUCTION_LIKE = Object.freeze({
  name: "production",
  bucket: "demo-bucket.firebasestorage.app",
  project: "demo-project",
  signer: "signer@demo-project.iam.gserviceaccount.com",
});

export const LOCAL_LIKE = Object.freeze({
  name: "local",
  bucket: "demo-bucket.appspot.com",
  origin: "http://127.0.0.1:9199",
});

export const IAM_CONFIG = Object.freeze({
  member: "user:owner@example.com",
  windowMinutes: 60,
});
