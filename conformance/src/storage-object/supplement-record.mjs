// Root's fixed production entry. Local test helpers cannot construct its private live epoch.
import { constants, lstatSync, readFileSync, unlinkSync } from "node:fs";
import { lstat, mkdir, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { performance } from "node:perf_hooks";
import {
  admissionProblem,
  LIMITS,
  parseSupplementJson,
  runSupplementProgram,
  sha256,
  supplementPlan,
  SUPPLEMENT_PATHS,
} from "./supplement.mjs";

export const ROOT_ACTOR = "Codex（調整役。台帳790/795によるClaude代行）";
export const ROOT_BASIS = "2026-09-28 調整役への委任（本番の送信）";
export const ORIGINAL_ROLE_PINS = Object.freeze([
  [365, "ce6ff1b509bb6c35cb5c5b6b6d3dc7c55a2a0da8f5fb11e5b0dad31a6dfff799"],
  [395, "8d673a3b76e53a597af4093312a02645ef3bb7a08bf2138bd0380252d52bbc4f"],
  [790, "1988e32c14174bbff07a6ed91f2cf4d1104ff24d7068446dac7ea02ee9a0e795"],
  [795, "b8296c52b4e9862e517892d12eb232c2e5d26405d1ef3e55356d80fa48b301b1"],
  [796, "a3cafcd6dbfa3a145e2298457c37925cc760d2fb53864505c6e507958458c416"],
]);
const SHA = /^[a-f0-9]{64}$/;
const SOURCE_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const EXTRA_SOURCE_PATHS = [
  "conformance/src/storage-object-compare/normalize.mjs",
  "conformance/src/storage-object-compare/compare.mjs",
];
const MARKER = "OBJECT-SUPPLEMENT-V2 ";
const liveEpochs = new WeakMap();
function fail(code) {
  throw new Error(code);
}
function closed(value, keys, code) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== keys.length ||
    keys.some(
      (key) =>
        !Object.hasOwn(value, key) ||
        !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"),
    )
  )
    fail(code);
  return value;
}
function integer(value, low, high, code) {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail(code);
  return value;
}
function hash(value, code) {
  if (typeof value !== "string" || !SHA.test(value)) fail(code);
  return value;
}
function text(value, maximum, code) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    [...value].some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
  )
    fail(code);
  return value;
}
function utf8(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export { parseSupplementJson } from "./supplement.mjs";
export function verifyOriginalRoleRows(rows) {
  if (!Array.isArray(rows) || rows.length !== 5) fail("ROLE_COUNT");
  for (let index = 0; index < 5; index++) {
    const row = closed(rows[index], ["line", "rawWithoutLF", "sha256"], "ROLE_SCHEMA");
    const [line, expected] = ORIGINAL_ROLE_PINS[index];
    if (
      row.line !== line ||
      row.sha256 !== expected ||
      typeof row.rawWithoutLF !== "string" ||
      row.rawWithoutLF.includes("\n") ||
      sha256(row.rawWithoutLF) !== expected
    )
      fail("ROLE_BYTES");
  }
  return Object.freeze({
    kind: "LOCAL_ONLY_ROLE_CHECK",
    actor: ROOT_ACTOR,
    basis: ROOT_BASIS,
    sendAuthorized: false,
  });
}
function mainRoot() {
  let root = resolve(SOURCE_ROOT);
  for (;;) {
    if (lstatSync(join(root, ".git")).isDirectory()) return root;
    const parent = dirname(root);
    if (parent === root) fail("MAIN_ROOT_NOT_FOUND");
    root = parent;
    while (!exists(join(root, ".git"))) {
      const next = dirname(root);
      if (next === root) fail("MAIN_ROOT_NOT_FOUND");
      root = next;
    }
  }
}
function exists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}
export function productionInputPaths() {
  const root = mainRoot();
  const runs = join(root, "docs.local", "runs");
  const home = join(runs, "storage-object-native-supplement");
  return Object.freeze({
    root,
    home,
    current: join(home, "current.json"),
    ownerLedger: join(root, "docs.local", "instructions", "owner-decisions.md"),
    ledger: join(runs, "sandbox-ledger.jsonl"),
    legacyLock: join(runs, "sandbox-ledger.jsonl.lock"),
    lockDir: join(runs, "sandbox-locks"),
    cost: join(home, "cost-current.json"),
  });
}
async function checkedAncestors(path) {
  let directory = dirname(path);
  const temporary = await realpath(tmpdir());
  for (;;) {
    const stat = await lstat(directory);
    // A root-owned sticky temp directory preserves ownership of each private child entry.
    const stickyTemporary = directory === temporary && stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      ((stat.mode & 0o022) !== 0 && !stickyTemporary) ||
      (stat.uid !== process.getuid() && stat.uid !== 0)
    )
      fail("UNSAFE_PARENT");
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
}
async function readOwned(path, maximum = 65536, privateMode = false) {
  if (!isAbsolute(path)) fail("ABSOLUTE_FILE_REQUIRED");
  await checkedAncestors(path);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile() ||
      before.uid !== BigInt(process.getuid()) ||
      (Number(before.mode) & (privateMode ? 0o077 : 0o022)) !== 0 ||
      before.nlink !== 1n ||
      before.size < 1n ||
      before.size > BigInt(maximum)
    )
      fail("UNSAFE_FILE");
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const current = await lstat(path, { bigint: true });
    if (
      BigInt(bytes.length) !== before.size ||
      ["dev", "ino", "mode", "uid", "size", "mtimeNs", "ctimeNs"].some(
        (key) => before[key] !== after[key] || before[key] !== current[key],
      )
    )
      fail("FILE_IDENTITY_CHANGED");
    return { bytes, sha256: sha256(bytes), identity: before };
  } finally {
    await handle.close();
  }
}
async function syncDirectory(path) {
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}
async function privateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stat = await lstat(path, { bigint: true });
  if (
    !stat.isDirectory() ||
    stat.uid !== BigInt(process.getuid()) ||
    (Number(stat.mode) & 0o777) !== 0o700
  )
    fail("PRIVATE_DIRECTORY_REQUIRED");
  await checkedAncestors(join(path, "entry"));
  return { path, identity: stat };
}
async function heldUsageParent(parent) {
  const current = await lstat(parent.path, { bigint: true });
  if (
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    current.dev !== parent.identity.dev ||
    current.ino !== parent.identity.ino ||
    current.birthtimeNs !== parent.identity.birthtimeNs ||
    current.uid !== parent.identity.uid ||
    current.uid !== BigInt(process.getuid()) ||
    (Number(current.mode) & 0o777) !== 0o700
  )
    fail("HELD_USAGE_PARENT_CHANGED");
}
async function exclusive(path, row, parent = null) {
  await checkedAncestors(path);
  if (parent) await heldUsageParent(parent);
  const handle = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    0o600,
  );
  const identity = await handle.stat({ bigint: true });
  const body = `${JSON.stringify(row)}\n`;
  const record = { path, handle, identity, body, parent };
  try {
    await appendHeld(record, row);
    await syncDirectory(dirname(path));
  } catch (error) {
    await handle.close();
    throw error;
  }
  return record;
}
async function append(handle, row) {
  const bytes = Buffer.from(`${JSON.stringify(row)}\n`);
  const result = await handle.write(bytes);
  if (result.bytesWritten !== bytes.length) fail("PARTIAL_DURABLE_WRITE");
  await handle.sync();
}
async function held(record, immutableBody = false) {
  if (record.parent) await heldUsageParent(record.parent);
  const opened = await record.handle.stat({ bigint: true });
  const current = await lstat(record.path, { bigint: true });
  if (
    ![opened, current].every(
      (stat) =>
        stat.isFile() &&
        stat.dev === record.identity.dev &&
        stat.ino === record.identity.ino &&
        stat.uid === BigInt(process.getuid()) &&
        (Number(stat.mode) & 0o777) === 0o600 &&
        stat.nlink === 1n &&
        stat.birthtimeNs === record.identity.birthtimeNs,
    )
  )
    fail("HELD_FD_CHANGED");
  if (immutableBody && (await readOwned(record.path)).bytes.toString() !== record.body)
    fail("LOCK_BODY_CHANGED");
}
async function appendHeld(record, row) {
  await held(record);
  await append(record.handle, row);
  await held(record);
}

/** A pure capture check; it cannot issue or replace Root's private authority. */
export function supplementCaptureProblem(capture, secrets) {
  const body = Buffer.from(capture.body ?? []);
  const fields = [
    ...Object.keys(capture.headers ?? {}),
    ...Object.values(capture.headers ?? {})
      .flat()
      .map(String),
    ...(capture.rawHeaders ?? []).map(String),
    body.toString("utf8"),
    body.toString("base64"),
  ];
  for (const secret of secrets) {
    if (!secret) continue;
    const bytes = Buffer.from(secret);
    const representations = new Set([
      secret,
      encodeURIComponent(secret),
      encodeURI(secret),
      new URLSearchParams({ value: secret }).toString().slice(6),
      JSON.stringify(secret).slice(1, -1),
      bytes.toString("base64"),
      bytes.toString("base64").replace(/=+$/, ""),
      bytes.toString("base64url"),
      bytes.toString("hex"),
      bytes.toString("hex").toUpperCase(),
      [...bytes].map((byte) => `%${byte.toString(16).padStart(2, "0")}`).join(""),
      Array.from(
        { length: secret.length },
        (_, index) => `\\u${secret.charCodeAt(index).toString(16).padStart(4, "0")}`,
      ).join(""),
    ]);
    for (const field of fields) {
      if ([...representations].some((representation) => field.includes(representation)))
        return "SECRET_IN_CAPTURE";
      // Mixed-case and partially escaped percent/JSON forms must not bypass the raw check.
      let decoded = field;
      for (let depth = 0; depth < 2; depth++) {
        decoded = decoded
          .replace(/(?:%[a-f0-9]{2})+/gi, (value) =>
            Buffer.from(value.replace(/%/g, ""), "hex").toString("utf8"),
          )
          .replace(/\\u([a-f0-9]{4})/gi, (_, value) => String.fromCharCode(parseInt(value, 16)));
        if (decoded.includes(secret)) return "SECRET_IN_CAPTURE";
      }
    }
  }
  return null;
}

/** The prior principal is a required input, never learned from the response being checked. */
export function verifySupplementTokenInfo({ data, principal, requestStartedAtMs, receivedAtMs }) {
  closed(principal, ["subject", "clientId", "requiredScopes"], "PRINCIPAL_SCHEMA");
  if (
    !data ||
    Object.getPrototypeOf(data) !== Object.prototype ||
    Object.keys(data).some(
      (key) =>
        ![
          "sub",
          "azp",
          "aud",
          "scope",
          "expires_in",
          "exp",
          "access_type",
          "email",
          "email_verified",
        ].includes(key),
    )
  )
    fail("TOKENINFO_SCHEMA");
  if (
    data.sub !== text(principal.subject, 256, "PRINCIPAL") ||
    data.azp !== text(principal.clientId, 256, "PRINCIPAL") ||
    data.aud !== principal.clientId
  )
    fail("TOKENINFO_PRINCIPAL");
  if (
    !Array.isArray(principal.requiredScopes) ||
    principal.requiredScopes.length < 1 ||
    principal.requiredScopes.length > 32 ||
    new Set(principal.requiredScopes).size !== principal.requiredScopes.length ||
    principal.requiredScopes.some(
      (scope) => typeof scope !== "string" || !/^[\x21-\x7e]{1,512}$/.test(scope),
    )
  )
    fail("PRINCIPAL_SCOPES");
  if (typeof data.scope !== "string" || !/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(data.scope))
    fail("TOKENINFO_SCOPES");
  const scopes = data.scope.split(" ");
  if (
    new Set(scopes).size !== scopes.length ||
    !principal.requiredScopes.every((scope) => scopes.includes(scope))
  )
    fail("TOKENINFO_SCOPES");
  if (
    !(
      typeof data.expires_in === "number" ||
      (typeof data.expires_in === "string" && /^[1-9][0-9]*$/.test(data.expires_in))
    )
  )
    fail("TOKENINFO_EXPIRY");
  const seconds = integer(Number(data.expires_in), 1, 3600, "TOKENINFO_EXPIRY");
  if (
    !Number.isFinite(requestStartedAtMs) ||
    !Number.isFinite(receivedAtMs) ||
    receivedAtMs < requestStartedAtMs ||
    receivedAtMs - requestStartedAtMs > 30000 ||
    requestStartedAtMs + seconds * 1000 - receivedAtMs <= 60000
  )
    fail("TOKENINFO_CLOCK_OR_EXPIRY");
  if (
    Object.hasOwn(data, "exp") &&
    !(Number.isSafeInteger(Number(data.exp)) && Number(data.exp) > 0)
  )
    fail("TOKENINFO_EXP");
  return Object.freeze({
    principalSha256: sha256(JSON.stringify(principal)),
    scopesSha256: sha256(JSON.stringify(scopes)),
    deadlineMonotonicMs: requestStartedAtMs + seconds * 1000,
  });
}
async function loadAdc(input) {
  closed(
    input,
    ["path", "expectedSha256", "expectedClientId", "expectedQuotaProjectId"],
    "ADC_INPUT",
  );
  const file = await readOwned(input.path, 65536, true);
  try {
    if (file.sha256 !== hash(input.expectedSha256, "ADC_HASH")) fail("ADC_HASH");
    const value = parseSupplementJson(file.bytes);
    if (
      !value ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).some(
        (key) =>
          ![
            "type",
            "client_id",
            "client_secret",
            "refresh_token",
            "quota_project_id",
            "universe_domain",
            "account",
          ].includes(key),
      ) ||
      value.type !== "authorized_user" ||
      value.client_id !== input.expectedClientId ||
      (value.quota_project_id !== undefined &&
        value.quota_project_id !== input.expectedQuotaProjectId) ||
      (value.universe_domain !== undefined && value.universe_domain !== "googleapis.com")
    )
      fail("ADC_IDENTITY");
    for (const key of ["client_id", "client_secret", "refresh_token"])
      if (typeof value[key] !== "string" || !/^[\x21-\x7e]{1,8192}$/.test(value[key]))
        fail("ADC_FIELDS");
    const form = Buffer.from(
      new URLSearchParams({
        grant_type: "refresh_token",
        client_id: value.client_id,
        client_secret: value.client_secret,
        refresh_token: value.refresh_token,
      }).toString(),
    );
    return {
      receipt: {
        sha256: file.sha256,
        type: value.type,
        clientId: value.client_id,
        quotaProjectId: value.quota_project_id ?? null,
      },
      form,
      secrets: [value.client_secret, value.refresh_token],
      dispose() {
        form.fill(0);
        value.client_secret = "";
        value.refresh_token = "";
        this.secrets.fill("");
      },
    };
  } finally {
    file.bytes.fill(0);
  }
}
export async function inspectLocalSupplementAdc(input) {
  const directory = await realpath(tmpdir());
  if (!isAbsolute(input?.path) || !resolve(input.path).startsWith(`${directory}/`))
    fail("LOCAL_ONLY_ADC");
  const adc = await loadAdc(input);
  try {
    return { ...adc.receipt, kind: "LOCAL_ONLY_ADC_CHECK", sendAuthorized: false };
  } finally {
    adc.dispose();
  }
}

/** One owned Node request, no redirect, retry, connection facade or token acquisition. */
async function oneWire(request, deadline, local = false) {
  const url = new URL(request.url);
  if (
    url.username ||
    url.password ||
    url.hash ||
    (local
      ? url.protocol !== "http:" || url.hostname !== "127.0.0.1"
      : url.protocol !== "https:" ||
        url.port ||
        ![
          "oauth2.googleapis.com",
          "firebaserules.googleapis.com",
          "storage.googleapis.com",
          "firebasestorage.googleapis.com",
        ].includes(url.hostname))
  )
    fail("WIRE_ORIGIN");
  const body = Buffer.from(request.body ?? []);
  if (
    body.length > 262144 ||
    !["GET", "POST", "PUT", "DELETE"].includes(request.method) ||
    (["GET", "DELETE"].includes(request.method) && body.length !== 0)
  )
    fail("WIRE_REQUEST");
  const started = performance.now();
  const duration = Math.min(30000, deadline - started);
  if (duration <= 0) fail("WIRE_DEADLINE");
  return new Promise((resolveResponse) => {
    let socket;
    let response;
    let done = false;
    let ended = false;
    let closedSocket = false;
    let fault = false;
    let bytes = 0;
    const chunks = [];
    let timer;
    const finish = () => {
      if (done || !closedSocket) return;
      done = true;
      clearTimeout(timer);
      const complete = ended && !fault && response?.complete === true;
      resolveResponse({
        status: complete ? response.statusCode : null,
        complete,
        headers: complete
          ? Object.fromEntries(
              Object.entries(response.headers).map(([key, value]) => [
                key,
                Array.isArray(value) ? value.join(", ") : String(value),
              ]),
            )
          : {},
        rawHeaders: complete ? response.rawHeaders : [],
        body: complete ? Buffer.concat(chunks) : Buffer.alloc(0),
        bodyBytes: complete ? bytes : 0,
        attemptedBodyBytes: bytes,
        requestBytesWritten: socket?.bytesWritten ?? 0,
        requestStartedAtMs: started,
        receivedAtMs: performance.now(),
      });
    };
    const destroy = () => {
      fault = true;
      native.destroy();
      socket?.destroy();
      if (!socket) {
        closedSocket = true;
        finish();
      }
    };
    const native = (local ? httpRequest : httpsRequest)(
      url,
      {
        method: request.method,
        agent: false,
        headers: { ...request.headers, "content-length": String(body.length), connection: "close" },
        maxHeaderSize: 32768,
        ...(local
          ? {}
          : { rejectUnauthorized: true, ALPNProtocols: ["http/1.1"], minVersion: "TLSv1.2" }),
      },
      (incoming) => {
        response = incoming;
        if (
          incoming.headers["content-encoding"] &&
          incoming.headers["content-encoding"] !== "identity"
        )
          destroy();
        incoming.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 524288) destroy();
          else chunks.push(chunk);
        });
        incoming.on("end", () => {
          ended = true;
          if (
            incoming.headers["content-length"] !== undefined &&
            Number(incoming.headers["content-length"]) !== bytes
          )
            fault = true;
          finish();
        });
        incoming.on("error", destroy);
        incoming.on("aborted", destroy);
      },
    );
    native.once("socket", (owned) => {
      socket = owned;
      owned.once("close", () => {
        closedSocket = true;
        finish();
      });
    });
    native.once("error", destroy);
    native.on("information", destroy);
    native.on("upgrade", destroy);
    timer = setTimeout(destroy, duration);
    native.end(body);
  });
}

/** A real temporary-filesystem/loopback validator; its receipts explicitly remain local-only. */
export async function observeLocalSupplement(options) {
  closed(options, ["origin", "directory", "requests"], "LOCAL_ONLY_OPTIONS");
  const url = new URL(options.origin);
  if (
    url.protocol !== "http:" ||
    url.hostname !== "127.0.0.1" ||
    !url.port ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  )
    fail("LOCAL_ONLY_ORIGIN");
  const temporary = await realpath(tmpdir());
  if (
    !resolve(options.directory).startsWith(`${temporary}/`) ||
    !Array.isArray(options.requests) ||
    options.requests.length > 66
  )
    fail("LOCAL_ONLY_DIRECTORY_OR_CAP");
  const path = join(options.directory, "events.jsonl");
  const journal = await exclusive(path, { kind: "STARTED", mode: "LOCAL_ONLY", pid: process.pid });
  const exchanges = [];
  let outcome = "LOCAL_COMPLETE";
  try {
    for (const request of options.requests) {
      closed(request, ["method", "path", "body"], "LOCAL_REQUEST");
      if (
        typeof request.path !== "string" ||
        !request.path.startsWith("/") ||
        new URL(request.path, url).origin !== url.origin
      )
        fail("LOCAL_ONLY_PATH");
      await held(journal);
      await append(journal.handle, {
        kind: "ATTEMPT",
        sequence: exchanges.length + 1,
        method: request.method,
        path: request.path,
        bodySha256: sha256(request.body),
      });
      await held(journal);
      const response = await oneWire(
        {
          method: request.method,
          url: new URL(request.path, url).href,
          body: Buffer.from(request.body),
          headers: {},
        },
        performance.now() + 30000,
        true,
      );
      exchanges.push(response);
      await append(journal.handle, {
        kind: "RESPONSE",
        sequence: exchanges.length,
        status: response.status,
        complete: response.complete,
        bodyBytes: response.bodyBytes,
        bodySha256: sha256(response.body),
      });
      if (!response.complete || response.status < 200 || response.status >= 300) {
        outcome = "UNKNOWN";
        break;
      }
    }
    await append(journal.handle, { kind: outcome });
    return { kind: "LOCAL_ONLY_PHYSICAL_OBSERVER", sendAuthorized: false, outcome, exchanges };
  } finally {
    await journal.handle.close();
  }
}

function sourceState() {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: SOURCE_ROOT,
    encoding: "utf8",
  }).trim();
  if (
    execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
      cwd: SOURCE_ROOT,
      encoding: "utf8",
    }).trim() !== ""
  )
    fail("SOURCE_NOT_CLEAN");
  if (process.version !== "v24.14.0") fail("NODE_VERSION");
  return commit;
}
export async function supplementSourcePins() {
  const files = [];
  for (const path of [...SUPPLEMENT_PATHS, ...EXTRA_SOURCE_PATHS])
    files.push({ path, sha256: (await readOwned(join(SOURCE_ROOT, path), 262144)).sha256 });
  return {
    commit: sourceState(),
    node: process.version,
    files,
    closureSha256: sha256(JSON.stringify(files)),
    planSha256: sha256(JSON.stringify(supplementPlan())),
  };
}
function foundation(pins) {
  if (
    JSON.stringify(pins) !==
    JSON.stringify(ORIGINAL_ROLE_PINS.map(([line, sha]) => ({ line, sha256: sha })))
  )
    fail("FOUNDATION_PINS");
}
export function validateSupplementPacket(packet) {
  closed(
    packet,
    [
      "schemaVersion",
      "kind",
      "actor",
      "basis",
      "foundation",
      "source",
      "grant",
      "adc",
      "principal",
      "principalReceipt",
      "target",
      "rules",
      "cost",
    ],
    "PACKET_SCHEMA",
  );
  if (
    packet.schemaVersion !== 2 ||
    packet.kind !== "ROOT_STORAGE_OBJECT_SUPPLEMENT" ||
    packet.actor !== ROOT_ACTOR ||
    packet.basis !== ROOT_BASIS
  )
    fail("ROOT_IDENTITY");
  foundation(packet.foundation);
  closed(
    packet.source,
    ["commit", "node", "files", "closureSha256", "planSha256"],
    "SOURCE_SCHEMA",
  );
  if (
    !/^[a-f0-9]{40}$/.test(packet.source.commit) ||
    packet.source.node !== "v24.14.0" ||
    !Array.isArray(packet.source.files) ||
    packet.source.files.length !== 7 ||
    packet.source.files.some((file, index) => {
      closed(file, ["path", "sha256"], "SOURCE_FILE");
      return (
        file.path !== [...SUPPLEMENT_PATHS, ...EXTRA_SOURCE_PATHS][index] || !SHA.test(file.sha256)
      );
    }) ||
    packet.source.closureSha256 !== sha256(JSON.stringify(packet.source.files)) ||
    packet.source.planSha256 !== sha256(JSON.stringify(supplementPlan()))
  )
    fail("SOURCE_PINS");
  closed(
    packet.grant,
    [
      "taskId",
      "stage",
      "recording",
      "runId",
      "nonce",
      "issuedAt",
      "expiresAt",
      "maxPhysicalRequests",
      "campaignId",
      "writes",
      "retries",
      "redirects",
      "stopOnUnknown",
    ],
    "GRANT_SCHEMA",
  );
  const grant = packet.grant;
  if (
    grant.taskId !== "STORAGE-OBJECT-SANDBOX" ||
    !["record1", "record2"].includes(grant.stage) ||
    grant.recording !== { precheck: 0, record1: 1, record2: 2 }[grant.stage] ||
    !/^[a-f0-9]{20}$/.test(grant.runId) ||
    !SHA.test(grant.nonce) ||
    !/^[a-zA-Z0-9._-]{1,128}$/.test(grant.campaignId) ||
    grant.maxPhysicalRequests !== 67 ||
    grant.writes !== (grant.stage !== "precheck") ||
    grant.retries !== 0 ||
    grant.redirects !== 0 ||
    grant.stopOnUnknown !== true ||
    !Number.isFinite(Date.parse(grant.issuedAt)) ||
    !Number.isFinite(Date.parse(grant.expiresAt)) ||
    Date.parse(grant.expiresAt) <= Date.parse(grant.issuedAt)
  )
    fail("GRANT_FIELDS");
  closed(
    packet.adc,
    ["path", "expectedSha256", "expectedClientId", "expectedQuotaProjectId"],
    "ADC_INPUT",
  );
  if (
    !isAbsolute(packet.adc.path) ||
    !SHA.test(packet.adc.expectedSha256) ||
    packet.adc.expectedClientId !== packet.principal?.clientId ||
    packet.adc.expectedQuotaProjectId !== "fireemu-oracle-query"
  )
    fail("ADC_PIN");
  closed(packet.principal, ["subject", "clientId", "requiredScopes"], "PRINCIPAL_SCHEMA");
  text(packet.principal.subject, 256, "PRINCIPAL_PIN");
  text(packet.principal.clientId, 256, "PRINCIPAL_PIN");
  if (
    !Array.isArray(packet.principal.requiredScopes) ||
    packet.principal.requiredScopes.length < 1 ||
    !packet.principal.requiredScopes.includes("https://www.googleapis.com/auth/cloud-platform")
  )
    fail("PRINCIPAL_SCOPE");
  closed(packet.principalReceipt, ["path", "sha256"], "PRINCIPAL_RECEIPT");
  hash(packet.principalReceipt.sha256, "PRINCIPAL_RECEIPT");
  closed(
    packet.target,
    ["projectId", "projectNumber", "bucket", "firebaseMappingReceipt"],
    "TARGET_SCHEMA",
  );
  if (
    packet.target.projectId !== "fireemu-oracle-query" ||
    !/^[1-9][0-9]{5,20}$/.test(packet.target.projectNumber) ||
    packet.target.bucket !== "fireemu-oracle-query.firebasestorage.app"
  )
    fail("TARGET_PIN");
  closed(packet.target.firebaseMappingReceipt, ["path", "sha256"], "MAPPING_RECEIPT");
  hash(packet.target.firebaseMappingReceipt.sha256, "MAPPING_RECEIPT");
  if (grant.stage === "precheck") {
    if (packet.rules !== null) fail("PRECHECK_NO_SELF_BASELINE");
  } else {
    closed(
      packet.rules,
      ["releaseName", "rulesetName", "createTime", "updateTime", "sourceSha256", "acceptedReceipt"],
      "RULES_SCHEMA",
    );
    hash(packet.rules.sourceSha256, "RULES_SOURCE");
    closed(packet.rules.acceptedReceipt, ["path", "sha256"], "RULES_RECEIPT");
    hash(packet.rules.acceptedReceipt.sha256, "RULES_RECEIPT");
  }
  closed(packet.cost, ["path", "sha256"], "COST_PIN");
  hash(packet.cost.sha256, "COST_PIN");
  return {
    kind: "LOCAL_ONLY_PACKET_CHECK",
    sendAuthorized: false,
    stage: grant.stage,
    physicalCap: grant.maxPhysicalRequests,
  };
}

/** Check actual raw rows, order and revocation. A successful data check remains local-only. */
export function verifySupplementDecisionRows({ ownerText, packet, packetSha256, references }) {
  validateSupplementPacket(packet);
  hash(packetSha256, "PACKET_HASH");
  const lines = ownerText.split("\n");
  verifyOriginalRoleRows(
    ORIGINAL_ROLE_PINS.map(([line, sha]) => ({ line, sha256: sha, rawWithoutLF: lines[line - 1] })),
  );
  closed(references, ["E", "V", "GO"], "DECISION_REFS");
  const selected = {};
  for (const kind of ["E", "V", "GO"]) {
    const ref = closed(references[kind], ["line", "sha256"], "DECISION_REF");
    integer(ref.line, 797, lines.length, "DECISION_LINE");
    hash(ref.sha256, "DECISION_HASH");
    const raw = lines[ref.line - 1];
    if (sha256(raw) !== ref.sha256 || !raw.includes(MARKER)) fail("DECISION_BYTES");
    const row = parseSupplementJson(raw.slice(raw.indexOf(MARKER) + MARKER.length));
    closed(
      row,
      [
        "kind",
        "actor",
        "basis",
        "foundation",
        "taskId",
        "stage",
        "nonce",
        "packetSha256",
        "sourceCommit",
        "review",
        "at",
      ],
      "DECISION_SCHEMA",
    );
    if (
      row.kind !== kind ||
      row.actor !== ROOT_ACTOR ||
      row.basis !== ROOT_BASIS ||
      row.taskId !== packet.grant.taskId ||
      row.stage !== packet.grant.stage ||
      row.nonce !== packet.grant.nonce ||
      row.packetSha256 !== packetSha256 ||
      row.sourceCommit !== packet.source.commit ||
      !Number.isFinite(Date.parse(row.at))
    )
      fail("DECISION_BINDING");
    foundation(row.foundation);
    closed(row.review, ["path", "sha256", "reviewer", "decision", "must", "should"], "REVIEW_REF");
    if (
      row.review.reviewer !== "independent-codex-gpt-6.1-sol" ||
      row.review.decision !== "APPROVE" ||
      row.review.must !== 0 ||
      row.review.should !== 0 ||
      !SHA.test(row.review.sha256)
    )
      fail("CLEAN_REVIEW");
    for (let index = ref.line; index < lines.length; index++) {
      if (!lines[index].includes(MARKER)) continue;
      const later = parseSupplementJson(
        lines[index].slice(lines[index].indexOf(MARKER) + MARKER.length),
      );
      if (later.kind === kind && later.taskId === row.taskId && later.stage === row.stage)
        fail("NOT_LATEST_DECISION");
    }
    selected[kind] = row;
  }
  if (
    !(references.E.line < references.V.line && references.V.line < references.GO.line) ||
    !(
      Date.parse(selected.E.at) <= Date.parse(selected.V.at) &&
      Date.parse(selected.V.at) <= Date.parse(selected.GO.at)
    ) ||
    JSON.stringify(selected.E.review) !== JSON.stringify(selected.V.review) ||
    JSON.stringify(selected.V.review) !== JSON.stringify(selected.GO.review)
  )
    fail("E_V_GO_ORDER");
  const identifiers = [
    packetSha256,
    packet.source.commit,
    packet.grant.nonce,
    packet.grant.campaignId,
  ].map((item) => item.toLowerCase());
  for (const raw of lines) {
    const line = raw.normalize("NFKC").toLowerCase();
    if (!/revoked|撤回|取消/.test(line)) continue;
    const otherExplicitPacket = /packetsha256\s*=\s*([a-f0-9]{64})/.exec(line)?.[1];
    if (
      (line.includes("調整役への委任") && !otherExplicitPacket) ||
      identifiers.some((identifier) => line.includes(identifier)) ||
      (line.match(/[a-f0-9]{8,40}/g) ?? []).some((fragment) =>
        packet.source.commit.startsWith(fragment),
      ) ||
      (line.includes("storage-object") &&
        (!otherExplicitPacket || otherExplicitPacket === packetSha256))
    )
      fail("LIVE_REVOCATION");
  }
  return {
    kind: "LOCAL_ONLY_DECISION_CHECK",
    sendAuthorized: false,
    review: selected.GO.review,
    goAt: selected.GO.at,
  };
}

async function referenced(root, ref, folder) {
  if (
    !isAbsolute(ref.path) ||
    !resolve(ref.path).startsWith(`${join(root, "docs.local", folder)}/`)
  )
    fail("FIXED_PRIVATE_REF");
  const file = await readOwned(ref.path, 8 * 1024 * 1024);
  if (file.sha256 !== ref.sha256) fail("PRIVATE_REF_HASH");
  return file;
}
async function authority(paths) {
  const currentFile = await readOwned(paths.current, 65536, true);
  const current = parseSupplementJson(currentFile.bytes);
  closed(current, ["schemaVersion", "kind", "packet", "decisions"], "CURRENT_SCHEMA");
  if (current.schemaVersion !== 2 || current.kind !== "ROOT_STORAGE_OBJECT_SUPPLEMENT_CURRENT")
    fail("CURRENT_V2");
  closed(current.packet, ["path", "sha256"], "PACKET_REF");
  const packetFile = await referenced(
    paths.root,
    current.packet,
    "runs/storage-object-native-supplement/packets",
  );
  const packet = parseSupplementJson(packetFile.bytes);
  validateSupplementPacket(packet);
  const actual = await supplementSourcePins();
  if (JSON.stringify(actual) !== JSON.stringify(packet.source)) fail("SOURCE_GENERATION");
  const owner = await readOwned(paths.ownerLedger, 8 * 1024 * 1024);
  const decisions = verifySupplementDecisionRows({
    ownerText: utf8(owner.bytes),
    packet,
    packetSha256: packetFile.sha256,
    references: current.decisions,
  });
  await referenced(paths.root, decisions.review, "reviews");
  const priorPrincipal = parseSupplementJson(
    (await referenced(paths.root, packet.principalReceipt, "runs")).bytes,
  );
  if (
    priorPrincipal.kind !== "ROOT_ACCEPTED_OWNER_PRINCIPAL" ||
    priorPrincipal.principalSha256 !== sha256(JSON.stringify(packet.principal)) ||
    !Number.isFinite(Date.parse(priorPrincipal.observedAt)) ||
    Date.parse(priorPrincipal.observedAt) >= Date.parse(decisions.goAt)
  )
    fail("PRIOR_PRINCIPAL_REQUIRED");
  const mapping = parseSupplementJson(
    (await referenced(paths.root, packet.target.firebaseMappingReceipt, "runs")).bytes,
  );
  if (
    mapping.kind !== "ROOT_ACCEPTED_FIREBASE_BUCKET_MAPPING" ||
    mapping.projectId !== packet.target.projectId ||
    mapping.projectNumber !== packet.target.projectNumber ||
    mapping.bucket !== packet.target.bucket
  )
    fail("ACCEPTED_FIREBASE_MAPPING");
  if (packet.rules) {
    const receipt = parseSupplementJson(
      (await referenced(paths.root, packet.rules.acceptedReceipt, "runs")).bytes,
    );
    if (
      receipt.kind !== "ROOT_ACCEPTED_OBJECT_RULES_BASELINE" ||
      receipt.targetSha256 !== sha256(JSON.stringify(packet.target)) ||
      receipt.snapshotSha256 !==
        sha256(
          JSON.stringify({
            releaseName: packet.rules.releaseName,
            rulesetName: packet.rules.rulesetName,
            createTime: packet.rules.createTime,
            updateTime: packet.rules.updateTime,
            sourceSha256: packet.rules.sourceSha256,
          }),
        )
    )
      fail("ACCEPTED_RULES_BASELINE");
  }
  const now = Date.now();
  if (
    now < Date.parse(packet.grant.issuedAt) ||
    now < Date.parse(decisions.goAt) ||
    now + 30000 >= Date.parse(packet.grant.expiresAt)
  )
    fail("ACTUAL_GRANT_CLOCK");
  return {
    packet,
    packetSha256: packetFile.sha256,
    currentSha256: currentFile.sha256,
    decisions,
    ownerSha256: owner.sha256,
  };
}
function historyAdmission(rows, packet, ownRun = null) {
  const latest = new Map();
  let previousTerminal = null;
  let campaignAttempts = 0;
  for (const row of rows) {
    const projects = [
      ...(typeof row.project === "string" ? row.project.split(",") : []),
      ...(Array.isArray(row.projects) ? row.projects : []),
    ];
    if (projects.includes(packet.target.projectId)) {
      if (typeof row.runId !== "string" || !Number.isFinite(Date.parse(row.ts)))
        fail("PROJECT_HISTORY_UNKNOWN");
      latest.set(row.runId, row);
    }
    if (row.campaignId === packet.grant.campaignId && row.event === "finished")
      campaignAttempts += integer(row.requests, 0, 67, "CAMPAIGN_HISTORY_UNKNOWN");
  }
  for (const [run, row] of latest) {
    if (run === ownRun) continue;
    if (
      row.event !== "finished" ||
      row.sandboxAtBaseline !== true ||
      !["recorded", "stopped-clean", "recovered-no-observation"].includes(row.outcome)
    )
      fail("PRIOR_PROJECT_RUN_OPEN");
    previousTerminal = Math.max(previousTerminal ?? 0, Date.parse(row.ts));
  }
  if (ownRun !== null) {
    const own = latest.get(ownRun);
    if (
      !own ||
      own.event !== "started" ||
      own.packetId !== packet.grant.nonce ||
      own.sourceCommit !== packet.source.commit ||
      own.pid !== process.pid ||
      own.uid !== process.getuid()
    )
      fail("DURABLE_START_MISSING_OR_CHANGED");
  }
  if (campaignAttempts + packet.grant.maxPhysicalRequests > 140) fail("CAMPAIGN_CAP");
  return { previousTerminal, campaignAttempts };
}
async function history(paths, packet, ownRun) {
  const file = await readOwned(paths.ledger, 8 * 1024 * 1024);
  const rows = utf8(file.bytes).trim().split("\n").map(parseSupplementJson);
  return { ...historyAdmission(rows, packet, ownRun), sha256: file.sha256 };
}
async function costAuthority(paths, packet) {
  if (packet.cost.path !== paths.cost) fail("FIXED_COST_PATH");
  const file = await readOwned(paths.cost, 65536, true);
  if (file.sha256 !== packet.cost.sha256) fail("COST_CHANGED");
  const value = parseSupplementJson(file.bytes);
  closed(
    value,
    [
      "schemaVersion",
      "kind",
      "currency",
      "unit",
      "producer",
      "taskId",
      "campaignId",
      "sourceCommit",
      "observedAt",
      "history",
      "status",
      "ratesMicroUsd",
      "priorSpentMicroUsd",
      "priorReservedMicroUsd",
      "reservationMicroUsd",
      "ceilingMicroUsd",
    ],
    "COST_SCHEMA",
  );
  if (
    value.schemaVersion !== 2 ||
    value.kind !== "ROOT_STORAGE_OBJECT_COST" ||
    value.currency !== "USD" ||
    value.unit !== "physical-request" ||
    value.taskId !== "STORAGE-OBJECT-SANDBOX" ||
    value.campaignId !== packet.grant.campaignId ||
    value.sourceCommit !== packet.source.commit ||
    value.status !== "KNOWN" ||
    Date.now() < Date.parse(value.observedAt) ||
    Date.now() - Date.parse(value.observedAt) > 300000 ||
    !Number.isFinite(Date.parse(value.observedAt))
  )
    fail("COST_UNKNOWN");
  closed(value.producer, ["path", "sha256"], "COST_PRODUCER");
  await referenced(paths.root, value.producer, "runs");
  closed(value.history, ["path", "sha256"], "COST_HISTORY");
  await referenced(paths.root, value.history, "runs");
  closed(value.ratesMicroUsd, ["storage", "oauth", "tokeninfo", "rules", "bucket"], "COST_RATES");
  let estimate = 0;
  for (const [family, rate] of Object.entries(value.ratesMicroUsd))
    estimate +=
      integer(rate, 0, 10000000, "COST_RATE_UNKNOWN") *
      (packet.grant.stage === "precheck" && family === "storage" ? 1 : LIMITS[family]);
  estimate += value.ratesMicroUsd.storage;
  for (const key of ["priorSpentMicroUsd", "priorReservedMicroUsd", "reservationMicroUsd"])
    integer(value[key], 0, 10000000, "COST_AMOUNT_UNKNOWN");
  if (
    value.ceilingMicroUsd !== 10000000 ||
    estimate > value.reservationMicroUsd ||
    value.priorSpentMicroUsd + value.priorReservedMicroUsd + value.reservationMicroUsd >
      value.ceilingMicroUsd
  )
    fail("COST_EXCEEDED");
  return value;
}

async function verifyEpoch(capability, family) {
  const epoch = liveEpochs.get(capability);
  if (
    !epoch ||
    epoch.pid !== process.pid ||
    epoch.uid !== process.getuid() ||
    epoch.failed ||
    !epoch.armed
  )
    fail("NO_LIVE_EPOCH");
  const actual = await authority(epoch.paths);
  if (actual.currentSha256 !== epoch.currentSha256 || actual.packetSha256 !== epoch.packetSha256)
    fail("LIVE_CURRENT_CHANGED");
  if (exists(epoch.paths.legacyLock)) fail("LEGACY_LOCK_PRESENT");
  for (const lock of epoch.locks) await held(lock, true);
  await heldSharedLedger(epoch.ledger);
  await held(epoch.usage);
  await held(epoch.events);
  const prior = await history(epoch.paths, epoch.packet, epoch.packet.grant.runId);
  const cost = await costAuthority(epoch.paths, epoch.packet);
  if (JSON.stringify(cost) !== JSON.stringify(epoch.cost)) fail("LIVE_COST_CHANGED");
  const now = Date.now();
  if (Math.abs(now - epoch.utcStarted - (performance.now() - epoch.monoStarted)) > 1000)
    fail("ACTUAL_CLOCK_DIVERGED");
  const problem = admissionProblem(
    {
      stage: epoch.packet.grant.stage,
      attempted: epoch.attempted,
      families: epoch.families,
      pending: epoch.pending,
      failed: epoch.failed,
      armed: epoch.armed,
      sourceCurrent: true,
      grantCurrent: true,
      locksHeld: true,
      precheckExtra: 1,
      ownerVerified: epoch.verified,
      ownerPending: Boolean(epoch.token) && !epoch.verified,
      now,
      started: epoch.utcStarted,
      previousTerminal: prior.previousTerminal,
      grantExpires: Date.parse(epoch.packet.grant.expiresAt),
      tokenExpires:
        epoch.tokenUntil === null ? 0 : epoch.utcStarted + epoch.tokenUntil - epoch.monoStarted,
      baselineObserved: epoch.baselineObserved,
      costKnown: true,
      priorSpent: cost.priorSpentMicroUsd,
      priorReserved: cost.priorReservedMicroUsd,
      reservation: cost.reservationMicroUsd,
      ceiling: cost.ceilingMicroUsd,
    },
    family,
  );
  if (problem) fail(problem);
  return epoch;
}
async function heldSharedLedger(record) {
  const descriptor = await record.handle.stat({ bigint: true });
  const current = await lstat(record.path, { bigint: true });
  if (
    ![descriptor, current].every(
      (stat) =>
        stat.isFile() &&
        stat.dev === record.identity.dev &&
        stat.ino === record.identity.ino &&
        stat.birthtimeNs === record.identity.birthtimeNs &&
        stat.uid === BigInt(process.getuid()) &&
        stat.nlink === 1n &&
        (Number(stat.mode) & 0o022) === 0,
    )
  )
    fail("SHARED_LEDGER_FD_CHANGED");
}
export function supplementOwnerRequest(family, body) {
  if (
    !["oauth", "tokeninfo"].includes(family) ||
    !Buffer.isBuffer(body) ||
    (family === "tokeninfo" && body.length !== 0) ||
    (family === "oauth" && (body.length === 0 || body.length > 65536))
  )
    fail("OWNER_ONE_PAIR_REQUEST");
  return {
    family,
    label: family === "oauth" ? "owner-exchange" : "owner-tokeninfo",
    method: "POST",
    url: `https://oauth2.googleapis.com/${family === "oauth" ? "token" : "tokeninfo"}`,
    headers: {
      accept: "application/json",
      "accept-encoding": "identity",
      "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
    },
    body,
  };
}
async function dispatch(capability, request) {
  const epoch = await verifyEpoch(capability, request.family);
  if (epoch.phase === "PRECHECK") {
    if (epoch.precheckReads >= 4) fail("PRECHECK_PHASE_CAP");
    epoch.precheckReads++;
  }
  const sequence = epoch.attempted + 1;
  const duplicate = epoch.labels.has(request.label);
  if (duplicate) fail("DUPLICATE_ACTION");
  const bearer = request.family === "oauth" ? null : epoch.token;
  if (
    request.family !== "oauth" &&
    (!bearer || (request.family !== "tokeninfo" && !epoch.verified))
  )
    fail("UNVERIFIED_OWNER");
  const headers = { ...request.headers, ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) };
  if (!["oauth", "tokeninfo"].includes(request.family))
    headers["x-goog-user-project"] = epoch.packet.target.projectId;
  const intent = {
    kind: "ATTEMPT",
    actor: ROOT_ACTOR,
    basis: ROOT_BASIS,
    foundation: epoch.packet.foundation,
    sourceCommit: epoch.packet.source.commit,
    packetSha256: epoch.packetSha256,
    currentSha256: epoch.currentSha256,
    nonce: epoch.packet.grant.nonce,
    epochSha256: epoch.epochSha256,
    sequence,
    family: request.family,
    phase: epoch.phase,
    label: request.label,
    method: request.method,
    url: request.url,
    bodyBytes: request.body.length,
    bodySha256: sha256(request.body),
    ts: new Date().toISOString(),
  };
  epoch.labels.add(request.label);
  epoch.attempted++;
  epoch.families[request.family]++;
  await appendHeld(epoch.usage, intent);
  await append(epoch.events.handle, intent);
  // Persistence can be held while Root revokes a grant; read the authority again before wire.
  epoch.attempted--;
  epoch.families[request.family]--;
  try {
    await verifyEpoch(capability, request.family);
  } finally {
    epoch.attempted++;
    epoch.families[request.family]++;
  }
  epoch.pending = 1;
  try {
    const response = await oneWire(
      { ...request, headers },
      Math.min(
        epoch.monoStarted + (epoch.packet.grant.stage === "precheck" ? 120000 : 900000),
        performance.now() + Date.parse(epoch.packet.grant.expiresAt) - Date.now(),
        epoch.tokenUntil ?? Infinity,
      ),
    );
    if (epoch.captureBytes + response.bodyBytes > 40 * 1024 * 1024) fail("RUN_CAPTURE_CAP");
    epoch.captureBytes += response.bodyBytes;
    const sensitive = ["oauth", "tokeninfo"].includes(request.family);
    if (!sensitive) {
      const captureProblem = supplementCaptureProblem(response, epoch.secrets);
      if (captureProblem) fail(captureProblem);
    }
    const saved = {
      kind: "RESPONSE",
      sequence,
      family: request.family,
      label: request.label,
      status: response.status,
      complete: response.complete,
      bodyBytes: response.bodyBytes,
      bodySha256: sha256(response.body),
      requestBytesWritten: response.requestBytesWritten,
      observedBodyBytes: response.attemptedBodyBytes,
      elapsedMs: response.receivedAtMs - response.requestStartedAtMs,
      ...(sensitive
        ? { credentialBodyOmitted: true }
        : {
            headers: response.headers,
            rawHeaders: response.rawHeaders,
            bodyBase64: response.body.toString("base64"),
          }),
    };
    await held(epoch.usage);
    await append(epoch.events.handle, saved);
    if (
      !response.complete ||
      response.status === null ||
      response.status >= 500 ||
      (response.status >= 300 &&
        response.status < 400 &&
        !(request.family === "storage" && response.status === 308))
    )
      epoch.failed = true;
    return response;
  } finally {
    epoch.pending = 0;
  }
}
async function ownerOnce(capability) {
  const epoch = await verifyEpoch(capability, "oauth");
  const adc = await loadAdc(epoch.packet.adc);
  epoch.secrets.push(...adc.secrets);
  try {
    const exchange = await dispatch(capability, supplementOwnerRequest("oauth", adc.form));
    if (
      !exchange.complete ||
      exchange.status !== 200 ||
      exchange.bodyBytes < 2 ||
      exchange.bodyBytes > 32768
    )
      fail("OAUTH_EXCHANGE_UNKNOWN");
    const data = parseSupplementJson(exchange.body);
    if (
      !data ||
      Object.keys(data).some(
        (key) => !["access_token", "expires_in", "scope", "token_type", "id_token"].includes(key),
      ) ||
      data.token_type !== "Bearer" ||
      typeof data.access_token !== "string" ||
      !/^[\x21-\x7e]{1,8192}$/.test(data.access_token)
    )
      fail("OAUTH_EXCHANGE_SCHEMA");
    const seconds = integer(data.expires_in, 61, 3600, "OAUTH_EXCHANGE_EXPIRY");
    epoch.token = data.access_token;
    epoch.secrets.push(epoch.token);
    epoch.tokenUntil = exchange.requestStartedAtMs + seconds * 1000;
    const tokeninfo = await dispatch(
      capability,
      supplementOwnerRequest("tokeninfo", Buffer.alloc(0)),
    );
    if (
      !tokeninfo.complete ||
      tokeninfo.status !== 200 ||
      tokeninfo.bodyBytes < 2 ||
      tokeninfo.bodyBytes > 32768
    )
      fail("TOKENINFO_UNKNOWN");
    const proof = verifySupplementTokenInfo({
      data: parseSupplementJson(tokeninfo.body),
      principal: epoch.packet.principal,
      requestStartedAtMs: tokeninfo.requestStartedAtMs,
      receivedAtMs: tokeninfo.receivedAtMs,
    });
    epoch.tokenUntil = Math.min(epoch.tokenUntil, proof.deadlineMonotonicMs);
    if (
      epoch.tokenUntil <
      epoch.monoStarted + (epoch.packet.grant.stage === "precheck" ? 120000 : 900000) + 60000
    )
      fail("OWNER_CANNOT_COVER_RUN");
    await append(epoch.events.handle, {
      kind: "OWNER_VERIFIED",
      actor: ROOT_ACTOR,
      basis: ROOT_BASIS,
      foundation: epoch.packet.foundation,
      sourceCommit: epoch.packet.source.commit,
      nonce: epoch.packet.grant.nonce,
      epochSha256: epoch.epochSha256,
      adc: adc.receipt,
      ...proof,
      tokenDeadlineMonotonicMs: epoch.tokenUntil,
      accessTokenSha256: sha256(epoch.token),
      accessTokenBytes: epoch.token.length,
    });
    epoch.verified = true;
  } finally {
    adc.dispose();
  }
}
async function rulesSnapshot(capability, side) {
  const epoch = liveEpochs.get(capability);
  const project = epoch.packet.target.projectId;
  const bucket = epoch.packet.target.bucket;
  const releaseName = `projects/${project}/releases/firebase.storage/${bucket}`;
  const release = await dispatch(capability, {
    family: "rules",
    label: `rules-${side}-release`,
    method: "GET",
    url: `https://firebaserules.googleapis.com/v1/${releaseName}`,
    headers: { accept: "application/json", "accept-encoding": "identity" },
    body: Buffer.alloc(0),
  });
  if (!release.complete || release.status !== 200) fail("RULES_RELEASE_UNKNOWN");
  const value = parseSupplementJson(release.body);
  if (
    value.name !== releaseName ||
    typeof value.rulesetName !== "string" ||
    !value.rulesetName.startsWith(`projects/${project}/rulesets/`) ||
    !/^[a-zA-Z0-9_-]{1,128}$/.test(
      value.rulesetName.slice(`projects/${project}/rulesets/`.length),
    ) ||
    !Number.isFinite(Date.parse(value.createTime)) ||
    !Number.isFinite(Date.parse(value.updateTime))
  )
    fail("RULES_RELEASE_BINDING");
  const ruleset = await dispatch(capability, {
    family: "rules",
    label: `rules-${side}-ruleset`,
    method: "GET",
    url: `https://firebaserules.googleapis.com/v1/${value.rulesetName}`,
    headers: { accept: "application/json", "accept-encoding": "identity" },
    body: Buffer.alloc(0),
  });
  if (!ruleset.complete || ruleset.status !== 200) fail("RULESET_UNKNOWN");
  const rules = parseSupplementJson(ruleset.body);
  if (
    rules.name !== value.rulesetName ||
    !Array.isArray(rules.source?.files) ||
    rules.source.files.length !== 1 ||
    typeof rules.source.files[0]?.content !== "string"
  )
    fail("RULESET_SOURCE_UNKNOWN");
  const snapshot = {
    releaseName,
    rulesetName: value.rulesetName,
    createTime: value.createTime,
    updateTime: value.updateTime,
    sourceSha256: sha256(rules.source.files[0].content),
  };
  if (epoch.packet.rules) {
    const { acceptedReceipt: _receipt, ...expected } = epoch.packet.rules;
    if (JSON.stringify(snapshot) !== JSON.stringify(expected)) fail("RULES_BASELINE_CHANGED");
  }
  epoch.baselineObserved = Date.now();
  await append(epoch.events.handle, {
    kind: "RULES_SNAPSHOT",
    side,
    snapshot,
    observedAt: new Date().toISOString(),
  });
  return snapshot;
}
async function bucketBinding(capability) {
  const epoch = liveEpochs.get(capability);
  const target = epoch.packet.target;
  const response = await dispatch(capability, {
    family: "bucket",
    label: "bucket-binding",
    method: "GET",
    url: `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(target.bucket)}`,
    headers: { accept: "application/json", "accept-encoding": "identity" },
    body: Buffer.alloc(0),
  });
  if (!response.complete || response.status !== 200) fail("BUCKET_UNKNOWN");
  const data = parseSupplementJson(response.body);
  if (
    data.name !== target.bucket ||
    String(data.projectNumber) !== target.projectNumber ||
    data.versioning?.enabled === true
  )
    fail("BUCKET_BINDING_OR_VERSIONING_CHANGED");
}

/** Only this zero-argument entry reads Root's actual fixed authority and credentials. */
export async function runRootSupplement(...args) {
  if (args.length !== 0) fail("NO_ARGUMENTS_PRODUCTION_ENTRY");
  if (
    [
      "NODE_OPTIONS",
      "NODE_EXTRA_CA_CERTS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "NODE_USE_ENV_PROXY",
      "HTTP_PROXY",
      "HTTPS_PROXY",
      "ALL_PROXY",
      "http_proxy",
      "https_proxy",
      "all_proxy",
    ].some((name) => process.env[name])
  )
    fail("NATIVE_ENV_OVERRIDE");
  const paths = productionInputPaths();
  const accepted = await authority(paths);
  const packet = accepted.packet;
  const prior = await history(paths, packet);
  const cost = await costAuthority(paths, packet);
  const utcStarted = Date.now();
  const monoStarted = performance.now();
  if (prior.previousTerminal !== null && utcStarted - prior.previousTerminal < 1800000)
    fail("PROJECT_SPACING");
  if (exists(paths.legacyLock)) fail("LEGACY_LOCK_PRESENT");
  await privateDirectory(paths.lockDir);
  const usageParent = await privateDirectory(join(paths.home, "usage"));
  await privateDirectory(join(paths.home, "records"));
  const runDirectory = join(paths.home, "records", packet.grant.runId);
  await mkdir(runDirectory, { mode: 0o700 });
  const locks = [];
  let usage;
  let events;
  let ledger;
  let started = false;
  let clean = false;
  const capability = Object.freeze(Object.create(null));
  const base = {
    actor: ROOT_ACTOR,
    basis: ROOT_BASIS,
    foundation: packet.foundation,
    taskId: packet.grant.taskId,
    packetId: packet.grant.nonce,
    packetSha256: accepted.packetSha256,
    sourceCommit: packet.source.commit,
    currentSha256: accepted.currentSha256,
    project: packet.target.projectId,
    campaignId: packet.grant.campaignId,
    runId: packet.grant.runId,
    pid: process.pid,
    uid: process.getuid(),
    processBirthUtcMs: Math.round(utcStarted - process.uptime() * 1000),
    monotonicStartedMs: monoStarted,
    ts: new Date(utcStarted).toISOString(),
  };
  try {
    for (const key of [`${packet.grant.taskId}.budget`, packet.target.projectId].toSorted())
      locks.push(await exclusive(join(paths.lockDir, `${key}.lock`), base));
    await history(paths, packet);
    const fresh = await authority(paths);
    if (fresh.currentSha256 !== accepted.currentSha256) fail("CURRENT_CHANGED_BEFORE_START");
    usage = await exclusive(
      join(paths.home, "usage", `${packet.grant.nonce}.jsonl`),
      {
        ...base,
        kind: "RESERVED",
        reservationMicroUsd: cost.reservationMicroUsd,
        maxPhysicalRequests: packet.grant.maxPhysicalRequests,
      },
      usageParent,
    );
    events = await exclusive(join(runDirectory, "events.jsonl"), {
      ...base,
      kind: "STARTED",
      node: process.version,
      planSha256: packet.source.planSha256,
    });
    ledger = await open(
      paths.ledger,
      constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW,
    );
    const ledgerIdentity = await ledger.stat({ bigint: true });
    if (
      !ledgerIdentity.isFile() ||
      ledgerIdentity.uid !== BigInt(process.getuid()) ||
      (Number(ledgerIdentity.mode) & 0o022) !== 0 ||
      ledgerIdentity.nlink !== 1n
    )
      fail("SHARED_LEDGER_UNSAFE");
    // From this point a partially durable start must retain locks for Root recovery.
    started = true;
    await append(ledger, {
      ...base,
      event: "started",
      gitSha: packet.source.commit,
      corpusDigest: packet.source.planSha256,
      maxRequests: packet.grant.maxPhysicalRequests,
      estimatedUsd: cost.reservationMicroUsd / 1000000,
    });
    await appendHeld(usage, {
      ...base,
      kind: "ACTIVE",
      epochSha256: sha256(JSON.stringify(base)),
    });
    const epoch = {
      ...accepted,
      paths,
      packet,
      cost,
      utcStarted,
      monoStarted,
      pid: process.pid,
      uid: process.getuid(),
      locks,
      usage,
      events,
      ledger: { path: paths.ledger, handle: ledger, identity: ledgerIdentity },
      armed: true,
      failed: false,
      pending: 0,
      attempted: 0,
      families: { storage: 0, oauth: 0, tokeninfo: 0, rules: 0, bucket: 0, precheck: 0 },
      phase: "OWNER",
      precheckReads: 0,
      labels: new Set(),
      token: null,
      tokenUntil: null,
      verified: false,
      baselineObserved: 0,
      secrets: [],
      captureBytes: 0,
      epochSha256: sha256(JSON.stringify(base)),
    };
    liveEpochs.set(capability, epoch);
    await ownerOnce(capability);
    epoch.phase = "PRECHECK";
    const before = await rulesSnapshot(capability, "before");
    await bucketBinding(capability);
    const precheck = await runSupplementProgram(
      (request) => dispatch(capability, { ...request, family: "precheck" }),
      { bucket: packet.target.bucket, runId: packet.grant.runId, stage: "precheck" },
    );
    if (precheck.outcome !== "PRECHECK_CANDIDATE" || epoch.precheckReads !== 4)
      fail("PRECHECK_EMPTY_UNKNOWN");
    await append(events.handle, {
      kind: "PRECHECK_COMPLETE",
      physical: 4,
      shared: 3,
      additional: 1,
      sourceCommit: packet.source.commit,
      nonce: packet.grant.nonce,
    });
    epoch.phase = "PROGRAM";
    const observed = await runSupplementProgram((request) => dispatch(capability, request), {
      bucket: packet.target.bucket,
      runId: packet.grant.runId,
      stage: packet.grant.stage,
    });
    if (!["RECORDED_UNREVIEWED", "PRECHECK_CANDIDATE"].includes(observed.outcome))
      fail(observed.reason);
    const after = await rulesSnapshot(capability, "after");
    if (JSON.stringify(before) !== JSON.stringify(after)) fail("RULES_CHANGED_DURING_RUN");
    if (epoch.pending !== 0 || epoch.failed) fail("PENDING_OR_FAILED_TERMINAL");
    await verifyEpoch(capability, packet.grant.stage === "precheck" ? "bucket" : "storage").catch(
      (error) => {
        if (error.message !== "PHYSICAL_CAP") throw error;
      },
    );
    const terminal = {
      ...base,
      ts: new Date().toISOString(),
      kind: observed.outcome,
      requests: epoch.attempted,
      families: epoch.families,
      snapshot: after,
      parentClosed: false,
      source: packet.source,
      packetSha256: accepted.packetSha256,
      node: process.version,
      pending: 0,
    };
    await append(events.handle, terminal);
    const journalSha256 = (await readOwned(events.path, 80 * 1024 * 1024, true)).sha256;
    const metadata = await exclusive(join(runDirectory, "manifest.json"), {
      ...terminal,
      schemaVersion: 2,
      kind: "STORAGE_OBJECT_SUPPLEMENT_PRIVATE_RECORD",
      journalSha256,
      originalConditionCount: 28,
      scope: "M1_M4_ONLY",
      recoveryExecution: "OPEN_NEW_GO_REQUIRED",
      nativeReview: "PENDING",
      fullCorpus: "OPEN",
    });
    await metadata.handle.close();
    await appendHeld(usage, { ...terminal, kind: "CONSUMED" });
    await heldSharedLedger(epoch.ledger);
    await append(ledger, {
      ...terminal,
      event: "finished",
      outcome: "recorded",
      sandboxAtBaseline: true,
      estimatedUsd: cost.reservationMicroUsd / 1000000,
    });
    for (const lock of locks) await held(lock, true);
    clean = true;
    return {
      outcome: observed.outcome,
      runDirectory,
      requests: epoch.attempted,
      sourceCommit: packet.source.commit,
      parentClosed: false,
    };
  } catch (error) {
    const reason =
      typeof error?.message === "string" && /^[A-Z][A-Z0-9_]{1,95}$/.test(error.message)
        ? error.message
        : "INTERNAL_FAILURE";
    const epoch = liveEpochs.get(capability);
    if (epoch) epoch.failed = true;
    if (started && ledger)
      await append(ledger, {
        ...base,
        ts: new Date().toISOString(),
        event: "needs-recovery",
        outcome: "unknown",
        sandboxAtBaseline: false,
        requests: epoch?.attempted ?? 0,
        reason,
      }).catch(() => {});
    if (usage)
      await appendHeld(usage, {
        ...base,
        kind: "UNKNOWN",
        requests: epoch?.attempted ?? 0,
      }).catch(() => {});
    if (events)
      await append(events.handle, {
        ...base,
        kind: "UNKNOWN",
        reason,
      }).catch(() => {});
    fail("STORAGE_OBJECT_SUPPLEMENT_STOP");
  } finally {
    const epoch = liveEpochs.get(capability);
    if (epoch) {
      epoch.armed = false;
      epoch.token = null;
      epoch.secrets.fill("");
    }
    liveEpochs.delete(capability);
    for (const record of [events, usage, ...locks].filter(Boolean)) await record.handle.close();
    if (ledger) await ledger.close();
    // Usage survives every outcome. UNKNOWN locks survive even when all private FDs close.
    if (clean || !started)
      for (const lock of locks.toReversed()) {
        const current = lstatSync(lock.path, { bigint: true });
        if (
          !current.isFile() ||
          current.dev !== lock.identity.dev ||
          current.ino !== lock.identity.ino ||
          current.uid !== BigInt(process.getuid()) ||
          (Number(current.mode) & 0o777) !== 0o600 ||
          readFileSync(lock.path, "utf8") !== lock.body
        )
          fail("LOCK_RELEASE_IDENTITY");
        unlinkSync(lock.path);
        await syncDirectory(paths.lockDir);
      }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  if (process.argv.length !== 3 || !["plan", "pins", "native"].includes(command))
    fail("USAGE_PLAN_PINS_NATIVE_ONLY");
  const result =
    command === "plan"
      ? supplementPlan()
      : command === "pins"
        ? await supplementSourcePins()
        : await runRootSupplement();
  console.log(JSON.stringify(result));
}
