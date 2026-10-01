import { createHash, randomBytes as systemRandomBytes } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { types } from "node:util";

// The explicitly named private packet of expected values a run is compared with, and the run's own fresh secrets. The packet
// is a private file (mode 0600, this user, one link), parsed as a closed data record. Its API keys sit under a
// non-enumerable property so serialising or listing the record never shows them. No path is searched, nothing is fetched.
const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const MAX_FILE_BYTES = 64 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;
const bad = () => { throw new Error("invalid private inputs"); };
const matches = (value, pattern) => typeof value === "string" && !/[\r\n\0]/.test(value) && pattern.test(value);

function record(value, keys) {
  if (types.isProxy(value) || value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) bad();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) bad();
  const out = {};
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) bad();
    out[key] = field.value;
  }
  return out;
}

function dataArray(value, maximum) {
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) bad();
  return value.map((_, index) => {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (!field?.enumerable || !Object.hasOwn(field, "value")) bad();
    return field.value;
  });
}

// The key the run uses in a project, by its API Keys v2 key ID (a UUID, or a custom ID such as the dedicated key's), with its uid, its
// API targets and the digest of its whole restriction object. Other live keys of the project do not matter to the run; the recorded key is
// compared exactly, and both keys must allow the two services the run signs in with.
const REQUIRED_SERVICES = ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"];
function project(value, projectId) {
  const row = record(value, ["projectId", "projectNumber", "apiKeyId", "apiKey", "keyUid", "apiTargets", "restrictionsSha256"]);
  const targets = dataArray(row.apiTargets, 64);
  if (
    row.projectId !== projectId || !matches(row.projectNumber, /^[1-9]\d{0,19}$/) || !matches(row.apiKeyId, /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z][a-z0-9-]{0,62})$/) ||
    !matches(row.apiKey, /^[A-Za-z0-9_-]{20,128}$/) || !matches(row.keyUid, /^[\x21-\x7e]{1,128}$/) || !HEX64.test(row.restrictionsSha256) ||
    targets.some((target, index) => !matches(target, /^[a-z0-9][a-z0-9.-]{2,127}$/) || (index > 0 && !(targets[index - 1] < target))) ||
    !REQUIRED_SERVICES.every((service) => targets.includes(service))
  ) bad();
  return { projectId: row.projectId, projectNumber: row.projectNumber, apiKeyId: row.apiKeyId, keyUid: row.keyUid, apiTargets: Object.freeze([...targets]), restrictionsSha256: row.restrictionsSha256, apiKey: row.apiKey };
}

/** Validate a packet object; the result is frozen, and the API keys are only under the non-enumerable `secrets`. */
export function parsePrivateInputs(value) {
  try {
    const top = record(value, ["schemaVersion", "adcPath", "owner", "projects", "bucket", "database", "queryProjectIamPolicySha256"]);
    const owner = record(top.owner, ["emailSha256", "subjectSha256"]);
    const projects = record(top.projects, ["query", "idp"]);
    const bucket = record(top.bucket, ["name", "location", "uniformBucketLevelAccess", "iamPolicySha256"]);
    const database = record(top.database, ["locationId", "type"]);
    const query = project(projects.query, QUERY);
    const idp = project(projects.idp, IDP);
    if (
      top.schemaVersion !== 1 || typeof top.adcPath !== "string" || top.adcPath.length > 1024 || !isAbsolute(top.adcPath) || /[\0\r\n]/.test(top.adcPath) ||
      !HEX64.test(owner.emailSha256) || !HEX64.test(owner.subjectSha256) ||
      query.projectNumber === idp.projectNumber || query.apiKeyId === idp.apiKeyId || query.apiKey === idp.apiKey ||
      !matches(bucket.name, /^[a-z0-9][a-z0-9._-]{2,221}$/) || !matches(bucket.location, /^[\x21-\x7e]{1,64}$/) || !(bucket.uniformBucketLevelAccess === null || typeof bucket.uniformBucketLevelAccess === "boolean") || !HEX64.test(bucket.iamPolicySha256) ||
      !matches(database.locationId, /^[\x21-\x7e]{1,64}$/) || !matches(database.type, /^[\x21-\x7e]{1,64}$/) || !HEX64.test(top.queryProjectIamPolicySha256)
    ) bad();
    const { apiKey: queryKey, ...queryPublic } = query;
    const { apiKey: idpKey, ...idpPublic } = idp;
    const inputs = {
      schemaVersion: 1, adcPath: top.adcPath, owner: Object.freeze({ ...owner }),
      projects: Object.freeze({ query: Object.freeze(queryPublic), idp: Object.freeze(idpPublic) }),
      bucket: Object.freeze({ ...bucket }), database: Object.freeze({ ...database }), queryProjectIamPolicySha256: top.queryProjectIamPolicySha256,
    };
    Object.defineProperty(inputs, "secrets", { value: Object.freeze({ apiKeys: Object.freeze({ query: queryKey, idp: idpKey }) }), enumerable: false });
    return Object.freeze(inputs);
  } catch { throw new Error("invalid private inputs"); }
}

// A JSON text with a repeated key in one object is refused: JSON.parse would keep only the last value silently.
function hasDuplicateKey(text) {
  const stack = [];
  let index = 0;
  const readString = () => {
    let out = "";
    index++;
    while (index < text.length && text[index] !== '"') {
      if (text[index] === "\\") { out += text.slice(index, index + 2); index += 2; } else { out += text[index]; index++; }
    }
    index++;
    return out;
  };
  let expectKey = false;
  while (index < text.length) {
    const char = text[index];
    if (char === "{") { stack.push(new Set()); expectKey = true; index++; }
    else if (char === "[") { stack.push(null); expectKey = false; index++; }
    else if (char === "}" || char === "]") { stack.pop(); expectKey = false; index++; }
    else if (char === ",") { expectKey = stack.at(-1) instanceof Set; index++; }
    else if (char === '"') {
      const value = readString();
      if (expectKey) {
        const keys = stack.at(-1);
        if (keys.has(value)) return true;
        keys.add(value);
        expectKey = false;
      }
    } else index++;
  }
  return false;
}

async function readPrivateFile(options, refusal, uid) {
  try {
    if (options === null || typeof options !== "object" || typeof options.path !== "string" || !isAbsolute(options.path) || options.path.includes("\0")) throw new Error();
    const expectedUid = options.uid === undefined ? process.getuid() : options.uid;
    if (!Number.isInteger(expectedUid)) throw new Error();
    // O_NONBLOCK: opening a FIFO would otherwise wait for a writer forever; it is refused below as not a regular file.
    const handle = await open(options.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.uid !== expectedUid || stat.nlink !== 1 || stat.size > MAX_FILE_BYTES) throw new Error();
      const bytes = await handle.readFile();
      if (bytes.length > MAX_FILE_BYTES || bytes.length !== stat.size) throw new Error();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      if (hasDuplicateKey(text)) throw new Error();
      return { parsed: JSON.parse(text), bytes };
    } finally { await handle.close(); }
  } catch { throw new Error(refusal); }
}

/** Read and validate the private packet file. Every failure, including invalid content, is one error that echoes nothing. */
export async function loadPrivateInputs(options) {
  const { parsed, bytes } = await readPrivateFile(options, "private inputs file refused");
  let inputs;
  try { inputs = parsePrivateInputs(parsed); } catch { throw new Error("private inputs file refused"); }
  const withProvenance = { ...inputs, provenance: Object.freeze({ sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length }) };
  Object.defineProperty(withProvenance, "secrets", { value: inputs.secrets, enumerable: false });
  return Object.freeze(withProvenance);
}

/** Read the ADC file the packet names (never searched for) and keep only the four fields the credential cache takes. */
export async function readAdcFile(options) {
  const { parsed } = await readPrivateFile(options, "ADC file refused");
  try {
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || parsed.type !== "authorized_user") throw new Error();
    for (const key of ["client_id", "client_secret", "refresh_token"]) if (!matches(parsed[key], /^[\x21-\x7e]{1,4096}$/)) throw new Error();
    return Object.freeze({ type: "authorized_user", client_id: parsed.client_id, client_secret: parsed.client_secret, refresh_token: parsed.refresh_token });
  } catch { throw new Error("ADC file refused"); }
}

/** The run's own secrets: the digest salt, the four fixture passwords and the two deliberately malformed credentials. */
export function generateRunSecrets({ randomBytes = systemRandomBytes } = {}) {
  const take = (size) => {
    const bytes = randomBytes(size);
    if (!Buffer.isBuffer(bytes) || bytes.length !== size) throw new Error("invalid random source");
    return bytes;
  };
  const text = (size) => take(size).toString("base64url");
  return Object.freeze({
    digestSalt: take(32).toString("hex"),
    passwords: Object.freeze(Object.fromEntries(["user-a", "user-b", "revoked-token", "foreign-project-token"].map((account) => [account, text(24)]))),
    malformed: Object.freeze({ "malformed-token": `Firebase ${text(24)}`, "malformed-oauth": `Bearer ya29.${text(24)}` }),
  });
}
