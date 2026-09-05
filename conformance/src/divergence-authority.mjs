// Structured authority for every documented divergence.
//
// `conformance/divergences.json` is the canonical register: a classifier may only promote a
// mismatch from `debt` to `documented-divergence` when the register carries a complete,
// verified authority record for that exact row. This module validates the register with the
// same semantics as the Rust gate (`tools/compat-check`, CC-10) so a standalone Node run
// cannot accept what the repository gate would refuse, and freezes the validated register so
// nothing can promote a row after validation.

import { readFileSync, realpathSync } from "node:fs";
import { resolve, sep } from "node:path";

import { REPO_ROOT } from "./config.mjs";

const KINDS = new Set([
  "production-spec",
  "official-emulator",
  "intentional-local-policy",
  "unverified",
]);
const SECTIONS = ["divergences", "firestoreMatrixDivergences", "rulesMatrixDivergences"];
const validatedMaps = new WeakSet();

const nonEmptyString = (value) => typeof value === "string" && value.length > 0;

const validDate = (value) => {
  if (!nonEmptyString(value) || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
};

/**
 * A source URL is accepted only as the exact text checked in: HTTPS, a dotted host, no
 * credentials, and no whitespace or control characters anywhere. The WHATWG parser strips
 * tabs and newlines before parsing, so the raw text is checked first.
 */
const validHttpsUrl = (value) => {
  if (!nonEmptyString(value)) return false;
  const rawWhitespaceOrControl = (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0x20 || (codePoint >= 0x7f && codePoint <= 0x9f) || /\s/u.test(character);
  };
  if ([...value].some(rawWhitespaceOrControl)) return false;
  if (!value.startsWith("https://")) return false;
  const authority = value.slice("https://".length).split(/[/?#]/, 1)[0];
  if (!authority || authority.includes("@") || !authority.includes(".")) return false;
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.hostname.length > 0 &&
      !parsed.username &&
      !parsed.password
    );
  } catch {
    return false;
  }
};

/**
 * A fixture reference is `conformance/<file>.json#<row>` or `conformance/<file>.json#<program>#<row>`,
 * repository-relative, with no parent or absolute segments.
 */
const FIXTURE_REFERENCE = /^conformance\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.json(#[^#]+){1,2}$/;

const wellFormedFixture = (value) =>
  nonEmptyString(value) &&
  FIXTURE_REFERENCE.test(value) &&
  !value
    .split("#")[0]
    .split("/")
    .some((segment) => segment === "." || segment === "..");

/** Whether the fixture file, symbolic links resolved, lies outside `root`. */
const fixtureEscapesRoot = (root, reference) => {
  const path = reference.split("#")[0];
  try {
    const file = realpathSync(resolve(root, path));
    const real = realpathSync(root);
    return file !== real && !file.startsWith(real + sep);
  } catch {
    return false;
  }
};

const readJson = (path) => {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
};

const rowId = (row) => (row && typeof row === "object" ? row.id : undefined);

/** Structural equality over JSON values, independent of object key order. */
const sameJson = (a, b) => {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((v, i) => sameJson(v, b[i]));
  const keys = Object.keys(a);
  return (
    keys.length === Object.keys(b).length &&
    keys.every((k) => Object.hasOwn(b, k) && sameJson(a[k], b[k]))
  );
};

/**
 * Resolves a fixture reference to the register key it identifies, mirroring
 * `fixture_row_key` in the Rust gate. `pinned` is the entry's `fireemu` value: an
 * object-shaped matrix row binds only when its recorded oracle answer differs from it,
 * because the matrix's own `divergence` marks are regenerated from the register.
 */
export function fixtureRowKey(root, reference, pinned) {
  const [path, ...fragments] = reference.split("#");
  const value = readJson(resolve(root, path));
  if (!value || typeof value !== "object") return undefined;
  if (fragments.length === 1) {
    const [step] = fragments;
    const steps = Array.isArray(value.steps) ? value.steps : undefined;
    if (steps?.some((row) => rowId(row) === step && row.status === "documented-divergence")) {
      return `${value.id ?? ""}#${step}`;
    }
    // Claim rows are keyed by their id alone, so only the Rules matrix may carry them.
    const claims =
      path === "conformance/rules-matrix.json" && Array.isArray(value.claims)
        ? value.claims
        : undefined;
    if (claims?.some((row) => rowId(row) === step && row.divergence !== undefined)) {
      return step;
    }
    return undefined;
  }
  const [programId, step] = fragments;
  const programs = Array.isArray(value.programs) ? value.programs : [];
  const program = programs.find((candidate) => rowId(candidate) === programId);
  const steps = program?.steps;
  const present = Array.isArray(steps)
    ? steps.some((row) => rowId(row) === step && row.status === "documented-divergence")
    : steps !== null &&
      typeof steps === "object" &&
      Object.hasOwn(steps, step) &&
      steps[step]?.oracle !== undefined &&
      pinned !== undefined &&
      !sameJson(steps[step].oracle, pinned);
  if (!present) return undefined;
  const prefix = path.endsWith("pubsub-matrix.json")
    ? "pubsub-probe/"
    : path.endsWith("storage-matrix.json")
      ? "storage-probe/"
      : "";
  return `${prefix}${programId}#${step}`;
}

function validateAuthority(key, authority, baselineVersion, root, problems, pinned) {
  if (!KINDS.has(authority.kind)) problems.push(`${key}: unknown authority kind`);
  if (authority.kind === "unverified") {
    problems.push(`${key}: unverified authority cannot justify a divergence`);
  }
  if (
    !Array.isArray(authority.sourceUrls) ||
    authority.sourceUrls.length === 0 ||
    !authority.sourceUrls.every(validHttpsUrl)
  ) {
    problems.push(`${key}: sourceUrls must contain valid HTTPS URLs`);
  }
  if (!validDate(authority.checkedOn)) problems.push(`${key}: checkedOn is invalid`);
  const baseline = authority.officialBaseline;
  if (
    !baseline ||
    typeof baseline !== "object" ||
    baseline.package !== "firebase-tools" ||
    baseline.version !== baselineVersion
  ) {
    problems.push(`${key}: officialBaseline must match firebase-tools ${baselineVersion}`);
  }
  if (!nonEmptyString(authority.decidedBy) && !nonEmptyString(authority.approvalRecord)) {
    problems.push(`${key}: decidedBy or approvalRecord is required`);
  }
  if (authority.fixture === undefined || authority.fixture === "") {
    problems.push(`${key}: fixture is required`);
    return;
  }
  if (!nonEmptyString(authority.fixture)) {
    problems.push(`${key}: fixture must be a non-empty string`);
    return;
  }
  if (!wellFormedFixture(authority.fixture)) {
    problems.push(`${key}: fixture must be a repository-relative conformance file`);
    return;
  }
  if (fixtureEscapesRoot(root, authority.fixture)) {
    problems.push(`${key}: fixture must stay inside the repository`);
    return;
  }
  const fixtureKey = fixtureRowKey(root, authority.fixture, pinned);
  if (fixtureKey === undefined) {
    problems.push(
      `${key}: fixture ${authority.fixture} does not name an existing documented-divergence row`,
    );
    return;
  }
  if (fixtureKey !== key) {
    problems.push(`${key}: fixture points to different row ${fixtureKey}`);
  }
}

/**
 * @param register parsed `divergences.json`
 * @param baselineVersion the pinned firebase-tools version every authority must name
 * @param options.root repository root the `fixture` references resolve against
 * @returns the problems found; an empty array means the register is acceptable
 */
export function validateDivergenceRegister(register, baselineVersion, { root = REPO_ROOT } = {}) {
  const problems = [];
  if (register?.schemaVersion !== 2) problems.push("schemaVersion must be 2");
  const seen = new Set();
  for (const section of SECTIONS) {
    const entries = register?.[section];
    if (!entries || Array.isArray(entries) || typeof entries !== "object") {
      problems.push(`${section} must be an object`);
      continue;
    }
    for (const [key, entry] of Object.entries(entries)) {
      if (seen.has(key)) problems.push(`${key}: declared twice`);
      seen.add(key);
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        problems.push(`${key}: entry must be an object`);
        continue;
      }
      if (entry.reason === undefined) problems.push(`${key}: reason is required`);
      else if (!nonEmptyString(entry.reason)) {
        problems.push(`${key}: reason must be a non-empty string`);
      }
      if (section === "divergences") {
        if (entry.documents === undefined) problems.push(`${key}: documents is required`);
        else if (!nonEmptyString(entry.documents)) {
          problems.push(`${key}: documents must be a non-empty string`);
        }
      } else if (!("fireemu" in entry)) {
        problems.push(`${key}: fireemu value is required`);
      }
      const authority = entry.authority;
      if (!authority || typeof authority !== "object" || Array.isArray(authority)) {
        problems.push(`${key}: authority is required`);
        continue;
      }
      validateAuthority(key, authority, baselineVersion, root, problems, entry.fireemu);
    }
  }
  return problems;
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

export function readValidatedDivergenceRegister() {
  const register = JSON.parse(
    readFileSync(new URL("../divergences.json", import.meta.url), "utf8"),
  );
  const packageManifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  const baselineVersion = packageManifest.dependencies["firebase-tools"];
  const problems = validateDivergenceRegister(register, baselineVersion, { root: REPO_ROOT });
  if (problems.length > 0) {
    throw new Error(`invalid divergence authority register:\n${problems.join("\n")}`);
  }
  deepFreeze(register);
  for (const section of SECTIONS) validatedMaps.add(register[section]);
  return register;
}

export const isValidatedDivergenceMap = (value) => validatedMaps.has(value);

/**
 * A frozen `{key: {fireemu, reason}}` view of one matrix section for the probes that pin
 * expectations, so a derived map is as immutable as the register it came from.
 */
export const frozenExpectations = (section) =>
  deepFreeze(
    Object.fromEntries(
      Object.entries(section ?? {}).map(([key, entry]) => [
        key,
        { fireemu: entry.fireemu, reason: entry.reason },
      ]),
    ),
  );
