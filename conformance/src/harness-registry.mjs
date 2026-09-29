// The harness digests a recorded production row is bound to, in one place.
//
// A fixture row records the digest of the harness that recorded it. A check refuses (STALE_FIXTURE)
// a row whose recorded digest is not the digest of today's harness, so a change to what a row means
// cannot go unnoticed. Two digests exist:
//
//   raw      the historical one: the sources as text, joined by a newline, then the extra inputs.
//            Every recorded fixture holds a raw digest. A comment or a provenance SHA in a source
//            changes it, which is how a history rewrite made every stage-1 row stale.
//   scheme 2 the same inputs as a token stream. Comments and whitespace do not count, everything
//            else does (identifiers, literals with their quotes, operators, template text).
//
// A recorded digest is accepted when it is today's raw or scheme-2 digest, or when a hop of
// harness-lineage.json connects it to today's scheme-2 digest. A hop is only sound if the recorded
// raw digest reproduces from the sources at the hop's commit and the scheme-2 digest of that commit
// equals today's, so the change between the recorded harness and today's is comments and
// whitespace and nothing else. Nothing is rewritten in a fixture.
//
//   node src/harness-registry.mjs verify [--json]     every enrolled lane, the lineage, enrollment

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { tokenizer } from "acorn";

import { PRINCIPALS as AUTH_FS_CROSS_PRINCIPALS } from "./auth-fs-cross/corpus.mjs";
import { STAGE2_PRINCIPALS } from "./auth-fs-cross/programs-stage2.mjs";
import { CONFORMANCE_DIR, REPO_ROOT } from "./config.mjs";
import { PRINCIPALS as FS_RULES_PRINCIPALS } from "./fs-rules/corpus.mjs";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The files stage 2's recorded rows depend on (its runner and recorder are not among them). */
export const STAGE2_HARNESS_FILES = [
  "fs-rules/harness.mjs",
  "auth-credential/tokens.mjs",
  "auth-fs-cross/stage2-session.mjs",
  "auth-fs-cross/stage2-orchestrator.mjs",
  "auth-fs-cross/listen-grpc.mjs",
  "auth-fs-cross/sdk-client.mjs",
  "auth-fs-cross/sdk-driver.mjs",
  "auth-fs-cross/sdk-driver-wire.mjs",
  "auth-fs-cross/sdk-wire.mjs",
  "auth-fs-cross/sdk-operations.mjs",
  "auth-fs-cross/browser-driver.mjs",
  "auth-fs-cross/browser-page.mjs",
];

/**
 * The lanes whose harness digest is bound here. `files` are under conformance/src and `extra` is
 * the JSON of the inputs that are data, not code. A lane's runner digests exactly this.
 */
export const HARNESS_LANES = {
  "fs-rules": {
    fixture: "fs-rules-production.json",
    files: ["fs-rules/harness.mjs", "fs-rules/session.mjs", "auth-credential/tokens.mjs"],
    extra: JSON.stringify(FS_RULES_PRINCIPALS),
  },
  "auth-fs-cross": {
    fixture: "auth-fs-cross-production.json",
    files: ["fs-rules/harness.mjs", "auth-fs-cross/session.mjs", "auth-credential/tokens.mjs"],
    extra: JSON.stringify(AUTH_FS_CROSS_PRINCIPALS),
  },
  "auth-fs-cross-stage2": {
    fixture: "auth-fs-cross-stage2-production.json",
    files: STAGE2_HARNESS_FILES,
    extra: JSON.stringify(STAGE2_PRINCIPALS),
  },
};

/**
 * Fixtures that hold a harnessDigest and are not enrolled yet: each lane's runner still computes
 * its digest privately. Adding one to HARNESS_LANES removes its entry here; a fixture in neither
 * list fails the selftest.
 */
const NOT_ENROLLED =
  "the lane's runner computes its harness digest privately and no other lane's change reaches its inputs; enroll it in harness-registry.mjs";
export const WAIVED_FIXTURES = [
  "auth-account-production.json",
  "auth-action-production.json",
  "auth-config-sdk-production.json",
  "auth-credential-production.json",
  "auth-federation-followup-production.json",
  "auth-federation-production.json",
  "auth-federation-saml-production.json",
  "auth-mfa-production.json",
  "auth-tenant-blocking-production.json",
  "fs-config-lifecycle-production.json",
  "fs-data-write-list-production.json",
  "fs-query-index-production.json",
].map((fixture) => ({ fixture, reason: NOT_ENROLLED }));

/**
 * Enrolled lanes whose recorded digest no lineage connects to today's, with the digest they were
 * last seen at: a further change flips the entry, so it cannot hide a second drift.
 */
export const KNOWN_UNCONNECTED = {
  "auth-fs-cross-stage2": {
    currentScheme2: "e25a081c8e4bb08abe2852357ec2610b7c89518d9512ce94d3474ade2e6cb9bb",
    reason:
      "the stop-time cleanup of stage2-session.mjs changed after the rows were recorded (3a7777242); no hop is written until a stage-2 rerun is planned and the owner decides on it",
  },
};

// ---- digests ---------------------------------------------------------------------------------

/** The tokens of a source, without comments and whitespace; source that does not parse throws. */
export function sourceTokens(text) {
  const tokens = [];
  for (const token of tokenizer(text, { ecmaVersion: "latest", sourceType: "module" }))
    tokens.push(text.slice(token.start, token.end));
  return tokens;
}

const withFile = (file, run) => {
  try {
    return run();
  } catch (error) {
    throw new Error(`${file}: ${error.message}`, { cause: error });
  }
};

/** The historical digest of a lane's inputs (see the header). */
export function rawDigest(lane, read) {
  return sha256(`${lane.files.map((file) => read(file)).join("\n")}\n${lane.extra}`);
}

/** The digest of a lane's inputs as token streams, the extra inputs and the file names. */
export function scheme2Digest(lane, read) {
  const files = lane.files.map((file) => ({
    file,
    tokens: sha256(JSON.stringify(withFile(file, () => sourceTokens(read(file))))),
  }));
  return sha256(JSON.stringify({ scheme: 2, files, extra: lane.extra }));
}

/** Reads a harness source from this checkout. */
export const treeReader = (file) => readFileSync(join(CONFORMANCE_DIR, "src", file), "utf8");

/** Reads a harness source as it was at `commit`. */
export const gitReader = (commit) => (file) =>
  execFileSync("git", ["show", `${commit}:conformance/src/${file}`], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

// ---- the acceptance rule -----------------------------------------------------------------------

/**
 * How a recorded digest relates to today's harness: `raw` and `scheme2` when it is today's digest,
 * `lineage` when a hop connects it, otherwise `stale`.
 */
export function checkFixtureDigest(name, lane, saved, { read = treeReader, lineage } = {}) {
  const hops = lineage ?? loadLineage().hops;
  const current = scheme2Digest(lane, read);
  if (saved === current) return { state: "scheme2", saved, current };
  if (saved === rawDigest(lane, read)) return { state: "raw", saved, current };
  const hop = hops.find((h) => h.lane === name && h.from === saved && h.to === current);
  return { state: hop ? "lineage" : "stale", saved, current };
}

/** The harness digests a lane's fixture records (every row's, or the one of the whole file). */
export function recordedDigests(name, fixture) {
  const found =
    name === "auth-fs-cross-stage2"
      ? [fixture.harnessDigest]
      : Object.values(fixture.programs ?? {}).map((program) => program.harnessDigest);
  if (found.length === 0 || found.some((digest) => !/^[0-9a-f]{64}$/.test(digest ?? "")))
    throw new Error(`${name}: the fixture has a row without a harnessDigest`);
  return [...new Set(found)];
}

/** The state of one lane against its fixture: the worst state over its recorded digests. */
export function laneStatus(
  name,
  lane,
  {
    read = treeReader,
    lineage,
    fixture = JSON.parse(readFileSync(join(CONFORMANCE_DIR, lane.fixture), "utf8")),
  } = {},
) {
  const results = recordedDigests(name, fixture).map((saved) =>
    checkFixtureDigest(name, lane, saved, { read, lineage }),
  );
  return (
    results.find((r) => r.state === "stale") ??
    results.find((r) => r.state === "lineage") ??
    results[0]
  );
}

// ---- the lineage file ---------------------------------------------------------------------------

export const LINEAGE_PATH = join(CONFORMANCE_DIR, "harness-lineage.json");
const HOP_KEYS = ["commit", "from", "kind", "lane", "to"];
const HOP_KINDS = ["scheme"];

export function loadLineage(path = LINEAGE_PATH) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * Everything wrong with the lineage: a malformed hop, a hop whose recorded digest does not
 * reproduce at its commit, whose scheme-2 digest is not that of its commit or of the current tree
 * (so the change between them is more than comments and whitespace), a commit that cannot be
 * read, and a shallow clone (history is needed, so this is a failure and never a skip).
 */
export function lineageProblems(lineage, { lanes, reader, shallow, current = treeReader }) {
  const problems = [];
  if (lineage?.version !== 1 || !Array.isArray(lineage.hops))
    return ["the lineage is not { version: 1, hops: [] }"];
  if (shallow && lineage.hops.length > 0)
    problems.push("this is a shallow clone: the lineage cannot be verified without the history");
  const seen = new Set();
  lineage.hops.forEach((hop, index) => {
    const at = `hop ${index}`;
    const before = problems.length;
    const extraKeys = Object.keys(hop).filter((key) => !HOP_KEYS.includes(key));
    if (extraKeys.length) problems.push(`${at}: unexpected ${extraKeys.join(", ")}`);
    const lane = lanes[hop.lane];
    if (!lane) return problems.push(`${at}: unknown lane ${hop.lane}`);
    if (!HOP_KINDS.includes(hop.kind))
      problems.push(`${at}: kind ${hop.kind} is not one of ${HOP_KINDS}`);
    if (!/^[0-9a-f]{40}$/.test(hop.commit ?? ""))
      problems.push(`${at}: commit is not a full 40-hex SHA`);
    for (const key of ["from", "to"])
      if (!/^[0-9a-f]{64}$/.test(hop[key] ?? ""))
        problems.push(`${at}: ${key} is not a 64-hex digest`);
    const id = `${hop.lane}/${hop.from}`;
    if (seen.has(id)) problems.push(`${at}: duplicate hop for ${id}`);
    seen.add(id);
    if (problems.length > before || shallow) return;
    let atCommit;
    try {
      const read = reader(hop.commit);
      lane.files.forEach((file) => read(file));
      atCommit = read;
    } catch (error) {
      return problems.push(
        `${at}: the sources at ${hop.commit} are not readable (${error.message})`,
      );
    }
    if (rawDigest(lane, atCommit) !== hop.from)
      problems.push(`${at}: the recorded digest does not reproduce at ${hop.commit}`);
    if (scheme2Digest(lane, atCommit) !== hop.to)
      problems.push(`${at}: the scheme-2 digest at ${hop.commit} is not the hop's`);
    if (scheme2Digest(lane, current) !== hop.to)
      problems.push(`${at}: the scheme-2 digest of the current tree is not the hop's`);
  });
  return problems;
}

// ---- enrollment --------------------------------------------------------------------------------

/** Every conformance fixture that holds a harnessDigest. */
export function fixturesWithHarnessDigest(dir = CONFORMANCE_DIR) {
  return readdirSync(dir)
    .filter((file) => file.endsWith("-production.json"))
    .filter((file) => /"harnessDigest"\s*:/.test(readFileSync(join(dir, file), "utf8")))
    .toSorted();
}

/** Fixtures neither enrolled nor waived, waivers without a reason, and entries for no fixture. */
export function enrollmentProblems({
  fixtures = fixturesWithHarnessDigest(),
  lanes = HARNESS_LANES,
  waived = WAIVED_FIXTURES,
} = {}) {
  const problems = [];
  const enrolled = new Set(Object.values(lanes).map((lane) => lane.fixture));
  const waivedNames = new Set(waived.map((w) => w.fixture));
  for (const fixture of fixtures)
    if (!enrolled.has(fixture) && !waivedNames.has(fixture))
      problems.push(`${fixture}: has a harnessDigest and is neither enrolled nor waived`);
  for (const { fixture, reason } of waived) {
    if (typeof reason !== "string" || reason.length < 20)
      problems.push(`${fixture}: the waiver needs a reason`);
    if (!fixtures.includes(fixture))
      problems.push(`${fixture}: waived, but no such fixture holds a harnessDigest`);
    if (enrolled.has(fixture)) problems.push(`${fixture}: both enrolled and waived`);
  }
  for (const fixture of enrolled)
    if (!fixtures.includes(fixture))
      problems.push(`${fixture}: enrolled, but no such fixture holds a harnessDigest`);
  return problems;
}

/**
 * Enrolled lanes whose recorded digest no hop connects to today's, except the ones listed in
 * KNOWN_UNCONNECTED at their present digest; and known entries that no longer apply.
 */
export function unconnectedProblems({
  lanes = HARNESS_LANES,
  known = KNOWN_UNCONNECTED,
  lineage,
} = {}) {
  const problems = [];
  for (const [name, lane] of Object.entries(lanes)) {
    const status = laneStatus(name, lane, { lineage });
    const entry = known[name];
    if (status.state === "stale") {
      if (!entry)
        problems.push(
          `${name}: the recorded digest ${status.saved} is not connected to ${status.current}`,
        );
      else if (entry.currentScheme2 !== status.current)
        problems.push(
          `${name}: the known-unconnected entry is out of date (now ${status.current})`,
        );
      else if (typeof entry.reason !== "string" || entry.reason.length < 20)
        problems.push(`${name}: the known-unconnected entry needs a reason`);
    } else if (entry) problems.push(`${name} is connected; drop its known-unconnected entry`);
  }
  for (const name of Object.keys(known))
    if (!lanes[name]) problems.push(`${name}: known-unconnected, but no such lane`);
  return problems;
}

/** Whether this checkout has only part of the history (a hop cannot be verified then). */
export function isShallowCheckout() {
  return (
    execFileSync("git", ["rev-parse", "--is-shallow-repository"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    }).trim() === "true"
  );
}

/** Everything the release gate and the selftest refuse: a shallow clone counts. */
export function bindingProblems({ reader = gitReader, shallow = isShallowCheckout() } = {}) {
  const lineage = loadLineage();
  return [
    ...lineageProblems(lineage, { lanes: HARNESS_LANES, reader, shallow }),
    ...enrollmentProblems(),
    ...unconnectedProblems({ lineage: lineage.hops }),
  ];
}

// ---- report ------------------------------------------------------------------------------------

/** What `verify` prints: each lane's recorded and current digest and its state. */
export function verifyReport({ reader = gitReader, shallow } = {}) {
  const isShallow = shallow ?? isShallowCheckout();
  const lineage = loadLineage();
  const lanes = Object.fromEntries(
    Object.entries(HARNESS_LANES).map(([name, lane]) => {
      const status = laneStatus(name, lane, { lineage: lineage.hops });
      return [name, { ...status, known: KNOWN_UNCONNECTED[name] !== undefined }];
    }),
  );
  return {
    lanes,
    lineageProblems: lineageProblems(lineage, { lanes: HARNESS_LANES, reader, shallow: isShallow }),
    enrollmentProblems: enrollmentProblems(),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] !== "verify") {
    console.error("usage: harness-registry.mjs verify [--json]");
    process.exitCode = 2;
  } else {
    const report = verifyReport();
    if (process.argv.includes("--json")) console.log(JSON.stringify(report, null, 2));
    else
      for (const [name, lane] of Object.entries(report.lanes))
        console.log(`${name}: ${lane.state} (recorded ${lane.saved}, current ${lane.current})`);
    const unconnected = Object.entries(report.lanes).filter(
      ([name, lane]) => lane.state === "stale" && !lane.known,
    );
    if (report.lineageProblems.length || report.enrollmentProblems.length || unconnected.length) {
      for (const problem of [...report.lineageProblems, ...report.enrollmentProblems])
        console.error(problem);
      for (const [name] of unconnected) console.error(`${name}: recorded digest is not connected`);
      process.exitCode = 1;
    }
  }
}
