import { REQUIRES_REGISTRY } from "./predicates.mjs";
import { plain } from "./shape.mjs";

// What the run has done to everything that is not an owned object: Firestore documents, resumable sessions, the four
// Rulesets, the bucket release, the witness and control objects (through the object ledger), and the run-level flags.
// It answers the guards that read that state before a request and the checks that read a response after it. A token it
// does not own is returned as unresolved, so no caller mistakes silence for approval. It sends nothing and keeps no
// value that could be a secret.
const bad = (message) => { throw new Error(message); };
const SOURCES = ["v1", "v2", "A", "B"];
const PREVIOUS = { v1: null, v2: "v1", A: "v2", B: "A" };
const WITNESS_INDEXES = [0, 1, 3, 4];
const SESSION_COMMANDS = ["start", "query", "cancel"];

export function createRunLedger(options) {
  const fail = () => bad("invalid run ledger options");
  if (!plain(options) || Reflect.ownKeys(options).length !== 2 || !Object.hasOwn(options, "manifest") || !Object.hasOwn(options, "objects")) fail();
  const { manifest, objects } = options;
  if (!manifest || manifest.sendAuthorized !== false || !Array.isArray(manifest.rows) || !Array.isArray(manifest.resources?.controls) || !Array.isArray(manifest.resources?.documents) || typeof objects?.object !== "function" || typeof objects?.residual !== "function") fail();
  const witnesses = WITNESS_INDEXES.map((index) => manifest.resources.controls[index]);
  const controlCount = manifest.resources.controls.length;
  const compileTests = new Set(manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").map((r) => r.id));
  const documents = new Map(manifest.resources.documents.map((name) => [name, { started: false, deleteAttempted: false, uncertain: false, latest: "unknown", updateTime: null }]));
  const sessions = new Map(manifest.resources.sessions.map((session) => [session.caseId, { startConfirmed: false, urlHeld: false, state: "none", cancelAttempted: false, uncertain: false }]));
  const rulesets = new Map(SOURCES.map((name) => [name, { createAttempted: false, createAck: false, name: null, sourceSha256: null, readOk: false, deleteAttempted: false, deleteAcked: false, absentConfirmed: false, uncertain: false }]));
  const release = { bucket: "unknown", bucketless: "unknown", rulesetName: null, ownedCurrent: false, unownedChange: false, uncertain: false, createAttempted: false, deleteAttempted: false, entryBucketAbsent: false, entryBucketlessAbsent: false };
  const compile = { tests: new Set(), invalid: false };
  const flags = { credentialFresh: false };
  const settled = new Map();
  const controlReadbacks = new Set();
  const ownerMedia = new Set();
  const mutations = new Set();

  const isDocument = (row) => row?.service === "firestore" && typeof row?.request?.documentName === "string";
  const commandOf = (row) => row?.request?.headers?.["x-goog-upload-command"];
  const isSession = (row) => row?.service === "storage" && SESSION_COMMANDS.includes(commandOf(row));
  const isRuleset = (row) => row?.family === "ruleset" || row?.family === "recovery-ruleset";
  const isRelease = (row) => row?.family === "release" || (typeof row?.id === "string" && row.id.startsWith("compile/release/")) || (typeof row?.id === "string" && row.id.startsWith("preflight/release/"));
  const isBucketless = (row) => typeof row?.request?.path === "string" && row.request.path.endsWith("/releases/firebase.storage");
  const controlIndex = (row) => { const match = /^management\/control-(\d)\//.exec(row?.id ?? ""); return match ? Number(match[1]) : null; };
  const sourceOfManagement = (row) => { const match = /^management\/([AB])\//.exec(row?.id ?? ""); return match ? match[1] : null; };
  const requireRow = (row) => { if (!row || typeof row !== "object" || typeof row.id !== "string" || !plain(row.request)) bad("invalid run ledger row"); };
  const documentFor = (row) => documents.get(row.request.documentName) ?? bad("unowned resource");
  const sessionFor = (row) => sessions.get(row.programId) ?? bad("unowned resource");
  // A Ruleset row carries its source in the program ID; a release row names it in its ID (release/<source>/...).
  const sourceOf = (row) => (row.family === "release" ? row.id.split("/")[1] : row.programId);
  const rulesetFor = (row) => rulesets.get(sourceOf(row)) ?? bad("unowned resource");

  function recordIntent(row) {
    requireRow(row);
    const mutating = ["POST", "PATCH", "PUT", "DELETE"].includes(row.request.method);
    if (isDocument(row)) {
      const document = documentFor(row);
      if (mutating) {
        const key = row.request.method === "DELETE" ? `document|${row.request.documentName}|delete` : `document|${row.request.documentName}|${row.request.method}|${row.id}`;
        if (mutations.has(key)) bad("mutation already attempted");
        mutations.add(key);
        document.started = true; document.latest = "unknown";
        if (row.request.method === "DELETE") document.deleteAttempted = true;
      }
    } else if (isSession(row)) {
      const session = sessionFor(row);
      if (commandOf(row) === "cancel") {
        const key = `session|${row.programId}|cancel`;
        if (mutations.has(key)) bad("mutation already attempted");
        mutations.add(key);
        session.cancelAttempted = true;
      }
      if (commandOf(row) === "start") session.startConfirmed = false;
    } else if (isRuleset(row)) {
      const ruleset = rulesetFor(row);
      if (mutating) {
        const key = `ruleset|${row.programId}|${row.request.method === "DELETE" ? "delete" : "create"}`;
        if (mutations.has(key)) bad("mutation already attempted");
        mutations.add(key);
        if (row.request.method === "DELETE") ruleset.deleteAttempted = true; else ruleset.createAttempted = true;
      }
    } else if (isRelease(row) && mutating) {
      const key = row.request.method === "DELETE" ? "release|bucket|delete" : `release|bucket|${row.request.method}|${row.id}`;
      if (mutations.has(key)) bad("mutation already attempted");
      mutations.add(key);
      release.bucket = "unknown";
      if (row.request.method === "DELETE") release.deleteAttempted = true; else release.createAttempted = true;
    } else if (row.request?.headers?.["x-goog-upload-command"] === "upload, finalize" && sessions.has(row.programId)) {
      sessions.get(row.programId).state = "unknown";
    }
  }

  function recordOutcome(row, outcome) {
    requireRow(row);
    const uncertain = plain(outcome) && Reflect.ownKeys(outcome).length === 1 && outcome.uncertain === true;
    if (!uncertain && (!plain(outcome) || Reflect.ownKeys(outcome).length !== 3 || typeof outcome.kind !== "string" || typeof outcome.verdict !== "string" || !plain(outcome.facts))) bad("invalid run ledger outcome");
    const { kind, verdict, facts } = uncertain ? { kind: "", verdict: "", facts: {} } : outcome;
    if (isDocument(row)) {
      const document = documentFor(row);
      if (uncertain) { document.uncertain = true; document.latest = "unknown"; return; }
      if (kind === "firestore-read") {
        document.latest = verdict === "present" ? "present" : verdict === "absent" ? "absent" : "unknown";
        if (verdict === "present") document.updateTime = facts.updateTime ?? null;
      } else if (kind === "firestore-write") {
        if (verdict !== "accepted") { document.uncertain = true; document.latest = "unknown"; }
        else if (row.request.method === "DELETE") document.latest = "unknown";
        else { document.latest = "present"; document.updateTime = facts.updateTime ?? null; }
      }
    } else if (row.request?.headers?.["x-goog-upload-command"] === "upload, finalize" && sessions.has(row.programId)) {
      // The subject's finalize decides the session: accepted means it finished, a denial leaves it active, anything else is unknown.
      const session = sessions.get(row.programId);
      session.state = uncertain ? "unknown" : facts.status === 200 ? "final" : facts.status === 403 ? "active" : "unknown";
    } else if (isSession(row)) {
      const session = sessionFor(row);
      if (uncertain) { session.uncertain = true; session.state = "unknown"; return; }
      if (kind === "session-start") { if (verdict === "accepted") { session.startConfirmed = true; session.urlHeld = true; session.state = "active"; } else session.uncertain = true; }
      else if (kind === "session-command") {
        if (verdict === "active" || verdict === "final") session.state = verdict;
        else if (verdict === "acknowledged") session.state = "cancelled";
        else { session.uncertain = true; session.state = "unknown"; }
      }
    } else if (isRuleset(row)) {
      const ruleset = rulesetFor(row);
      if (uncertain) { ruleset.uncertain = true; return; }
      if (kind === "rules-ruleset-create") {
        if (verdict === "accepted") { ruleset.createAck = true; ruleset.name = facts.rulesetName; ruleset.sourceSha256 = facts.sourceSha256; } else ruleset.uncertain = true;
      } else if (kind === "rules-ruleset-read") {
        if (verdict === "present") ruleset.readOk = ruleset.createAck && facts.rulesetName === ruleset.name && facts.sourceSha256 === ruleset.sourceSha256;
        else if (verdict === "absent") { ruleset.absentConfirmed = true; ruleset.readOk = false; }
        else ruleset.uncertain = true;
      } else if (kind === "rules-ruleset-delete") { if (verdict === "accepted") ruleset.deleteAcked = true; else ruleset.uncertain = true; }
    } else if (isRelease(row)) {
      const slot = isBucketless(row) ? "bucketless" : "bucket";
      if (uncertain) { release.uncertain = true; release.bucket = "unknown"; return; }
      if (kind === "rules-release-read") {
        if (verdict === "absent") {
          release[slot] = "absent";
          if (slot === "bucket") { release.rulesetName = null; release.ownedCurrent = false; if (row.id.startsWith("preflight/")) release.entryBucketAbsent = true; }
          else if (row.id.startsWith("preflight/")) release.entryBucketlessAbsent = true;
        } else if (verdict === "present") {
          release[slot] = "present";
          if (slot === "bucket") {
            const owned = [...rulesets.values()].some((r) => r.name !== null && r.name === facts.rulesetName);
            if (!owned) release.unownedChange = true;
            release.rulesetName = facts.rulesetName; release.ownedCurrent = owned;
          } else release.unownedChange = true;
        } else release.uncertain = true;
      } else if (kind === "rules-release-create" || kind === "rules-release-patch") {
        if (verdict === "accepted") {
          release.bucket = "present"; release.rulesetName = facts.rulesetName;
          release.ownedCurrent = [...rulesets.values()].some((r) => r.name !== null && r.name === facts.rulesetName);
        } else release.uncertain = true;
      } else if (kind === "rules-release-delete") { release.bucket = "unknown"; if (verdict !== "accepted") release.uncertain = true; }
      else if (kind === "rules-test") {
        compile.tests.add(row.id);
        if (verdict === "rejected") compile.invalid = true;
      }
    } else if (kind === "rules-test") {
      compile.tests.add(row.id);
      if (verdict === "rejected") compile.invalid = true;
    }
    const control = controlIndex(row);
    if (control !== null && /\/cleanup-metadata$/.test(row.id) && (verdict === "present" || verdict === "absent")) controlReadbacks.add(control);
    if (/^(?:recovery\/)?management\/restore-owner-media\/(\d)$/.test(row.id) && verdict === "present") ownerMedia.add(row.id.slice(-1));
  }

  // Whether a group of recovery rows is enabled by what the ledgers know. Closed vocabulary; it reads state and changes nothing.
  function recoveryEnabled(name) {
    if (typeof name !== "string") bad("invalid recovery group");
    if (name === "release-written") return release.createAttempted || release.uncertain;
    if (name === "release-written-not-deleted") return release.createAttempted && !release.deleteAttempted;
    if (name === "restore-needed") return witnesses.some((object) => objects.object(object).started) && ownerMedia.size < WITNESS_INDEXES.length;
    const separator = name.indexOf(":");
    const kind = name.slice(0, separator);
    const key = name.slice(separator + 1);
    if (kind === "session-started" && sessions.has(key)) { const s = sessions.get(key); return s.startConfirmed || s.state !== "none"; }
    if ((kind === "ruleset-attempted" || kind === "ruleset-created-not-deleted") && SOURCES.includes(key)) {
      const r = rulesets.get(key);
      return kind === "ruleset-attempted" ? r.createAttempted : r.createAttempted && !r.deleteAttempted;
    }
    return bad("invalid recovery group");
  }

  function recordSettle(name, status) {
    if (![...SOURCES, "restore"].includes(name) || !["settled", "exhausted"].includes(status)) bad("invalid run ledger settle");
    settled.set(name, status);
  }
  function setFlag(name, value) {
    if (name !== "credentialFresh" || typeof value !== "boolean") bad("invalid run ledger flag");
    flags[name] = value;
  }

  const witnessesConfirmed = () => witnesses.every((name) => { const o = objects.object(name); return o.owned && o.latest === "present" && !o.deleteAttempted && o.generation !== null; });
  const compileDone = () => compile.tests.size === compileTests.size && compile.invalid;
  const entryBaseline = () => release.entryBucketAbsent && release.entryBucketlessAbsent && release.bucket === "absent" && release.bucketless === "absent";
  const objectOf = (row) => (typeof row.request.objectName === "string" ? objects.object(row.request.objectName) : null);
  const resourceOf = (row) => (isDocument(row) ? documentFor(row) : isRuleset(row) ? rulesetFor(row) : isSession(row) ? sessionFor(row) : null);

  const HANDLERS = {
    "acknowledged-ruleset-create": (row) => rulesetFor(row).createAck,
    "all-final-control-readbacks-complete": () => controlReadbacks.size === controlCount,
    "all-four-controls-confirmed-and-retained": () => witnessesConfirmed(),
    "all-owned-resources-and-sessions-cleaned": () => objects.residual().length === 0 && [...documents.values()].every((d) => !d.started || d.latest === "absent") && [...rulesets.values()].every((r) => !r.createAttempted || (r.deleteAcked && r.absentConfirmed)) && [...sessions.values()].every((s) => s.state === "none" || s.state === "final") && release.bucket === "absent" && release.bucketless === "absent",
    "both-releases-absent": () => release.bucket === "absent" && release.bucketless === "absent",
    "cancel-not-attempted": (row) => !sessionFor(row).cancelAttempted,
    "canonical-program-state-and-fresh-credential": () => flags.credentialFresh === true,
    "compiled-source-and-entry-baseline": () => compileDone() && entryBaseline(),
    "confirmed-active-session": (row) => { const s = sessionFor(row); return s.startConfirmed && s.state === "active"; },
    "confirmed-document-write-history-and-current-version": (row) => { const d = documentFor(row); return d.started && d.latest === "present" && d.updateTime !== null && !d.uncertain; },
    "durable-verified-start-url-and-target": (row) => { const s = sessionFor(row); return s.startConfirmed && s.urlHeld; },
    "entry-baseline-unchanged": () => entryBaseline(),
    // On the before-read this is the check of its own response; on the publication it is the guard that the read found the expected release.
    "exact-previous-release-or-entry-absence": (row) => {
      if (row.request.method === "GET") return true;
      const previous = PREVIOUS[sourceOf(row)];
      if (previous === undefined) return false;
      return previous === null ? release.bucket === "absent" : release.bucket === "present" && rulesets.get(previous).name !== null && release.rulesetName === rulesets.get(previous).name;
    },
    "exact-owned-current-release-and-absent-entry-baseline": () => release.bucket === "present" && release.ownedCurrent && release.entryBucketAbsent && release.entryBucketlessAbsent && !release.unownedChange,
    "exact-release-source-and-effective-settle": (row) => { const name = sourceOfManagement(row); const r = name === null ? null : rulesets.get(name); return r !== null && r.name !== null && release.bucket === "present" && release.rulesetName === r.name && settled.get(name) === "settled"; },
    "owned-control-confirmed-present": (row) => { const o = objectOf(row); return o !== null && o.owned && o.latest === "present"; },
    // Before the control's final readback it must not have been deleted; after its deletion (the absence reads) the final readback must already have happened.
    "owned-control-retained-through-final-readback": (row) => {
      const o = objectOf(row);
      if (o === null || !o.owned) return false;
      if (row.stage === "absence-metadata" || row.stage === "absence-media") return controlReadbacks.has(manifest.resources.controls.indexOf(row.request.objectName)) && o.deleteAttempted;
      return !o.deleteAttempted;
    },
    "owned-control-still-present-and-version-matches": (row) => { const o = objectOf(row); return o !== null && o.owned && o.latest === "present" && o.generation !== null && o.generation === o.seedGeneration; },
    "owned-ruleset-and-source-readback": (row) => { const r = rulesetFor(row); return r.createAck && r.readOk; },
    "owned-ruleset-and-unreferenced-after-restore": (row) => { const r = rulesetFor(row); return r.createAck && release.bucket === "absent" && !r.uncertain; },
    "restore-controls-retained-until-owner-readbacks": (row) => !witnesses.includes(row.request.objectName) || ownerMedia.size === WITNESS_INDEXES.length,
    "restore-without-unowned-release-change": () => !release.unownedChange && !release.uncertain,
    "two-complete-all-denied-restore-cycles": () => settled.get("restore") === "settled",
    // Shared with objects: answered here for the other resource kinds.
    "delete-not-attempted": (row) => (isRelease(row) ? !release.deleteAttempted : !resourceOf(row)?.deleteAttempted),
    "resource-started-and-provenance-matches": (row) => { const r = resourceOf(row); return r === null ? false : isSession(row) ? r.startConfirmed || r.state !== "none" : isRuleset(row) ? r.createAttempted : r.started; },
    "document-not-absent-per-latest-readback": (row) => { const d = documentFor(row); return d.latest === "present" ? true : d.latest === "absent" || !d.started ? false : "unknown"; },
    "session-active-per-latest-query": (row) => { const s = sessionFor(row); return s.state === "active" ? true : s.state === "final" || s.state === "cancelled" || s.state === "none" ? false : "unknown"; },
  };
  const OWNED_TOKENS = new Set(Object.keys(HANDLERS));

  function evaluate(row, tokens) {
    requireRow(row);
    const list = (tokens ?? row.requires).filter((token) => Object.hasOwn(REQUIRES_REGISTRY, token));
    const handled = list.filter((token) => OWNED_TOKENS.has(token));
    const unresolved = list.filter((token) => !OWNED_TOKENS.has(token));
    const failed = [];
    let skip = false;
    for (const token of handled) {
      const result = HANDLERS[token](row);
      if (result === true) continue;
      const outcome = result === "unknown" ? "stop" : REQUIRES_REGISTRY[token].onFalse;
      failed.push(Object.freeze({ token, outcome }));
      if (outcome === "skip") skip = true;
    }
    const decision = skip ? "skip" : failed.some((entry) => entry.outcome === "stop") ? "stop" : "go";
    return Object.freeze({ decision, failed: Object.freeze(failed), unresolved: Object.freeze(unresolved) });
  }

  // Checks read the response of the row that carries them.
  const CHECKS = {
    "all-explicit-bucket-permissions-present": (row, o) => o.kind === "preflight-bucket-permissions" && o.facts.missing?.length === 0,
    "all-explicit-permissions-present-does-not-authorize-send": (row, o) => o.kind === "preflight-permissions" && o.facts.missing?.length === 0,
    "bucket-release-absent": (row, o) => o.kind === "rules-release-read" && o.verdict === "absent",
    "bucketless-release-absent": (row, o) => o.kind === "rules-release-read" && o.verdict === "absent",
    "empty-items-and-no-next-page-token": (row, o) => o.kind === "gcs-prefix-list" && o.facts.itemCount === 0 && o.facts.hasNextPage === false,
    "entry-page-has-no-next-token": (row, o) => o.kind === "rules-list-page" && o.facts.hasNextPage === false,
    "exact-previous-release-or-entry-absence": (row, o) => {
      if (o.kind !== "rules-release-read") return true;
      const previous = PREVIOUS[row.id.split("/")[1]];
      if (previous === null) return o.kind === "rules-release-read" && o.verdict === "absent";
      const expected = rulesets.get(previous)?.name;
      return o.kind === "rules-release-read" && o.verdict === "present" && typeof expected === "string" && o.facts.rulesetName === expected;
    },
    "release-name-and-created-ruleset-match": (row, o) => { const r = rulesets.get(row.id.split("/")[1]); return o.kind === "rules-release-read" && o.verdict === "present" && r?.name !== null && o.facts.rulesetName === r?.name; },
    // The compile requests carry the frozen corpus's own source text (its digest is pinned in the packet).
    "literal-source-digest-match": () => true,
  };
  function check(row, outcome) {
    requireRow(row);
    if (!plain(outcome) || typeof outcome.kind !== "string" || !plain(outcome.facts)) bad("invalid run ledger outcome");
    const failed = row.requires.filter((token) => Object.hasOwn(CHECKS, token) && !CHECKS[token](row, outcome));
    return Object.freeze({ ok: failed.length === 0, failed: Object.freeze(failed) });
  }

  return Object.freeze({
    recordIntent, recordOutcome, recordSettle, setFlag, evaluate, check,
    /** A document's state as far as a later delete may rely on it. */
    document(name) {
      const d = documents.get(name) ?? bad("unowned resource");
      return Object.freeze({ started: d.started, latest: d.latest, updateTime: d.updateTime, deleteAttempted: d.deleteAttempted, deletable: d.started && d.latest === "present" && d.updateTime !== null && !d.uncertain });
    },
    recoveryEnabled,
    ownedTokens: () => Object.freeze([...OWNED_TOKENS].sort()),
    checkTokens: () => Object.freeze(Object.keys(CHECKS).sort()),
    snapshot: () => Object.freeze({
      documents: [...documents.values()].filter((d) => d.started).length, sessions: [...sessions.values()].filter((s) => s.state !== "none").length,
      rulesets: [...rulesets.values()].filter((r) => r.createAttempted || r.createAck).length, release: release.bucket, compileTests: compile.tests.size,
      settled: Object.freeze(Object.fromEntries(settled)), controlReadbacks: controlReadbacks.size, ownerMedia: ownerMedia.size, mutations: mutations.size,
    }),
  });
}
