// Orchestrator of the Storage Rules observation (sibling audit S1-S4, S7-S10). Target-agnostic:
// `deps` supplies the network, the credentials and the clock, so the same code runs against
// production, against fireemu and the official emulator (the dry runs) and against the fake world
// of the tests.
//
// Order: preflight (bucket, baseline release, rulesets, empty run root), then per recording:
// objects, the three released programs (ruleset create, release, settle by marker, rows,
// still-in-force reads), the three load-only rulesets, and the release back to the baseline.
// Cleanup runs in a `finally`: release restored, own rulesets deleted, own objects deleted and
// read back absent. An unknown answer to a write is never retried and ends in cleanup.

import { Buffer } from "node:buffer";

import { GuardError, RequestBudget, validateBaseline } from "./guard.mjs";
import {
  compareRecordings,
  compileRecord,
  parseCreated,
  parseJson,
  parseObjectList,
  parseRelease,
  parseRulesetList,
  rowRecord,
  sameRulesetList,
  mask,
} from "./judge.mjs";
import {
  LOAD_ONLY,
  LOCAL_BASELINE_RULES,
  OBJECTS,
  PROGRAMS,
  RECORDINGS,
  ROWS,
  SETTLE_MAX_POLLS,
  SETTLE_POLL_MS,
  SETTLE_STREAK,
  STILL_IN_FORCE_READS,
  objectName,
  plannedNames,
  recordingPrefix,
  rowsOf,
  runRoot,
  staticBounds,
} from "./plan.mjs";
import { UnknownAnswer, createWire } from "./wire.mjs";

export { UnknownAnswer };

export class StopRun extends Error {}

const enc = encodeURIComponent;

/**
 * @param {object} options
 * @param {object} options.target `{name: "production" | "local", bucket, project?, origin?}`
 * @param {string} options.runId `sr-xxxxxxxx`
 * @param {string} options.baseline `"absent"`, a full ruleset name (production) or `"local"`
 * @param {object} options.deps `{net, adminHeaders, now, sleep}`
 * @param {object} options.out `{journal(entry), save(name, data)}`
 * @param {Set<string>|null} [options.rowFilter] row ids to read (dry runs only; null: all)
 */
export async function observe({
  target,
  runId,
  baseline,
  deps,
  out: rawOut,
  recordings = RECORDINGS,
  caps = null,
  rowFilter = null,
}) {
  const production = target.name === "production";
  if (production) validateBaseline(baseline, target.project);
  const bounds = staticBounds(recordings);
  const budget = new RequestBudget(caps?.main ?? bounds.main, caps?.total ?? bounds.total);
  const reportingErrors = [];
  const noteReportingError = (text) => {
    if (reportingErrors.length < 20 && !reportingErrors.includes(text)) reportingErrors.push(text);
  };
  const out = {
    journal(entry) {
      try {
        rawOut.journal(entry);
      } catch (error) {
        noteReportingError(`journal: ${error?.message ?? error}`);
      }
    },
    save(name, data) {
      try {
        rawOut.save(name, data);
      } catch (error) {
        noteReportingError(`${name}: ${error?.message ?? error}`);
      }
    },
  };
  const root = runRoot(runId);
  const ownRulesets = new Set();
  const state = { runId, root, ownRulesets, baseline };
  const { wire, unknownLabels, unknownReads } = createWire({ target, state, budget, deps, out });
  const bucket = target.bucket;
  const gcs = production ? "https://storage.googleapis.com" : target.origin;
  const firebase = production ? "https://firebasestorage.googleapis.com" : target.origin;
  const rulesApi = "https://firebaserules.googleapis.com";
  const releaseName = `projects/${target.project}/releases/firebase.storage/${bucket}`;
  const sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));

  const created = new Map(); // name -> generation, from a 2xx create answer
  const unconfirmed = new Set(); // names of creates whose answer was unknown
  const refusedCreates = new Set(); // names whose create was refused or stored under another name
  const rowsAll = [];
  const loads = [];
  const publications = [];
  const problems = [];
  let entryRulesets = null;
  let releaseExists = baseline !== "absent";
  let released = false; // this run changed the bucket release
  let lastMarker = null;
  let stopped = null;

  const problem = (text) => {
    if (!problems.includes(text)) problems.push(text);
  };
  const json = (value) => Buffer.from(JSON.stringify(value));
  const jsonHeaders = { "content-type": "application/json" };

  // ---- primitives ----------------------------------------------------------------------------

  const gcsObjectUrl = (name, query = "") =>
    `${gcs}/storage/v1/b/${enc(bucket)}/o/${enc(name)}${query}`;
  const v0ObjectUrl = (name, query = "") =>
    `${firebase}/v0/b/${enc(bucket)}/o/${enc(name)}${query}`;
  const gcsList = (prefix) =>
    `${gcs}/storage/v1/b/${enc(bucket)}/o?prefix=${enc(prefix)}&maxResults=1000`;

  /** The multipart/related body of an upload with custom metadata (JSON part, then the bytes). */
  function multipart(name, object) {
    const boundary = "s9boundary0123";
    const parts = [
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify({ name, metadata: object.metadata })}\r\n`,
      `--${boundary}\r\nContent-Type: text/plain\r\n\r\n${object.body}\r\n--${boundary}--`,
    ];
    return { boundary, body: Buffer.from(parts.join("")) };
  }

  async function createObject(P, id) {
    const name = objectName(id, P);
    const object = OBJECTS[id];
    const upload = object.metadata ? multipart(name, object) : null;
    const res = await wire(
      `create/${id}`,
      {
        method: "POST",
        url: `${gcs}/upload/storage/v1/b/${enc(bucket)}/o?uploadType=${upload ? "multipart" : "media"}&name=${enc(name)}&ifGenerationMatch=0`,
        headers: {
          "content-type": upload ? `multipart/related; boundary=${upload.boundary}` : "text/plain",
        },
        body: upload ? upload.body : Buffer.from(object.body),
      },
      { admin: true },
    ).catch((error) => {
      if (error instanceof UnknownAnswer) unconfirmed.add(name);
      throw error;
    });
    if (res.status === 200) {
      const parsed = parseCreated(res);
      if (parsed === null) {
        unconfirmed.add(name);
        throw new StopRun(`create of ${id} answered 200 with an unrecorded body`);
      }
      if (parsed.name !== name) {
        // The server stored the bytes under another name (for example without a leading slash): the
        // cleanup deletes what it reports, and the rows of this object are not evaluated.
        created.set(parsed.name, parsed.generation);
        refusedCreates.add(name);
        problem(`create of ${id} was stored under another name`);
        return;
      }
      if (object.metadata && JSON.stringify(parsed.metadata) !== JSON.stringify(object.metadata)) {
        created.set(name, parsed.generation);
        throw new StopRun(`create of ${id} did not keep the custom metadata`);
      }
      created.set(name, parsed.generation);
      return;
    }
    if ([401, 403, 429].includes(res.status))
      throw new StopRun(`create of ${id} refused with ${res.status}`);
    // A 412 means another object already holds the name (for example a server that reads
    // `/x` and `x` as one object): the row is not evaluated and the run says so.
    refusedCreates.add(name);
    problem(`create of ${id} refused with ${res.status}`);
  }

  const markerStatus = async (label, P, markerId) => {
    const res = await wire(
      label,
      { method: "GET", url: v0ObjectUrl(objectName(markerId, P)) },
      { read: true },
    );
    return res;
  };

  /** Polls until `settleStreak` consecutive polls see `markerId` readable and `previousId` (if any) not. */
  async function settle(label, P, markerId, previousId) {
    if (!production) {
      const res = await markerStatus(`${label}/marker`, P, markerId);
      if (res.status !== 200)
        throw new StopRun(`${label}: the marker is not readable (${res.status})`);
      return { polls: 1 };
    }
    let streak = 0;
    for (let poll = 1; poll <= SETTLE_MAX_POLLS; poll += 1) {
      const now = await markerStatus(`${label}/poll${poll}/new`, P, markerId);
      let ok = now.status === 200;
      if (ok && previousId) {
        const before = await markerStatus(`${label}/poll${poll}/old`, P, previousId);
        ok = !before.unknown && before.status !== 200;
      }
      streak = ok ? streak + 1 : 0;
      if (streak >= SETTLE_STREAK) return { polls: poll };
      await sleep(SETTLE_POLL_MS);
    }
    throw new StopRun(`${label}: did not settle in ${SETTLE_MAX_POLLS} polls`);
  }

  // ---- rules plane ---------------------------------------------------------------------------

  async function setLocalRules(label, source) {
    return wire(
      label,
      {
        method: "PUT",
        url: `${target.origin}/internal/setRules`,
        headers: jsonHeaders,
        body: json({ rules: { files: [{ name: "storage.rules", content: source }] } }),
      },
      { admin: true, read: true },
    );
  }

  async function createRuleset(label, source) {
    const res = await wire(
      label,
      {
        method: "POST",
        url: `${rulesApi}/v1/projects/${target.project}/rulesets`,
        headers: jsonHeaders,
        body: json({ source: { files: [{ name: "storage.rules", content: source }] } }),
      },
      { admin: true },
    );
    if (res.status === 200) {
      const body = parseJson(res.body);
      if (
        !new RegExp(`^projects/${target.project}/rulesets/[A-Za-z0-9_-]{1,128}$`).test(
          body?.name ?? "",
        )
      )
        throw new StopRun(`${label}: the created ruleset has an unrecorded name`);
      ownRulesets.add(body.name);
      return { res, name: body.name };
    }
    if (res.status === 400) return { res, name: null };
    throw new StopRun(`${label}: ruleset create answered ${res.status}`);
  }

  /** The release, or null when the answer is not a recorded shape. A `read` caller gets null for an unknown answer too. */
  async function readRelease(label, read = false) {
    const res = await wire(
      label,
      {
        method: "GET",
        url: `${rulesApi}/v1/${releaseName}`,
      },
      { admin: true, read },
    );
    return res.unknown ? null : parseRelease(res, releaseName);
  }

  async function writeRelease(label, rulesetName) {
    // From the first byte on, the release may differ from the baseline, answer or not.
    released = true;
    const patch = () =>
      wire(
        `${label}/patch`,
        {
          method: "PATCH",
          url: `${rulesApi}/v1/${releaseName}`,
          headers: jsonHeaders,
          body: json({ release: { name: releaseName, rulesetName }, updateMask: "rulesetName" }),
        },
        { admin: true },
      );
    let res;
    if (releaseExists) {
      res = await patch();
      if (res.status === 404) releaseExists = false;
    }
    if (!releaseExists) {
      res = await wire(
        `${label}/post`,
        {
          method: "POST",
          url: `${rulesApi}/v1/projects/${target.project}/releases`,
          headers: jsonHeaders,
          body: json({ name: releaseName, rulesetName }),
        },
        { admin: true },
      );
    }
    if (res.status === 200) {
      releaseExists = true;
      return { ok: true };
    }
    if (res.status === 400) return { ok: false, status: 400 };
    throw new StopRun(`${label}: release write answered ${res.status}`);
  }

  // ---- steps ---------------------------------------------------------------------------------

  async function preflight() {
    if (!production) {
      const res = await setLocalRules("preflight/local-baseline", LOCAL_BASELINE_RULES);
      if (res.status !== 200) throw new StopRun(`local baseline rules answered ${res.status}`);
      return;
    }
    const bucketRes = await wire(
      "preflight/bucket",
      {
        method: "GET",
        url: `${gcs}/storage/v1/b/${enc(bucket)}`,
      },
      { admin: true },
    );
    const bucketBody = bucketRes.status === 200 ? parseJson(bucketRes.body) : null;
    if (bucketBody?.name !== bucket) throw new StopRun("the bucket is not the expected one");
    const release = await readRelease("preflight/release");
    if (release === null) throw new StopRun("the bucket release read is not a recorded shape");
    if (
      baseline === "absent"
        ? release.state !== "absent"
        : release.state !== "present" || release.rulesetName !== baseline
    )
      throw new StopRun("the bucket release is not the baseline the packet names");
    const bucketless = await wire(
      "preflight/release-bucketless",
      {
        method: "GET",
        url: `${rulesApi}/v1/projects/${target.project}/releases/firebase.storage`,
      },
      { admin: true },
    );
    if (bucketless.status !== 404) throw new StopRun("the bucketless release is not absent");
    const list = await wire(
      "preflight/rulesets",
      {
        method: "GET",
        url: `${rulesApi}/v1/projects/${target.project}/rulesets?pageSize=100`,
      },
      { admin: true },
    );
    entryRulesets = parseRulesetList(list);
    if (entryRulesets === null) throw new StopRun("the ruleset list is not a recorded single page");
    if (baseline !== "absent" && !entryRulesets.some((r) => r.name === baseline))
      throw new StopRun("the baseline ruleset is not in the ruleset list");
    for (const prefix of [root, `/${root}`]) {
      const res = await wire(
        `preflight/empty${prefix.startsWith("/") ? "-slash" : ""}`,
        {
          method: "GET",
          url: gcsList(prefix),
        },
        { admin: true },
      );
      const items = parseObjectList(res);
      if (items === null || items.length !== 0) throw new StopRun("the run root is not empty");
    }
  }

  async function setup(P) {
    for (const id of Object.keys(OBJECTS)) await createObject(P, id);
    // Each marker must be unreadable before its program: a settle needs a change to see.
    for (const program of PROGRAMS) {
      const res = await markerStatus(`setup/marker/${program.id}`, P, program.marker);
      if (res.status === 200)
        throw new StopRun(`marker ${program.marker} is readable before its program`);
    }
  }

  function skippedRow(recording, row, why) {
    rowsAll.push({
      recording,
      program: row.program,
      id: row.id,
      op: row.op,
      plan: row.plan,
      class: "not-evaluated",
      why,
      answer: { status: null },
    });
  }

  async function readRow(recording, P, row, masks) {
    let url;
    let request;
    if (row.op === "list") {
      const prefix = row.prefix(P);
      url = `${firebase}/v0/b/${enc(bucket)}/o?prefix=${enc(prefix)}${row.delimiter ? `&delimiter=${enc(row.delimiter)}` : ""}`;
      request = {
        method: "GET",
        kind: "v0-list",
        prefix: mask(prefix, masks),
        delimiter: row.delimiter ?? null,
      };
    } else {
      const name = objectName(row.object, P);
      url = v0ObjectUrl(name, row.op === "media" ? "?alt=media" : "");
      request = {
        method: "GET",
        kind: row.op === "media" ? "v0-media" : "v0-meta",
        name: mask(name, masks),
      };
    }
    const res = await wire(`row/${recording}/${row.id}`, { method: "GET", url }, { read: true });
    const record = rowRecord({
      recording,
      row,
      request,
      response: { status: res.status, headers: res.headers, body: res.body },
      masks,
    });
    rowsAll.push(record);
    return record;
  }

  async function runProgram(recording, P, program, previous, masks) {
    const label = `rec${recording}/${program.id}`;
    const rows = rowsOf(program.id).filter((row) => rowFilter === null || rowFilter.has(row.id));
    if (rows.length === 0) return { published: false, skipped: true };
    const source = program.source(P);
    let rulesetName = null;
    if (production) {
      const made = await createRuleset(`${label}/ruleset`, source);
      if (made.name === null) {
        const record = compileRecord({ recording, id: program.id, response: made.res, masks });
        loads.push({ ...record, stage: "released-program" });
        for (const row of rows) skippedRow(recording, row, "ruleset refused at create");
        return { published: false };
      }
      rulesetName = made.name;
      const wrote = await writeRelease(`${label}/release`, rulesetName);
      if (!wrote.ok) {
        loads.push({
          recording,
          id: program.id,
          stage: "release",
          compiled: false,
          status: wrote.status,
        });
        for (const row of rows) skippedRow(recording, row, "release refused");
        return { published: false };
      }
      const after = await readRelease(`${label}/release-readback`);
      if (after?.state !== "present" || after.rulesetName !== rulesetName)
        throw new StopRun(`${label}: the release did not read back`);
    } else {
      const res = await setLocalRules(`${label}/set-rules`, source);
      if (res.status !== 200) {
        loads.push({
          recording,
          id: program.id,
          stage: "released-program",
          compiled: false,
          status: res.status,
        });
        for (const row of rows) skippedRow(recording, row, `setRules answered ${res.status}`);
        return { published: false };
      }
    }
    lastMarker = program.marker;
    const settled = await settle(label, P, program.marker, previous);
    const read = [];
    for (const row of rows) {
      if (row.object && refusedCreates.has(objectName(row.object, P)))
        skippedRow(recording, row, "the object could not be created");
      else read.push(await readRow(recording, P, row, masks));
    }
    let inForce = true;
    if (production) {
      for (let i = 0; i < STILL_IN_FORCE_READS; i += 1) {
        const res = await markerStatus(`${label}/still${i + 1}`, P, program.marker);
        if (res.status !== 200) inForce = false;
      }
      if (!inForce) problem(`${label}: the marker stopped answering 200 while the rows were read`);
    }
    publications.push({ recording, program: program.id, polls: settled.polls, inForce });
    return { published: true, marker: program.marker, rows: read.length };
  }

  async function loadOnly(recording, P, masks) {
    for (const item of LOAD_ONLY) {
      const source = item.source(P);
      if (production) {
        const label = `rec${recording}/load/${item.id}`;
        const made = await createRuleset(label, source);
        loads.push({
          ...compileRecord({ recording, id: item.id, response: made.res, masks }),
          stage: "load-only",
        });
        if (made.name !== null) await deleteRuleset(`${label}/delete`, made.name);
      } else {
        const res = await setLocalRules(`rec${recording}/load/${item.id}`, source);
        loads.push({
          ...compileRecord({ recording, id: item.id, response: res, masks, local: true }),
          stage: "load-only",
        });
      }
    }
  }

  const deletedRulesets = new Set();
  async function deleteRuleset(label, name) {
    const res = await wire(
      label,
      {
        method: "DELETE",
        url: `${rulesApi}/v1/${name}`,
      },
      { admin: true },
    );
    if (res.status === 200 || res.status === 404) {
      deletedRulesets.add(name);
      if (res.status === 404) problem(`${label}: the ruleset was already gone`);
      return;
    }
    problem(`${label}: ruleset delete answered ${res.status}`);
  }

  /** The release back to the baseline, read back, and the last marker no longer readable. */
  async function restore(label, P) {
    if (!production) {
      await setLocalRules(`${label}/local-baseline`, LOCAL_BASELINE_RULES);
      return;
    }
    if (!released) return;
    const isBaseline = (release) =>
      baseline === "absent"
        ? release?.state === "absent"
        : release?.state === "present" && release.rulesetName === baseline;
    // Read first: an unknown answer to an earlier write is settled by this read, never by a second write.
    let current = await readRelease(`${label}/read`, true);
    if (!isBaseline(current)) {
      if (baseline === "absent") {
        if (unknownLabels.some((l) => l.includes("restore") && l.endsWith("/delete"))) {
          problem(`${label}: the release delete was unknown and is not re-sent`);
        } else {
          const res = await wire(
            `${label}/delete`,
            {
              method: "DELETE",
              url: `${rulesApi}/v1/${releaseName}`,
            },
            { admin: true },
          );
          if (res.status !== 200 && res.status !== 404)
            problem(`${label}: release delete answered ${res.status}`);
        }
      } else {
        const wrote = await writeRelease(`${label}/patch`, baseline);
        if (!wrote.ok) problem(`${label}: the baseline release was refused`);
      }
      current = await readRelease(`${label}/readback`, true);
    }
    if (!isBaseline(current)) problem(`${label}: the release did not read back as the baseline`);
    else {
      released = false;
      releaseExists = baseline !== "absent";
    }
    if (lastMarker && P) {
      let streak = 0;
      let settledAt = null;
      for (let poll = 1; poll <= SETTLE_MAX_POLLS && settledAt === null; poll += 1) {
        const res = await markerStatus(`${label}/poll${poll}`, P, lastMarker);
        streak = !res.unknown && res.status !== 200 ? streak + 1 : 0;
        if (streak >= SETTLE_STREAK) settledAt = poll;
        else await sleep(SETTLE_POLL_MS);
      }
      if (settledAt === null) problem(`${label}: the last marker still answers 200 or unknown`);
      else publications.push({ label, restoreSettlePolls: settledAt });
    }
  }

  async function deleteOwnRulesets() {
    for (const name of ownRulesets) {
      if (deletedRulesets.has(name)) continue;
      try {
        await deleteRuleset(`cleanup/ruleset/${name.split("/").pop()}`, name);
      } catch (error) {
        // An unknown delete is recorded by the wire and never re-sent; the others still go.
        if (!(error instanceof UnknownAnswer)) throw error;
      }
    }
  }

  async function cleanupObjects() {
    const toDelete = new Map(); // name -> generation
    for (const [name, generation] of created) toDelete.set(name, generation);
    const planned = new Set(plannedNames(runId, recordings));
    for (const prefix of [root, `/${root}`]) {
      const res = await wire(
        `cleanup/list${prefix.startsWith("/") ? "-slash" : ""}`,
        {
          method: "GET",
          url: gcsList(prefix),
        },
        { admin: true, read: true },
      );
      const items = parseObjectList(res);
      if (items === null) {
        problem("cleanup list is not a recorded single page");
        continue;
      }
      for (const item of items) {
        // Only names this run plans are its own; anything else under the root is left alone and reported.
        if (planned.has(item.name) || created.has(item.name))
          toDelete.set(item.name, item.generation);
        else problem("an unexpected object is listed under the run root");
      }
    }
    const deleteUnknown = new Set();
    for (const [name, generation] of toDelete) {
      try {
        const res = await wire(
          `cleanup/delete/${enc(name).slice(-24)}`,
          {
            method: "DELETE",
            url: gcsObjectUrl(name, `?ifGenerationMatch=${generation}`),
          },
          { admin: true },
        );
        if (res.status !== 204 && res.status !== 404)
          problem(`cleanup delete of an object answered ${res.status}`);
      } catch (error) {
        if (error instanceof UnknownAnswer) deleteUnknown.add(name);
        else throw error;
      }
    }
    const seen = new Set([...created.keys(), ...unconfirmed, ...toDelete.keys()]);
    for (const name of seen) {
      if (deleteUnknown.has(name)) continue;
      const res = await wire(
        `cleanup/absent/${enc(name).slice(-24)}`,
        { method: "GET", url: gcsObjectUrl(name) },
        { admin: true, read: true },
      );
      if (res.status !== 404) problem(`an object still reads ${res.status} after cleanup`);
    }
    for (const prefix of [root, `/${root}`]) {
      const res = await wire(
        `cleanup/final-list${prefix.startsWith("/") ? "-slash" : ""}`,
        {
          method: "GET",
          url: gcsList(prefix),
        },
        { admin: true, read: true },
      );
      const items = parseObjectList(res);
      if (items === null || items.length !== 0) problem("the run root is not empty after cleanup");
    }
  }

  async function finalAudit() {
    if (!production) return;
    const release = await readRelease("final/release", true);
    const ok =
      baseline === "absent"
        ? release?.state === "absent"
        : release?.state === "present" && release.rulesetName === baseline;
    if (!ok) problem("the bucket release is not the baseline at the end");
    const list = await wire(
      "final/rulesets",
      {
        method: "GET",
        url: `${rulesApi}/v1/projects/${target.project}/rulesets?pageSize=100`,
      },
      { admin: true, read: true },
    );
    const finalList = parseRulesetList(list);
    if (finalList === null || entryRulesets === null || !sameRulesetList(finalList, entryRulesets))
      problem("the ruleset list is not what it was at entry");
  }

  // ---- run -----------------------------------------------------------------------------------

  const guardedStep = async (name, step) => {
    try {
      await step();
    } catch (error) {
      if (
        error instanceof StopRun ||
        error instanceof UnknownAnswer ||
        error instanceof GuardError
      ) {
        stopped ??= `${name}: ${error.message}`;
        problem(`${name}: ${error.message}`);
      } else throw error;
    }
  };

  let currentP = null;
  try {
    await guardedStep("preflight", preflight);
    if (entryRulesets !== null) out.save("entry.json", { baseline, entryRulesets });
    for (let recording = 1; recording <= recordings && stopped === null; recording += 1) {
      const P = recordingPrefix(runId, recording);
      currentP = P;
      const masks = [
        [P, "<P>"],
        [runId, "<run>"],
        [bucket, "<bucket>"],
        [target.project ?? "", "<project>"],
      ];
      await guardedStep(`rec${recording}/setup`, () => setup(P));
      let previous = null;
      for (const program of PROGRAMS) {
        if (stopped !== null) break;
        await guardedStep(`rec${recording}/${program.id}`, async () => {
          const result = await runProgram(recording, P, program, previous, masks);
          if (result.published) previous = result.marker;
        });
      }
      if (stopped === null)
        await guardedStep(`rec${recording}/load-only`, () => loadOnly(recording, P, masks));
      await guardedStep(`rec${recording}/restore`, () => restore(`rec${recording}/restore`, P));
    }
  } finally {
    budget.cleanup = true;
    // Whatever stopped the run, the release goes back, own rulesets and objects go, and the rest is read.
    if (released) await guardedStep("cleanup/restore", () => restore("cleanup/restore", currentP));
    await guardedStep("cleanup/rulesets", deleteOwnRulesets);
    await guardedStep("cleanup/objects", cleanupObjects);
    await guardedStep("cleanup/audit", finalAudit);
  }

  const first = rowsAll.filter((r) => r.recording === 1);
  const second = rowsAll.filter((r) => r.recording === 2);
  const agreement = second.length > 0 ? compareRecordings(first, second) : [];
  const unknowns = [...new Set(unknownLabels)];
  const expectedRows =
    ROWS.filter((row) => rowFilter === null || rowFilter.has(row.id)).length * recordings;
  const complete = stopped === null && rowsAll.length === expectedRows;
  const report = {
    runId,
    target: target.name,
    baseline,
    requests: budget.count,
    stopped,
    complete,
    closureReady:
      complete && unknowns.length === 0 && problems.length === 0 && reportingErrors.length === 0,
    unknowns,
    unknownReads: new Set(unknownReads).size,
    problems,
    reportingErrors,
    rows: rowsAll,
    loads,
    publications,
    agreement,
    disagreeing: agreement.filter((r) => !r.agree).map((r) => r.id),
    entryRulesets: entryRulesets === null ? null : entryRulesets.length,
  };
  out.save("results.json", { rows: rowsAll, loads, publications, agreement });
  return { report };
}

/**
 * The A2 read-back (a separate command, at least 10 minutes after the last request): the bucket
 * release is the baseline, the ruleset list is the list at entry, the run root lists empty and every
 * planned object name reads 404. Reads only.
 */
export async function readback({
  target,
  runId,
  baseline,
  entry,
  deps,
  out,
  recordings = RECORDINGS,
  cap = 70,
}) {
  const root = runRoot(runId);
  const state = { runId, root, ownRulesets: new Set(), baseline };
  const budget = new RequestBudget(cap, cap);
  const { wire, unknownReads } = createWire({ target, state, budget, deps, out });
  const bucket = target.bucket;
  const releaseName = `projects/${target.project}/releases/firebase.storage/${bucket}`;
  const problems = [];
  const release = parseRelease(
    await wire(
      "readback/release",
      { method: "GET", url: `https://firebaserules.googleapis.com/v1/${releaseName}` },
      { admin: true, read: true },
    ),
    releaseName,
  );
  const releaseOk =
    baseline === "absent"
      ? release?.state === "absent"
      : release?.state === "present" && release.rulesetName === baseline;
  if (!releaseOk) problems.push("the bucket release is not the baseline");
  const list = parseRulesetList(
    await wire(
      "readback/rulesets",
      {
        method: "GET",
        url: `https://firebaserules.googleapis.com/v1/projects/${target.project}/rulesets?pageSize=100`,
      },
      { admin: true, read: true },
    ),
  );
  if (list === null || !sameRulesetList(list, entry))
    problems.push("the ruleset list is not the list at entry");
  for (const prefix of [root, `/${root}`]) {
    const items = parseObjectList(
      await wire(
        "readback/list",
        {
          method: "GET",
          url: `https://storage.googleapis.com/storage/v1/b/${enc(bucket)}/o?prefix=${enc(prefix)}&maxResults=1000`,
        },
        { admin: true, read: true },
      ),
    );
    if (items === null || items.length !== 0) problems.push("the run root is not empty");
  }
  const names = [];
  for (let recording = 1; recording <= recordings; recording += 1) {
    const P = recordingPrefix(runId, recording);
    for (const id of Object.keys(OBJECTS)) names.push(objectName(id, P));
  }
  for (const name of names) {
    const res = await wire(
      "readback/object",
      {
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${enc(bucket)}/o/${enc(name)}`,
      },
      { admin: true, read: true },
    );
    if (res.status !== 404) problems.push("an object still reads");
  }
  const report = {
    runId,
    requests: budget.count,
    unknownReads: unknownReads.length,
    problems: [...new Set(problems)],
    closed: problems.length === 0 && unknownReads.length === 0,
  };
  out.save("readback.json", report);
  return report;
}
