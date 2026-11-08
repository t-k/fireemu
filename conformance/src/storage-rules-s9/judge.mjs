// Answers, row records and comparisons of the Storage Rules observation. Judges read the shapes
// recorded from production (conformance/src/storage-rules-production-fixtures.mjs) and nothing else:
// a body or status outside them is `other` (recorded, never read as an allow or a refusal).

import { isUnknownStatus } from "./guard.mjs";

const text = (body) => Buffer.from(body ?? []).toString("utf8");

function parseJson(body) {
  try {
    const value = JSON.parse(text(body));
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/** Replaces the run-specific names in a string stored in the results. */
export function mask(value, masks) {
  let out = String(value);
  for (const [from, to] of masks) if (from) out = out.split(from).join(to);
  return out;
}

const VOLATILE = new Set([
  "id",
  "selfLink",
  "mediaLink",
  "generation",
  "metageneration",
  "timeCreated",
  "updated",
  "timeStorageClassUpdated",
  "etag",
  "md5Hash",
  "crc32c",
  "downloadTokens",
]);

/** A v0 or JSON API object resource without the fields that differ between runs. */
function stableResource(resource, masks) {
  const out = {};
  for (const [key, value] of Object.entries(resource)) {
    if (VOLATILE.has(key)) continue;
    out[key] = typeof value === "string" ? mask(value, masks) : value;
  }
  return out;
}

/**
 * The class of one answer to a v0 read. `allow`: a 200 with a JSON object (metadata and list) or any
 * 200 body (media); `deny`: 403 with the recorded body `{"error":{"code":403,
 * "message":"Permission denied."}}`; `no-release`: the recorded 400; `not-found`: 404; `unknown`:
 * below 200, 3xx, 5xx or no answer; `other`: anything else.
 */
export function classifyAnswer(row, { status, body }) {
  if (!Number.isInteger(status) || isUnknownStatus(status)) return "unknown";
  const json = parseJson(body);
  if (status === 200) {
    if (row.op === "media") return "allow";
    return json !== null ? "allow" : "other";
  }
  if (status === 403) {
    const message = json?.error?.message;
    return json?.error?.code === 403 &&
      typeof message === "string" &&
      message.startsWith("Permission denied")
      ? "deny"
      : "other";
  }
  if (status === 400) {
    return (json?.error?.message ?? "").startsWith("Your bucket has not been set up properly")
      ? "no-release"
      : "other";
  }
  if (status === 404) return "not-found";
  return "other";
}

/** Body shape of an answer: what the table compares between recordings and targets. */
export function normalizeAnswer(row, { status, headers, body }, masks) {
  const json = parseJson(body);
  const contentType = headers?.["content-type"] ?? null;
  const bytes = Buffer.from(body ?? []).length;
  const out = { status, contentType, bodyBytes: bytes };
  if (row.op === "media" && status === 200) {
    out.text = mask(text(body), masks);
    return out;
  }
  if (json === null) {
    if (bytes > 0) out.text = mask(text(body).slice(0, 400), masks);
    return out;
  }
  if (status === 200 && row.op === "meta") out.resource = stableResource(json, masks);
  else if (status === 200 && row.op === "list") {
    out.list = {
      kind: json.kind ?? null,
      items: (json.items ?? []).map((item) => mask(item.name, masks)).sort(),
      prefixes: (json.prefixes ?? []).map((p) => mask(p, masks)).sort(),
      nextPageToken: json.nextPageToken === undefined ? undefined : "<token>",
    };
  } else if (json.error) {
    out.error = {
      code: json.error.code ?? null,
      status: json.error.status ?? null,
      message: mask(json.error.message ?? "", masks),
    };
  } else out.json = Object.keys(json).sort();
  return out;
}

/** One recorded row. `unknown` rows keep their raw status (NaN is a transport failure). */
export function rowRecord({ recording, row, request, response, masks }) {
  const cls = classifyAnswer(row, response);
  return {
    recording,
    program: row.program,
    id: row.id,
    op: row.op,
    plan: row.plan,
    request,
    class: cls,
    answer: normalizeAnswer(row, response, masks),
  };
}

const stable = (answer) =>
  JSON.stringify(answer, (key, value) => (key === "bodyBytes" ? undefined : value));

/**
 * Two recordings (or a production and a local recording) agree on a row when the class and the
 * normalized answer are equal. Layout (`bodyBytes`) is compared only for refusals and errors, where
 * the body is the same text every time; metadata and list bodies vary in digit counts.
 */
export function rowsAgree(a, b) {
  if (a.class !== b.class) return false;
  if (stable(a.answer) !== stable(b.answer)) return false;
  if (a.class === "allow") return true;
  return a.answer.bodyBytes === b.answer.bodyBytes;
}

export function compareRecordings(first, second) {
  const byId = new Map(second.map((row) => [row.id, row]));
  return first.map((row) => {
    const other = byId.get(row.id);
    return {
      id: row.id,
      program: row.program,
      agree: other !== undefined && rowsAgree(row, other),
    };
  });
}

/** Rows (with their `plan` note) as a compact table for the report. */
export function tableOf(rows) {
  return rows.map((row) => ({
    id: row.id,
    plan: row.plan,
    class: row.class,
    status: row.answer.status,
  }));
}

/** A load-only record: the compile answer of `rulesets.create` (or the local equivalent). */
export function compileRecord({ recording, id, response, masks, local = false }) {
  const json = parseJson(response.body);
  const status = response.status;
  // A local emulator answers a rules load with a bare 200.
  if (local && status === 200) return { recording, id, compiled: true, status };
  if (status === 200 && typeof json?.name === "string")
    return { recording, id, compiled: true, status };
  if (status === 400)
    return {
      recording,
      id,
      compiled: false,
      status,
      message: mask(json?.error?.message ?? text(response.body).slice(0, 400), masks),
    };
  return {
    recording,
    id,
    compiled: null,
    status,
    message: mask(text(response.body).slice(0, 400), masks),
  };
}

/** The ruleset names and services of a `rulesets` list page, as the recorded list answers them. */
export function parseRulesetList({ status, body }) {
  const json = parseJson(body);
  if (status !== 200 || json === null) return null;
  if (json.nextPageToken !== undefined) return null;
  const rulesets = json.rulesets ?? [];
  if (!Array.isArray(rulesets)) return null;
  const out = [];
  for (const entry of rulesets) {
    const services = entry?.metadata?.services;
    if (typeof entry?.name !== "string" || !Array.isArray(services)) return null;
    out.push({ name: entry.name, services: [...services].sort() });
  }
  return out.sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0));
}

export const sameRulesetList = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/** A release answer: `{state: "present", rulesetName}`, `{state: "absent"}` or null for any other answer. */
export function parseRelease({ status, body }, expectedName) {
  const json = parseJson(body);
  if (status === 404 && json?.error?.code === 404 && json.error.status === "NOT_FOUND")
    return { state: "absent" };
  if (
    status === 200 &&
    json !== null &&
    json.name === expectedName &&
    typeof json.rulesetName === "string"
  )
    return { state: "present", rulesetName: json.rulesetName };
  return null;
}

/** A created object: the generation and name from the 200 body. */
export function parseCreated({ status, body }) {
  const json = parseJson(body);
  if (status !== 200 || json === null || json.kind !== "storage#object") return null;
  if (typeof json.name !== "string" || !/^[1-9]\d{0,19}$/.test(String(json.generation ?? "")))
    return null;
  return { name: json.name, generation: String(json.generation), metadata: json.metadata ?? null };
}

/** A JSON API list page: names and generations. Null for any other answer or a next page. */
export function parseObjectList({ status, body }) {
  const json = parseJson(body);
  if (status !== 200 || json === null || json.kind !== "storage#objects") return null;
  if (json.nextPageToken !== undefined) return null;
  const items = json.items ?? [];
  if (!Array.isArray(items)) return null;
  const out = [];
  for (const item of items) {
    if (typeof item?.name !== "string" || !/^[1-9]\d{0,19}$/.test(String(item.generation ?? "")))
      return null;
    out.push({ name: item.name, generation: String(item.generation) });
  }
  return out;
}

/**
 * A side-by-side table of several runs (`production`, `official`, `fireemu-strict`, ...). One line
 * per row id; each cell is `class/status` of recording 1, with `*` when recording 2 disagrees and
 * `=` when the cell equals the first run's.
 */
export function renderTable(runs) {
  const ids = [];
  for (const run of runs) for (const row of run.rows) if (!ids.includes(row.id)) ids.push(row.id);
  const cell = (run, id) => {
    const rows = run.rows.filter((row) => row.id === id);
    if (rows.length === 0) return { label: "-", star: false };
    const [first, second] = rows;
    return {
      label: `${first.class}/${first.answer.status ?? "-"}`,
      star: Boolean(second) && !rowsAgree(first, second),
    };
  };
  const header = ["row", "plan", ...runs.map((run) => run.label)];
  const lines = [header.join("\t")];
  for (const id of ids) {
    const plan = runs.flatMap((run) => run.rows).find((row) => row.id === id)?.plan ?? "";
    const cells = runs.map((run) => cell(run, id));
    lines.push(
      [
        id,
        plan,
        ...cells.map((c, i) =>
          i > 0 && c.label === cells[0].label && !c.star ? "=" : `${c.label}${c.star ? "*" : ""}`,
        ),
      ].join("\t"),
    );
  }
  return lines.join("\n");
}

/** Load-only and release-time compile answers of several runs, one line per id. */
export function renderLoads(runs) {
  const ids = [];
  for (const run of runs)
    for (const load of run.loads) if (!ids.includes(load.id)) ids.push(load.id);
  const lines = [["load", ...runs.map((run) => run.label)].join("\t")];
  for (const id of ids)
    lines.push(
      [
        id,
        ...runs.map((run) => {
          const load = run.loads.find((l) => l.id === id);
          return load
            ? `${load.compiled === true ? "loads" : load.compiled === false ? "refused" : "?"}/${load.status}`
            : "-";
        }),
      ].join("\t"),
    );
  return lines.join("\n");
}
