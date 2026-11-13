import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isSuccess, isUnknownStatus } from "./guard.mjs";

export function readJournal(path) {
  const text = readFileSync(path, "utf8");
  if (!text.endsWith("\n")) throw new Error("incomplete journal");
  return text
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
}

export function settlement(entries) {
  const states = new Map();
  const answered = new Set(
    entries
      .filter((entry) => entry.phase === "after")
      .map((entry) => `${entry.session ?? "run"}:${entry.n}`),
  );
  for (const entry of entries) {
    if (
      entry.phase !== "after" &&
      !(entry.phase === "before" && !answered.has(`${entry.session ?? "run"}:${entry.n}`))
    )
      continue;
    if (!entry.resource || !entry.action) continue;
    // Preflight reads of the default bucket confer no ownership or deletion obligation.
    if (entry.action === "read" && !states.has(entry.resource)) continue;
    const state = states.get(entry.resource) ?? {
      resource: entry.resource,
      confirmed: false,
      unknownCreate: false,
      unknownDelete: false,
      deleted: false,
      absent: false,
    };
    states.set(entry.resource, state);
    const unknown = entry.phase === "before" || entry.unknown || isUnknownStatus(entry.status);
    if (entry.action === "create") {
      if (unknown) {
        state.unknownCreate = true;
        state.absent = false;
        state.deleted = false;
      } else if (isSuccess(entry.status)) {
        state.confirmed = true;
        state.absent = false;
        state.deleted = false;
      }
    }
    if (entry.action === "delete") {
      if (unknown) {
        state.unknownDelete = true;
        state.absent = false;
      } else if (isSuccess(entry.status)) {
        state.deleted = true;
        state.absent = false;
      }
    }
    if (entry.action === "read" && !unknown) {
      if (isSuccess(entry.status) && entry.showsResource) {
        state.confirmed = true;
        state.unknownCreate = false;
        state.absent = false;
        state.deleted = false;
      }
      if (entry.status === 404 && !state.unknownCreate) {
        if (entry.session === "a2" || (state.deleted && !state.unknownDelete)) state.absent = true;
        if (entry.session === "a2") state.unknownDelete = false;
      }
    }
  }
  const unresolved = [...states.values()]
    .filter((s) => s.unknownCreate || s.unknownDelete || (s.confirmed && !s.absent))
    .map((s) =>
      Object.assign({}, s, {
        reason: s.unknownCreate
          ? "unconfirmed create"
          : s.unknownDelete
            ? "unknown delete"
            : "created, not deleted and read back absent",
      }),
    );
  return { closureReady: unresolved.length === 0, unresolved };
}

export function parseXmlError(text) {
  const match = /^(?:<\?xml\s+[^?]*\?>\s*)?<Error>([\s\S]*)<\/Error>\s*$/.exec(text);
  if (!match) return null;
  const fields = {};
  let remainder = match[1];
  const entity = (value) =>
    value.replace(
      /&(?:amp|lt|gt|quot|apos);/g,
      (s) => ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" })[s],
    );
  while (remainder.trim()) {
    const field =
      /^\s*<(Code|Message|Details|Resource|RequestId|HostId|BucketName)>([^<]*)<\/\1>/.exec(
        remainder,
      );
    if (!field || Object.hasOwn(fields, field[1]) || /&(?!(?:amp|lt|gt|quot|apos);)/.test(field[2]))
      return null;
    fields[field[1]] = entity(field[2]);
    remainder = remainder.slice(field[0].length);
  }
  return fields.Code && fields.Message ? { Code: fields.Code, Message: fields.Message } : null;
}

export function judgeAnswer(entry) {
  const body = Buffer.from(entry.bodyBase64 ?? "", "base64");
  const headers = Object.fromEntries(new Headers(entry.headers ?? {}).entries());
  const headerNames = Object.keys(headers).toSorted();
  const row = {
    case: entry.case,
    status: entry.status,
    bodyBytes: entry.bodyBytes,
    sha256: createHash("sha256").update(body).digest("hex"),
    headerNames,
    headers: Object.fromEntries(
      headerNames
        .filter(
          (name) =>
            name.startsWith("access-control-") || name === "vary" || name === "content-length",
        )
        .map((name) => [name, headers[name]]),
    ),
    json: null,
    xml: null,
    shape: "unrecorded",
    known: false,
  };
  const text = body.toString("utf8");
  try {
    const value = JSON.parse(text);
    const error = value?.error;
    if (error && typeof error === "object") {
      row.json = {
        code: error.code ?? null,
        message: error.message ?? null,
        reason: error.errors?.[0]?.reason ?? null,
      };
      if (
        Object.keys(value).length === 1 &&
        Object.keys(error).every((key) => ["code", "message", "errors"].includes(key)) &&
        Number.isInteger(error.code) &&
        error.code >= 400 &&
        error.code < 500 &&
        error.code === entry.status &&
        typeof error.message === "string" &&
        (error.errors === undefined ||
          (Array.isArray(error.errors) &&
            error.errors.length > 0 &&
            error.errors.every(
              (item) =>
                item &&
                typeof item.reason === "string" &&
                Object.keys(item).every((key) =>
                  ["reason", "message", "domain", "location", "locationType"].includes(key),
                ),
            )))
      )
        row.shape = "json-error";
    }
    // Resource and list JSON are retained in full bytes but require review: their layouts are not recorded fixtures.
  } catch {
    row.xml = parseXmlError(text);
    if (row.xml && entry.status >= 400 && entry.status < 500) row.shape = "xml-error";
    else if (
      !body.length &&
      ((entry.method === "OPTIONS" && entry.status === 200) ||
        (entry.method === "DELETE" && entry.status === 204))
    )
      row.shape = "empty";
    else if (text === "fire" && entry.status === 200 && ["C5", "C6"].includes(entry.case))
      row.shape = "media";
  }
  row.known =
    row.shape !== "unrecorded" &&
    !entry.unknown &&
    !entry.withheld &&
    !entry.headersRedacted &&
    !isUnknownStatus(entry.status) &&
    Number.isInteger(entry.bodyBytes) &&
    entry.bodyBytes === body.length &&
    body.toString("base64") === entry.bodyBase64;
  return row;
}

export function judgeJournal(entries) {
  const after = new Map(
    entries.filter((entry) => entry.phase === "after").map((entry) => [entry.n, entry]),
  );
  return entries
    .filter((entry) => entry.phase === "before")
    .map((entry) =>
      judgeAnswer(
        after.get(entry.n) ?? {
          ...entry,
          unknown: true,
          status: null,
          bodyBytes: 0,
          bodyBase64: "",
        },
      ),
    );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(judgeJournal(readJournal(process.argv[2])), null, 2));
  } catch {
    console.error("Could not judge journal");
    process.exitCode = 1;
  }
}
