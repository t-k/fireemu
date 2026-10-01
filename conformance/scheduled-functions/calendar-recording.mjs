// Offline admission only; no credentials, network, processes or sandbox mutation.
import { createHash } from "node:crypto";
import { readFileSync, constants } from "node:fs";
import { lstat, realpath, open } from "node:fs/promises";
import { join, sep } from "node:path";
import { calendarRequests, CALENDAR_CASES } from "./calendar.mjs";
import { nativeCalendarInput, calendarInstantNanos } from "./calendar-local.mjs";
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fail = (message) => {
  throw new Error(message);
};
export function recordedCalendarInputs({ packetBytes, journalBytes, corpusBytes, pins }) {
  for (const [bytes, pin] of [
    [packetBytes, pins?.packetSha256],
    [journalBytes, pins?.journalSha256],
    [corpusBytes, pins?.corpusSha256],
  ])
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length > 16 * 1024 * 1024 ||
      !/^[a-f0-9]{64}$/.test(pin ?? "") ||
      sha(bytes) !== pin
    )
      fail("recorded calendar whole-byte digest binding differs");
  if (!corpusBytes.equals(readFileSync(new URL("./calendar-cases.json", import.meta.url))))
    fail("recorded calendar corpus binding differs");
  const packet = JSON.parse(packetBytes);
  if (
    packet.schemaVersion !== 1 ||
    packet.kind !== "calendar-seed" ||
    packet.project !== "fireemu-oracle-sbx" ||
    packet.maxRequests !== 64 ||
    packet.maxExtraRequests !== 3 ||
    packet.reserveUsd !== 0.25 ||
    packet.runId !== pins.runId ||
    packet.sourceCommit !== pins.sourceCommit ||
    !/^[a-f0-9]{40}$/.test(pins.sourceCommit ?? "") ||
    packet.harnessDigest !== pins.harnessSha256 ||
    !/^[a-f0-9]{64}$/.test(pins.harnessSha256 ?? "") ||
    packet.corpusDigest !== pins.corpusSha256
  )
    fail("recorded calendar packet binding differs");
  const rows = journalBytes
    .toString("utf8")
    .split("\n")
    .filter((s) => s.trim())
    .map(JSON.parse);
  const requests = rows.filter((r) => r?.state === "before-send");
  if (requests.length > 64) fail("recorded calendar request bound differs");
  const templates = new Map(
    calendarRequests(
      packet.runId,
      packet.projectNumber,
      requests.length ? Date.parse(requests[0].dispatchAt) : Date.parse("2026-09-30T00:00:00Z"),
    ).map((r) => [r.id, r]),
  );
  const groups = new Map();
  let active = null,
    extras = 0;
  for (const row of rows) {
    if (
      !row ||
      typeof row.id !== "string" ||
      ![
        "before-send",
        "response-headers",
        "response-persisted",
        "transport-unknown",
        "body-unknown",
      ].includes(row.state)
    )
      fail("recorded calendar journal row differs");
    if (row.state === "before-send") {
      if (active || groups.has(row.id)) fail("recorded calendar journal request ordering differs");
      let id = row.id;
      if (/^read-topic-poll-[1-3]$/.test(id)) {
        id = "read-topic";
        extras++;
      } else if (/^c0[1-8]-read-before-pause$/.test(id)) {
        id = id.slice(0, 3) + "-read-paused";
        extras++;
      } else if (/^c0[1-8]-delete-retry-[1-3]$/.test(id)) {
        id = id.slice(0, 3) + "-delete";
        extras++;
      }
      const spec = templates.get(id);
      if (
        !spec ||
        row.method !== spec.method ||
        row.url !== spec.url ||
        (row.timeoutMs !== undefined && row.timeoutMs !== (spec.timeoutMs ?? 10000)) ||
        JSON.stringify(row.json ?? null) !== JSON.stringify(spec.json ?? null) ||
        typeof row.dispatchAt !== "string"
      )
        fail("recorded calendar request binding differs");
      calendarInstantNanos(row.dispatchAt);
      active = [row];
      groups.set(row.id, active);
      continue;
    }
    if (!active || active[0].id !== row.id)
      fail("recorded calendar journal response ordering differs");
    const expected =
      active.length === 1
        ? ["response-headers", "transport-unknown"]
        : ["response-persisted", "body-unknown"];
    if (
      !expected.includes(row.state) ||
      calendarInstantNanos(row.responseAt) <
        calendarInstantNanos(active.at(-1).responseAt ?? active[0].dispatchAt)
    )
      fail("recorded calendar journal response proof differs");
    if (
      row.state !== "transport-unknown" &&
      (!Number.isSafeInteger(row.status) ||
        row.status < 100 ||
        row.status > 599 ||
        (active.length === 2 && row.status !== active[1].status))
    )
      fail("recorded calendar response status proof differs");
    if (row.state === "response-persisted") {
      if (row.dispatchAt !== active[0].dispatchAt || typeof row.bodyBase64 !== "string")
        fail("recorded calendar response body proof differs");
      const bytes = Buffer.from(row.bodyBase64, "base64");
      if (
        bytes.toString("base64") !== row.bodyBase64 ||
        bytes.length !== row.bodyBytes ||
        bytes.length > 1048576
      )
        fail("recorded calendar response body proof differs");
    }
    active.push(row);
    if (row.state !== "response-headers") active = null;
  }
  if (extras > 3) fail("recorded calendar request extra bound differs");
  const cases = CALENDAR_CASES.map((item) => {
    const group = groups.get(item.id + "-create");
    if (!group) return { caseId: item.id, classification: "unrecorded" };
    const response = group.at(-1);
    if (group.length !== 3 || response.state !== "response-persisted")
      return { caseId: item.id, classification: "unresolved" };
    const bytes = Buffer.from(response.bodyBase64, "base64");
    const proof = {
      caseId: item.id,
      status: response.status,
      bodySha256: sha(bytes),
      bodyBase64: response.bodyBase64,
      anchors: [group[0].dispatchAt, group[1].responseAt],
    };
    if (response.status === 200) {
      try {
        return Object.assign(proof, {
          classification: "accepted",
          input: nativeCalendarInput({
            journal: rows,
            runId: packet.runId,
            projectNumber: packet.projectNumber,
            caseId: item.id,
          }),
        });
      } catch (error) {
        return Object.assign(proof, { classification: "unresolved", reason: error.message });
      }
    }
    return Object.assign(proof, {
      classification:
        response.status >= 400 && response.status < 500 ? "observed-refusal" : "unresolved",
    });
  });
  return { schemaVersion: 1, productionParity: false, pins: { ...pins }, cases };
}

export async function loadRecordedCalendarInputs({ lane, directory, pins }) {
  const base = await realpath(lane),
    resolved = await realpath(directory),
    parent = await lstat(directory);
  if (
    !resolved.startsWith(base + sep) ||
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    parent.mode & 0o077
  )
    fail("recorded calendar directory must be private and inside its lane");
  const proof = async (name) => {
    const path = join(resolved, name),
      stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.mode & 0o077)
      fail("recorded calendar proof must be a private regular file");
    if (stat.size > 16 * 1024 * 1024) fail("recorded calendar proof exceeds byte bound");
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat();
      if (
        opened.ino !== stat.ino ||
        opened.dev !== stat.dev ||
        opened.mode & 0o077 ||
        !opened.isFile() ||
        opened.size > 16 * 1024 * 1024
      )
        fail("recorded calendar private proof changed");
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  };
  const packetBytes = await proof("raw-packet.json"),
    journalBytes = await proof("requests.jsonl"),
    corpusBytes = readFileSync(new URL("./calendar-cases.json", import.meta.url));
  return recordedCalendarInputs({ packetBytes, journalBytes, corpusBytes, pins });
}
