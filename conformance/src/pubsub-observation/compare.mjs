import { readFileSync, lstatSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { protos } from "@google-cloud/pubsub";
import { sanitize } from "../pubsub-production/capture.mjs";
import { prepareObservation, compareObservation } from "./compare-core.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function pinned(pin, max) {
  if (typeof pin?.path !== "string" || !/^[0-9a-f]{64}$/.test(pin.sha256))
    throw new Error("invalid input pin");
  const stat = lstatSync(pin.path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > max)
    throw new Error("input file bound");
  const bytes = readFileSync(pin.path);
  if (bytes.length > max || sha(bytes) !== pin.sha256) throw new Error("input hash mismatch");
  return bytes;
}
const text = (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
function jsonl(bytes) {
  const lines = text(bytes)
    .trim()
    .split("\n")
    .filter((line) => line.trim());
  if (lines.length > 20000) throw new Error("input row bound");
  return lines.map((line) => JSON.parse(line));
}
function frameProof(row, directory, runId) {
  try {
    const blob = row.blob;
    if (
      !blob ||
      !new RegExp(`^frame-${runId}-[0-9]{4}\\.pb$`).test(blob.path) ||
      !Number.isSafeInteger(blob.bytes) ||
      blob.bytes < 0 ||
      blob.bytes > 65536 ||
      !["in", "out"].includes(row.direction)
    )
      return false;
    const raw = pinned({ path: resolve(directory, blob.path), sha256: blob.sha256 }, 65536);
    if (raw.length !== blob.bytes) return false;
    const Type =
      protos.google.pubsub.v1[
        row.direction === "out" ? "StreamingPullRequest" : "StreamingPullResponse"
      ];
    const decoded = Type.toObject(Type.decode(raw), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    });
    return isDeepStrictEqual(sanitize(decoded), row.body);
  } catch {
    return false;
  }
}
export function readPinnedBundle(bundle) {
  if (bundle.schema !== 1 || !["fixture", "production", "local"].includes(bundle.evidenceKind))
    throw new Error("bundle schema/evidence kind");
  // Hash every declared input before parsing any of the journal bodies.
  const bytes = Object.fromEntries(
    ["packet", "descriptor", "capture", "issued", "summary"].map((k) => [
      k,
      pinned(bundle[k], k === "capture" ? 83886080 : k === "issued" ? 16000000 : 4000000),
    ]),
  );
  if (bundle.evidenceKind === "production") {
    const manifest = text(pinned(bundle.coordinatorManifest, 1000000)).split("\n").filter(Boolean);
    for (const name of ["capture", "issued", "summary"]) {
      const entries = manifest
        .map((line) => line.trim().split(/\s+/, 2))
        .filter(
          (parts) =>
            parts[1]?.replace(/^\*/, "").replace(/^\.\//, "") === basename(bundle[name].path),
        );
      if (entries.length !== 1 || entries[0][0] !== bundle[name].sha256)
        throw new Error("coordinator manifest binding");
    }
  }
  const packet = JSON.parse(text(bytes.packet)),
    descriptor = JSON.parse(text(bytes.descriptor)),
    summary = JSON.parse(text(bytes.summary)),
    rows = jsonl(bytes.capture),
    issued = jsonl(bytes.issued);
  if (
    summary.captureSha256 !== bundle.capture.sha256 ||
    summary.issuedSha256 !== bundle.issued.sha256
  )
    throw new Error("summary journal hash binding");
  const frames = rows.filter((row) => row.event === "stream-frame");
  if (frames.length > 204) throw new Error("native frame count bound");
  const verifiedFrames = new Set(
    frames
      .filter((row) => frameProof(row, dirname(resolve(bundle.capture.path)), summary.runId))
      .map((row) => row.n),
  );
  return {
    rows,
    issued,
    packet,
    descriptor,
    summary,
    packetSha256: bundle.packet.sha256,
    descriptorSha256: bundle.descriptor.sha256,
    evidenceKind: bundle.evidenceKind,
    verifiedFrames,
  };
}
export function main(argv = process.argv.slice(2)) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (
      !["--input", "--input-sha256", "--out"].includes(argv[i]) ||
      !argv[i + 1] ||
      Object.hasOwn(options, argv[i])
    )
      throw new Error("expected unique --input --input-sha256 --out pairs");
    options[argv[i]] = argv[i + 1];
  }
  if (Object.keys(options).length !== 3) throw new Error("expected --input --input-sha256 --out");
  const indexBytes = pinned(
    { path: options["--input"], sha256: options["--input-sha256"] },
    262144,
  );
  const index = JSON.parse(text(indexBytes));
  if (!index.source || Object.keys(index).some((k) => !["source", "local"].includes(k)))
    throw new Error("index expects source and optional local only");
  const source = prepareObservation(readPinnedBundle(index.source));
  let report = {
    ...source,
    kind: "pubsub-observation-a-replay-preparation",
    status: "PREPARATION_ONLY_NO_REPLAY_NO_PROMOTION",
  };
  if (index.local) {
    if (!["local", "fixture"].includes(index.local.evidenceKind))
      throw new Error("local journal must be labelled local or fixture");
    report = compareObservation(source, prepareObservation(readPinnedBundle(index.local)));
  }
  report.inputIndexSha256 = sha(indexBytes);
  report.inputPins = index;
  writeFileSync(options["--out"], `${JSON.stringify(report, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return report;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
