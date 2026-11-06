import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { publicEvidence, publicEvidenceBytes } from "./evidence.mjs";
import { historicalArtifactIdentity } from "./firestore-probe/historical-production-check.mjs";

const [, , tablePath] = process.argv;
if (!tablePath) throw new Error("usage: public-evidence-pict-check <generated.tsv>");
const [headerLine, ...lines] = readFileSync(tablePath, "utf8").trimEnd().split("\n");
const headers = headerLine.split("\t");
const values = {
  repoRelative: "target/release/fireemu",
  normalizedRepo: "target/../target/fireemu",
  parentEscape: "../private/fireemu",
  normalizedEscape: "safe/../../outside",
  posixAbsolute: "/var/tmp/fireemu",
  windowsDriveAbsolute: "C:\\private\\fireemu",
  windowsUNC: "\\\\server\\share\\fireemu",
  backslashEscape: "..\\private\\fireemu",
  privateDocsLocal: "docs.local/private.json",
  privateCodex: ".codex/private.json",
  privateSuperpowers: "docs/superpowers/private.md",
  privateSuperpowersDot: "docs/./superpowers/private.md",
  privateSuperpowersRepeated: "docs//superpowers/private.md",
  privateSuperpowersParent: "docs/intermediate/../superpowers/private.md",
  httpsUrl: "https://example.invalid/v1/projects/demo",
  fileUrl: "file:///tmp/private.json",
  apiRoute: "/v1/projects/demo/databases/(default)/documents",
  apiActionRoute: "/v1/projects/demo/databases/(default)/documents:executePipeline",
  apiDotTraversal: "/v1/projects/../etc/private.json",
  firestoreRpc: "/google.firestore.v1.Firestore/Commit",
  rpcDotTraversal: "/google.firestore.v1.Firestore/../../etc/private.json",
  resourceIdentifier: "projects/demo/topics/topic-a",
  jsonPointer: "/rows/0/status",
  arbitrarySlashRooted: "/arbitrary/private/path",
  absoluteInProse: "diagnostic at /tmp/private.json",
  rootRoute: "/",
  base64Binary: "/w==",
  base64BinaryUnpadded: "/wAA",
  base64TextPath: "/tmp/private.json",
  duplicateJsonKey: "unused",
  artifactOutside: "unused",
  artifactPrivate: "unused",
};
const keyFor = (context) =>
  ({
    path: "path",
    pathSuffix: "artifactPath",
    route: "route",
    url: "url",
    selector: "selector",
    coordinate: "coordinate",
    knownDifference: "knownDifferences",
    recordedRootRoute: "production",
    bytesValue: "bytesValue",
    rawJson: "rawJson",
    resource: "resourceName",
    generic: "note",
    dictionaryKey: "note",
    artifactPath: "path",
  })[context];

let checked = 0;
const fixture = mkdtempSync(join(tmpdir(), "public-evidence-pict-"));
const repo = join(fixture, "repo");
const artifact = join(repo, "target", "release", "fireemu");
const outside = join(fixture, "outside", "fireemu");
mkdirSync(join(repo, "target", "release"), { recursive: true });
mkdirSync(join(repo, ".codex"), { recursive: true });
mkdirSync(join(fixture, "outside"), { recursive: true });
writeFileSync(artifact, "artifact");
writeFileSync(outside, "artifact");
const outsideLink = join(repo, "target", "release", "external-link");
symlinkSync(outside, outsideLink);
const sha = "a".repeat(64);
for (const line of lines) {
  const row = Object.fromEntries(line.split("\t").map((field, index) => [headers[index], field]));
  let value =
    row.KeyContext === "coordinate" && row.ValueForm === "jsonPointer"
      ? "/conditions/2/cases/1"
      : row.KeyContext === "knownDifference" && row.ValueForm === "jsonPointer"
        ? "/knownDifferences/example"
        : values[row.ValueForm];
  if (row.ValueForm === "base64Binary") value = Buffer.from([0xff]).toString("base64");
  if (row.ValueForm === "base64BinaryUnpadded")
    value = Buffer.from([0xff, 0x00, 0x00]).toString("base64");
  if (row.ValueForm === "base64TextPath")
    value = Buffer.from("/tmp/private.json").toString("base64");
  if (row.ValueForm === "duplicateJsonKey") {
    let passed = true;
    try {
      publicEvidenceBytes(
        Buffer.from('{"extra":{"path":"docs.local/private.json","path":"safe"}}'),
      );
    } catch {
      passed = false;
    }
    if (passed) throw new Error(`PICT row ${checked + 2} accepted duplicate object keys`);
    checked++;
    continue;
  }
  const contextKey = keyFor(row.KeyContext);
  let candidate;
  if (row.KeyContext === "artifactPath") {
    const binary =
      row.ValueForm === "artifactPrivate"
        ? join(repo, ".codex", "fireemu")
        : row.ValueForm !== "artifactOutside"
          ? artifact
          : row.ArtifactState === "symlinkExternal"
            ? outsideLink
            : outside;
    let result;
    try {
      result = historicalArtifactIdentity({
        root: repo,
        binary,
        before: sha,
        after: sha,
        version: "fireemu 1\n",
      });
      if (row.ValueForm === "artifactPrivate") {
        throw new Error(`PICT row ${checked + 2} accepted a private artifact`);
      }
      const expectedOutside = row.ValueForm === "artifactOutside";
      if ((result.outsideRepository === true) !== expectedOutside) {
        throw new Error(`PICT row ${checked + 2} returned the wrong artifact projection`);
      }
    } catch (error) {
      if (row.ValueForm !== "artifactPrivate") throw error;
    }
    checked++;
    continue;
  }
  const decodedBytes =
    row.KeyContext === "bytesValue" ? Buffer.from(value, "base64") : Buffer.alloc(0);
  const canonicalBinaryBytesValue =
    row.KeyContext === "bytesValue" &&
    /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) &&
    decodedBytes.toString("base64") === value &&
    !Buffer.from(decodedBytes.toString("utf8"), "utf8").equals(decodedBytes);
  if (row.KeyContext === "dictionaryKey" && row.ValueForm.startsWith("private")) {
    candidate = { [value]: "synthetic" };
  } else if (row.Container === "scalar") candidate = value;
  else if (row.Container === "object") candidate = { [contextKey]: value };
  else if (row.Container === "array") candidate = { [contextKey]: [value] };
  else candidate = { envelope: [{ [contextKey]: value }] };

  const mustPass =
    (row.ValueForm === "httpsUrl" && row.KeyContext === "url" && row.Container !== "scalar") ||
    (["apiRoute", "apiActionRoute"].includes(row.ValueForm) &&
      ["path", "route"].includes(row.KeyContext) &&
      row.Container !== "scalar") ||
    (row.ValueForm === "firestoreRpc" &&
      ["path", "route"].includes(row.KeyContext) &&
      row.Container !== "scalar") ||
    (row.ValueForm === "jsonPointer" &&
      row.KeyContext === "selector" &&
      row.Container !== "scalar") ||
    (row.ValueForm === "jsonPointer" &&
      row.KeyContext === "coordinate" &&
      row.Container !== "scalar") ||
    (row.ValueForm === "jsonPointer" &&
      row.KeyContext === "knownDifference" &&
      row.Container !== "scalar") ||
    (row.ValueForm === "rootRoute" &&
      ["url", "selector", "recordedRootRoute"].includes(row.KeyContext) &&
      row.Container !== "scalar") ||
    (["base64Binary", "base64BinaryUnpadded"].includes(row.ValueForm) &&
      row.Container !== "scalar") ||
    (row.ValueForm === "base64TextPath" && row.Container === "scalar") ||
    canonicalBinaryBytesValue ||
    ["repoRelative", "normalizedRepo", "resourceIdentifier"].includes(row.ValueForm);
  let passed = true;
  try {
    publicEvidence(candidate);
  } catch {
    passed = false;
  }
  if (passed !== mustPass) {
    throw new Error(
      `PICT row ${checked + 2} violated its expected ${mustPass ? "accept" : "reject"} result`,
    );
  }
  checked++;
}
rmSync(fixture, { recursive: true, force: true });
if (checked !== lines.length)
  throw new Error(`PICT checker consumed ${checked} of ${lines.length} generated rows`);
process.stdout.write(`validated ${checked} generated PICT rows\n`);
