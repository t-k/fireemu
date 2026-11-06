import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { publicEvidence } from "./evidence.mjs";
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
  httpsUrl: "https://example.invalid/v1/projects/demo",
  fileUrl: "file:///tmp/private.json",
  apiRoute: "/v1/projects/demo/databases/(default)/documents",
  firestoreRpc: "/google.firestore.v1.Firestore/Commit",
  resourceIdentifier: "projects/demo/topics/topic-a",
  jsonPointer: "/rows/0/status",
  arbitrarySlashRooted: "/arbitrary/private/path",
  absoluteInProse: "diagnostic at /tmp/private.json",
  rootRoute: "/",
  base64Binary: "/w==",
  base64TextPath: "/tmp/private.json",
  artifactOutside: "unused",
  artifactPrivate: "unused",
};
const keyFor = (context) =>
  ({
    path: "path",
    pathSuffix: "artifactPath",
    url: "url",
    selector: "selector",
    coordinate: "coordinate",
    knownDifference: "knownDifferences",
    recordedRootRoute: "production",
    bytesValue: "bytesValue",
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
  if (row.ValueForm === "base64TextPath") value = Buffer.from("/tmp/private.json").toString("base64");
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
  if (row.KeyContext === "dictionaryKey" && row.ValueForm.startsWith("private")) {
    candidate = { [value]: "synthetic" };
  } else if (row.Container === "scalar") candidate = value;
  else if (row.Container === "object") candidate = { [contextKey]: value };
  else if (row.Container === "array") candidate = { [contextKey]: [value] };
  else candidate = { envelope: [{ [contextKey]: value }] };

  const mustPass =
    (row.ValueForm === "httpsUrl" && row.KeyContext === "url" && row.Container !== "scalar") ||
    (row.ValueForm === "apiRoute" &&
      ["path", "pathSuffix"].includes(row.KeyContext) &&
      row.Container !== "scalar") ||
    (row.ValueForm === "firestoreRpc" &&
      ["path", "pathSuffix"].includes(row.KeyContext) &&
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
      ["url", "recordedRootRoute"].includes(row.KeyContext) &&
      row.Container !== "scalar") ||
    (row.ValueForm === "base64Binary" && row.Container !== "scalar") ||
    (row.ValueForm === "base64TextPath" && row.Container === "scalar") ||
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
