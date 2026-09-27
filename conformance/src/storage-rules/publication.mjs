import { createHash } from "node:crypto";

const header = "service firebase.storage {\n  match /b/{bucket}/o {\n";
const footer = "\n  }\n}\n";
const version2 = "rules_version = '2';\n";

function matchBody(entry, prefix) {
  const source = entry.rulesSource;
  if (typeof source !== "string") throw new Error(`missing Rules source: ${entry.id}`);
  const version = source.startsWith(version2) ? 2 : 1;
  const withoutVersion = version === 2 ? source.slice(version2.length) : source;
  if (!withoutVersion.startsWith(header) || !withoutVersion.endsWith(footer)) {
    throw new Error(`invalid Rules wrapper: ${entry.id}`);
  }
  const body = withoutVersion.slice(header.length, -footer.length);
  const matchLines = body.match(/^    match \/[^\n]+ \{$/gm) ?? [];
  if (matchLines.length !== 1) throw new Error(`invalid Rules wrapper match count: ${entry.id}`);
  if (!matchLines[0].startsWith(`    match /${prefix}`)) {
    throw new Error(`changed Rules match prefix: ${entry.id}`);
  }
  return { id: entry.id, prefix, version, body };
}

export function buildPublicationSources(corpus, binding) {
  if (!binding?.prefix?.startsWith("STORAGE-RULES/")) throw new Error("invalid owned prefix");
  const entries = [
    ...corpus.cases.map((entry) => matchBody(entry, entry.casePrefix)),
    ...corpus.firestorePrograms.map((entry) => matchBody(entry, `${binding.prefix}${entry.id}/`)),
  ];
  if (new Set(entries.map((entry) => entry.id)).size !== entries.length) {
    throw new Error("duplicate case id");
  }
  for (let i = 0; i < entries.length; i++) {
    for (let j = i + 1; j < entries.length; j++) {
      const a = entries[i].prefix;
      const b = entries[j].prefix;
      if (a.startsWith(b) || b.startsWith(a)) throw new Error(`overlapping owned paths: ${entries[i].id}, ${entries[j].id}`);
    }
  }
  return [1, 2].map((version) => {
    const selected = entries.filter((entry) => entry.version === version);
    if (selected.length === 0) throw new Error(`missing Rules version ${version}`);
    const content = `${version === 2 ? version2 : ""}${header}${selected.map((entry) => entry.body).join("\n")}\n  }\n}\n`;
    const bytes = Buffer.byteLength(content);
    if (bytes >= 256 * 1024) throw new Error(`Rules version ${version} exceeds source limit`);
    return {
      version,
      caseIds: selected.map((entry) => entry.id),
      content,
      bytes,
      sha256: createHash("sha256").update(content).digest("hex"),
    };
  });
}
