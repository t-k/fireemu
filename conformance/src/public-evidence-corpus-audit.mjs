import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { relative } from "node:path";
import { REPO_ROOT } from "./config.mjs";
import { publicEvidence } from "./evidence.mjs";

const roots = ["spec/compatibility/evidence", "spec/compatibility/closure/evidence"];
const files = execFileSync("git", ["ls-files", "--", ...roots], {
  cwd: REPO_ROOT,
  encoding: "utf8",
})
  .trim()
  .split("\n")
  .filter((path) => path.endsWith(".json"));
const findings = new Map();
const categories = new Map();
const pointer = (parts) =>
  parts.length
    ? "/" + parts.map((part) => String(part).replaceAll("~", "~0").replaceAll("/", "~1")).join("/")
    : "/";
const record = (file, parts, code = "UNKNOWN") => {
  const location = `${relative(REPO_ROOT, file)}#${pointer(parts)}`;
  findings.set(location, (findings.get(location) ?? 0) + 1);
  const byCode = categories.get(location) ?? new Map();
  byCode.set(code, (byCode.get(code) ?? 0) + 1);
  categories.set(location, byCode);
};
const safeLocationPart = (key) => {
  try {
    publicEvidence({ [key]: null });
    return key;
  } catch {
    return "<unsafe-key>";
  }
};
const visit = (value, file, parts = [], contextKey = "") => {
  if (typeof value === "string") {
    try {
      publicEvidence({ [contextKey || "evidenceValue"]: value });
    } catch (error) {
      record(file, parts, error.code);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => visit(item, file, [...parts, index], contextKey));
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      const locationKey = safeLocationPart(key);
      try {
        publicEvidence({ [key]: null });
      } catch (error) {
        record(file, [...parts, locationKey], error.code);
      }
      visit(child, file, [...parts, locationKey], key);
    }
  }
};

for (const path of files) {
  try {
    visit(JSON.parse(readFileSync(`${REPO_ROOT}/${path}`, "utf8")), `${REPO_ROOT}/${path}`);
  } catch {
    findings.set(`${path}#<invalid-json>`, 1);
  }
}
for (const [location, count] of findings) {
  const summary = [...categories.get(location)]
    .map(([code, occurrences]) => `${code}:${occurrences}`)
    .join(",");
  process.stdout.write(`${location}\t${count}\t${summary}\n`);
}
process.stdout.write(
  `public evidence audit: ${findings.size} violating field locations across ${files.length} files\n`,
);
if (findings.size) process.exitCode = 1;
