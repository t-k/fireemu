import { readFileSync } from "node:fs";

const KINDS = new Set([
  "production-spec",
  "official-emulator",
  "intentional-local-policy",
  "unverified",
]);

const validDate = (value) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value ?? "")) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
};

export function validateDivergenceRegister(register, baselineVersion) {
  const problems = [];
  if (register?.schemaVersion !== 2) problems.push("schemaVersion must be 2");
  for (const section of ["divergences", "firestoreMatrixDivergences"]) {
    const entries = register?.[section];
    if (!entries || Array.isArray(entries) || typeof entries !== "object") {
      problems.push(`${section} must be an object`);
      continue;
    }
    for (const [key, entry] of Object.entries(entries)) {
      const authority = entry?.authority;
      if (!authority || typeof authority !== "object") {
        problems.push(`${key}: authority is required`);
        continue;
      }
      if (!KINDS.has(authority.kind)) problems.push(`${key}: unknown authority kind`);
      if (authority.kind === "unverified") {
        problems.push(`${key}: unverified authority cannot justify a divergence`);
      }
      if (
        !Array.isArray(authority.sourceUrls) ||
        authority.sourceUrls.length === 0 ||
        authority.sourceUrls.some((url) => {
          try {
            return new URL(url).protocol !== "https:";
          } catch {
            return true;
          }
        })
      ) {
        problems.push(`${key}: sourceUrls must contain valid HTTPS URLs`);
      }
      if (!validDate(authority.checkedOn)) problems.push(`${key}: checkedOn is invalid`);
      if (
        authority.officialBaseline?.package !== "firebase-tools" ||
        authority.officialBaseline?.version !== baselineVersion
      ) {
        problems.push(`${key}: officialBaseline must match firebase-tools ${baselineVersion}`);
      }
      if (!authority.fixture) problems.push(`${key}: fixture is required`);
      if (!authority.decidedBy && !authority.approvalRecord) {
        problems.push(`${key}: decidedBy or approvalRecord is required`);
      }
    }
  }
  return problems;
}

export function readValidatedDivergenceRegister() {
  const register = JSON.parse(
    readFileSync(new URL("../divergences.json", import.meta.url), "utf8"),
  );
  const packageManifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  const baselineVersion = packageManifest.dependencies["firebase-tools"];
  const problems = validateDivergenceRegister(register, baselineVersion);
  if (problems.length > 0) {
    throw new Error(`invalid divergence authority register:\n${problems.join("\n")}`);
  }
  return register;
}
