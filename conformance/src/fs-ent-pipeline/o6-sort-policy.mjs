// Owner2114: two strict REST evidence contracts, never a general sort waiver or runtime path.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";
import { compareBag, subset } from "./o7-order-policy.mjs";
const recipes = [
  {
    id: "fs-ent-pipeline/o6/sort-kinds-cross#v-desc",
    requestSha256: "1e616423f8a48f87fedb4ece337a0465227164863a1ae1b092dbe848c52e4e47",
    seedSha256: "95ae3f6ffedaeafb8deb55ce83026bdd47e2bf2914e603c6303305765632ab1d",
    fixtureStepSha256: "fa018cbba8b01a611bdd48998a2400e980785aac904630d025bd38c323ea8de1",
    preludeRequestSha256: "1a7044a376cff9b8c0e2e8be22e49578d4d7680ac4b46ece8a782f8ef6aba1e5",
    preludeFixtureSha256: "f41c2363558b762f7e3c348ed13c7506a98139e36a3d6003ed7b30ca49f776b6",
  },
  {
    id: "fs-ent-pipeline/o6/sort-ties#g-asc-limit2",
    requestSha256: "0fa1dab2b8453fabe766d7bb5d989a73c7bafb08deb9f5d5ec4c5e43a5143299",
    seedSha256: "b9a6bc3daa8ecacd03c7f490a5c9f6b45add6cbd362e93005a6b61e589d3eccd",
    fixtureStepSha256: "9932d0268ee2762a4b7e435278552071ae170d748aa1d9b941f294cf45faa64e",
    companionRequestSha256: "ba3cde9fdb294f45b1b20f42825db67be4a08da7b4c85f928d62998fd6843436",
    companionFixtureSha256: "dd1fe25899bf3b79e6a673ce43cce75fe04ed209c5094b7a26c50d9f3bf781de",
  },
];
const hash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
function unpack(step) {
  if (
    step?.status !== 200 ||
    !Array.isArray(step.body) ||
    step.body.length !== 1 ||
    !Array.isArray(step.body[0].results)
  )
    throw Error("response shape");
  const shell = structuredClone(step),
    results = shell.body[0].results;
  delete shell.body[0].results;
  return { shell, results };
}
function sameShell(values) {
  return values.every((value) => isDeepStrictEqual(value.shell, values[0].shell));
}
function nullState(row) {
  const fields = row?.fields ?? {};
  if (!Object.hasOwn(fields, "v")) return "absent";
  return isDeepStrictEqual(fields.v, { nullValue: null }) ? "null" : "other";
}
function integerKey(row) {
  const g = row?.fields?.g;
  if (
    !g ||
    Object.keys(g).length !== 1 ||
    typeof g.integerValue !== "string" ||
    !/^(-?[1-9]\d*|0)$/.test(g.integerValue)
  )
    throw Error("typed sort key");
  return BigInt(g.integerValue);
}
function ascending(rows) {
  let last;
  for (const row of rows) {
    const key = integerKey(row);
    if (last !== undefined && key < last) return false;
    last = key;
  }
  return true;
}
/** The caller must separately bind normalized input to the actual final source/binary/raw producer. */
export function evaluate(input) {
  try {
    const p = recipes.find((recipe) => recipe.id === input?.id);
    if (
      !p ||
      input.profile !== "strict" ||
      input.rawStatus !== "MISMATCH" ||
      hash(input.request) !== p.requestSha256 ||
      hash(input.seed) !== p.seedSha256 ||
      hash(input.production) !== p.fixtureStepSha256 ||
      hash(input.production2) !== p.fixtureStepSha256
    )
      return null;
    const values = [input.production, input.production2, input.local].map(unpack);
    if (!sameShell(values)) return null;
    const common = {
      id: p.id,
      rawStatus: "MISMATCH",
      authority: "owner2114",
      requestSha256: p.requestSha256,
      seedSha256: p.seedSha256,
      fixtureStepSha256: p.fixtureStepSha256,
      dependencySha256: hash(p),
    };
    if (p.preludeRequestSha256) {
      if (
        hash(input.preludeRequest) !== p.preludeRequestSha256 ||
        hash(input.preludeProduction) !== p.preludeFixtureSha256 ||
        !isDeepStrictEqual(input.preludeLocal, input.preludeProduction)
      )
        return null;
      if (
        !input.seed.some(
          ([, fields]) => Object.hasOwn(fields, "v") && Object.hasOwn(fields.v, "nullValue"),
        ) ||
        !input.seed.some(([, fields]) => !Object.hasOwn(fields, "v"))
      )
        return null;
      const expected = values[0].results,
        tail = expected.slice(14);
      if (tail.map(nullState).sort().join(",") !== "absent,null") return null;
      if (
        !values.every(
          (value) =>
            value.results.length === 16 &&
            compareBag(value.results, expected) &&
            isDeepStrictEqual(value.results.slice(0, 14), expected.slice(0, 14)) &&
            compareBag(value.results.slice(14), tail),
        )
      )
        return null;
      return {
        ...common,
        proofClassification: "ORDERED_TYPED_NULL_ABSENT_TIE_EQUIVALENT",
        resultCount: 16,
        fixedPrefixCount: 14,
        tieClassCount: 2,
        sourceProof: "BOUND_ORIGINAL_SEED_AND_SEED_VECTOR_PRELUDE",
      };
    }
    if (
      hash(input.companionRequest) !== p.companionRequestSha256 ||
      hash(input.companionProduction) !== p.companionFixtureSha256 ||
      hash(input.companionProduction2) !== p.companionFixtureSha256
    )
      return null;
    const all = [input.companionProduction, input.companionProduction2, input.companionLocal].map(
      unpack,
    );
    if (
      !sameShell(all) ||
      !isDeepStrictEqual(all[0].shell, values[0].shell) ||
      !all.every(
        (value) =>
          value.results.length === 8 &&
          compareBag(value.results, all[0].results) &&
          ascending(value.results),
      )
    )
      return null;
    const seeded = input.seed.map(([, fields]) => integerKey({ fields }));
    const minimum = seeded.reduce((a, b) => (a < b ? a : b));
    if (minimum !== 1n || seeded.filter((value) => value === minimum).length !== 3) return null;
    // Derived from the existing full companion, not presented as another observed response.
    const eligible = all[0].results.filter((row) => integerKey(row) === minimum);
    if (
      eligible.length !== 3 ||
      eligible.some((row, i) => eligible.slice(i + 1).some((other) => compareBag([row], [other])))
    )
      return null;
    if (!values.every((value) => subset(value.results, eligible, 2))) return null;
    return {
      ...common,
      proofClassification: "LEGAL_UNORDERED_SELECTION",
      resultCount: 2,
      eligibleCount: 3,
      selectedCount: 2,
      minimumKey: { integerValue: "1" },
      eligibleOrigin: "DERIVED_FROM_BOUND_EXISTING_COMPANION_AND_SEED",
      companion: "fs-ent-pipeline/o6/sort-ties#g-asc",
      companionRequestSha256: p.companionRequestSha256,
    };
  } catch {
    return null;
  }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const result = evaluate(JSON.parse(readFileSync(process.argv[2], "utf8")));
  process.stdout.write(JSON.stringify({ binding: "UNVERIFIED", result }) + "\n");
  if (!result) process.exitCode = 1;
}
