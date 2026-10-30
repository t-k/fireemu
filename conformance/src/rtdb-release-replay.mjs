// Local-only replay of the recorded RTDB comparisons on the installed release binary.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { summarize as summarizeResidual } from "../../tools/sdk-smoke-database/rtdb-residual-fixture.mjs";
import { summarize as summarizeS5 } from "../../tools/sdk-smoke-database/rtdb-s5-fixture.mjs";
import { comparison as compareAuth } from "../../tools/sdk-smoke-database/cv11-fixture.mjs";
import { judgeCaptured } from "../../tools/sdk-smoke-database/cv07-ondisconnect.mjs";
import { compareRecordings, readFrames } from "./rtdb-functions/compare-local.mjs";

const T = "tools/sdk-smoke-database";
const names = {
  "rest-old": "rest",
  "rest-v033": "rest",
  ondisconnect: "ondisconnect",
  auth: "auth",
  residual: "residual",
  s5: "s5",
  functions: "functions",
  smoke: "smoke",
};
const scripts = {
  rest: `${T}/rest-replay.mjs`,
  ondisconnect: `${T}/cv07-ondisconnect.mjs`,
  auth: `${T}/cv11-genuine-auth.mjs`,
  residual: `${T}/rtdb-residual.mjs`,
  s5: `${T}/rtdb-s5.mjs`,
  functions: "conformance/src/rtdb-functions/local-run.mjs",
};
export function campaignPlan(name, binary, out) {
  const campaign = Object.hasOwn(names, name) ? names[name] : undefined;
  if (!campaign || !binary || !out) return undefined;
  if (campaign === "smoke")
    return {
      campaign,
      argv: [
        binary,
        "exec",
        "--no-config-discovery",
        "--only",
        "database",
        "--",
        process.execPath,
        `${T}/run.mjs`,
        "--only",
        "crud",
      ],
    };
  const argv = [process.execPath, scripts[campaign]];
  if (campaign !== "functions") argv.push("local");
  argv.push("--fireemu", binary, "--out", out);
  if (["residual", "s5", "functions"].includes(campaign)) argv.push("--profile", "strict");
  if (["ondisconnect", "auth", "residual", "s5"].includes(campaign))
    argv.push("--modules", resolve(T, "node_modules"));
  return { campaign, argv };
}
export function judgeExport(name, observed, binarySha256) {
  if (
    !Object.hasOwn(names, name) ||
    !observed ||
    observed.campaign !== names[name] ||
    observed.binarySha256 !== binarySha256 ||
    !/^[a-f0-9]{64}$/.test(binarySha256 ?? "") ||
    observed.match !== true
  )
    return ["RTDB replay missing, failed, or bound to the wrong campaign or binary"];
  return [];
}
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const fixture = (name) => json(join(T, "fixtures", name));
const digestFile = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
export function sourceResources(campaign) {
  const paths = {
    rest: [
      `${T}/rest-replay.mjs`,
      `${T}/production-corpus.mjs`,
      `${T}/fixtures/production-rest.json`,
      "spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json",
    ],
    ondisconnect: [
      `${T}/cv07-ondisconnect.mjs`,
      `${T}/production-live.mjs`,
      `${T}/fixtures/production-sdk-ondisconnect.json`,
    ],
    auth: [
      `${T}/cv11-genuine-auth.mjs`,
      `${T}/cv11-genuine-auth-page.js`,
      `${T}/cv11-fixture.mjs`,
      `${T}/fixtures/production-cv11-genuine-auth.json`,
    ],
    residual: [
      `${T}/rtdb-residual.mjs`,
      `${T}/rtdb-residual-page.js`,
      `${T}/rtdb-residual-fixture.mjs`,
      `${T}/rtdb-residual-judge.mjs`,
      `${T}/fixtures/production-rtdb-residual.json`,
    ],
    s5: [
      `${T}/rtdb-s5.mjs`,
      `${T}/rtdb-s5-page.js`,
      `${T}/rtdb-s5-fixture.mjs`,
      `${T}/rtdb-s5-judge.mjs`,
      `${T}/fixtures/production-rtdb-s5.json`,
    ],
    functions: [
      "conformance/src/rtdb-functions/local-run.mjs",
      "conformance/src/rtdb-functions/compare-local.mjs",
      "conformance/src/rtdb-functions/sequence.mjs",
      "conformance/src/rtdb-functions/recorded/production-rtdb-triggers.json",
    ],
    smoke: [`${T}/run.mjs`, `${T}/smokes.mjs`, `${T}/fixtures/official-emulator-4.11.2/crud.json`],
  }[campaign];
  if (!paths) throw Error("unknown RTDB campaign");
  const shared = [
    "conformance/src/rtdb-release-replay.mjs",
    `${T}/cv11-genuine-auth.mjs`,
    `${T}/adc-preflight.mjs`,
    `${T}/rtdb-admin.mjs`,
    `${T}/rtdb-residual.mjs`,
    `${T}/rtdb-residual-judge.mjs`,
    `${T}/cv07-ondisconnect.mjs`,
    `${T}/production-live.mjs`,
    `${T}/jar.mjs`,
    `${T}/compare.mjs`,
    "conformance/src/rtdb-functions/frames.mjs",
    "conformance/src/rtdb-functions/mask-recording.mjs",
    "conformance/src/rtdb-functions/firebase.json",
  ];
  return Object.fromEntries(
    [...new Set([...paths, ...shared])].map((path) => [path, digestFile(path)]),
  );
}
export function runtimeResources(
  campaign,
  root = campaign === "functions" ? "conformance/src/rtdb-functions/fixtures" : T,
) {
  if (campaign === "functions") {
    for (const [name, version] of [
      ["firebase-functions", "7.3.2"],
      ["firebase-admin", "14.3.0"],
    ]) {
      if (json(join(root, "node_modules", name, "package.json")).version !== version)
        throw Error(`RTDB ${name} version mismatch`);
    }
    return Object.fromEntries(
      [
        "package-lock.json",
        "index.js",
        "frames.js",
        "node_modules/firebase-functions/package.json",
        "node_modules/firebase-admin/package.json",
      ].map((path) => [path, digestFile(join(root, path))]),
    );
  }
  if (!["ondisconnect", "auth", "residual", "s5", "smoke"].includes(campaign)) return {};
  for (const [name, version] of [
    ["firebase", "12.18.0"],
    ["firebase-admin", "14.3.0"],
    ["playwright", "1.62.1"],
  ]) {
    if (json(join(root, "node_modules", name, "package.json")).version !== version)
      throw Error(`RTDB ${name} version mismatch`);
  }
  const paths = [
    "package-lock.json",
    ...["firebase", "firebase-admin", "playwright"].map(
      (name) => `node_modules/${name}/package.json`,
    ),
    ...["firebase-app.js", "firebase-auth.js", "firebase-database.js"].map(
      (name) => `node_modules/firebase/${name}`,
    ),
  ];
  return Object.fromEntries(paths.map((path) => [path, digestFile(join(root, path))]));
}
export function adjudicate(campaign, out) {
  if (campaign === "smoke")
    return { match: true, basis: "official emulator CRUD smoke, not production evidence" };
  if (campaign === "rest") {
    const result = json(join(out, "comparison.json"));
    const expected = json("spec/compatibility/closure/evidence/RTDB-rest-v033-comparison.json");
    const all = [result.rows, result.m14];
    const keys = (rows, fields) => rows?.map((row) => fields.map((field) => row[field]));
    const identities =
      isDeepStrictEqual(keys(result.rows, ["round", "id"]), keys(expected.rows, ["round", "id"])) &&
      isDeepStrictEqual(
        keys(result.m14, ["round", "expressionIndex", "context"]),
        keys(expected.m14, ["round", "expressionIndex", "context"]),
      );
    return {
      match:
        identities &&
        all[0]?.length === 124 &&
        all[1]?.length === 48 &&
        all.every((rows) => rows.every((row) => row.verdict === "MATCH")),
      result,
    };
  }
  if (campaign === "ondisconnect") {
    const result = judgeCaptured(
      json(join(out, "journal.json")),
      fixture("production-sdk-ondisconnect.json"),
    );
    return {
      match:
        result.matched &&
        result.timing.within &&
        result.nativeEvents === 36 &&
        result.localEvents === 36,
      result,
    };
  }
  if (campaign === "auth") {
    const result = compareAuth(
      fixture("production-cv11-genuine-auth.json"),
      json(join(out, "journal.json")),
    );
    return {
      match:
        result.match &&
        result.profiles.length === 4 &&
        result.profiles.reduce((n, p) => n + p.localEvents, 0) === 92,
      result,
    };
  }
  if (campaign === "residual") {
    const result = summarizeResidual(
      fixture("production-rtdb-residual.json"),
      json(join(out, "journal.json")),
    );
    return {
      match: result.match && result.profiles.length === 8 && result.rows.MATCH === 8,
      result,
    };
  }
  if (campaign === "s5") {
    const result = summarizeS5(fixture("production-rtdb-s5.json"), json(join(out, "journal.json")));
    return { match: result.match && result.rounds.length === 2, result };
  }
  if (campaign === "functions") {
    const production = json(
      "conformance/src/rtdb-functions/recorded/production-rtdb-triggers.json",
    ).frames.map(({ n: _n, step: _step, ...frame }) => frame);
    const result = compareRecordings({ production, local: readFrames(join(out, "frames.jsonl")) });
    const writes = json(join(out, "writes.json"));
    return {
      match:
        result.totals.rows === 72 &&
        result.totals.match === 72 &&
        result.totals.difference === 0 &&
        result.facts.length === 2 &&
        result.facts.every((f) => f.oneTimePerWrite && f.distinctIds) &&
        Object.values(result.unattributed).every((x) => x.length === 0) &&
        writes.length === 9 &&
        writes.every(
          (w, i) => w.step === `s${i + 1}` && w.n === i + 1 && w.status >= 200 && w.status < 300,
        ),
      result,
      writes,
    };
  }
  throw Error("unknown RTDB campaign");
}
async function main(argv) {
  const [mode, name] = argv;
  const option = (key) => argv[argv.indexOf(key) + 1];
  if (
    mode !== "local" ||
    !argv.includes("--fireemu") ||
    !argv.includes("--out") ||
    !argv.includes("--export")
  )
    throw Error("usage: local <campaign> --fireemu <binary> --out <new dir> --export <file>");
  const binary = realpathSync(resolve(option("--fireemu")));
  const plan = campaignPlan(name, binary, resolve(option("--out")));
  if (!plan) throw Error("unknown RTDB campaign");
  const binarySha256 = digestFile(binary);
  const resources = runtimeResources(plan.campaign);
  const sources = sourceResources(plan.campaign);
  const child = spawnSync(plan.argv[0], plan.argv.slice(1), { stdio: "inherit", env: process.env });
  if (child.status !== 0) throw Error(`RTDB producer exited ${child.status ?? child.signal}`);
  if (digestFile(binary) !== binarySha256) throw Error("RTDB binary changed during replay");
  if (!isDeepStrictEqual(sourceResources(plan.campaign), sources))
    throw Error("RTDB sources changed during replay");
  if (!isDeepStrictEqual(runtimeResources(plan.campaign), resources))
    throw Error("RTDB SDK resources changed during replay");
  const verdict = adjudicate(plan.campaign, resolve(option("--out")));
  writeFileSync(
    option("--export"),
    `${JSON.stringify({ campaign: plan.campaign, binarySha256, resources, sources, ...verdict }, null, 2)}\n`,
    { flag: "wx" },
  );
  return verdict.match ? 0 : 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error.stack);
      process.exitCode = 2;
    },
  );
