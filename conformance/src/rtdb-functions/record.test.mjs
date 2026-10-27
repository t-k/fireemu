// The entry of the CV14 recorder: admission by a reviewed approval file and packet, the pins of the
// packet, the token provider, and a run's private output. A run itself is exercised on the fakes.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { assembleStage2 } from "./assemble.mjs";
import { FIXTURE_HANDLERS } from "./frames.mjs";
import {
  admitRun,
  assertApproval,
  createTokenProvider,
  estimatedUsd,
  executeRun,
  exitCodeOf,
  parsePacketPins,
  tokenProviderWithSecrets,
} from "./record.mjs";
import { createRehearsalEnvironment } from "./world.fake.mjs";

const SHA = "a".repeat(64);
const GIT = "b".repeat(40);

test("an approval binds one decision, one commit and one packet, and nothing else says otherwise", () => {
  const ok = `Decision: APPROVE\ngitSha: ${GIT}\npacketSha256: ${SHA}\nNotes follow.\n`;
  assert.doesNotThrow(() => assertApproval(ok, GIT, SHA));
  for (const bad of [
    ok.replace("APPROVE", "CHANGES REQUESTED"),
    ok.replace(GIT, "c".repeat(40)),
    ok.replace(SHA, "d".repeat(64)),
    `${ok}Decision: CHANGES REQUESTED\n`,
    `${ok}  gitSha: ${GIT}\n`,
    `${ok}> packetSha256: ${SHA}\n`,
    "",
  ]) {
    assert.throws(() => assertApproval(bad, GIT, SHA), /APPROVE must bind/, bad.slice(0, 40));
  }
  assert.doesNotThrow(() => assertApproval(ok.replaceAll("\n", "\r\n"), GIT, SHA));
});

test("the packet carries its machine-readable pins in one fenced block", () => {
  const block = (body) => `# Packet\n\ntext\n\n\`\`\`json cv14-pins\n${body}\n\`\`\`\n`;
  assert.deepEqual(parsePacketPins(block(JSON.stringify({ baselineRulesSha256: SHA }))), {
    baselineRulesSha256: SHA,
  });
  for (const bad of [
    "no block",
    block("{not json"),
    block(JSON.stringify({ baselineRulesSha256: "short" })),
    block(JSON.stringify({ baselineRulesSha256: SHA, extra: 1 })),
    block(JSON.stringify({})),
    `${block(JSON.stringify({ baselineRulesSha256: SHA }))}${block(JSON.stringify({ baselineRulesSha256: SHA }))}`,
  ]) {
    assert.throws(() => parsePacketPins(bad), /packet pins/, bad.slice(0, 40));
  }
});

test("the token provider refreshes after the token expired and counts every refresh", async () => {
  let n = 0;
  let nowMs = 1_000;
  const seen = [];
  const acquire = async (_adc, budget, kind) => {
    budget.take(kind);
    seen.push(kind);
    return { value: `tok-${++n}`, expiresAt: nowMs + 10_000 };
  };
  const taken = [];
  const budget = { take: (kind) => taken.push(kind) };
  const provider = createTokenProvider({ file: 1 }, budget, { acquire, now: () => nowMs });
  assert.equal(await provider(), "tok-1");
  assert.equal(await provider(), "tok-1");
  nowMs += 20_000;
  assert.equal(await provider(), "tok-2");
  assert.deepEqual(seen, ["token", "token"]);
  // every token the provider gets is handed to the caller, which keeps it out of stored files
  const known = [];
  const watched = createTokenProvider({ file: 1 }, budget, {
    acquire,
    now: () => nowMs,
    onToken: (v) => known.push(v),
  });
  await watched();
  await watched();
  assert.equal(known.length, 1);
  nowMs += 20_000;
  await watched();
  assert.deepEqual(known, ["tok-3", "tok-4"]);
  // the entry keeps them as the secrets a stored file is checked against
  const kept = tokenProviderWithSecrets({ file: 1 }, budget, { acquire, now: () => nowMs });
  await kept.getToken();
  assert.deepEqual(kept.secrets, ["tok-5"]);
});

test("the cost is the FUNCTIONS-HTTP constant per deploy, and the exit code tells recorded, review and residue apart", () => {
  assert.equal(estimatedUsd({ cliDeploy: 8 }), 4.41);
  assert.equal(estimatedUsd({ cliDeploy: 0 }), 0.01);
  assert.equal(exitCodeOf({ outcome: "recorded", residual: false }), 0);
  assert.equal(exitCodeOf({ outcome: "stopped-needs-review", residual: false }), 2);
  assert.equal(exitCodeOf({ outcome: "stopped-needs-review", residual: true }), 3);
});

async function rehearse(arg) {
  const runDir = await mkdtemp(join(tmpdir(), "cv14-record-"));
  const rehearsal = createRehearsalEnvironment(arg);
  const summary = await executeRun({
    environment: rehearsal.environment,
    runDir,
    packetPins: { baselineRulesSha256: rehearsal.environment.rtdbPacket.baselineRulesSha256 },
  });
  return { runDir, summary, ...rehearsal };
}

test("IAM bindings a deploy added are reported masked; one that disappeared is a reason", async () => {
  const added = await rehearse({ options: { iamAddedByDeploy: true } });
  try {
    assert.equal(added.summary.outcome, "recorded");
    const grants = JSON.parse(await readFile(join(added.runDir, "grants.json"), "utf8"));
    assert.deepEqual(grants.iam.added, [
      "roles/eventarc.eventReceiver|serviceAccount:123456789012-compute@developer.gserviceaccount.com",
    ]);
    assert.deepEqual(grants.iam.removed, []);
  } finally {
    await rm(added.runDir, { recursive: true, force: true });
  }
  const removed = await rehearse({
    options: {
      iamBindings: [{ role: "roles/viewer", members: ["user:someone"] }],
      iamRemovedByDeploy: true,
    },
  });
  try {
    assert.equal(removed.summary.outcome, "stopped-needs-review");
    assert.match(
      JSON.parse(await readFile(join(removed.runDir, "result.json"), "utf8")).reasons.join(";"),
      /binding\(s\) disappeared/,
    );
  } finally {
    await rm(removed.runDir, { recursive: true, force: true });
  }
});

test("a service-agent role that disappeared during the run is a reason and leaves the run residual", async () => {
  const w = await rehearse({ options: { agentRemovedByDeploy: true } });
  try {
    assert.equal(w.summary.outcome, "stopped-needs-review");
    assert.equal(w.summary.residual, true);
    assert.match(
      JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8")).reasons.join(";"),
      /service-agent grant disappeared/,
    );
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("result.json says how each failed deploy ended", async () => {
  const w = await rehearse({ options: { failDeploy: "rtdbCreatedV2", failDeployKind: "refused" } });
  try {
    const result = JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8"));
    assert.equal(result.deploys.rtdbCreatedV2.class, "refused");
    assert.equal(result.deploys.rtdbCreatedV2.functionSeen, false);
    assert.equal(w.summary.residual, false);
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("a stored file is refused when it holds a secret", async () => {
  const w = await rehearse({ options: { secretInRecord: "test-token" } });
  try {
    assert.equal(w.summary.outcome, "stopped-needs-review");
    assert.match(
      JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8")).reasons.join(";"),
      /output was refused/,
    );
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("a run writes its private output and a summary of counts only", async () => {
  const w = await rehearse();
  try {
    assert.equal(w.summary.outcome, "recorded", JSON.stringify(w.summary));
    assert.equal(w.summary.residual, false);
    assert.equal(w.summary.estimatedUsd, 4.41);
    assert.deepEqual(Object.keys(w.summary).toSorted(), [
      "estimatedUsd",
      "outcome",
      "requests",
      "residual",
      "runDir",
    ]);
    const names = (await readdir(w.runDir)).toSorted();
    for (const file of [
      "frames.jsonl",
      "forms.json",
      "grants.json",
      "inventory.json",
      "journal.jsonl",
      "lines-masked.txt",
      "owned-uploads.jsonl",
      "records.json",
      "report.json",
      "result.json",
    ]) {
      assert.ok(names.includes(file), file);
      // the ledger of owned uploads is written by its own module inside the private directory
      if (file !== "owned-uploads.jsonl") {
        assert.equal((await stat(join(w.runDir, file))).mode & 0o077, 0, `${file} is private`);
      }
    }
    const result = JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8"));
    assert.equal(result.outcome, "recorded");
    assert.match(result.nonce, /^[0-9a-f]{16}$/u);
    assert.equal(result.deployed, 8);
    const report = JSON.parse(await readFile(join(w.runDir, "report.json"), "utf8"));
    assert.equal(report.steps.length, 9);
    const records = JSON.parse(await readFile(join(w.runDir, "records.json"), "utf8"));
    assert.deepEqual(
      Object.keys(records),
      FIXTURE_HANDLERS.map((h) => h.name),
    );
    // no token, no signed URL and no project number reaches a stored file
    for (const file of names) {
      const text = await readFile(join(w.runDir, file), "utf8");
      assert.ok(!text.includes("test-token"), file);
      assert.ok(!text.includes("SECRET-MARKER"), file);
    }
    const masked = await readFile(join(w.runDir, "records.json"), "utf8");
    assert.ok(
      !masked.includes(w.environment.projectNumber) ||
        w.environment.projectNumber === "123456789012",
    );
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

test("a run that leaves residue says so in the summary and the exit code", async () => {
  const w = await rehearse({ options: { keepFunction: "rtdbDeletedV2" } });
  try {
    assert.equal(w.summary.outcome, "stopped-needs-review");
    assert.equal(w.summary.residual, true);
    assert.equal(exitCodeOf(w.summary), 3);
    const result = JSON.parse(await readFile(join(w.runDir, "result.json"), "utf8"));
    assert.match(result.reasons.join(";"), /rtdbDeletedV2 was not cleaned/);
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
});

// ---- admission and the output of a run ----

const PRIVATE = "/private/docs.local";
const PINS = JSON.stringify({ baselineRulesSha256: SHA });
const PACKET = Buffer.from(`# Packet\n\n\`\`\`json cv14-pins\n${PINS}\n\`\`\`\n`);
const packetSha = createHash("sha256").update(PACKET).digest("hex");

const gitWithIgnored = (ignored) => async (args) =>
  args[0] === "rev-parse" ? `${GIT}\n` : args.includes("--ignored") ? ignored : "";

/** An admission whose outside effects are all fakes; `over` replaces one of them. */
function admission(over = {}) {
  const calls = [];
  const deps = {
    git: async (args) => {
      calls.push(`git ${args.includes("--ignored") ? "ignored" : args[0]}`);
      if (args[0] === "rev-parse") return `${GIT}\n`;
      return args.includes("--ignored")
        ? "!! conformance/src/rtdb-functions/fixtures/node_modules/\n"
        : "";
    },
    readFile: async (path) => {
      calls.push(`read ${path.split("/").at(-1)}`);
      return path.endsWith("review.md")
        ? `Decision: APPROVE\ngitSha: ${GIT}\npacketSha256: ${packetSha}\n`
        : PACKET;
    },
    requiredSources: async () => calls.push("sources"),
    adcVerdict: async () => (calls.push("adc"), { ok: true }),
    ...over.deps,
  };
  const env = {
    FIREEMU_CV14_REVIEW: `${PRIVATE}/review.md`,
    FIREEMU_CV14_PACKET: `${PRIVATE}/packet.md`,
    ...over.env,
  };
  return {
    run: () => admitRun({ env, privateRoot: PRIVATE, root: over.root ?? "/repo", deps }),
    calls,
  };
}

test("an admission needs private paths, a clean tree, the approval, the pins, the sources and a usable ADC token, in that order", async () => {
  const ok = admission();
  assert.deepEqual(await ok.run(), { gitSha: GIT, packetPins: { baselineRulesSha256: SHA } });
  assert.deepEqual(ok.calls, [
    "git rev-parse",
    "git status",
    "git ignored",
    "read packet.md",
    "read review.md",
    "sources",
    "adc",
  ]);
  const refusals = [
    [{ env: { FIREEMU_CV14_REVIEW: undefined } }, /private review and packet paths/],
    [{ env: { FIREEMU_CV14_PACKET: "/elsewhere/packet.md" } }, /private review and packet paths/],
    [{ env: { FIREEMU_CV14_REVIEW: `${PRIVATE}-x/review.md` } }, /private review and packet paths/],
    [
      {
        deps: {
          git: async (args) =>
            args[0] === "rev-parse" ? `${GIT}\n` : " M conformance/src/rtdb-functions/flow.mjs\n",
        },
      },
      /clean reviewed commit/,
    ],
    [
      { deps: { git: gitWithIgnored("!! conformance/src/rtdb-functions/fixtures/.env.local\n") } },
      /files git does not track: 1 entry/,
    ],
    [
      {
        deps: {
          git: gitWithIgnored(
            "!! conformance/src/rtdb-functions/fixtures/node_modules/\n!! conformance/src/rtdb-functions/fixtures/.env\n",
          ),
        },
      },
      /files git does not track: 1 entry/,
    ],
    [
      {
        deps: {
          git: gitWithIgnored("!! conformance/src/rtdb-functions/fixtures/node_modules/x/\n"),
        },
      },
      /files git does not track/,
    ],
    [
      {
        deps: {
          readFile: async (path) => (path.endsWith("review.md") ? "Decision: APPROVE\n" : PACKET),
        },
      },
      /APPROVE must bind/,
    ],
    [
      {
        deps: {
          readFile: async (path) =>
            path.endsWith("review.md")
              ? `Decision: APPROVE\ngitSha: ${GIT}\npacketSha256: ${SHA}\n`
              : PACKET,
        },
      },
      /APPROVE must bind/,
    ],
    [
      {
        deps: {
          readFile: async (path) =>
            path.endsWith("review.md")
              ? `Decision: APPROVE\ngitSha: ${GIT}\npacketSha256: ${createHash("sha256").update("# no pins").digest("hex")}\n`
              : Buffer.from("# no pins"),
        },
      },
      /packet pins/,
    ],
    [
      {
        deps: {
          requiredSources: async () => {
            throw new Error("reviewed source changed: x");
          },
        },
      },
      /reviewed source changed/,
    ],
    [
      { deps: { adcVerdict: async () => ({ ok: false, reason: "adc-scopes-missing" }) } },
      /ADC token is not usable \(adc-scopes-missing\)/,
    ],
  ];
  for (const [over, message] of refusals) {
    await assert.rejects(() => admission(over).run(), message, JSON.stringify(Object.keys(over)));
  }
  // nothing after the failing step is asked: no ADC token is minted for a tree that is not clean
  const dirty = admission({ deps: { git: async (args) => (args[0] === "rev-parse" ? GIT : "M") } });
  await assert.rejects(() => dirty.run(), /clean reviewed commit/);
  assert.deepEqual(dirty.calls, []);
});

async function rehearseWith(arg, extra = {}) {
  const runDir = await mkdtemp(join(tmpdir(), "cv14-record-"));
  const rehearsal = createRehearsalEnvironment(arg);
  const assembled = [];
  const summary = await executeRun({
    environment: rehearsal.environment,
    runDir,
    packetPins: { baselineRulesSha256: rehearsal.environment.rtdbPacket.baselineRulesSha256 },
    assemble: (options) => {
      const made = assembleStage2(options);
      assembled.push(made);
      return made;
    },
    ...extra,
  });
  return { runDir, summary, assembled, ...rehearsal };
}

test("the project number is masked in every stored file, and a secret-shaped text is refused whatever the list says", async () => {
  const number = "424242424242";
  const w = await rehearseWith({ options: { projectNumber: number, numberInRecord: true } });
  try {
    assert.equal(w.summary.outcome, "recorded", JSON.stringify(w.summary));
    for (const file of await readdir(w.runDir)) {
      if (file === "owned-uploads.jsonl" || file === "journal.jsonl") continue;
      const text = await readFile(join(w.runDir, file), "utf8");
      assert.ok(!text.includes(number), `${file} holds the number`);
    }
    const records = await readFile(join(w.runDir, "records.json"), "utf8");
    assert.ok(records.includes("projects/123456789012/locations"), "the masked number stands in");
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
  for (const leak of [
    "ya29.a0AbCdEfGhIjKlMnOp",
    "AIzaSyA-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "eyJhbGciOiJSUzI1NiIs",
    "Bearer abcdefghijklmnop",
  ]) {
    const refused = await rehearseWith({ options: { secretInRecord: leak } });
    try {
      assert.match(
        JSON.parse(await readFile(join(refused.runDir, "result.json"), "utf8")).reasons.join(";"),
        /output was refused/,
        leak,
      );
    } finally {
      await rm(refused.runDir, { recursive: true, force: true });
    }
  }
});

test("after a deploy the grants are read again, and the upload ledger is closed at the end", async () => {
  const w = await rehearseWith({});
  try {
    const grants = JSON.parse(await readFile(join(w.runDir, "grants.json"), "utf8"));
    assert.notEqual(grants.after, null);
    assert.notEqual(grants.iam.after, null);
    assert.equal(w.assembled.length, 1);
    // a closed ledger takes no further deploy
    await assert.rejects(() => w.assembled[0].uploads.beginDeploy("after-close"), /./u);
  } finally {
    await rm(w.runDir, { recursive: true, force: true });
  }
  const none = await rehearseWith({ options: { loggingState: "DISABLED" } });
  try {
    const grants = JSON.parse(await readFile(join(none.runDir, "grants.json"), "utf8"));
    assert.equal(grants.after, null, "no deploy, no grants read after the run");
  } finally {
    await rm(none.runDir, { recursive: true, force: true });
  }
});

test("both status calls of the admission name the untracked files explicitly, whatever the git config says", async () => {
  const statuses = [];
  const run = admission({
    deps: {
      git: async (args) => {
        if (args[0] === "rev-parse") return `${GIT}\n`;
        statuses.push(args);
        return args.includes("--ignored")
          ? "!! conformance/src/rtdb-functions/fixtures/node_modules/\n"
          : "";
      },
    },
  });
  await run.run();
  assert.equal(statuses.length, 2);
  // the clean-tree call lists every untracked file; the ignored-file call keeps an ignored directory as one entry
  assert.ok(statuses[0].includes("--untracked-files=all"), statuses[0].join(" "));
  assert.ok(statuses[1].includes("--untracked-files=normal"), statuses[1].join(" "));
  assert.ok(statuses[1].includes("--ignored"));
  assert.ok(!statuses[0].includes("--ignored"));
  // an untracked file the first call reports is refused
  const untracked = admission({
    deps: {
      git: async (args) =>
        args[0] === "rev-parse" ? GIT : "?? conformance/src/rtdb-functions/fixtures/.env\n",
    },
  });
  await assert.rejects(() => untracked.run(), /clean reviewed commit/);
});

// ---- admission against real git (a fake that checks for a flag cannot show what git prints) ----

const FIXTURES = "conformance/src/rtdb-functions/fixtures";
const GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.com",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.com",
};
const realGit = (args, cwd) => execFileSync("git", args, { cwd, env: GIT_ENV, encoding: "utf8" });

/** A throwaway repository (no signing configuration: it is not the project) with a committed fixture directory. */
async function fixtureRepo() {
  const root = await mkdtemp(join(tmpdir(), "cv14-git-"));
  realGit(["init", "-q", "."], root);
  await mkdir(join(root, FIXTURES), { recursive: true });
  await writeFile(join(root, ".gitignore"), "node_modules/\n.env\n");
  await writeFile(join(root, FIXTURES, "index.js"), "module.exports = {};\n");
  await writeFile(join(root, FIXTURES, "package.json"), "{}\n");
  realGit(["add", "-A"], root);
  realGit(["commit", "-q", "-m", "fixture"], root);
  return root;
}
const installDependencies = async (root) => {
  for (const name of ["firebase-functions", "firebase-admin"]) {
    const dir = join(root, FIXTURES, "node_modules", name, "lib");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "index.js"), "x\n");
    await writeFile(join(root, FIXTURES, "node_modules", name, "package.json"), "{}\n");
  }
};
const realGitAdmission = (root) =>
  admission({
    root,
    deps: { git: async (args, cwd) => (args[0] === "rev-parse" ? `${GIT}\n` : realGit(args, cwd)) },
  });

test("with real git: an installed node_modules is allowed, an untracked or other ignored fixture file is refused, whatever status.showUntrackedFiles says", async () => {
  const root = await fixtureRepo();
  try {
    await installDependencies(root);
    // many files in an ignored directory: git must show one entry for it
    assert.deepEqual(await realGitAdmission(root).run(), {
      gitSha: GIT,
      packetPins: { baselineRulesSha256: SHA },
    });
    for (const setting of [undefined, "no"]) {
      if (setting) realGit(["config", "status.showUntrackedFiles", setting], root);
      await writeFile(join(root, FIXTURES, "new.js"), "x\n");
      await assert.rejects(
        () => realGitAdmission(root).run(),
        /clean reviewed commit/,
        `untracked, ${setting}`,
      );
      await rm(join(root, FIXTURES, "new.js"));
      await mkdir(join(root, FIXTURES, "sub"), { recursive: true });
      await writeFile(join(root, FIXTURES, "sub", "deep.js"), "x\n");
      await assert.rejects(
        () => realGitAdmission(root).run(),
        /clean reviewed commit/,
        `nested, ${setting}`,
      );
      await rm(join(root, FIXTURES, "sub"), { recursive: true });
      await writeFile(join(root, FIXTURES, ".env"), "SECRET=1\n");
      await assert.rejects(
        () => realGitAdmission(root).run(),
        /files git does not track: 1 entry/,
        `ignored .env, ${setting}`,
      );
      await rm(join(root, FIXTURES, ".env"));
    }
    // and it is allowed again once the stray files are gone
    assert.equal((await realGitAdmission(root).run()).gitSha, GIT);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
