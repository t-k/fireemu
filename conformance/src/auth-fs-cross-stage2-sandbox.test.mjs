import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  acquireProjectLocks,
  closingLines,
  covers,
  DECLARED_PROJECTS,
  destinationProblem,
  keyRestrictionProblems,
  packetApproval,
  recordingProblems,
  releaseProjectLock,
  SANDBOX_PROJECT,
  startedLine,
  TASK_ID,
} from "./auth-fs-cross/stage2-sandbox.mjs";

const PACKET = "a".repeat(64);
const COMMIT = "b".repeat(40);
const HARNESS = "c".repeat(64);
const RUNNER = { project: SANDBOX_PROJECT, maxRequests: 900, reserveUsd: 1 };
const pins = `packetSha256=${PACKET}; sourceCommit=${COMMIT}; harnessDigest=${HARNESS}`;
const envelope = (extra = "") =>
  `- 2026-09-29 | AUTH-FS-CROSS stage-2 packet envelope | envelopeId=AUTH-FS-CROSS-stage-2-packet-1; project=${SANDBOX_PROJECT}; maxRequests=1000; reserveUsd=2; writes=run-owned; iamConfig=none; retries=none${extra} | オーナー（Claude経由） | docs.local/x.md`;
const delegated = (id = "AUTH-FS-CROSS-stage-2-packet-1") =>
  `- 2026-09-29 | AUTH-FS-CROSS stage-2 packet | decision=APPROVE; envelopeId=${id}; ${pins} | Claude（委任。枠の内の承認し直し） | docs.local/p.md`;
const owned = `- 2026-09-29 | AUTH-FS-CROSS stage-2 packet | decision=APPROVE; ${pins} | オーナー（直接） | docs.local/p.md`;
const approve = (text, runner = RUNNER) =>
  packetApproval(text, {
    packetSha256: PACKET,
    sourceCommit: COMMIT,
    harnessDigest: HARNESS,
    runner,
  });

test("a stage-2 run may reach only the declared project on the harness hosts", () => {
  assert.deepEqual(DECLARED_PROJECTS, ["fireemu-oracle-idp"]);
  for (const url of [
    `https://identitytoolkit.googleapis.com/v1/projects/${SANDBOX_PROJECT}/accounts:query`,
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/(default)/documents:commit`,
    `https://securetoken.googleapis.com/v1/token?key=k`,
    `https://firebaserules.googleapis.com/v1/projects/${SANDBOX_PROJECT}/releases`,
  ])
    assert.equal(destinationProblem(url), null, url);
  assert.match(
    destinationProblem(
      "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:lookup",
    ),
    /undeclared project fireemu-oracle-query/,
  );
  assert.match(
    destinationProblem(
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/x:signJwt",
    ),
    /undeclared host/,
  );
  assert.match(
    destinationProblem(`https://iam.googleapis.com/v1/projects/-/serviceAccounts/x:getIamPolicy`),
    /undeclared project -/,
  );
  assert.match(
    destinationProblem(`https://firestore.googleapis.com/v1/projects%2Ffireemu-35fe6/databases`),
    /undeclared project fireemu-35fe6/,
  );
  assert.match(
    destinationProblem(`http://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}`),
    /not https/,
  );
  assert.match(destinationProblem("https://evil.example/v1"), /undeclared host evil.example/);
  assert.match(destinationProblem("::"), /not a URL/);
});

test("an owner line or an envelope with its delegated line approves; anything else does not", () => {
  assert.equal(approve(owned).approval.kind, "owner");
  const byEnvelope = approve(`${envelope()}\n${delegated()}`);
  assert.equal(byEnvelope.approval.kind, "envelope");
  assert.equal(byEnvelope.approval.envelopeId, "AUTH-FS-CROSS-stage-2-packet-1");
  for (const [name, text, runner] of [
    ["nothing", "", RUNNER],
    ["a delegated line without its envelope", delegated(), RUNNER],
    ["a delegated line before its envelope", `${delegated()}\n${envelope()}`, RUNNER],
    ["a delegated line of another envelope", `${envelope()}\n${delegated("other-1")}`, RUNNER],
    [
      "an envelope of another project",
      `${envelope().replace(`project=${SANDBOX_PROJECT}`, "project=fireemu-oracle-query")}\n${delegated()}`,
      RUNNER,
    ],
    [
      "an envelope under the runner's request cap",
      `${envelope()}\n${delegated()}`,
      { ...RUNNER, maxRequests: 1001 },
    ],
    [
      "an envelope under the runner's reserve",
      `${envelope()}\n${delegated()}`,
      { ...RUNNER, reserveUsd: 2.5 },
    ],
    [
      "an envelope written by someone else",
      `${envelope().replace("オーナー（Claude経由）", "Claude（委任）")}\n${delegated()}`,
      RUNNER,
    ],
    ["a version line of another commit", owned.replace(COMMIT, "d".repeat(40)), RUNNER],
    ["a version line of another harness", owned.replace(HARNESS, "e".repeat(64)), RUNNER],
    [
      "a version line that declines",
      owned.replace("decision=APPROVE", "decision=REQUEST_CHANGES"),
      RUNNER,
    ],
    ["a line of stage 1", owned.replace("stage-2 packet", "stage-1 packet"), RUNNER],
    [
      "a revoked version",
      `${owned}\n- 2026-09-30 | AUTH-FS-CROSS stage-2 packet | REVOKED ${PACKET} | オーナー（直接） | -`,
      RUNNER,
    ],
    [
      "a revoked envelope",
      `${envelope()}\n${delegated()}\n- 2026-09-30 | AUTH-FS-CROSS stage-2 packet envelope | REVOKED envelopeId=AUTH-FS-CROSS-stage-2-packet-1 | オーナー（直接） | -`,
      RUNNER,
    ],
  ])
    assert.deepEqual(approve(text, runner).problems.length, 1, name);
  // A revocation before the approval withdraws nothing that came after it.
  assert.equal(
    approve(
      `- 2026-09-28 | AUTH-FS-CROSS stage-2 packet | REVOKED ${PACKET} | オーナー（直接） | -\n${owned}`,
    ).approval.kind,
    "owner",
  );
  assert.equal(
    covers({ project: SANDBOX_PROJECT, maxRequests: "1e9", reserveUsd: "5" }, RUNNER),
    false,
  );
});

const ledgerLine = (entry) =>
  JSON.stringify({
    taskId: TASK_ID,
    stage: 2,
    packetSha256: PACKET,
    project: SANDBOX_PROJECT,
    ts: "2026-09-29T00:00:00Z",
    ...entry,
  });

test("recording 1 starts once, recording 2 only after recording 1 ended recorded at baseline", () => {
  assert.deepEqual(recordingProblems("", PACKET, 1), []);
  assert.match(recordingProblems("", PACKET, 3)[0], /not 1 or 2/);
  assert.match(recordingProblems("", PACKET, 2)[0], /recording 1 of this packet did not end/);
  const started = ledgerLine({ event: "started", recording: 1 });
  assert.match(
    recordingProblems(started, PACKET, 1)[0],
    /recording 1 of this packet already started/,
  );
  assert.equal(recordingProblems(started, PACKET, 2).length, 1);
  const finished = `${started}\n${ledgerLine({ event: "finished", recording: 1, outcome: "recorded", sandboxAtBaseline: true })}`;
  assert.deepEqual(recordingProblems(finished, PACKET, 2), []);
  const aborted = `${started}\n${ledgerLine({ event: "finished", recording: 1, outcome: "aborted", sandboxAtBaseline: true })}`;
  assert.equal(recordingProblems(aborted, PACKET, 2).length, 1);
  const recovering = `${started}\n${ledgerLine({ event: "needs-recovery", recording: 1, sandboxAtBaseline: false })}`;
  assert.equal(recordingProblems(recovering, PACKET, 2).length, 1);
  assert.deepEqual(
    recordingProblems(finished.replaceAll(PACKET, "f".repeat(64)), PACKET, 2).length,
    1,
  );
  const twice = `${finished}\n${ledgerLine({ event: "started", recording: 2 })}`;
  assert.match(
    recordingProblems(twice, PACKET, 2)[0],
    /recording 2 of this packet already started/,
  );
});

test("the ledger lines name the stage, the recording and only the declared project", () => {
  const locks = [{ sha256: "1".repeat(64) }];
  const started = startedLine({
    ts: "t",
    sha: COMMIT,
    packetSha256: PACKET,
    recording: 2,
    programDigest: "p",
    locks,
    approval: { kind: "envelope", envelopeId: "E-1" },
    reserveUsd: 1,
  });
  assert.deepEqual(
    [
      started.event,
      started.project,
      started.stage,
      started.recording,
      started.envelopeId,
      started.maxEstimatedUsd,
    ],
    ["started", SANDBOX_PROJECT, 2, 2, "E-1", 1],
  );
  const counts = { requests: 5, estimatedUsd: 0.1 };
  const ok = closingLines({
    ts: "t",
    sha: COMMIT,
    recording: 1,
    programDigest: "p",
    outcome: "recorded",
    atBaseline: true,
    counts,
  });
  assert.deepEqual(
    ok.map((l) => [l.event, l.outcome, l.sandboxAtBaseline, l.project]),
    [["finished", "recorded", true, SANDBOX_PROJECT]],
  );
  const aborted = closingLines({
    ts: "t",
    sha: COMMIT,
    recording: 1,
    programDigest: "p",
    outcome: "aborted",
    atBaseline: true,
    counts,
  });
  assert.deepEqual(
    aborted.map((l) => l.event),
    ["finished", "cleanup-verified"],
  );
  const off = closingLines({
    ts: "t",
    sha: COMMIT,
    recording: 1,
    programDigest: "p",
    outcome: "aborted",
    atBaseline: false,
    counts,
    error: "x",
  });
  assert.deepEqual(
    off.map((l) => [l.event, l.sandboxAtBaseline, l.error]),
    [["needs-recovery", false, "x"]],
  );
});

async function scratch() {
  const dir = await mkdtemp(join(tmpdir(), "afc2-locks-"));
  return {
    dir,
    lockDir: join(dir, "sandbox-locks"),
    legacyLock: join(dir, "sandbox-ledger.jsonl.lock"),
  };
}

test("locks are taken in ascending order, all or none, and never over another lock", async () => {
  const { dir, lockDir, legacyLock } = await scratch();
  try {
    const body = {
      taskId: TASK_ID,
      packetId: PACKET,
      sourceCommit: COMMIT,
      pid: 1,
      acquiredAt: "t",
    };
    const locks = await acquireProjectLocks({
      lockDir,
      legacyLock,
      projects: ["b-project", "a-project"],
      body,
    });
    assert.deepEqual(
      locks.map((l) => l.project),
      ["a-project", "b-project"],
    );
    assert.equal((await stat(lockDir)).mode & 0o777, 0o700);
    assert.equal((await stat(locks[0].path)).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(await readFile(locks[0].path, "utf8")), body);
    // Another project's lock does not stop a run; the same project's does.
    const other = await acquireProjectLocks({ lockDir, legacyLock, projects: ["c-project"], body });
    await assert.rejects(
      acquireProjectLocks({ lockDir, legacyLock, projects: ["d-project", "b-project"], body }),
      /the lock of b-project is held/,
    );
    // The refused call left nothing of its own: d-project was never reached, b-project is intact.
    assert.deepEqual((await readdir(lockDir)).toSorted(), [
      "a-project.lock",
      "b-project.lock",
      "c-project.lock",
    ]);
    await assert.rejects(
      acquireProjectLocks({ lockDir, legacyLock, projects: ["a0-project", "b-project"], body }),
      /held/,
    );
    assert.deepEqual((await readdir(lockDir)).toSorted(), [
      "a-project.lock",
      "b-project.lock",
      "c-project.lock",
    ]);
    for (const lock of [...locks, ...other]) await releaseProjectLock(lock);
    assert.deepEqual(await readdir(lockDir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the legacy shared lock stops a run, and a lock that changed is left in place", async () => {
  const { dir, lockDir, legacyLock } = await scratch();
  try {
    const body = { taskId: TASK_ID };
    await writeFile(legacyLock, "{}");
    await assert.rejects(
      acquireProjectLocks({ lockDir, legacyLock, projects: ["a-project"], body }),
      /legacy shared lock is held/,
    );
    await rm(legacyLock);
    const [lock] = await acquireProjectLocks({
      lockDir,
      legacyLock,
      projects: ["a-project"],
      body,
    });
    await writeFile(lock.path, '{"taskId":"someone-else"}');
    await assert.rejects(releaseProjectLock(lock), /rewritten; left in place/);
    await rm(lock.path);
    await writeFile(lock.path, JSON.stringify(body));
    await assert.rejects(releaseProjectLock(lock), /replaced; left in place/);
    assert.deepEqual(await readdir(lockDir), ["a-project.lock"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the API keys read passes only when no key has an application restriction", () => {
  const target = { restrictions: { apiTargets: [{ service: "firestore.googleapis.com" }] } };
  assert.deepEqual(keyRestrictionProblems({ status: 200, json: { keys: [target, {}] } }), []);
  assert.deepEqual(keyRestrictionProblems({ status: 200, json: {} }), []);
  for (const restriction of [
    "browserKeyRestrictions",
    "serverKeyRestrictions",
    "androidKeyRestrictions",
    "iosKeyRestrictions",
  ])
    assert.deepEqual(
      keyRestrictionProblems({
        status: 200,
        json: { keys: [target, { displayName: "k", restrictions: { [restriction]: {} } }] },
      }),
      ["API key k has an application restriction"],
      restriction,
    );
  assert.deepEqual(keyRestrictionProblems({ status: 403, json: null }), [
    "API keys read failed (HTTP 403)",
  ]);
  assert.deepEqual(
    keyRestrictionProblems({ status: 200, json: { keys: [], nextPageToken: "n" } }),
    ["API keys read has more than one page"],
  );
  assert.equal(
    destinationProblem(
      `https://apikeys.googleapis.com/v2/projects/${SANDBOX_PROJECT}/locations/global/keys`,
    ),
    null,
  );
  assert.match(
    destinationProblem(
      "https://apikeys.googleapis.com/v2/projects/fireemu-oracle-query/locations/global/keys",
    ),
    /undeclared project/,
  );
});
