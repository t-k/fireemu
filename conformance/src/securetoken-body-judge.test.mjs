// The judge of the Secure Token body recording: recorded production answers replayed through it,
// near misses of each recorded shape, the merge of two recordings and the comparison with fireemu.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { CONFORMANCE_DIR } from "./config.mjs";
import { ROWS } from "./securetoken-body/corpus.mjs";
import {
  CITATIONS,
  buildReport,
  classifyAnswer,
  compareRow,
  describe,
  mergeRecordings,
  openRuns,
  preflightProblems,
  readRow,
  recentAbort,
  sameClassification,
} from "./securetoken-body/judge.mjs";
import { generator } from "./securetoken-body/test-support.mjs";

const fixture = (name) => JSON.parse(readFileSync(join(CONFORMANCE_DIR, name), "utf8"));
const credential = fixture("auth-credential-production.json");
const tenantFixture = fixture("auth-tenant-blocking-production.json");
const refusals = credential.programs["auth-credential/refresh/refusals"].steps;
const selection = tenantFixture.programs["atb/tenant/selection"].steps;

/** Renames the recorded masks to this recording's accounts, so the shapes are the real ones. */
function asRun(recorded, userId, tenant) {
  let text = JSON.stringify(recorded)
    .replaceAll('"<generated-localId>"', `"${userId}"`)
    .replaceAll('"aa-<run>-a1"', `"${userId}"`);
  if (tenant) text = text.replaceAll(/"<tenant:[^"]*>"/g, '"<tenant>"');
  return JSON.parse(text);
}

const success = (user = "a", tenant = false) =>
  asRun(
    tenant ? selection["refresh-a1"] : refusals["control-still-valid"],
    `stb-<run>-${user}`,
    tenant,
  );

test("replay: the recorded 200 of a project refresh is accepted, citing its program", () => {
  const c = classifyAnswer(success("a"));
  assert.deepEqual(
    { kind: c.kind, user: c.user, tenant: c.tenant },
    { kind: "accepted", user: "a", tenant: false },
  );
  assert.equal(c.cite, CITATIONS.accepted.project);
  assert.match(c.cite, /control-still-valid$/);
});

test("replay: the recorded tenant 200 is accepted as the tenant account", () => {
  const c = classifyAnswer(success("t", true));
  assert.deepEqual(
    { kind: c.kind, user: c.user, tenant: c.tenant },
    { kind: "accepted", user: "t", tenant: true },
  );
  assert.equal(c.cite, CITATIONS.accepted.tenant);
});

test("replay: every recorded 400 of the refusals program is read, or unknown, never guessed", () => {
  const read = {};
  for (const [step, recorded] of Object.entries(refusals)) {
    if (recorded.status !== 400) continue;
    read[step] = classifyAnswer(recorded);
  }
  assert.equal(read["no-refresh-token"].message, "MISSING_REFRESH_TOKEN");
  assert.equal(read["no-grant-type"].message, "MISSING_GRANT_TYPE");
  assert.equal(read["password-grant-type"].message, "INVALID_GRANT_TYPE");
  assert.equal(read["authorization-code-grant-type"].message, "INVALID_GRANT_TYPE");
  assert.equal(read["malformed-refresh-token"].message, "INVALID_REFRESH_TOKEN");
  assert.equal(read["empty-refresh-token"].message, "MISSING_REFRESH_TOKEN");
  assert.equal(read["id-token-as-refresh-token"].message, "INVALID_REFRESH_TOKEN");
  assert.equal(read["truncated-refresh-token"].message, "INVALID_REFRESH_TOKEN");
  assert.equal(read["empty-body"].message, "MISSING_GRANT_TYPE");
  // The API key refusal is a 400 of another shape (details): it is not a refresh answer.
  assert.equal(read["invalid-api-key"].kind, "unknown");
  // Every citation names a recorded step whose message is the one cited.
  for (const c of Object.values(read)) {
    if (c.kind !== "refused") continue;
    const [file, program, step] = c.cite.split("#");
    assert.equal(file, "auth-credential-production.json");
    assert.equal(credential.programs[program].steps[step].body.error.message, c.message);
  }
  for (const [message, cite] of Object.entries(CITATIONS.refused)) {
    const [, program, step] = cite.split("#");
    assert.equal(credential.programs[program].steps[step].body.error.message, message);
  }
  const [, program, step] = CITATIONS.accepted.tenant.split("#");
  assert.equal(tenantFixture.programs[program].steps[step].status, 200);
});

test("replay: the 403 without a key and every non-refresh answer is unknown", () => {
  assert.equal(classifyAnswer(refusals["no-api-key"]).kind, "unknown");
  for (const recorded of [
    { status: 401, body: { error: { code: 401, message: "x", status: "UNAUTHENTICATED" } } },
    {
      status: 429,
      body: {
        error: { code: 429, message: "TOO_MANY_ATTEMPTS_TRY_LATER", status: "RESOURCE_EXHAUSTED" },
      },
    },
    { status: 500, body: { error: { code: 500, message: "x", status: "INTERNAL" } } },
    { status: 302, body: {} },
    { status: 0, transport: "ECONNRESET" },
    { status: 200, nonJson: true },
    undefined,
    null,
  ])
    assert.equal(classifyAnswer(recorded).kind, "unknown");
});

test("near misses of the recorded 200 are unknown", () => {
  const mutate = (change) => {
    const body = structuredClone(success("a").body);
    change(body);
    return { status: 200, body };
  };
  const cases = {
    "an extra key": (b) => (b.scope = "x"),
    "a missing key": (b) => delete b.user_id,
    "another lifetime": (b) => (b.expires_in = "7200"),
    "another token type": (b) => (b.token_type = "bearer"),
    "a refresh token left in clear": (b) => (b.refresh_token = "AMf-abc"),
    "another project": (b) => (b.project_id = "123456789012"),
    "another user": (b) => (b.user_id = "someone-else"),
    "an unsigned token": (b) => (b.id_token["<jwt>"].header.alg = "none"),
    "a token without a key id": (b) => (b.access_token["<jwt>"].header.kid = "<absent>"),
    "a token of another subject": (b) => (b.id_token["<jwt>"].claims.sub = "stb-<run>-b"),
    "a token of another issuer": (b) => (b.id_token["<jwt>"].claims.iss = "https://example.com/x"),
    "a tenant claim on a project user": (b) =>
      (b.id_token["<jwt>"].claims.firebase.tenant = "<tenant>"),
    "an undecodable token": (b) => (b.id_token = "<undecodable-jwt>"),
  };
  for (const [name, change] of Object.entries(cases))
    assert.equal(classifyAnswer(mutate(change)).kind, "unknown", name);
  // The tenant user must carry the tenant claim, and the project user must not.
  const tenant = success("t", true);
  delete tenant.body.id_token["<jwt>"].claims.firebase.tenant;
  assert.equal(classifyAnswer(tenant).kind, "unknown");
});

test("near misses of a recorded 400 are unknown", () => {
  const base = { code: 400, message: "INVALID_REFRESH_TOKEN", status: "INVALID_ARGUMENT" };
  const answer = (error, status = 400) => ({ status, body: { error } });
  assert.equal(classifyAnswer(answer(base)).kind, "refused");
  for (const [name, recorded] of Object.entries({
    "another message": answer({ ...base, message: "TOKEN_EXPIRED" }),
    "a message with a suffix": answer({ ...base, message: "INVALID_REFRESH_TOKEN : x" }),
    "an extra member": answer({ ...base, errors: [] }),
    "another status string": answer({ ...base, status: "FAILED_PRECONDITION" }),
    "another code": answer({ ...base, code: 401 }),
    "an extra top-level key": { status: 400, body: { error: base, extra: 1 } },
    "a 403 with the same body": answer(base, 403),
    "a 404 with the same body": answer(base, 404),
    "a string body": { status: 400, body: "INVALID_REFRESH_TOKEN" },
    "a null error": { status: 400, body: { error: null } },
  }))
    assert.equal(classifyAnswer(recorded).kind, "unknown", name);
});

test("two recordings merge only when both state the same known answer", () => {
  const a = success("a");
  const b = success("b");
  const refused = (message) => ({
    status: 400,
    body: { error: { code: 400, message, status: "INVALID_ARGUMENT" } },
  });
  assert.equal(mergeRecordings([a, a]).kind, "accepted");
  assert.equal(mergeRecordings([a, b]).kind, "unknown");
  assert.match(mergeRecordings([a, b]).why, /recordings differ/);
  assert.equal(
    mergeRecordings([refused("INVALID_REFRESH_TOKEN"), refused("INVALID_REFRESH_TOKEN")]).kind,
    "refused",
  );
  assert.equal(
    mergeRecordings([refused("INVALID_REFRESH_TOKEN"), refused("MISSING_GRANT_TYPE")]).kind,
    "unknown",
  );
  assert.equal(mergeRecordings([a, a, refused("INVALID_GRANT_TYPE")]).kind, "unknown");
  assert.equal(mergeRecordings([a, { status: 0, transport: "x" }]).kind, "unknown");
  assert.equal(mergeRecordings([{ status: 500 }, a]).kind, "unknown");
  assert.equal(mergeRecordings([]).kind, "unknown");
  assert.equal(mergeRecordings([a]).kind, "accepted");
});

test("property: merge is order-independent and an unknown anywhere makes the row unknown", () => {
  const rng = generator(0xbeef);
  const answers = [
    success("a"),
    success("b"),
    success("t", true),
    {
      status: 400,
      body: { error: { code: 400, message: "MISSING_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
    },
    {
      status: 400,
      body: { error: { code: 400, message: "INVALID_REFRESH_TOKEN", status: "INVALID_ARGUMENT" } },
    },
    { status: 0, transport: "ETIMEDOUT" },
    { status: 500, body: {} },
  ];
  for (let round = 0; round < 400; round += 1) {
    const set = Array.from({ length: 1 + rng.int(3) }, () => rng.pick(answers));
    const shuffled = [...set].toSorted(() => rng.next() - 0.5);
    const merged = mergeRecordings(set);
    const other = mergeRecordings(shuffled);
    assert.equal(merged.kind, other.kind);
    if (merged.kind !== "unknown") assert.ok(sameClassification(merged, other));
    const kinds = set.map((s) => classifyAnswer(s));
    if (kinds.some((k) => k.kind === "unknown")) assert.equal(merged.kind, "unknown");
    if (merged.kind !== "unknown") assert.ok(kinds.every((k) => sameClassification(k, merged)));
  }
});

test("readRow names the spelling that won when a row offers two accounts", () => {
  const both = ROWS.find((r) => r.id === "json-both-tokens-camel-first");
  assert.equal(
    readRow(both, classifyAnswer(success("a"))),
    "accepted; the snake_case token was used",
  );
  assert.equal(
    readRow(both, classifyAnswer(success("b"))),
    "accepted; the camelCase token was used",
  );
  assert.match(readRow(both, classifyAnswer(success("t", true))), /no field named/);
  const single = ROWS.find((r) => r.id === "json-camel");
  assert.equal(readRow(single, classifyAnswer(success("a"))), "accepted as a");
  assert.match(readRow(single, { kind: "unknown", why: "x" }), /^unknown: x/);
});

test("compareRow: agrees, differs, unknown and no-claim", () => {
  const acc = classifyAnswer(success("a"));
  const ref = classifyAnswer({
    status: 400,
    body: { error: { code: 400, message: "MISSING_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  });
  const unk = { kind: "unknown", why: "x" };
  assert.equal(compareRow(acc, acc), "agrees");
  assert.equal(compareRow(acc, ref), "differs");
  assert.equal(compareRow(ref, classifyAnswer(success("t", true))), "differs");
  assert.equal(compareRow(unk, acc), "unknown");
  assert.equal(compareRow(acc, unk), "unknown");
  assert.equal(compareRow(undefined, acc), "no-claim");
  assert.equal(describe(acc), "accepted as a");
});

test("buildReport pairs production with fireemu row by row and keeps unknowns unknown", () => {
  const prod = { rows: Object.fromEntries(ROWS.map((r) => [r.id, success("a")])) };
  prod.rows["json-camel"] = {
    status: 400,
    body: { error: { code: 400, message: "MISSING_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  };
  prod.rows["form-camel"] = { status: 500 };
  const local = { rows: Object.fromEntries(ROWS.map((r) => [r.id, success("a")])) };
  const report = Object.fromEntries(
    buildReport({ productionRecordings: [prod, prod], localRecordings: [local] }).map((r) => [
      r.row,
      r,
    ]),
  );
  assert.equal(report["json-camel"].status, "differs");
  assert.equal(report["form-camel"].status, "unknown");
  assert.equal(report["json-snake"].status, "agrees");
  assert.equal(buildReport({ localRecordings: [local] })[0].status, "no-claim");
  assert.equal(buildReport({ productionRecordings: [prod] })[0].fireemu, undefined);
});

test("ledger helpers: a recent abort, open runs of others, and the preflight problems", () => {
  const now = Date.parse("2026-11-08T12:00:00Z");
  const line = (o) => `${JSON.stringify(o)}\n`;
  const ended = line({
    ts: "2026-11-08T11:30:00Z",
    taskId: "SECURETOKEN-BODY",
    outcome: "aborted-fatal",
  });
  assert.equal(recentAbort(ended, now)?.outcome, "aborted-fatal");
  assert.equal(recentAbort(ended, now + 2 * 3_600_000), undefined);
  assert.equal(
    recentAbort(
      line({ ts: "2026-11-08T11:30:00Z", taskId: "SECURETOKEN-BODY", outcome: "recorded" }),
      now,
    ),
    undefined,
  );
  assert.equal(
    recentAbort(line({ ts: "2026-11-08T11:30:00Z", taskId: "OTHER", outcome: "aborted" }), now),
    undefined,
  );
  assert.equal(recentAbort("not json\n", now), undefined);
  const started = line({
    ts: "2026-11-08T11:00:00Z",
    event: "started",
    taskId: "OTHER",
    project: "p",
  });
  assert.deepEqual(openRuns(started, "p", now), ["OTHER"]);
  assert.deepEqual(openRuns(started, "q", now), []);
  assert.deepEqual(
    openRuns(
      started +
        line({ ts: "2026-11-08T11:10:00Z", taskId: "OTHER", project: "p", outcome: "recorded" }),
      "p",
      now,
    ),
    [],
  );
  assert.deepEqual(openRuns(started, "p", now + 7 * 3_600_000), []);
  const clean = {
    failedReads: [],
    projectAccounts: 0,
    tenants: 0,
    passwordEnabled: true,
    openRuns: [],
  };
  assert.deepEqual(preflightProblems(clean), []);
  assert.equal(preflightProblems({ ...clean, projectAccounts: 2 }).length, 1);
  assert.equal(preflightProblems({ ...clean, projectAccounts: -1 }).length, 1);
  assert.equal(preflightProblems({ ...clean, tenants: 1 }).length, 1);
  assert.equal(preflightProblems({ ...clean, passwordEnabled: false }).length, 1);
  assert.equal(preflightProblems({ ...clean, openRuns: ["X"] }).length, 1);
  assert.equal(preflightProblems({ ...clean, failedReads: ["config (HTTP 403)"] }).length, 1);
});

test("an unknown answer says why, in the words of the first check it fails", () => {
  const ok = () => structuredClone(success("a").body);
  const with200 = (change) => {
    const body = ok();
    change(body);
    return { status: 200, body };
  };
  const refusal = (error) => ({ status: 400, body: { error } });
  const cases = [
    [undefined, "no answer"],
    [null, "no answer"],
    [{ status: 0, transport: "ETIMEDOUT" }, "transport failure"],
    [{ status: 200, transport: "ETIMEDOUT", body: ok() }, "transport failure"],
    [{ status: 0 }, "transport failure"],
    [{ status: 200, nonJson: true }, "non-JSON body"],
    [{ status: "200", body: ok() }, "no readable answer"],
    [{ status: 200 }, "no readable answer"],
    [{ body: ok() }, "no readable answer"],
    [{ status: 200, body: null }, "200 without an object body"],
    [{ status: 200, body: "x" }, "200 without an object body"],
    [{ status: 200, body: [] }, "200 without an object body"],
    [
      with200((b) => (b.extra = 1)),
      "200 with keys access_token,expires_in,extra,id_token,project_id,refresh_token,token_type,user_id",
    ],
    [with200((b) => (b.expires_in = "1")), "200 with another lifetime or token type"],
    [with200((b) => (b.token_type = "x")), "200 with another lifetime or token type"],
    [with200((b) => (b.refresh_token = "x")), "200 without a refresh token"],
    [with200((b) => (b.project_id = "x")), "200 naming another project"],
    [with200((b) => (b.user_id = "x")), "200 for an account this run did not create"],
    [with200((b) => (b.user_id = "stb-<run>-z")), "200 for an account this run did not create"],
    [with200((b) => (b.user_id = "xstb-<run>-a")), "200 for an account this run did not create"],
    [with200((b) => (b.user_id = "stb-<run>-ab")), "200 for an account this run did not create"],
    [with200((b) => (b.id_token = "x")), "200 with a token of another shape"],
    [with200((b) => (b.id_token = { "<jwt>": null })), "200 with a token of another shape"],
    [with200((b) => (b.id_token = { "<jwt>": "x" })), "200 with a token of another shape"],
    [with200((b) => (b.id_token = { other: 1 })), "200 with a token of another shape"],
    [with200((b) => (b.access_token = "x")), "200 with a token of another shape"],
    [
      with200((b) => (b.id_token["<jwt>"].header.alg = "HS256")),
      "200 with a token of another shape",
    ],
    [with200((b) => (b.id_token["<jwt>"].header.typ = "x")), "200 with a token of another shape"],
    [
      with200((b) => (b.id_token["<jwt>"].header.kid = "<absent>")),
      "200 with a token of another shape",
    ],
    [
      with200((b) => (b.id_token["<jwt>"].signature = "<absent>")),
      "200 with a token of another shape",
    ],
    [
      with200((b) => (b.access_token["<jwt>"].claims.aud = "x")),
      "200 with a token that names another subject or project",
    ],
    [
      with200((b) => (b.id_token["<jwt>"].claims.user_id = "stb-<run>-b")),
      "200 with a token that names another subject or project",
    ],
    [
      with200((b) => (b.id_token["<jwt>"].claims.firebase.tenant = "<tenant>")),
      "200 with a tenant claim that does not match the account",
    ],
    [refusal(null), "400 with a body of another shape"],
    [
      refusal({ code: 400, message: "X", status: "INVALID_ARGUMENT", more: 1 }),
      "400 with a body of another shape",
    ],
    [refusal({ code: 400, message: "X" }), "400 with a body of another shape"],
    [
      refusal({ code: 401, message: "X", status: "INVALID_ARGUMENT" }),
      "400 with a body of another shape",
    ],
    [
      {
        status: 400,
        body: { error: { code: 400, message: "X", status: "INVALID_ARGUMENT" }, e: 1 },
      },
      "400 with a body of another shape",
    ],
    [
      refusal({ code: 400, message: "X", status: "INVALID_ARGUMENT" }),
      "400 with a message no recording shows: X",
    ],
    [{ status: 403, body: {} }, "status 403 is not a recorded refresh answer"],
    [{ status: 500, body: {} }, "status 500 is not a recorded refresh answer"],
  ];
  for (const [recorded, why] of cases) {
    const c = classifyAnswer(recorded);
    assert.equal(c.kind, "unknown", why);
    assert.equal(c.why, why);
  }
  // Only the first 80 characters of an unseen message are quoted.
  const long = classifyAnswer(
    refusal({ code: 400, message: "M".repeat(200), status: "INVALID_ARGUMENT" }),
  );
  assert.equal(long.why, `400 with a message no recording shows: ${"M".repeat(80)}`);
  // A 200 and a 400 that are exactly the recorded shapes are not unknown.
  assert.equal(classifyAnswer({ status: 200, body: ok() }).kind, "accepted");
});

test("sameClassification and mergeRecordings state their edges", () => {
  const rawA = success("a");
  const rawB = success("b");
  const rawR1 = {
    status: 400,
    body: { error: { code: 400, message: "INVALID_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  };
  const rawR2 = {
    status: 400,
    body: { error: { code: 400, message: "MISSING_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  };
  const a = classifyAnswer(rawA);
  const b = classifyAnswer(rawB);
  const t = classifyAnswer(success("t", true));
  const r1 = classifyAnswer({
    status: 400,
    body: { error: { code: 400, message: "INVALID_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  });
  const r2 = classifyAnswer({
    status: 400,
    body: { error: { code: 400, message: "MISSING_GRANT_TYPE", status: "INVALID_ARGUMENT" } },
  });
  const unk = { kind: "unknown", why: "x" };
  assert.equal(sameClassification(a, a), true);
  assert.equal(sameClassification(a, b), false);
  assert.equal(sameClassification(a, t), false);
  assert.equal(sameClassification(r1, r1), true);
  assert.equal(sameClassification(r1, r2), false);
  assert.equal(sameClassification(a, r1), false);
  assert.equal(sameClassification(r1, a), false);
  assert.equal(sameClassification(unk, unk), false);
  assert.equal(sameClassification({ ...unk }, { kind: "unknown", why: "x" }), false);
  assert.deepEqual(mergeRecordings([]), { kind: "unknown", why: "not recorded" });
  assert.equal(mergeRecordings([rawA, rawA, rawA]).kind, "accepted");
  assert.match(
    mergeRecordings([rawA, rawB]).why,
    /^recordings differ \(accepted as a \/ accepted as b\)$/,
  );
  assert.match(
    mergeRecordings([rawR1, rawR2]).why,
    /^recordings differ \(refused INVALID_GRANT_TYPE \/ refused MISSING_GRANT_TYPE\)$/,
  );
  assert.equal(describe(r1), "refused INVALID_GRANT_TYPE");
  assert.equal(describe(unk), "unknown (x)");
});

test("the digests are sha-256 of the sources and the ledger cost is a pure function of the count", async () => {
  const { sha256, harnessDigest, HARNESS_FILES, estimatedUsd } =
    await import("./securetoken-body/judge.mjs");
  assert.equal(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const read = async (file) => `<${file}>`;
  const digest = await harnessDigest(read);
  assert.equal(digest, sha256(HARNESS_FILES.map((f) => `<${f}>`).join("\n")));
  const changed = await harnessDigest(async (file) =>
    file.endsWith("judge.mjs") ? "x" : `<${file}>`,
  );
  assert.notEqual(changed, digest);
  assert.ok(
    HARNESS_FILES.includes("securetoken-body/judge.mjs") &&
      HARNESS_FILES.includes("shared/ownership.mjs"),
  );
  assert.equal(estimatedUsd(0), 0.01);
  assert.equal(estimatedUsd(94), 0.0102);
});

test("the harness digest covers exactly the sources the recording runs, read from disk", async () => {
  const { sha256, harnessDigest, HARNESS_FILES } = await import("./securetoken-body/judge.mjs");
  assert.deepEqual(HARNESS_FILES, [
    "securetoken-body/corpus.mjs",
    "securetoken-body/harness.mjs",
    "securetoken-body/judge.mjs",
    "securetoken-body/session.mjs",
    "securetoken-body/record.mjs",
    "securetoken-body/recording.mjs",
    "securetoken-body/preflight.mjs",
    "auth-account/harness.mjs",
    "auth-credential/tokens.mjs",
    "shared/ownership.mjs",
  ]);
  const sources = HARNESS_FILES.map((file) =>
    readFileSync(join(CONFORMANCE_DIR, "src", file), "utf8"),
  );
  assert.equal(await harnessDigest(), sha256(sources.join("\n")));
  assert.match(await harnessDigest(), /^[0-9a-f]{64}$/);
});

test("a first recording that is unknown decides the row before the others are read", () => {
  const rawA = success("a");
  const merged = mergeRecordings([{ status: 0, transport: "x" }, rawA]);
  assert.deepEqual(merged, { kind: "unknown", why: "transport failure" });
  assert.deepEqual(mergeRecordings([{ status: 500, body: {} }, rawA, rawA]), {
    kind: "unknown",
    why: "status 500 is not a recorded refresh answer",
  });
});

test("a report with no local recording has nothing to compare, and keeps the production reading", () => {
  const prod = { rows: Object.fromEntries(ROWS.map((r) => [r.id, success("a")])) };
  const report = buildReport({ productionRecordings: [prod] });
  assert.equal(report.length, ROWS.length);
  for (const r of report) {
    assert.equal(r.status, "no-claim");
    assert.equal(r.fireemu, undefined);
    assert.ok(typeof r.production === "string");
    assert.equal(r.question, ROWS.find((x) => x.id === r.row).question);
  }
  assert.equal(report.find((r) => r.row === "json-camel").cite, CITATIONS.accepted.project);
});

test("the one-hour and six-hour windows of the ledger helpers include their last millisecond only", () => {
  const line = (o) => `${JSON.stringify(o)}\n`;
  const at = (ms) => new Date(ms).toISOString();
  const t0 = Date.parse("2026-11-08T08:00:00Z");
  const end = line({ ts: at(t0), taskId: "SECURETOKEN-BODY", outcome: "needs-recovery" });
  assert.ok(recentAbort(end, t0 + 3_600_000 - 1));
  assert.equal(recentAbort(end, t0 + 3_600_000), undefined);
  assert.equal(recentAbort(end, t0 + 3_600_001), undefined);
  assert.ok(recentAbort(end, t0));
  const started = line({ ts: at(t0), event: "started", taskId: "OTHER", project: "p" });
  assert.deepEqual(openRuns(started, "p", t0 + 6 * 3_600_000 - 1), ["OTHER"]);
  assert.deepEqual(openRuns(started, "p", t0 + 6 * 3_600_000), []);
  assert.deepEqual(openRuns(started, "p", t0 + 7 * 3_600_000), []);
  // Own runs, runs without a task, and other projects never count; the last line of a task decides.
  const noise =
    line({ ts: at(t0), event: "started", taskId: "SECURETOKEN-BODY", project: "p" }) +
    line({ ts: at(t0), event: "started", project: "p" }) +
    line({ ts: at(t0), event: "started", taskId: "ELSEWHERE", project: "q" });
  assert.deepEqual(openRuns(noise, "p", t0 + 1000), []);
  const two = started + line({ ts: at(t0), event: "started", taskId: "THIRD", project: "p" });
  assert.deepEqual(openRuns(two, "p", t0 + 1000).toSorted(), ["OTHER", "THIRD"]);
  assert.deepEqual(
    openRuns(
      two + line({ ts: at(t0 + 10), taskId: "THIRD", project: "p", outcome: "recorded" }),
      "p",
      t0 + 1000,
    ),
    ["OTHER"],
  );
});

test("each preflight problem is stated in its own words", () => {
  const clean = {
    failedReads: [],
    projectAccounts: 0,
    tenants: 0,
    passwordEnabled: true,
    openRuns: [],
  };
  assert.deepEqual(
    preflightProblems({ ...clean, failedReads: ["config (HTTP 403)", "accounts (HTTP 0)"] }),
    ["preflight read failed: config (HTTP 403)", "preflight read failed: accounts (HTTP 0)"],
  );
  assert.deepEqual(preflightProblems({ ...clean, projectAccounts: 2 }), [
    "2 project-level account(s) exist",
  ]);
  assert.deepEqual(preflightProblems({ ...clean, tenants: 3 }), ["3 tenant(s) exist"]);
  assert.deepEqual(preflightProblems({ ...clean, passwordEnabled: false }), [
    "email/password sign-in is not enabled",
  ]);
  assert.deepEqual(preflightProblems({ ...clean, openRuns: ["A", "B"] }), [
    "runs still open: A, B",
  ]);
});
