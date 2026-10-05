import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { channelDelete, channelLifecycle } from "./eventarc-production/cases/channels.mjs";
import { CASES } from "./eventarc-production/cases/index.mjs";
import { authErrors } from "./eventarc-production/cases/errors.mjs";
import {
  publishContent,
  publishEnvelope,
  publishLimits,
} from "./eventarc-production/cases/publish.mjs";
import { adminSdkPublish } from "./eventarc-production/cases/sdk.mjs";
import { preconditions } from "./eventarc-production/cases/service.mjs";
import { createProbe } from "./eventarc-production/cases/create-probe.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { createShapeRefusal, createWorld } from "./eventarc-production/testing/world.mjs";
import { ledgerFacts } from "./eventarc-production/cleanup.mjs";
import { runCases } from "./eventarc-production/runner.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";
const NOT_FOUND = { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
const OPERATION = `projects/${PROJECT}/locations/us-central1/operations/op-1`;

/**
 * A channel service with long-running operations: an operation is done after `doneAfter` reads, a name
 * can be made to exist beforehand (`existing`), refuse a creation (`refuse`), end its operation with an
 * error (`failWith`), or have its deletion answered unknown or never finish.
 */
function channelService({
  existing = [],
  refuse = new Set(),
  failWith = new Map(),
  unknownDelete = false,
  deleteNeverDone = false,
  deleteError = undefined,
  deleteNoEffect = false,
  deleteLate = false,
  deleteBadAnswer = false,
  doneAfter = 1,
  createNeverDone = false,
  duplicate409 = false,
  createInvisible = false,
  createUnknown = false,
  createAppears = false,
} = {}) {
  const live = new Set(existing);
  const accepted = new Set();
  const calls = [];
  const operations = new Map();
  const shapeRefusals = [];
  return {
    live,
    calls,
    shapeRefusals,
    async request(call) {
      const { method, path, op } = call;
      calls.push({
        method,
        path,
        op,
        caseId: call.label?.case,
        body: call.body,
        token: call.token,
        quotaProject: call.quotaProject,
      });
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      if (op === "getOperation") {
        const state = operations.get(bare) ?? { reads: 0, error: undefined };
        state.reads += 1;
        operations.set(bare, state);
        const done = state.pending ? false : state.reads >= doneAfter;
        return {
          status: 200,
          body: { name: bare, done, ...(done && state.error ? { error: state.error } : {}) },
          unknown: false,
        };
      }
      if (op === "listChannels") return { status: 200, body: {}, unknown: false };
      if (op === "publishEvents") return { status: 200, body: {}, unknown: false };
      if (op === "getChannel") {
        if (live.has(bare)) return { status: 200, body: { name: bare }, unknown: false };
        if (/channels\/(GOOG|a[0-9]$)/.test(bare))
          return { status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false };
        return NOT_FOUND;
      }
      if (op === "createChannel") {
        // Production refuses a body without the channel's full name: so does this service.
        const shape = createShapeRefusal(call);
        if (shape !== null) {
          shapeRefusals.push(shape.kind);
          return { ...shape.answer, unknown: false };
        }
        const id = new URL(`http://x${path}`).searchParams.get("channelId");
        const name = `${path.split("?")[0].replace(/^\/v1\//, "")}/${id}`;
        // An answer that does not say what was done (a 503); the channel may or may not have appeared.
        if (createUnknown) {
          if (createAppears) live.add(name);
          return { status: 503, body: {}, unknown: true };
        }
        // A name that cannot exist is refused, as it is read (400).
        if (refuse.has(id) || /^(GOOG|a[0-9a-f]$)/.test(id))
          return { status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false };
        // A creation of a name that exists ends with ALREADY_EXISTS inside its operation, or is answered 409.
        const existed = live.has(name) || accepted.has(name);
        if (existed && duplicate409)
          return { status: 409, body: { error: { status: "ALREADY_EXISTS" } }, unknown: false };
        // An operation that never finishes, with a name of its own.
        if (createNeverDone && !existed) {
          accepted.add(name);
          const own = `${OPERATION}-create-${id}`;
          operations.set(own, { reads: 0, pending: true });
          if (!createInvisible) live.add(name);
          return { status: 200, body: { name: own, done: false }, unknown: false };
        }
        operations.set(OPERATION, {
          reads: 0,
          error: failWith.get(id) ?? (existed ? { code: 6 } : undefined),
        });
        if (!existed && !failWith.has(id) && !createInvisible) live.add(name);
        return { status: 200, body: { name: OPERATION, done: false }, unknown: false };
      }
      if (op === "deleteChannel") {
        if (unknownDelete) {
          live.delete(bare);
          return { status: 503, body: {}, unknown: true };
        }
        // An unknown answer is not trusted even if its body looks like a finished operation.
        if (deleteBadAnswer) {
          live.delete(bare);
          return { status: 503, body: { name: OPERATION, done: true }, unknown: true };
        }
        if (!live.has(bare)) return NOT_FOUND;
        operations.set(OPERATION, {
          reads: 0,
          pending: deleteNeverDone || deleteLate,
          error: deleteError,
        });
        if ((!deleteNeverDone || deleteLate) && !deleteNoEffect) live.delete(bare);
        return { status: 200, body: { name: OPERATION, done: false }, unknown: false };
      }
      throw new Error(`unexpected ${method} ${path}`);
    },
  };
}

async function run(
  service,
  { runId = RUN, cases = [channelLifecycle], makeSdk = null, usageProject = PROJECT, scopedToken, sleep } = {},
) {
  const ownership = createOwnership({ project: PROJECT, runId });
  const ledger = createLedger();
  const notes = [];
  const capture = createCapture({ journal: { write: (entry) => notes.push(entry) } });
  const transport = { name: "rest", request: (call) => service.request(call) };
  const cleanupClient = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
    ledger,
  });
  const summary = await runCases({
    cases,
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient,
    ownership,
    capture,
    options: {
      production: false,
      location: "us-central1",
      usageProject,
      publishPrefix: "/v1",
    },
    sleep: sleep ?? (async () => {}),
    ledger,
    makeSdk,
    ...(scopedToken === undefined ? {} : { scopedToken }),
  });
  return { summary, ledger, notes, ownership };
}

const ledgerFactsOf = (ledger, name) => ledgerFacts(ledger.state().get(name));
const posts = (service) =>
  service.calls.filter((call) => call.method === "POST").map((call) => call.path);
const deletes = (service, suffix) =>
  service.calls.filter((call) => call.method === "DELETE" && call.path.endsWith(suffix));
/** The deletions the case itself sent (cleanup is a separate step with its own rules). */
const caseDeletes = (service, suffix) =>
  deletes(service, suffix).filter((call) => call.caseId !== "cleanup");

const P1 = `fe${RUN}-cp-p1`;
const nameOf = (id) => `projects/${PROJECT}/locations/us-central1/channels/${id}`;

test("the create probe creates a channel with its name, reads it, lists it, deletes it, polls every operation, and sends the second deletion only after the recorded 404", async () => {
  const service = channelService();
  const { summary, ledger } = await run(service, { cases: [createProbe] });
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
  assert.deepEqual(service.shapeRefusals, [], "every creation carried the channel's name");
  assert.equal(deletes(service, P1).length, 2, "the deletion and its repetition after the read-back");
  const name = nameOf(P1);
  assert.deepEqual(ledger.state().get(name).creates, [`unknown@${OPERATION}`, `ok@${OPERATION}`]);
  assert.ok(ledger.state().get(name).deletes.includes(`ok@${OPERATION}`));
  // Every creation and deletion that was accepted had its operation read.
  assert.ok(service.calls.filter((call) => call.op === "getOperation").length >= 2);
  assert.deepEqual(summary.cleanup.unsettled, []);
  // The order the plan names: read, create, read, list, list, delete, read back, second delete.
  assert.deepEqual(
    service.calls.filter((call) => call.caseId === "create-probe").map((call) => call.op),
    [
      "getChannel",
      "createChannel",
      "getOperation",
      "getChannel",
      "listChannels",
      "listChannels",
      "deleteChannel",
      "getOperation",
      "getChannel",
      "deleteChannel",
    ],
  );
});

test("a creation that is refused or not confirmed stops the whole run cleanly: no other case is sent, and the cleanup still runs", async () => {
  for (const [label, options] of [
    ["refused", { refuse: new Set([P1]) }],
    ["its operation ends with an error", { failWith: new Map([[P1, { code: 13 }]]) }],
    ["its operation never finishes", { createNeverDone: true }],
  ]) {
    const service = channelService(options);
    const { summary } = await run(service, { cases: [createProbe, channelLifecycle] });
    assert.deepEqual(
      summary.cases.map((c) => [c.id, c.outcome]),
      [["create-probe", "stopped"]],
      label,
    );
    assert.match(summary.stopped, /nothing else is created/, label);
    assert.equal(
      service.calls.some((call) => call.caseId === "channel-lifecycle"),
      false,
      label,
    );
    assert.equal(
      service.calls.filter((call) => call.caseId === "create-probe" && call.method === "DELETE").length,
      0,
      `${label}: nothing is deleted by the case`,
    );
    assert.notEqual(summary.cleanup, null, label);
  }
});

test("an unknown create is never settled by a 404: the case stops, the cleanup reads the name, and only a positive read of it settles", async () => {
  // The answer to the creation is a 503: unknown. The channel did appear, so the cleanup's read shows it.
  const present = channelService({ createUnknown: true, createAppears: true });
  const first = await run(present, { cases: [createProbe] });
  assert.equal(first.summary.cases[0].outcome, "stopped");
  const name = nameOf(P1);
  assert.ok(ledgerFactsOf(first.ledger, name).mayExist);
  assert.ok(first.summary.cleanup.settled.some((item) => item.name === name && item.how === "deleted"));
  assert.equal(present.live.has(name), false);
  // Near miss: the channel never shows, only 404s: the name stays unsettled and unconfirmed.
  const absent = channelService({ createUnknown: true });
  const second = await run(absent, { cases: [createProbe] });
  assert.ok(second.summary.cleanup.unsettled.includes(name));
  assert.ok(second.summary.cleanup.unconfirmed.includes(name));
  assert.ok(!second.summary.cleanup.settled.some((item) => item.name === name));
  assert.equal(deletes(absent, P1).length, 0, "nothing is deleted on a 404");
});

test("a confirmed create whose channel then reads 404 in the run is not settled, and a 409 from a later request settles nothing", async () => {
  // The creation is confirmed by its operation, yet the channel reads 404 (a lag, or a channel that is
  // gone): the case stops, and the cleanup cannot settle it from a 404 in the same run.
  const lagging = channelService({ createInvisible: true });
  const { summary, ledger } = await run(lagging, { cases: [createProbe] });
  const name = nameOf(P1);
  assert.ok(ledger.state().get(name).creates.includes(`ok@${OPERATION}`));
  assert.ok(summary.cleanup.unsettled.includes(name), "stays open until the A2 read-back");
  assert.ok(!summary.cleanup.settled.some((item) => item.name === name));
  assert.equal(deletes(lagging, P1).length, 0);
  // A duplicate answered 409 does not settle an earlier unknown creation either (lifecycle).
  const service = channelService({ duplicate409: true });
  const duplicated = await run(service);
  const c1 = nameOf(`fe${RUN}-cl-c1`);
  assert.ok(duplicated.ledger.state().get(c1).creates.includes(`ok@${OPERATION}`));
  assert.equal(service.shapeRefusals.length, 0);
});

test("the lifecycle creates two channels, follows the pages of a list, and deletes nothing itself", async () => {
  const service = channelService();
  const { summary, ledger } = await run(service);
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
  assert.deepEqual(service.shapeRefusals, []);
  const c1 = `fe${RUN}-cl-c1`;
  assert.equal(caseDeletes(service, c1).length, 0, "the cleanup deletes them");
  assert.equal(deletes(service, c1).length, 1, "once, by the cleanup");
  assert.ok(ledger.state().get(nameOf(c1)).creates.includes(`ok@${OPERATION}`));
  assert.ok(
    ledger.state().get(nameOf(c1)).creates.some((kind) => kind === `conflict@${OPERATION}`),
    "the repetition of the creation ended with a conflict in its operation",
  );
  assert.deepEqual(summary.cleanup.unsettled, []);
});

test("V2-M1(a) replayed: a duplicate whose own operation ends with ALREADY_EXISTS never settles another creation, and the first creation stays confirmed", async () => {
  const service = channelService();
  const { summary, ledger } = await run(service);
  const name = nameOf(`fe${RUN}-cl-c1`);
  const creates = ledger.state().get(name).creates;
  assert.deepEqual(
    creates.filter((kind) => kind.startsWith("ok@")),
    [`ok@${OPERATION}`],
  );
  assert.ok(creates.some((kind) => kind === `conflict@${OPERATION}`));
  assert.ok(summary.cleanup.settled.some((item) => item.name === name && item.how === "deleted"));
});

test("V2-M1(b) replayed: a deletion whose operation is never read as done and a 404 afterwards stay unsettled in the recording", async () => {
  const name = nameOf(P1);
  const { summary, ledger } = await run(channelService({ deleteLate: true }), { cases: [createProbe] });
  assert.ok(ledgerFactsOf(ledger, name).deletePending);
  assert.deepEqual(
    summary.cleanup.settled.filter((item) => item.name === name),
    [],
  );
  assert.ok(summary.cleanup.unsettled.includes(name));
  // Near miss: an operation read as done settles by the 404 as before.
  const finished = await run(channelService(), { cases: [createProbe] });
  assert.ok(finished.summary.cleanup.settled.some((item) => item.name === name));
  assert.ok(!finished.summary.cleanup.unsettled.includes(name));
});

test("the probes are derived from the run, differ between runs, and are read before they are created", async () => {
  const first = channelService();
  await run(first);
  const second = channelService();
  await run(second, { runId: "fedcba987654" });
  const probes = (service, runId) =>
    posts(service)
      .map((path) => new URL(`http://x${path}`).searchParams.get("channelId"))
      .filter((id) => id && !id.startsWith(`fe${runId}-`));
  assert.deepEqual(probes(first, RUN), [
    `GOOG-${RUN.toUpperCase()}`,
    `a${RUN[0]}`,
    `goog-${RUN}`,
    `1-${RUN}`,
    `bad_${RUN}`,
    `nowhere-${RUN}`,
  ]);
  assert.deepEqual(probes(second, "fedcba987654"), [
    "GOOG-FEDCBA987654",
    "af",
    "goog-fedcba987654",
    "1-fedcba987654",
    "bad_fedcba987654",
    "nowhere-fedcba987654",
  ]);
  // The long probe carries the prefix and is 64 characters.
  const long = posts(first)
    .map((path) => new URL(`http://x${path}`).searchParams.get("channelId"))
    .find((id) => id?.length === 64);
  assert.ok(long.startsWith(`fe${RUN}-`));
  // Each probe is read just before its creation.
  for (const id of [`GOOG-${RUN.toUpperCase()}`, `goog-${RUN}`, `1-${RUN}`, `bad_${RUN}`]) {
    const read = first.calls.findIndex(
      (call) => call.op === "getChannel" && call.path.endsWith(`/${id}`),
    );
    const create = first.calls.findIndex(
      (call) => call.op === "createChannel" && call.path.includes(`channelId=${id}`),
    );
    assert.ok(read >= 0 && create > read, id);
  }
});

test("a probe that exists is not the run's: it is not created, not ledgered, and never deleted", async () => {
  const name = nameOf(`goog-${RUN}`);
  const service = channelService({ existing: [name] });
  const { ledger, notes } = await run(service);
  assert.equal(
    posts(service).some((path) => path.includes(`channelId=goog-${RUN}`)),
    false,
  );
  assert.equal(ledger.state().has(name), false);
  assert.ok(notes.some((n) => n.note === "probe-exists" && n.name === name));
  assert.equal(service.live.has(name), true);
  assert.equal(
    service.calls.some((call) => call.method === "DELETE" && call.path.endsWith(`goog-${RUN}`)),
    false,
  );
});

test("a probe whose operation ends with ALREADY_EXISTS is a conflict: it is never deleted, though a 2xx answered the creation", async () => {
  const id = `1-${RUN}`;
  const name = nameOf(id);
  const service = channelService({
    failWith: new Map([[id, { code: 6, message: "exists" }]]),
    existing: [],
  });
  service.live.add(name); // someone else's channel with that name appears after the read
  const reads = service.request.bind(service);
  let seen = false;
  service.request = async (call) => {
    // The first read of the probe does not see it yet (it was created in the meantime).
    if (call.op === "getChannel" && call.path.endsWith(`/${id}`) && !seen) {
      seen = true;
      return NOT_FOUND;
    }
    return reads(call);
  };
  const { ledger, summary } = await run(service);
  assert.deepEqual(ledger.state().get(name).creates, [
    `unknown@${OPERATION}`,
    `conflict@${OPERATION}`,
  ]);
  assert.equal(
    service.calls.some((call) => call.method === "DELETE" && call.path.endsWith(`/${id}`)),
    false,
  );
  assert.equal(service.live.has(name), true);
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
});

test("after an unknown first deletion, or one whose operation never finishes, no second deletion is sent", async () => {
  const unknown = channelService({ unknownDelete: true });
  await run(unknown, { cases: [createProbe] });
  assert.equal(deletes(unknown, P1).length, 1, "the first deletion only");
  const stuck = channelService({ deleteNeverDone: true });
  const { ledger } = await run(stuck, { cases: [createProbe] });
  assert.equal(deletes(stuck, P1).length, 1);
  assert.deepEqual(
    ledger.state().get(nameOf(P1)).deletes.slice(0, 2),
    [`unknown@${OPERATION}`, `unknown@${OPERATION}`],
    "the 2xx and the operation that was not done",
  );
});

test("a creation of the lifecycle that is refused stops that case with its reason, and nothing that needs the channel is sent", async () => {
  const c1 = `fe${RUN}-cl-c1`;
  const service = channelService({ refuse: new Set([c1]) });
  const { summary, ledger, notes } = await run(service);
  assert.deepEqual(
    summary.cases.map((c) => [c.outcome, c.reason]),
    [["aborted", "the creation of c1 did not succeed (INVALID_ARGUMENT)"]],
  );
  assert.ok(notes.some((n) => n.note === "channel-not-confirmed" && n.status === 400));
  assert.equal(deletes(service, c1).length, 0);
  assert.deepEqual(
    ledger
      .state()
      .get(nameOf(c1))
      .creates.filter((kind) => kind.startsWith("ok")),
    [],
  );
  assert.deepEqual(
    service.calls.filter((call) => call.caseId === "channel-lifecycle").map((call) => call.op),
    ["createChannel"],
    "only the refused creation was sent",
  );
});

test("a case that needs a channel never sends to a name it did not create (publish, SDK, errors)", async () => {
  for (const item of [publishEnvelope, publishContent, publishLimits, adminSdkPublish, authErrors]) {
    const service = channelService({ refuse: new Set(["fe0123456789ab-x"]), createNeverDone: true });
    const makeSdk = async () => ({
      publish: async () => assert.fail("the SDK was used"),
      close: async () => {},
    });
    const { summary } = await run(service, { cases: [item], makeSdk });
    assert.equal(summary.cases[0].outcome, "aborted", item.id);
    assert.equal(
      service.calls.some((call) => call.op === "publishEvents"),
      false,
      item.id,
    );
  }
});

test("the default channel is published to only after the recorded JSON 404: a text 404 or an existing channel opens nothing", async () => {
  const firebase = nameOf("firebase");
  for (const [reply, opened] of [
    [NOT_FOUND, true],
    [{ status: 404, body: { raw: "Not Found" }, unknown: false }, false],
    [{ status: 200, body: { name: firebase }, unknown: false }, false],
  ]) {
    const service = channelService();
    const handler = service.request.bind(service);
    service.request = async (call) =>
      call.op === "getChannel" && call.path.endsWith("/channels/firebase") ? reply : handler(call);
    const published = [];
    const makeSdk = async () => ({
      publish: async (spec) => (published.push(spec), { threw: false, requests: 0, suppressed: 0 }),
      close: async () => {},
    });
    const { ownership } = await run(service, { cases: [adminSdkPublish], makeSdk });
    const names = published.map((spec) => spec.channel);
    const defaultCall = published.filter((spec) => spec.channel === undefined);
    assert.equal(defaultCall.length, opened ? 1 : 0, JSON.stringify(reply));
    if (opened) assert.doesNotThrow(() => ownership.assertPublishable(firebase));
    else assert.throws(() => ownership.assertPublishable(firebase), /refusing to publish/);
    assert.equal(names.length >= 5, true);
  }
});

test("the preconditions stop the run, with nothing created, unless the publishing API is ENABLED; the default channel is only read", async () => {
  for (const [state, stops] of [
    ["ENABLED", false],
    ["DISABLED", true],
    ["STATE_UNSPECIFIED", true],
    [undefined, true],
  ]) {
    const calls = [];
    const service = {
      request: async (call) => {
        calls.push(call);
        if (call.op === "getService") return { status: 200, body: { state }, unknown: false };
        return NOT_FOUND;
      },
    };
    const { summary, notes } = await run(service, { cases: [preconditions, createProbe] });
    assert.deepEqual(
      summary.cases.map((c) => c.outcome),
      stops ? ["stopped"] : ["completed", "stopped"],
      String(state),
    );
    assert.deepEqual(
      calls.filter((call) => call.method !== "GET" && (stops || call.label.case === "preconditions")),
      [],
      "the preconditions send nothing that changes anything, and nothing follows a refusal",
    );
    assert.equal(
      calls.some((call) => call.op === "enableService"),
      false,
    );
    if (!stops)
      assert.ok(notes.some((n) => n.note === "default-channel" && n.absent === true && n.status === 404));
  }
});

test("the second deletion needs every condition: the first answered, its operation done without an error, and the recorded 404 read back", async () => {
  for (const [label, options] of [
    ["an unknown answer whose body looks finished", { deleteBadAnswer: true }],
    ["an operation done with an error, the channel gone", { deleteError: { code: 13 } }],
    ["an operation done, the channel still there", { deleteNoEffect: true }],
    ["an operation never done, the channel gone", { deleteLate: true }],
  ]) {
    const service = channelService(options);
    await run(service, { cases: [createProbe] });
    assert.equal(caseDeletes(service, P1).length, 1, `${label}: the first deletion only`);
    const other = channelService(options);
    await run(other, { cases: [channelDelete] });
    assert.equal(caseDeletes(other, `fe${RUN}-cd-d1`).length, 1, `${label} (delete case)`);
  }
  // Every condition met: both are sent.
  const service = channelService();
  await run(service, { cases: [createProbe, channelDelete] });
  assert.equal(caseDeletes(service, P1).length, 2);
  assert.equal(caseDeletes(service, `fe${RUN}-cd-d1`).length, 2);
});

test("the delete case reads the channel back, lists, publishes to the name after the deletion, and deletes nothing it did not create", async () => {
  const service = channelService();
  const { summary } = await run(service, { cases: [channelDelete] });
  assert.equal(summary.cases[0].outcome, "completed");
  const ops = service.calls.filter((call) => call.caseId === "channel-delete").map((call) => call.op);
  const afterDelete = ops.slice(ops.indexOf("deleteChannel"));
  assert.deepEqual(afterDelete, [
    "deleteChannel",
    "getOperation",
    "getChannel",
    "listChannels",
    "publishEvents",
    "deleteChannel",
  ]);
  // d2 is deleted by the cleanup, with the same rules.
  assert.equal(deletes(service, `fe${RUN}-cd-d2`).length, 1);
});

const published = (service) =>
  service.calls.filter((call) => call.op === "publishEvents").map((call) => call.body.events ?? []);

test("the case ceilings are the ones the plan was measured against, in the order the cases run", () => {
  assert.deepEqual(
    CASES.map(({ id, requests }) => [id, requests]),
    [
      ["preconditions", 3],
      ["create-probe", 31],
      ["channel-lifecycle", 134],
      ["channel-delete", 41],
      ["publish-envelope", 42],
      ["publish-content", 31],
      ["publish-limits", 40],
      ["admin-sdk-publish", 31],
      ["auth-errors", 36],
    ],
  );
});

test("the content case sends the bytes 0, 1, 2, 255 as base64, and the envelope case a member the service does not know", async () => {
  const service = channelService();
  await run(service, { cases: [publishContent, publishEnvelope] });
  const events = published(service).flat();
  const binary = events.filter(
    (event) => event.binaryData !== undefined && event.binaryData !== "***not base64***",
  );
  const decoded = binary.map((event) => Array.from(Buffer.from(event.binaryData, "base64")));
  assert.deepEqual(decoded[0], [0, 1, 2, 255]);
  assert.equal(decoded.length, 2, "the second is the event that has both text and binary data");
  assert.deepEqual(
    events.filter((event) => "noSuchMember" in event).map((event) => event.noSuchMember),
    [1],
  );
});

test("the envelope case adds the handler-side checks of an existing channel: a duplicate id in one request, a bare event, every attribute kind", async () => {
  const service = channelService();
  await run(service, { cases: [publishEnvelope] });
  const requests = published(service);
  const duplicated = requests.find((events) => events.length === 2 && events[0].id === events[1].id);
  assert.ok(duplicated, "the same id twice in one request");
  assert.ok(requests.some((events) => events.length === 1 && Object.keys(events[0]).length === 1));
  const kinds = requests
    .flat()
    .flatMap((event) => Object.values(event.attributes ?? {}).flatMap((value) => Object.keys(value)));
  for (const kind of ["ceBoolean", "ceInteger", "ceUri", "ceUriRef", "ceBytes", "ceString", "ceTimestamp"])
    assert.ok(kinds.includes(kind), kind);
});

test("a channel that cannot exist is never listed, in the lifecycle and in the errors case, and the lists use the page sizes of the plan", async () => {
  for (const [item, name] of [
    [channelLifecycle, "nowhere"],
    [authErrors, "nowhere-pub"],
  ]) {
    const service = channelService();
    await run(service, { cases: [item] });
    const lists = service.calls.filter((call) => call.op === "listChannels");
    assert.equal(
      lists.some((call) => call.path.includes("no-such-location1")),
      false,
      name,
    );
  }
  const service = channelService();
  await run(service, { cases: [channelLifecycle] });
  const lists = service.calls
    .filter((call) => call.op === "listChannels" && call.caseId === "channel-lifecycle")
    .map((call) => call.path);
  for (const tail of [
    "/locations/us-central1/channels?pageSize=1",
    "/locations/us-central1/channels?pageSize=2",
    "/locations/-/channels?pageSize=5",
    "/locations/europe-west1/channels",
    "/locations/us-east99/channels",
  ])
    assert.ok(
      lists.some((path) => path.endsWith(tail)),
      tail,
    );
});

test("the limits are searched, not assumed: against a model with any limit the boundary is pinned within the plan's requests", async () => {
  let seed = 3;
  const next = (n) => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed % n;
  };
  for (let round = 0; round < 12; round += 1) {
    const eventLimit = 9 + next(300);
    const textLimit = 3 + next(5 * 1024 * 1024);
    const world = createWorld({ project: PROJECT, eventLimit, textLimit });
    const { summary, notes } = await run(world, { cases: [publishLimits] });
    assert.equal(summary.cases[0].outcome, "completed", `${eventLimit} ${textLimit}`);
    const boundary = (name) => notes.find((n) => n.note === "limit-boundary" && n.name === name);
    const bracket = (name) => notes.find((n) => n.note === "limit-bracket" && n.name === name);
    // The count: the largest accepted is the limit, unless the ladder never reached a refusal.
    const count = boundary("event-count") ?? bracket("event-count");
    if (eventLimit >= 256) assert.equal(bracket("event-count").high, null);
    else {
      assert.equal(count.accepted, eventLimit, `event limit ${eventLimit}`);
      assert.equal(count.refused, eventLimit + 1);
    }
    const size = boundary("event-text-length") ?? bracket("event-text-length");
    if (size.high === null) assert.ok(textLimit >= 4 * 1024 * 1024);
    else {
      // The text sent is the string with its quotes: a text of N characters is accepted when N - 2 <= limit.
      assert.ok(size.accepted - 2 <= textLimit && size.refused - 2 > textLimit, `${textLimit}`);
      const { low, high } = bracket("event-text-length");
      assert.ok(size.refused - size.accepted <= Math.ceil((high - low) / 1024), "ten halvings");
    }
  }
});

test("the project number is used in a path only when the run was given one, for reads only, and the case never writes it anywhere else", async () => {
  const none = channelService();
  await run(none);
  assert.equal(
    none.calls.some((call) => /\/projects\/\d+\//.test(call.path)),
    false,
  );
  const given = channelService();
  await run(given, { usageProject: "123456789012" });
  const numbered = given.calls.filter((call) => /\/projects\/123456789012\//.test(call.path));
  assert.deepEqual(
    numbered.map((call) => [call.method, call.op]),
    [
      ["GET", "listChannels"],
      ["GET", "getChannel"],
    ],
    "one list and one read, nothing that changes anything",
  );
});

test("the credential probes: each token mode and the quota project of one call reach the transport by name, and a wrong-scope token only when one can be had", async () => {
  const modes = async (scopedToken) => {
    const service = channelService();
    const { notes } = await run(service, { cases: [authErrors], scopedToken });
    return { calls: service.calls, notes };
  };
  const calls = (await modes(async () => null)).calls;
  const sent = (call) => call.token ?? "default";
  const tokenCalls = calls.filter((call) => call.caseId === "auth-errors" && ["listChannels", "publishEvents"].includes(call.op));
  assert.deepEqual(
    [...new Set(tokenCalls.map(sent))].filter((mode) => mode !== "default"),
    ["none", "invalid", "ya29-garbage", "jwt-garbage", "jwt-expired-unsigned"],
  );
  const stub = await modes(async (scope) => {
    assert.equal(scope, "https://www.googleapis.com/auth/userinfo.email");
    return "ya29.stub-token-of-the-narrow-scope";
  });
  assert.ok(stub.calls.some((call) => call.token?.label === "wrong-scope"));
  const quota = stub.calls.filter((call) => call.quotaProject !== undefined);
  assert.deepEqual(
    quota.map((call) => [call.op, call.quotaProject]),
    [
      ["listChannels", "fireemu-no-such-project-0"],
      ["publishEvents", "fireemu-no-such-project-0"],
    ],
  );
  assert.equal(
    stub.notes.some((n) => n.note === "wrong-scope-skipped"),
    false,
  );
  assert.ok((await modes(async () => null)).notes.some((n) => n.note === "wrong-scope-skipped"));
});

test("the count ladder pins the recorded boundary exactly: 255 events accepted, 256 refused, in two requests beyond the first", async () => {
  const world = createWorld({ project: PROJECT });
  const { notes } = await run(world, { cases: [publishLimits] });
  const boundary = notes.find((n) => n.note === "limit-boundary" && n.name === "event-count");
  assert.deepEqual(
    [boundary.accepted, boundary.refused, boundary.steps, boundary.unknown],
    [255, 256, 0, false],
  );
  const counts = world.calls
    .filter((call) => call.op === "publishEvents")
    .map((call) => call.body.events.length);
  assert.deepEqual(counts.slice(0, 3), [8, 255, 256], "the ladder, in order, and nothing else");
});

test("a limit search that gets an answer that does not say stops there and sends nothing again", async () => {
  const world = createWorld({ project: PROJECT });
  const unreadable = async (call) => {
    const answer = await world.request(call);
    return call.op === "publishEvents" && call.body.events.length === 255
      ? { status: 503, body: {}, unknown: true }
      : answer;
  };
  const { notes } = await run({ request: unreadable, calls: world.calls, live: new Set() }, { cases: [publishLimits] });
  const bracket = notes.find((n) => n.note === "limit-bracket" && n.name === "event-count");
  assert.deepEqual([bracket.low, bracket.high, bracket.unknown], [8, null, true]);
  assert.equal(
    notes.some((n) => n.note === "limit-boundary" && n.name === "event-count"),
    false,
  );
  const sent = world.calls
    .filter((call) => call.op === "publishEvents")
    .map((call) => call.body.events.length);
  assert.equal(sent.filter((count) => count === 255).length, 1, "the 255 is not asked twice");
  assert.equal(sent.includes(256), false);
});

test("a case that publishes waits for its channel to read ACTIVE (a few reads, three seconds apart), records the state it ends with, and goes on whatever it is", async () => {
  const sleeps = [];
  const reads = (service, name) =>
    service.calls.filter(
      (call) =>
        call.op === "getChannel" && call.caseId === "publish-envelope" && call.path.endsWith(`/${name}`),
    );
  const cases = { channel: `fe${RUN}-pe-env`, item: publishEnvelope };
  // No state member: one read, nothing to wait for.
  const none = createWorld({ project: PROJECT });
  const first = await run(none, { cases: [cases.item] });
  assert.equal(reads(none, cases.channel).length, 1);
  assert.deepEqual(
    first.notes.filter((n) => n.note === "channel-state").map((n) => n.state ?? null),
    [null],
  );
  // PENDING for two reads: three reads, the publishes only after the third.
  const slow = createWorld({ project: PROJECT, withState: true, pendingReads: 2 });
  const second = await run(slow, { cases: [cases.item], sleep: async (ms) => sleeps.push(ms) });
  assert.equal(reads(slow, cases.channel).length, 3);
  assert.deepEqual(sleeps, [3000, 3000]);
  const lastRead = slow.calls.findLastIndex(
    (call) => call.op === "getChannel" && call.caseId === "publish-envelope",
  );
  const firstPublish = slow.calls.findIndex((call) => call.op === "publishEvents");
  assert.ok(lastRead < firstPublish, "no publish before the channel read ACTIVE");
  assert.deepEqual(
    second.notes.filter((n) => n.note === "channel-state").map((n) => n.state),
    ["ACTIVE"],
  );
  // PENDING for good: five reads at most, the case goes on and records PENDING.
  const stuck = createWorld({ project: PROJECT, withState: true, stuckPending: true });
  const third = await run(stuck, { cases: [cases.item] });
  assert.equal(reads(stuck, cases.channel).length, 5);
  assert.equal(third.summary.cases[0].outcome, "completed");
  assert.deepEqual(
    third.notes.filter((n) => n.note === "channel-state").map((n) => n.state),
    ["PENDING"],
  );
});

const listPathsOf = (service, caseId) =>
  service.calls.filter((call) => call.op === "listChannels" && call.caseId === caseId).map((call) => call.path);

test("the lifecycle follows the pages of a list one token at a time and stops after three pages", async () => {
  // Two channels of the run: the page of one has a token, the second page has none.
  const two = createWorld({ project: PROJECT });
  await run(two);
  const pages = listPathsOf(two, "channel-lifecycle").filter((path) => /pageSize=1(&|$)/.test(path));
  assert.equal(pages.length, 2);
  assert.ok(pages[0].endsWith("channels?pageSize=1"), "the first page carries no token");
  assert.match(pages[1], /channels\?pageSize=1&pageToken=[A-Za-z0-9_-]+$/);
  // Many channels: never more than three pages, and each token is the one the page before returned.
  const existing = Array.from({ length: 8 }, (_, i) => nameOf(`other-${i}`));
  const many = createWorld({ project: PROJECT, existing });
  await run(many);
  const long = listPathsOf(many, "channel-lifecycle").filter((path) => /pageSize=1(&|$)/.test(path));
  assert.equal(long.length, 3, "three pages at most");
  const tokens = long.slice(1).map((path) => new URL(`http://x${path}`).searchParams.get("pageToken"));
  assert.equal(new Set(tokens).size, 2, "each page asks for a different token");
  // A token that is not a non-empty string ends the list.
  const odd = channelService();
  const handler = odd.request.bind(odd);
  for (const token of ["", 5, null]) {
    odd.calls.length = 0;
    odd.request = async (call) => {
      const answer = await handler(call);
      return call.op === "listChannels" && call.path.includes("pageSize=1")
        ? { status: 200, body: { nextPageToken: token }, unknown: false }
        : answer;
    };
    await run(odd);
    assert.equal(listPathsOf(odd, "channel-lifecycle").filter((path) => /pageSize=1(&|$)/.test(path)).length, 1, String(token));
  }
  // A page that is not a 2xx ends the list too, whatever its body says.
  odd.request = async (call) => {
    const answer = await handler(call);
    return call.op === "listChannels" && call.path.includes("pageSize=1")
      ? { status: 503, body: { nextPageToken: "x" }, unknown: true }
      : answer;
  };
  odd.calls.length = 0;
  await run(odd);
  assert.equal(listPathsOf(odd, "channel-lifecycle").filter((path) => /pageSize=1(&|$)/.test(path)).length, 1);
});

test("a probe is created only after the recorded 404 or a 400, never after another refusal or an unknown read", async () => {
  const id = `1-${RUN}`;
  for (const [label, reply, created] of [
    ["the recorded 404", NOT_FOUND, true],
    ["a 400", { status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false }, true],
    ["a 403", { status: 403, body: { error: { status: "PERMISSION_DENIED" } }, unknown: false }, false],
    ["a 500", { status: 500, body: { error: { status: "INTERNAL" } }, unknown: false }, false],
    ["an unknown 400", { status: 400, body: {}, unknown: true }, false],
    ["an unknown 503", { status: 503, body: {}, unknown: true }, false],
  ]) {
    const service = channelService();
    const handler = service.request.bind(service);
    service.request = async (call) =>
      call.op === "getChannel" && call.path.endsWith(`/${id}`) ? reply : handler(call);
    const { notes } = await run(service);
    const sent = service.calls.some((call) => call.op === "createChannel" && call.path.includes(`channelId=${id}`));
    assert.equal(sent, created, label);
    if (!created) assert.ok(notes.some((n) => n.note === "probe-read-unclear" && n.name === nameOf(id)), label);
  }
});

test("the number path is not read when no number was given, and the paths never name a missing number", async () => {
  const service = channelService();
  await run(service);
  assert.equal(
    service.calls.some((call) => /\/projects\/(null|undefined|\d+)\//.test(call.path)),
    false,
  );
  const listsOfTheProject = service.calls.filter(
    (call) => call.op === "listChannels" && call.caseId === "channel-lifecycle" && call.path.startsWith(`/v1/projects/${PROJECT}/`),
  );
  assert.ok(listsOfTheProject.length >= 6);
});

test("the create probe's list is a page of one, and a refused creation leaves its note", async () => {
  const service = channelService();
  await run(service, { cases: [createProbe] });
  const lists = listPathsOf(service, "create-probe");
  assert.equal(lists.length, 2);
  assert.ok(lists[0].endsWith("/channels"), "the first list has no page size");
  assert.ok(lists[1].endsWith("/channels?pageSize=1"));
  const refused = channelService({ refuse: new Set([P1]) });
  const { notes } = await run(refused, { cases: [createProbe] });
  assert.ok(notes.some((n) => n.note === "create-probe-refused" && n.status === 400));
});

test("the preconditions note the state they read, and a channel's state is only a state when the read answered", async () => {
  const service = {
    request: async (call) =>
      call.op === "getService"
        ? { status: 200, body: { state: "ENABLED" }, unknown: false }
        : NOT_FOUND,
  };
  const { notes } = await run(service, { cases: [preconditions] });
  assert.ok(notes.some((n) => n.note === "service-state" && n.state === "ENABLED"));
  // A read that is not a 2xx but whose body has a `state` is no state: one read, nothing waited for.
  const flaky = channelService();
  const handler = flaky.request.bind(flaky);
  flaky.request = async (call) =>
    call.op === "getChannel" && call.caseId === undefined && call.label?.case === "publish-envelope"
      ? { status: 503, body: { state: "PENDING" }, unknown: true }
      : handler(call);
  const sleeps = [];
  const result = await run(flaky, { cases: [publishEnvelope], sleep: async (ms) => sleeps.push(ms) });
  assert.deepEqual(sleeps, []);
  assert.deepEqual(
    result.notes.filter((n) => n.note === "channel-state").map((n) => n.state),
    [null],
  );
});

test("the ladders send the values the plan names, in order, and the searches use their step bounds", async () => {
  const KiB = 1024;
  const sizes = (service) =>
    service.calls
      .filter((call) => call.op === "publishEvents" && call.body.events.length === 1)
      .map((call) => call.body.events[0].textData?.length)
      .filter((length) => length > 1000);
  // Limits far above every ladder value: three accepted sizes, nothing to bisect.
  const wide = createWorld({ project: PROJECT, textLimit: 100 * KiB * KiB });
  await run(wide, { cases: [publishLimits] });
  assert.deepEqual(sizes(wide).slice(0, 3), [256 * KiB, KiB * KiB, 4 * KiB * KiB]);
  assert.equal(sizes(wide).filter((length) => length >= 4 * KiB * KiB).length, 1, "no search above the last value");
  // A limit between 256 KiB and 1 MiB: the bisection takes at most ten steps and no more.
  const mid = createWorld({ project: PROJECT, textLimit: 600_000 });
  await run(mid, { cases: [publishLimits] });
  assert.equal(sizes(mid).length, 2 + 10 + 0, "two bracket values, then ten bisection steps (the first value above 1 MiB is not sent)");
  // A count limit of one: the first ladder value is refused and the search starts from one event.
  const tiny = createWorld({ project: PROJECT, eventLimit: 1, textLimit: 1 });
  const { notes } = await run(tiny, { cases: [publishLimits] });
  const count = notes.find((n) => n.note === "limit-boundary" && n.name === "event-count");
  assert.deepEqual([count.accepted, count.refused], [1, 2]);
  const size = notes.find((n) => n.note === "limit-boundary" && n.name === "event-text-length");
  assert.equal(size.accepted, 1, "the text-length search starts from one character, which a limit of 1 accepts");
  assert.ok(size.refused > 1 && size.refused - size.accepted <= Math.ceil(262144 / 1024));
});

test("the extension attributes of the envelope case carry the values the plan names", async () => {
  const service = channelService();
  await run(service, { cases: [publishEnvelope] });
  const event = published(service)
    .flat()
    .find((candidate) => candidate.attributes?.flag !== undefined);
  assert.deepEqual(
    Object.fromEntries(Object.entries(event.attributes).filter(([key]) => key !== "time" && key !== "datacontenttype")),
    {
      flag: { ceBoolean: true },
      count: { ceInteger: 1 },
      link: { ceUri: "https://example.com/x" },
      relative: { ceUriRef: "/x" },
      bytes: { ceBytes: "AAE=" },
    },
  );
});

test("a limit search ends on an answer that is not the recorded limit answer: a 404 or a 403 is not a boundary", async () => {
  for (const answer of [
    { status: 404, body: { error: { code: 404, status: "NOT_FOUND", message: "Associated channel does not exist." } }, unknown: false },
    { status: 403, body: { error: { code: 403, status: "PERMISSION_DENIED", message: "denied" } }, unknown: false },
    { status: 400, body: { error: { code: 400, status: "INVALID_ARGUMENT", message: "some other problem" } }, unknown: false },
  ]) {
    const world = createWorld({ project: PROJECT });
    const odd = async (call) =>
      call.op === "publishEvents" && call.body.events.length === 255 ? answer : world.request(call);
    const { notes } = await run({ request: odd, calls: world.calls, live: new Set() }, { cases: [publishLimits] });
    const bracket = notes.find((n) => n.note === "limit-bracket" && n.name === "event-count");
    assert.deepEqual([bracket.low, bracket.high, bracket.unknown], [8, null, true], JSON.stringify(answer.status));
    assert.equal(notes.some((n) => n.note === "limit-boundary" && n.name === "event-count"), false);
  }
});
