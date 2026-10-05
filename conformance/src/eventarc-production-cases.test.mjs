import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { channelLifecycle } from "./eventarc-production/cases/channels.mjs";
import { CASES } from "./eventarc-production/cases/index.mjs";
import { authErrors } from "./eventarc-production/cases/errors.mjs";
import {
  publishContent,
  publishEnvelope,
  publishLimits,
} from "./eventarc-production/cases/publish.mjs";
import { adminSdkPublish } from "./eventarc-production/cases/sdk.mjs";
import { serviceState } from "./eventarc-production/cases/service.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
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
} = {}) {
  const live = new Set(existing);
  const calls = [];
  const operations = new Map();
  return {
    live,
    calls,
    async request(call) {
      const { method, path, op } = call;
      calls.push({ method, path, op, caseId: call.label?.case, body: call.body });
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
        const id = new URL(`http://x${path}`).searchParams.get("channelId");
        const name = `${path.split("?")[0].replace(/^\/v1\//, "")}/${id}`;
        // A name that cannot exist is refused, as it is read (400).
        if (refuse.has(id) || /^(GOOG|a[0-9a-f]$)/.test(id))
          return { status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false };
        // A creation of a name that exists ends with ALREADY_EXISTS inside its operation.
        const existed = live.has(name);
        operations.set(OPERATION, {
          reads: 0,
          error: failWith.get(id) ?? (existed ? { code: 6 } : undefined),
        });
        if (!existed && !failWith.has(id)) live.add(name);
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

async function run(service, { runId = RUN, cases = [channelLifecycle], makeSdk = null } = {}) {
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
      usageProject: PROJECT,
      publishPrefix: "/v1",
    },
    sleep: async () => {},
    ledger,
    makeSdk,
  });
  return { summary, ledger, notes, ownership };
}

const posts = (service) =>
  service.calls.filter((call) => call.method === "POST").map((call) => call.path);
const deletes = (service, suffix) =>
  service.calls.filter((call) => call.method === "DELETE" && call.path.endsWith(suffix));
/** The deletions the case itself sent (cleanup is a separate step with its own rules). */
const caseDeletes = (service, suffix) =>
  deletes(service, suffix).filter((call) => call.caseId !== "cleanup");

test("the lifecycle creates and deletes its channel, polls every operation, and sends the second deletion only after the recorded 404", async () => {
  const service = channelService();
  const { summary, ledger } = await run(service);
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
  const c1 = `fe${RUN}-cl-c1`;
  assert.equal(
    deletes(service, c1).length,
    2,
    "the deletion and its repetition after the read-back",
  );
  const name = `projects/${PROJECT}/locations/us-central1/channels/${c1}`;
  assert.deepEqual(
    ledger.state().get(name).creates.at(-1),
    "conflict",
    "the repetition of the creation ended with a conflict",
  );
  assert.ok(ledger.state().get(name).creates.includes("ok"));
  assert.ok(ledger.state().get(name).deletes.includes("ok"));
  // Every creation that was accepted had its operation read.
  assert.ok(service.calls.filter((call) => call.op === "getOperation").length >= 3);
  assert.deepEqual(summary.cleanup.unsettled, []);
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
    `nowhere-${RUN}`,
  ]);
  assert.deepEqual(probes(second, "fedcba987654"), [
    "GOOG-FEDCBA987654",
    "af",
    "goog-fedcba987654",
    "1-fedcba987654",
    "nowhere-fedcba987654",
  ]);
  // The long probe carries the prefix and is 64 characters.
  const long = posts(first)
    .map((path) => new URL(`http://x${path}`).searchParams.get("channelId"))
    .find((id) => id?.length === 64);
  assert.ok(long.startsWith(`fe${RUN}-`));
  // Each probe is read just before its creation.
  for (const id of [`GOOG-${RUN.toUpperCase()}`, `goog-${RUN}`, `1-${RUN}`]) {
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
  const name = `projects/${PROJECT}/locations/us-central1/channels/goog-${RUN}`;
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
  const name = `projects/${PROJECT}/locations/us-central1/channels/${id}`;
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
  assert.deepEqual(ledger.state().get(name).creates, ["unknown", "conflict"]);
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
  const c1 = `fe${RUN}-cl-c1`;
  const unknown = channelService({ unknownDelete: true });
  await run(unknown);
  assert.equal(deletes(unknown, c1).length, 1, "the first deletion only");
  const stuck = channelService({ deleteNeverDone: true });
  const { ledger } = await run(stuck);
  assert.equal(deletes(stuck, c1).length, 1);
  const name = `projects/${PROJECT}/locations/us-central1/channels/${c1}`;
  assert.deepEqual(
    ledger.state().get(name).deletes.slice(0, 2),
    ["unknown", "unknown"],
    "the 2xx and the operation that was not done",
  );
});

test("a creation that is refused is not ours, and the steps that need the channel are skipped", async () => {
  const service = channelService({ refuse: new Set([`fe${RUN}-cl-c1`]) });
  const { summary, ledger } = await run(service);
  const c1 = `fe${RUN}-cl-c1`;
  assert.equal(deletes(service, c1).length, 0);
  const name = `projects/${PROJECT}/locations/us-central1/channels/${c1}`;
  assert.deepEqual(
    ledger
      .state()
      .get(name)
      .creates.filter((kind) => kind === "ok"),
    [],
  );
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
});

test("the default channel is published to only after the recorded JSON 404: a text 404 or an existing channel opens nothing", async () => {
  const firebase = `projects/${PROJECT}/locations/us-central1/channels/firebase`;
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

test("the service-state case sends its enabled-state publish only to its own channel and, while DISABLED, to the default channel only after the recorded JSON 404", async () => {
  const firebase = `projects/${PROJECT}/locations/us-central1/channels/firebase`;
  for (const [reply, expected] of [
    [NOT_FOUND, true],
    [{ status: 404, body: { raw: "Not Found" }, unknown: false }, false],
  ]) {
    const calls = [];
    const service = {
      request: async (call) => {
        calls.push(call);
        if (call.op === "getService")
          return {
            status: 200,
            body: {
              state: calls.filter((c) => c.op === "getService").length < 2 ? "DISABLED" : "ENABLED",
            },
            unknown: false,
          };
        if (call.op === "listEnabledServices")
          return { status: 200, body: { services: [] }, unknown: false };
        if (call.op === "enableService")
          return { status: 200, body: { name: "operations/x", done: true }, unknown: false };
        if (call.op === "getChannel" && call.path.endsWith("/channels/firebase")) return reply;
        return NOT_FOUND;
      },
    };
    await run(service, { cases: [serviceState] });
    const toFirebase = calls.some(
      (call) => call.op === "publishEvents" && call.path.includes("/channels/firebase:"),
    );
    assert.equal(toFirebase, expected);
    assert.ok(
      calls.some((call) => call.op === "listChannels" && /[?&]pageSize=10($|&)/.test(call.path)),
      "the list while disabled asks for pages of 10",
    );
    void firebase;
  }
});

test("the second deletion needs every condition: the first answered, its operation done without an error, and the recorded 404 read back", async () => {
  const c1 = `fe${RUN}-cl-c1`;
  for (const [label, options] of [
    ["an unknown answer whose body looks finished", { deleteBadAnswer: true }],
    ["an operation done with an error, the channel gone", { deleteError: { code: 13 } }],
    ["an operation done, the channel still there", { deleteNoEffect: true }],
    ["an operation never done, the channel gone", { deleteLate: true }],
  ]) {
    const service = channelService(options);
    await run(service);
    assert.equal(caseDeletes(service, c1).length, 1, `${label}: the first deletion only`);
  }
  // Every condition met: both are sent.
  const service = channelService();
  await run(service);
  assert.equal(caseDeletes(service, c1).length, 2);
});

const published = (service) =>
  service.calls.filter((call) => call.op === "publishEvents").map((call) => call.body.events ?? []);

test("the case ceilings are the ones the plan was measured against, in the order the cases run", () => {
  assert.deepEqual(
    CASES.map(({ id, requests }) => [id, requests]),
    [
      ["service-state", 36],
      ["channel-lifecycle", 110],
      ["publish-envelope", 34],
      ["publish-content", 26],
      ["publish-limits", 26],
      ["admin-sdk-publish", 16],
      ["auth-errors", 22],
    ],
  );
});

test("the publish limits are a ladder: the counts, the sizes, the request sizes, the attributes and the mixed batch", async () => {
  const service = channelService();
  const { summary } = await run(service, { cases: [publishLimits] });
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
  const KiB = 1024;
  const calls = published(service);
  const text = (event) => event.textData?.length;
  assert.deepEqual(
    calls.slice(0, 9).map((events) => [events.length, text(events[0])]),
    [
      [256, 1],
      [257, 1],
      [1000, 1],
      [1, 256 * KiB],
      [1, KiB * KiB],
      [1, 4 * KiB * KiB],
      [1, 10 * KiB * KiB],
      [8, 128 * KiB],
      [8, KiB * KiB],
    ],
  );
  assert.deepEqual(
    calls.slice(9).map((events) => events.length),
    [1, 1, 3],
  );
  // Every event of a ladder step has the same text size.
  for (const events of calls.slice(0, 9)) {
    assert.equal(new Set(events.map(text)).size, 1);
  }
  // Attributes: 100 extra ones (plus the base ones), then one name of 256 characters.
  const base = Object.keys(calls[0][0].attributes).length;
  assert.equal(Object.keys(calls[9][0].attributes).length, base + 100);
  const names = Object.keys(calls[10][0].attributes).filter((name) => name.length > 100);
  assert.deepEqual(
    names.map((name) => name.length),
    [256],
  );
  // The mixed batch: the second event has no type.
  assert.deepEqual(
    calls[11].map((event) => event.type !== undefined),
    [true, false, true],
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
  assert.ok(lists.some((path) => path.endsWith("/locations/us-central1/channels?pageSize=1")));
  assert.ok(lists.some((path) => path.endsWith("/locations/-/channels?pageSize=5")));
});

test("the enabled-services note says complete only when both reads were", async () => {
  const run1 = async (afterEnableToken) => {
    let enabled = false;
    const service = {
      request: async (call) => {
        if (call.op === "getService")
          return {
            status: 200,
            body: { state: enabled ? "ENABLED" : "DISABLED" },
            unknown: false,
          };
        if (call.op === "listEnabledServices")
          return {
            status: 200,
            body: {
              services: [{ name: "a" }],
              ...(enabled && afterEnableToken ? { nextPageToken: "more" } : {}),
            },
            unknown: false,
          };
        if (call.op === "enableService") {
          enabled = true;
          return { status: 200, body: { name: "operations/x", done: true }, unknown: false };
        }
        if (call.op === "listChannels") return { status: 200, body: {}, unknown: false };
        return NOT_FOUND;
      },
    };
    const { notes } = await run(service, { cases: [serviceState] });
    return notes.find((entry) => entry.note === "enabled-services");
  };
  assert.equal((await run1(false)).complete, true);
  assert.equal((await run1(true)).complete, false);
});
