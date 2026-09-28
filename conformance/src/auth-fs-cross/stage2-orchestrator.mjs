// Runs one AUTH-FS-CROSS stage-2 recording: the program of programs-stage2.mjs against one
// target, with native Listen streams in this process and each SDK client in its own child.
//
// A row is what one step observed, with run values masked and no times: a probe's row is every
// event each observed listener received from the probe's commit to the end of its window. The
// timed events are kept apart as evidence. Nothing here decides whether an event was expected.

import { createRequire } from "node:module";

import { decodeJwt } from "../auth-credential/tokens.mjs";
import { documentsName, PASSWORD } from "../fs-rules/harness.mjs";
import { openListen as openListenDefault } from "./listen-grpc.mjs";
import { WINDOW_MS } from "./programs-stage2.mjs";
import { DRIVERS, spawnSdk } from "./sdk-client.mjs";
import { createSession as createSessionDefault, fatal } from "./stage2-session.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");

/** The metadata of a native Listen: the principal's bearer and the database routing. */
export function listenMetadata(bearer, database) {
  const metadata = new grpc.Metadata();
  if (bearer !== undefined) metadata.set("authorization", bearer);
  metadata.set("google-cloud-resource-prefix", database);
  metadata.set("x-goog-request-params", `database=${encodeURIComponent(database)}`);
  return metadata;
}

/** A Listen frame as a row compares it: no resume tokens, read times or heartbeats. */
export function frameRow(frame, documentsRoot) {
  const relative = (name) => String(name ?? "").replace(`${documentsRoot}/`, "");
  switch (frame.kind) {
    case "targetChange": {
      const change = frame.targetChange ?? {};
      const targetIds = change.targetIds ?? [];
      // A global NO_CHANGE is a heartbeat: how many arrive depends only on time.
      if ((change.targetChangeType ?? "NO_CHANGE") === "NO_CHANGE" && targetIds.length === 0)
        return null;
      return {
        kind: "targetChange",
        type: change.targetChangeType ?? "NO_CHANGE",
        targetIds,
        cause: change.cause ? { code: change.cause.code, message: change.cause.message } : null,
      };
    }
    case "documentChange": {
      const change = frame.documentChange ?? {};
      return {
        kind: "documentChange",
        doc: relative(change.document?.name),
        n: change.document?.fields?.n?.integerValue ?? null,
        targetIds: change.targetIds ?? [],
        removedTargetIds: change.removedTargetIds ?? [],
      };
    }
    case "documentDelete":
    case "documentRemove": {
      const change = frame[frame.kind] ?? {};
      return {
        kind: frame.kind,
        doc: relative(change.document),
        removedTargetIds: change.removedTargetIds ?? [],
      };
    }
    case "filter":
      return { kind: "filter", targetId: frame.filter?.targetId, count: frame.filter?.count };
    default:
      return { kind: String(frame.kind) };
  }
}

/** An SDK listener's event as a row compares it. */
export function listenerRow(event) {
  if (event.event === "listen-error") return { kind: "error", code: event.code };
  return {
    kind: "snapshot",
    fromCache: event.fromCache,
    pending: event.hasPendingWrites,
    docs: event.docs.map(({ path, exists, data }) => ({ path, exists, n: data?.n ?? null })),
  };
}

/** The service and method of one wire record, the same for production and the local target. */
export function wireCall({ host, path }) {
  const local = /^\/([a-z]+)\.googleapis\.com(\/.*)$/.exec(path);
  if (local) return { service: local[1], method: local[2] };
  if (path.startsWith("/google.firestore.")) return { service: "firestore", method: path };
  return { service: host.split(".")[0], method: path };
}

/** A client's own event (not a listener's) as a row compares it. */
export function clientRow(event, ops) {
  switch (event.event) {
    case "wire":
      return { kind: "wire", ...wireCall(event), principal: event.principal };
    case "write-settled":
      return {
        kind: "write-settled",
        writeId: event.writeId,
        ok: event.ok,
        code: event.code ?? null,
      };
    case "auth":
      return { kind: "auth", uid: event.uid };
    case "result":
      return {
        kind: "result",
        op: ops.get(event.id) ?? null,
        ok: event.ok,
        code: event.code ?? null,
        ...(event.attempts === undefined ? {} : { attempts: event.attempts }),
      };
    default:
      return null;
  }
}

/** The equality filters of a listener's query as a structured query. */
function structuredQuery(collection, where) {
  const filters = where.map(([field, value]) => ({
    fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: { stringValue: value } },
  }));
  return {
    from: [{ collectionId: collection }],
    where: filters.length === 1 ? filters[0] : { compositeFilter: { op: "AND", filters } },
  };
}

/**
 * Interprets one program's steps after setup. `deps` injects the session, the SDK and Listen
 * factories and the clock, so the interpretation is testable without a target.
 */
export function createInterpreter(program, deps) {
  const { session, ctx, spawnClient, openListen, sdkConfig, now = () => Date.now() } = deps;
  const log = deps.log ?? (() => {});
  const started = now();
  const documentsRoot = documentsName(ctx, "default");
  const streams = new Map();
  const clients = new Map();
  const marks = new Map();
  const rows = {};
  const timeline = [];
  const note = (source, event) => timeline.push({ at: now() - started, source, ...event });

  /** Where every stream and client stood: later events are the mark's. */
  const takeMark = () => ({
    streams: new Map(
      [...streams].map(([name, s]) => [
        name,
        { frames: s.recorder.frames.length, ended: Boolean(s.recorder.ended()) },
      ]),
    ),
    clients: new Map([...clients].map(([name, c]) => [name, c.sdk.events.length])),
  });

  function streamEvents(name, mark) {
    const { recorder } = streams.get(name);
    const at = mark.streams.get(name) ?? { frames: 0, ended: false };
    const end = recorder.ended();
    return {
      events: recorder
        .since(at.frames)
        .map((f) => frameRow(f, documentsRoot))
        .filter(Boolean),
      // An end before the mark is the stream's, not this step's.
      endedBefore: at.ended,
      end: end && !at.ended ? { reason: end.reason, code: end.code } : null,
    };
  }

  function listenerEvents(ref, mark) {
    const [name, listener] = ref.split("/");
    const client = clients.get(name);
    const from = mark.clients.get(name) ?? client.sdk.events.length;
    return {
      events: client.sdk.events
        .slice(from)
        .filter(
          (e) => (e.event === "snapshot" || e.event === "listen-error") && e.name === listener,
        )
        .map(listenerRow),
    };
  }

  function clientEvents(name, mark) {
    const client = clients.get(name);
    const from = mark.clients.get(name) ?? client.sdk.events.length;
    return client.sdk.events
      .slice(from)
      .map((e) => clientRow(e, client.ops))
      .filter(Boolean);
  }

  function observation(step, mark) {
    const listeners = {};
    for (const ref of step.observe ?? [])
      listeners[ref] = ref.startsWith("grpc-")
        ? streamEvents(ref, mark)
        : listenerEvents(ref, mark);
    const byClient = {};
    for (const name of step.clients ?? []) byClient[name] = clientEvents(name, mark);
    return { listeners, clients: byClient };
  }

  const conditionsOf = (step) => step.conditions ?? [step.condition];
  /** The SDK clients a step's row depends on (all of them for the final row). */
  function clientsIn(step) {
    if (step.do === "close-all") return [...clients.keys()];
    const names = new Set([...(step.clients ?? []), ...(step.client ? [step.client] : [])]);
    const refs = [...(step.observe ?? []), ...(step.probes ?? []).flatMap((p) => p.observe)];
    for (const ref of refs) if (!ref.startsWith("grpc-")) names.add(ref.split("/")[0]);
    return [...names];
  }

  /**
   * A row names the clients whose request cap refused something by the time it was recorded:
   * such a row shows the harness's limit, not production's behavior, and is never compared.
   */
  const record = (step, value) => {
    const capped = clientsIn(step)
      .filter((name) => clients.get(name)?.sdk.events.some((e) => e.event === "wire-refused"))
      .toSorted();
    rows[step.id] = session.mask({
      id: step.id,
      conditions: conditionsOf(step),
      ...value,
      ...(capped.length ? { capped } : {}),
    });
  };

  async function send(step) {
    const client = clients.get(step.client);
    const fields = { ...step };
    for (const key of ["do", "client", "op", "mark", "await", "commandId", "as"])
      delete fields[key];
    if (step.op === "signIn") {
      const principal = session.principals.get(step.as);
      if (!principal) throw fatal(`no principal ${step.as}`);
      fields.email = session.emailOf(step.as);
      fields.password = PASSWORD;
      fields.tenantId = principal.tenantId ?? null;
    }
    if (step.where) fields.where = step.where.map(([f, op, v]) => [f, op, session.resolve(v)]);
    if (step.data) fields.data = session.resolve(step.data);
    if (step.write) fields.write = { ...step.write, data: session.resolve(step.write.data) };
    client.sent += 1;
    // Every command carries its own id, so a result row can name its op.
    fields.id = step.commandId ?? `${step.op}-${client.sent}`;
    client.ops.set(fields.id, step.op);
    if (step.op === "transaction") client.transactions.set(step.name, fields.id);
    const isCapped = () => client.sdk.events.some((e) => e.event === "wire-refused");
    // A client ended by its cap answers every later command as failed; its rows are marked.
    const pending = client.sdk.send(step.op, fields).catch((error) => {
      if (!isCapped()) throw error;
      return { event: "result", id: fields.id, ok: false, code: "client-ended-by-cap" };
    });
    note(step.client, { op: step.op });
    if (step.await === false) {
      pending.catch(() => {});
      return;
    }
    const result = await pending;
    note(step.client, { result: step.op, ok: result.ok, code: result.code ?? null });
    // A client that cannot sign in or listen makes the rest of its scenario meaningless, unless
    // its request cap refused something: then its rows already show the harness's limit, and the
    // run goes on.
    if (!result.ok && (step.op === "signIn" || step.op === "listen") && !isCapped())
      throw new Error(`${step.client} ${step.op} failed: ${result.code ?? result.error}`);
  }

  async function openStream(step) {
    const targets = step.targets.map((target) =>
      target.document
        ? {
            targetId: target.targetId,
            documents: { documents: [`${documentsRoot}/${target.document}`] },
          }
        : {
            targetId: target.targetId,
            query: {
              parent: documentsRoot,
              structuredQuery: structuredQuery(
                target.collection,
                target.where.map(([f, v]) => [f, session.resolve(v)]),
              ),
            },
          },
    );
    const database = `projects/${ctx.project}/databases/(default)`;
    // A stream is one request of the harness, counted under its ceiling like any other.
    session.chargeHarness();
    const recorder = openListen({
      client: session.grpcClient,
      protos: session.protos,
      database,
      targets,
      metadata: listenMetadata(session.bearerFor(step.as), database),
    });
    streams.set(step.name, { recorder, as: step.as });
    note(step.name, { opened: true });
  }

  /** How long a probe's listeners are watched. */
  const windowOf = (step) => step.windowMs ?? WINDOW_MS;

  async function commitProbe(step) {
    const mark = takeMark();
    await session.seed(step.writes);
    note("harness", { probe: step.id });
    await session.pause(windowOf(step));
    record(step, observation(step, mark));
  }

  /** The expiry of the token a probe is timed from. */
  function expiryOf(probe) {
    const exp = probe.token.principal
      ? decodeJwt(session.principals.get(probe.token.principal)?.idToken ?? "")?.claims?.exp
      : clients
          .get(probe.token.client)
          // The first token the client held: the one issued when the window opened.
          .sdk.events.find((e) => e.event === "auth" && typeof e.exp === "number")?.exp;
    if (typeof exp !== "number") throw fatal(`no expiry for ${JSON.stringify(probe.token)}`);
    return exp;
  }

  async function probeOnce(step, probe, onTime) {
    const mark = takeMark();
    await session.seed([probe.write]);
    note("harness", { probe: step.id, doc: probe.write.doc, onTime });
    await session.pause(windowOf(step));
    return { doc: probe.write.doc, onTime, ...observation(probe, mark) };
  }

  /**
   * Each probe at its own token's expiry plus `plus`, concurrently; or, with `align: "latest"`,
   * all of them one after another from the latest of those instants, so every token is past its
   * mark before the first commit and each stream's end is seen against its own commit.
   */
  async function expiryProbes(step) {
    const target = (probe) => (expiryOf(probe) + step.plus) * 1000 + 300;
    let results;
    if (step.align === "latest") {
      const onTime = await session.sleepUntil(Math.max(...step.probes.map(target)));
      results = [];
      for (const probe of step.probes) results.push(await probeOnce(step, probe, onTime));
    } else {
      results = await Promise.all(
        step.probes.map(async (probe) =>
          probeOnce(step, probe, await session.sleepUntil(target(probe))),
        ),
      );
    }
    // A late timer makes its probe indeterminate (as in stage 1), never a different outcome.
    record(step, { probes: results });
  }

  async function closeAll(step) {
    const life = { streams: {}, listeners: {} };
    for (const [name, stream] of streams) {
      const end = stream.recorder.ended();
      life.streams[name] = end ? { reason: end.reason, code: end.code } : { reason: "open" };
    }
    for (const [name, client] of clients) {
      for (const event of client.sdk.events)
        if (event.event === "listen-error")
          life.listeners[`${name}/${event.name}`] = { reason: "error", code: event.code };
    }
    await closeEverything();
    if (step) record(step, life);
  }

  async function closeEverything() {
    for (const stream of streams.values()) await stream.recorder.close();
    await Promise.all([...clients.values()].map((c) => (c.closed ? null : c.sdk.close())));
    for (const client of clients.values()) client.closed = true;
  }

  const executors = {
    stream: openStream,
    async client(step) {
      const sdk = spawnClient(step.transport, { ...sdkConfig, wireCap: step.wireCap });
      clients.set(step.client, {
        sdk,
        transport: step.transport,
        ops: new Map(),
        transactions: new Map(),
        sent: 0,
      });
      await sdk.ready();
      note(step.client, { spawned: step.transport });
    },
    async sdk(step) {
      if (step.mark) marks.set(step.mark, takeMark());
      await send(step);
    },
    async await(step) {
      const client = clients.get(step.client);
      // A transaction that fails before its reads (its request refused, say) never reports
      // them: its own result ends the wait instead, and the steps that follow record it.
      const transaction = client.transactions.get(step.name);
      const match =
        step.event === "result"
          ? (e) => e.event === "result" && e.id === step.commandId
          : (e) =>
              (e.event === step.event && e.name === step.name) ||
              (e.event === "result" && e.id === transaction && !e.ok);
      let event;
      try {
        event = await client.sdk.waitFor(match);
      } catch (error) {
        // A client ended by its cap never answers: its rows are marked, the run goes on.
        if (!client.sdk.events.some((e) => e.event === "wire-refused")) throw error;
        event = { event: "result", id: step.commandId, ok: false, code: "client-ended-by-cap" };
      }
      note(step.client, { awaited: step.event, ok: event.ok ?? null });
      if (step.id) {
        const mark = marks.get(step.since) ?? takeMark();
        record(step, {
          result: clientRow(event, client.ops),
          clients: { [step.client]: clientEvents(step.client, mark) },
        });
      }
    },
    probe: commitProbe,
    async observe(step) {
      const mark = step.since ? marks.get(step.since) : takeMark();
      await session.pause(windowOf(step));
      record(step, observation(step, mark));
    },
    async server(step) {
      const docs = {};
      for (const doc of step.docs) docs[doc] = await session.ownerRead(doc);
      record(step, { docs });
    },
    async auth(step) {
      await session.act(
        {
          action: step.action,
          principal: step.principal,
          tenant: step.tenant,
          claims: step.claims,
        },
        new Map(),
      );
      note("harness", {
        auth: step.action,
        principal: step.principal ?? null,
        tenant: step.tenant ?? null,
      });
    },
    async sleep(step) {
      await session.pause(step.ms);
    },
    "expiry-probes": expiryProbes,
    /** Groups of expiry probes that run at the same time, each recorded as its own row. */
    async "expiry-groups"(step) {
      await Promise.all(step.groups.map((group) => expiryProbes(group)));
    },
    async "close-client"(step) {
      const client = clients.get(step.client);
      await client.sdk.close();
      client.closed = true;
    },
    "close-all": closeAll,
  };

  return {
    async run() {
      for (const step of program.steps) {
        const execute = executors[step.do];
        if (!execute) throw fatal(`unknown step ${step.do}`);
        log(`${step.do} ${step.id ?? step.client ?? step.name ?? step.action ?? ""}`.trim());
        await execute(step);
      }
      return rows;
    },
    rows,
    timeline: () => session.mask(timeline),
    /** The requests each client's wire guard admitted. */
    wireCounts: () =>
      Object.fromEntries(
        [...clients].map(([name, c]) => [
          name,
          c.sdk.events.filter((e) => e.event === "wire").length,
        ]),
      ),
    streams,
    clients,
    /** Closes every stream and client; always called, also after a failure. */
    closeEverything,
  };
}

/**
 * Runs one recording: setup (sign-in baseline, tenants, principals, Rules, documents), the
 * program, then cleanup in reverse order, which always runs.
 */
export async function runStage2Window(program, ctx, options = {}) {
  const {
    createSession = createSessionDefault,
    spawnClient = (transport, config) => {
      const driver = DRIVERS[transport];
      if (!driver) throw fatal(`no driver for ${transport}`);
      return spawnSdk(config, { timeoutMs: 90_000, driver });
    },
    openListen = openListenDefault,
    sdkConfig,
    sessionOptions = {},
    log = () => {},
  } = options;
  const session = createSession(ctx, sessionOptions);
  let interpreter;
  let rows = {};
  let fatalError;
  try {
    await session.prepareSignIn();
    for (const slot of program.tenants) await session.createTenant(slot);
    for (const name of program.principals)
      await session.createPrincipal(name, options.principals[name]);
    await session.wipe();
    await session.publish(program.ruleset);
    await session.seed(program.seed);
    interpreter = createInterpreter(program, {
      session,
      ctx,
      spawnClient,
      openListen,
      sdkConfig,
      log,
    });
    rows = await interpreter.run();
  } catch (error) {
    fatalError = error;
  }
  const cleanupErrors = [];
  const cleanup = [
    () => interpreter?.closeEverything(),
    () => session.beginCleanup(),
    ...session.touchedDatabases().map((which) => () => session.publish(null, which)),
    () => session.wipe(),
    () => session.deletePrincipals(),
    () => session.deleteTenants(),
    () => session.deleteCreatedRulesets(),
    async () => {
      const problems = await session.audit();
      if (problems.length) throw new Error(`audit: ${problems.join("; ")}`);
    },
  ];
  for (const step of cleanup) {
    try {
      await step();
    } catch (error) {
      cleanupErrors.push(String(error.message ?? error));
    }
  }
  await session.close();
  const out = {
    context: { run: ctx.run, startedMs: ctx.startedMs },
    rows,
    timeline: interpreter?.timeline() ?? [],
    wire: interpreter?.wireCounts() ?? {},
    cleanupErrors,
    ...session.evidence(),
    ...session.counts(),
  };
  if (fatalError) throw Object.assign(fatalError, { partial: out });
  if (cleanupErrors.length)
    throw Object.assign(fatal(`cleanup failed: ${cleanupErrors.join("; ")}`), { partial: out });
  return out;
}
