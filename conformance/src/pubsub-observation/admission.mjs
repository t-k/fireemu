import { unusedRunPreflight } from "./safety.mjs";
import { createLedger } from "./ledger.mjs";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import {
  SOURCE_FILES as inheritedSources,
  runtimeIdentity,
  sha256,
  verifyLiveLock,
} from "../pubsub-production/admission.mjs";
import { SUITE, TASK, PROJECT, validatePlan } from "./plan.mjs";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const SOURCE_FILES = Object.freeze([
  ...inheritedSources,
  ...[
    "admission",
    "credentials",
    "journal",
    "ledger",
    "metadata",
    "meter",
    "payload",
    "plan",
    "record",
    "scenarios",
    "safety",
    "stream",
    "wire",
  ].map((name) => `conformance/src/pubsub-observation/${name}.mjs`),
  "conformance/src/pubsub-production-observation-a.test.mjs",
  "conformance/src/pubsub-production-observation-safety.test.mjs",
  "conformance/src/pubsub-observation/fixtures/recorded-resources.json",
]);
const git = (...args) =>
  execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 4194304 }).trim();
export function describeSource() {
  return {
    schema: 1,
    requestBudgetAuthority:
      "hash-bound packet.plan.caps; ceilings include unused fresh cells and two IAM read reservations",
    suite: SUITE,
    head: git("rev-parse", "HEAD"),
    runtime: runtimeIdentity(),
    sources: SOURCE_FILES.map((path) => ({
      path,
      sha256: sha256(readFileSync(resolve(root, path))),
    })),
  };
}
export function verifyDescriptor(descriptor) {
  const actual = describeSource();
  if (JSON.stringify(descriptor) !== JSON.stringify(actual))
    throw new Error("descriptor source/runtime mismatch");
  git("verify-commit", descriptor.head);
  for (const pin of descriptor.sources)
    if (
      sha256(
        execFileSync("git", ["-C", root, "show", `${descriptor.head}:${pin.path}`], {
          maxBuffer: 4194304,
        }),
      ) !== pin.sha256
    )
      throw new Error("descriptor lacks signed source bytes");
  return actual;
}
const fields = [
  "taskId",
  "suite",
  "envelopeId",
  "sourceHead",
  "descriptorSha256",
  "packetSha256",
  "project",
  "runIds",
  "runOutputs",
  "recoveryOutputs",
  "expiresAt",
  "plan",
  "recoveryBindings",
  "previousAttempt",
];
const projectScope = (value) => Object.fromEntries(fields.map((key) => [key, value[key]]));
export const scopeDigest = (value) =>
  sha256(JSON.stringify({ kind: value.kind, ...projectScope(value) }));
export function verifyScope(scope, descriptor, digest, options, now = Date.now()) {
  validatePlan(scope.plan);
  if (
    scope.taskId !== TASK ||
    scope.suite !== SUITE ||
    scope.project !== PROJECT ||
    !/^[A-Z][A-Z0-9-]{3,95}$/.test(scope.envelopeId ?? "") ||
    scope.sourceHead !== descriptor.head ||
    scope.descriptorSha256 !== digest ||
    !/^[a-f0-9]{64}$/.test(scope.packetSha256 ?? "") ||
    !Array.isArray(scope.runIds) ||
    scope.runIds.length !== scope.plan.recordings ||
    new Set(scope.runIds).size !== scope.plan.recordings ||
    scope.runIds.some((id) => !/^[a-f0-9]{12}$/.test(id)) ||
    !scope.runIds.includes(options.runId) ||
    !Number.isFinite(Date.parse(scope.expiresAt)) ||
    Date.parse(scope.expiresAt) <= now
  )
    throw new Error("source-bound scope mismatch");
  for (const key of ["runOutputs", "recoveryOutputs"])
    if (
      !scope[key] ||
      JSON.stringify(Object.keys(scope[key]).sort()) !== JSON.stringify([...scope.runIds].sort()) ||
      Object.values(scope[key]).some((path) => typeof path !== "string" || resolve(path) !== path)
    )
      throw new Error("absolute output scope required");
  const all = [...Object.values(scope.runOutputs), ...Object.values(scope.recoveryOutputs)];
  if (
    new Set(all).size !== scope.plan.recordings * 2 ||
    all.some((a, index) => all.some((b, j) => index !== j && b.startsWith(`${a}/`)))
  )
    throw new Error("distinct output scope required");
  if (
    resolve(options.out ?? "") !==
    (options.a2 ? scope.recoveryOutputs : scope.runOutputs)[options.runId]
  )
    throw new Error("output scope mismatch");
  return scope;
}
export function verifyProof(row, line, scope, kind) {
  if (
    row.kind !== kind ||
    row.state !== "APPROVED" ||
    JSON.stringify(projectScope(row)) !== JSON.stringify(projectScope(scope))
  )
    throw new Error("proof scope mismatch");
  const label = kind === "E" ? `${TASK} envelope` : TASK;
  if (
    typeof line !== "string" ||
    !line.includes(`| ${label} |`) ||
    !line.includes("decision=APPROVE;") ||
    !line.includes(`envelopeId=${scope.envelopeId};`) ||
    !line.includes(`scopeSha256=${scopeDigest(row)} `)
  )
    throw new Error("ledger does not approve exact scope");
}
export function readJson(path) {
  const bytes = readFileSync(path);
  if (bytes.length > 4194304) throw new Error("admission file byte cap");
  return { value: JSON.parse(bytes), sha256: sha256(bytes) };
}
export function verifyPacket(packet, scope, descriptor, descriptorSha256) {
  if (
    packet.sha256 !== scope.packetSha256 ||
    packet.value.schema !== 1 ||
    packet.value.taskId !== TASK ||
    packet.value.version !== "v1" ||
    packet.value.sourceHead !== descriptor.head ||
    packet.value.descriptorSha256 !== descriptorSha256 ||
    JSON.stringify(packet.value.runIds) !== JSON.stringify(scope.runIds) ||
    JSON.stringify(packet.value.runOutputs) !== JSON.stringify(scope.runOutputs) ||
    JSON.stringify(packet.value.recoveryOutputs) !== JSON.stringify(scope.recoveryOutputs) ||
    JSON.stringify(packet.value.plan) !== JSON.stringify(scope.plan)
  )
    throw new Error("packet identity mismatch");
  validatePlan(packet.value.plan);
  return packet.value.plan;
}
// Task28 binds a semantic source record separately from eligible read-only settlement.
export function verifySourceRecord(binding, plan, descriptor, read = readFileSync) {
  const fail = () => {
    throw new Error("complete closed source record proof required");
  };
  const bytes = (pin, cap = 4194304) => {
    if (
      !pin ||
      typeof pin.path !== "string" ||
      resolve(pin.path) !== pin.path ||
      !/^[a-f0-9]{64}$/.test(pin.sha256 ?? "")
    )
      fail();
    const value = read(pin.path);
    if (!Buffer.isBuffer(value) || value.length > cap || sha256(value) !== pin.sha256) fail();
    return value;
  };
  const json = (pin) => JSON.parse(bytes(pin));
  const rows = (pin) => {
    const value = bytes(pin, 80 * 1024 * 1024)
      .toString("utf8")
      .split("\n")
      .filter((line) => line.trim())
      .map(JSON.parse);
    if (value.length > 20000) fail();
    return value;
  };
  if (
    !binding ||
    !/^[a-f0-9]{12}$/.test(binding.runId ?? "") ||
    !/^[a-f0-9]{40}$/.test(binding.sourceHead ?? "") ||
    !/^PUBSUB-OBSERVATION-A-[A-Z0-9-]+$/.test(binding.envelopeId ?? "") ||
    !/^[a-f0-9]{64}$/.test(binding.packetSha256 ?? "")
  )
    fail();
  const originalDescriptor = json(binding.descriptor),
    packet = json(binding.packet),
    summary = json(binding.summary);
  const context = (value) =>
    value.runId === binding.runId &&
    value.sourceHead === binding.sourceHead &&
    value.envelopeId === binding.envelopeId &&
    value.packetSha256 === binding.packetSha256 &&
    value.project === PROJECT &&
    value.suite === SUITE;
  const sameCore = (value) => {
    const exemptions = new Set([
      "conformance/src/pubsub-observation/admission.mjs",
      "conformance/src/pubsub-production-observation-a.test.mjs",
      "conformance/src/pubsub-production-observation-safety.test.mjs",
    ]);
    if (
      !Array.isArray(value.sources) ||
      new Set(value.sources.map((pin) => pin.path)).size !== value.sources.length ||
      value.sources.some(
        (pin) => typeof pin.path !== "string" || !/^[a-f0-9]{64}$/.test(pin.sha256 ?? ""),
      )
    )
      fail();
    return JSON.stringify(
      value.sources
        .filter((pin) => !exemptions.has(pin.path))
        .toSorted((a, b) => a.path.localeCompare(b.path)),
    );
  };
  const ids = plan.cells.filter((cell) => !cell.reserve).map((cell) => cell.id);
  if (
    originalDescriptor.head !== binding.sourceHead ||
    sameCore(originalDescriptor) !== sameCore(descriptor) ||
    binding.packet.sha256 !== binding.packetSha256 ||
    packet.sourceHead !== binding.sourceHead ||
    packet.descriptorSha256 !== binding.descriptor.sha256 ||
    packet.taskId !== TASK ||
    !packet.runIds?.includes(binding.runId) ||
    JSON.stringify(packet.plan) !== JSON.stringify(plan) ||
    !context(summary) ||
    summary.a2 !== false ||
    summary.recordingComplete !== true ||
    summary.error !== null ||
    summary.signalled !== false ||
    summary.captureSha256 !== binding.capture?.sha256 ||
    summary.issuedSha256 !== binding.issued?.sha256 ||
    !Array.isArray(summary.results) ||
    JSON.stringify(summary.results.map((result) => result.cellId)) !== JSON.stringify(ids) ||
    summary.results.some((result) => result.complete !== true)
  )
    fail();
  if (
    plan.selection &&
    JSON.stringify(summary.recordingDomain) !==
      JSON.stringify({ selection: plan.selection, cellIds: ids })
  )
    fail();
  const capture = rows(binding.capture),
    issued = rows(binding.issued);
  const starts = capture.filter((row) => row.event === "run-start");
  if (
    starts.length !== 1 ||
    !context(starts[0]) ||
    starts[0].descriptorSha256 !== binding.descriptor.sha256
  )
    fail();
  const ledger = createLedger();
  for (const row of issued) {
    if (
      typeof row.name !== "string" ||
      !new RegExp(
        `^projects/${PROJECT}/(topics|subscriptions)/fe${binding.runId}-[a-z0-9-]+$`,
      ).test(row.name)
    )
      fail();
    if (row.phase === "sent") ledger.sent(row);
    else if (row.phase === "answered") ledger.answered(row);
    else if (row.phase === "resolved") ledger.replayResolution(row);
    else fail();
  }
  const closed = () =>
    [...ledger.state().values()].every((item) =>
      item.requests.every((request) =>
        ["rejected", "gone", "gone-a2"].includes(request.resolution),
      ),
    );
  if (!binding.settlement) {
    if (summary.resourcesClosed !== true || !closed()) fail();
    return { summary, descriptor: originalDescriptor };
  }
  const a2 = json(binding.settlement.summary),
    a2Capture = rows(binding.settlement.capture),
    a2Issued = rows(binding.settlement.issued),
    maintenance = binding.settlement.maintenance;
  if (
    !context(a2) ||
    a2.a2 !== true ||
    a2.recordingComplete !== false ||
    a2.resourcesClosed !== !maintenance ||
    a2.error !== null ||
    a2.signalled !== false ||
    a2.closureReady !== false ||
    a2.parentClosureReady !== false ||
    a2.captureSha256 !== binding.settlement.capture.sha256 ||
    a2.issuedSha256 !== binding.settlement.issued.sha256 ||
    a2.results?.length !== 1 ||
    a2.results[0].closed !== !maintenance
  )
    fail();
  const a2Starts = a2Capture.filter((row) => row.event === "run-start");
  if (
    a2Starts.length !== 1 ||
    !context(a2Starts[0]) ||
    a2Starts[0].descriptorSha256 !== binding.descriptor.sha256
  )
    fail();
  const originalIds = new Set(
    [...ledger.state().values()].flatMap((item) => item.requests.map((request) => request.id)),
  );
  const times = capture.flatMap((row) =>
    [row.at, row.requestDeadlineAt].filter((at) => at !== undefined).map(Date.parse),
  );
  if (times.length === 0 || times.some((at) => !Number.isFinite(at))) fail();
  const last = Math.max(...times),
    elapsedMs = maintenance ? Date.parse(a2Starts[0].at) - last : a2Issued[0]?.proof?.elapsedMs;
  if (!Number.isFinite(elapsedMs) || elapsedMs < 600000) fail();
  const generated = [],
    replay = ledger.withJournal({ write: (row) => generated.push(row) });
  const dispatches = a2Capture.filter((row) => row.event === "request-dispatch"),
    responses = a2Capture.filter((row) => row.event === "response");
  if (
    dispatches.length === 0 ||
    new Set(dispatches.map((row) => row.requestId)).size !== dispatches.length ||
    responses.length !== dispatches.length ||
    new Set(responses.map((row) => row.requestId)).size !== responses.length
  )
    fail();
  let resourceReads = 0,
    unknownDeleteReads = 0;
  const names = new Set();
  for (const dispatch of dispatches) {
    const name = dispatch.request?.name,
      response = responses.find((row) => row.requestId === dispatch.requestId);
    const category = replay.deleting(name) ? "unknownDeleteRead" : "resourceRead";
    if (
      !ledger.state().has(name) ||
      names.has(name) ||
      dispatch.cellId !== "A2" ||
      dispatch.transport !== "rest" ||
      dispatch.category !== category ||
      dispatch.method !== (name.includes("/topics/") ? "GetTopic" : "GetSubscription") ||
      JSON.stringify(dispatch.request) !== JSON.stringify({ name }) ||
      !Number.isFinite(Date.parse(dispatch.at)) ||
      Date.parse(dispatch.at) - last < elapsedMs ||
      response.cellId !== "A2" ||
      response.transport !== "rest" ||
      response.method !== dispatch.method
    )
      fail();
    names.add(name);
    if (category === "resourceRead") resourceReads++;
    else unknownDeleteReads++;
    replay.observeRead(name, response.reply);
    if (maintenance) {
      if (
        response.reply?.ok !== true ||
        response.reply.status !== 200 ||
        response.reply.code !== "OK" ||
        response.reply.unknown !== false ||
        response.reply.body?.name !== name ||
        replay.unconfirmed(name) ||
        replay.deleting(name)
      )
        fail();
    } else if (
      response.reply?.status !== 404 ||
      response.reply.ok !== false ||
      response.reply.code !== "NOT_FOUND" ||
      response.reply.unknown !== false ||
      response.reply.body?.error?.status !== "NOT_FOUND" ||
      !replay.settleAbsent(name, response.reply, {
        a2ElapsedMs: elapsedMs,
        a2EligibleRequestIds: originalIds,
      })
    )
      fail();
  }
  const withoutAt = (values) => values.map(({ at: _at, ...row }) => row);
  if (
    resourceReads > 6 ||
    unknownDeleteReads > 6 ||
    (!maintenance && !closed()) ||
    JSON.stringify(withoutAt(generated)) !== JSON.stringify(withoutAt(a2Issued)) ||
    a2.results[0].reads !== dispatches.length ||
    a2.results[0].resourceReads !== resourceReads ||
    a2.results[0].unknownDeleteReads !== unknownDeleteReads ||
    a2.results[0].iamReads !== 0 ||
    a2.results[0].outstanding?.length !== 0
  )
    fail();
  if (maintenance) {
    bytes(maintenance.source);
    const receipt = json(maintenance.summary),
      cleanupCapture = rows(maintenance.capture),
      cleanupIssued = rows(maintenance.issued);
    const pins = (value) =>
      Object.fromEntries(
        ["capture", "issued", "summary"].map((field) => [field + "Sha256", value[field].sha256]),
      );
    const maintenanceContext = (value) =>
      context(value) &&
      value.cleanupSourceSha256 === maintenance.source.sha256 &&
      value.cleanupEnvelopeId === maintenance.envelopeId &&
      value.cleanupPacketSha256 === maintenance.packetSha256;
    if (
      !/^[A-Z][A-Z0-9-]{3,95}$/.test(maintenance.envelopeId ?? "") ||
      !/^[a-f0-9]{64}$/.test(maintenance.packetSha256 ?? "") ||
      !maintenanceContext(receipt) ||
      receipt.maintenance !== true ||
      receipt.resourcesClosed !== true ||
      receipt.recordingComplete !== false ||
      receipt.closureReady !== false ||
      receipt.parentClosureReady !== false ||
      receipt.error !== null ||
      receipt.signalled !== false ||
      JSON.stringify(receipt.original) !== JSON.stringify(pins(binding)) ||
      JSON.stringify(receipt.priorA2) !== JSON.stringify(pins(binding.settlement)) ||
      receipt.captureSha256 !== maintenance.capture.sha256 ||
      receipt.issuedSha256 !== maintenance.issued.sha256 ||
      receipt.results?.length !== 1 ||
      receipt.results[0].closed !== true ||
      receipt.results[0].reads !== 2 ||
      receipt.results[0].deletes !== 1 ||
      receipt.results[0].outstanding?.length !== 0
    )
      fail();
    const cleanupStarts = cleanupCapture.filter((row) => row.event === "run-start"),
      calls = cleanupCapture.filter((row) => row.event === "request-dispatch"),
      answers = cleanupCapture.filter((row) => row.event === "response");
    if (
      cleanupStarts.length !== 1 ||
      !maintenanceContext(cleanupStarts[0]) ||
      cleanupStarts[0].descriptorSha256 !== binding.descriptor.sha256 ||
      calls.length !== 3 ||
      answers.length !== 3 ||
      new Set(calls.map((row) => row.requestId)).size !== 3 ||
      new Set(answers.map((row) => row.requestId)).size !== 3 ||
      names.size !== 1
    )
      fail();
    const name = [...names][0],
      delta = [],
      ownedLedger = ledger.withJournal({ write: (row) => delta.push(row) });
    for (const [index, call] of calls.entries()) {
      const method = index === 1 ? "DeleteSubscription" : "GetSubscription",
        answer = answers.find((row) => row.requestId === call.requestId);
      if (
        !name.includes("/subscriptions/") ||
        call.cellId !== "R2" ||
        call.transport !== "rest" ||
        call.method !== method ||
        call.category !== (index === 1 ? "cleanupDelete" : "cleanupGet") ||
        JSON.stringify(call.request) !== JSON.stringify({ name }) ||
        answer.cellId !== "R2" ||
        answer.transport !== "rest" ||
        answer.method !== method ||
        cleanupCapture.indexOf(answer) <= cleanupCapture.indexOf(call) ||
        (index > 0 &&
          cleanupCapture.indexOf(call) <=
            cleanupCapture.indexOf(
              answers.find((row) => row.requestId === calls[index - 1].requestId),
            ))
      )
        fail();
      const reply = answer.reply;
      if (index === 0) {
        if (
          ownedLedger.unconfirmed(name) ||
          ownedLedger.deleting(name) ||
          reply?.ok !== true ||
          reply.status !== 200 ||
          reply.code !== "OK" ||
          reply.unknown !== false ||
          reply.body?.name !== name ||
          reply.body?.state !== "ACTIVE" ||
          reply.body?.topic !== "_deleted-topic_"
        )
          fail();
        ownedLedger.observeRead(name, reply);
      } else if (index === 1) {
        if (
          reply?.ok !== true ||
          !Number.isInteger(reply.status) ||
          reply.status < 200 ||
          reply.status >= 300 ||
          reply.code !== "OK" ||
          reply.unknown !== false ||
          !reply.body ||
          typeof reply.body !== "object" ||
          Array.isArray(reply.body) ||
          "error" in reply.body ||
          "done" in reply.body
        )
          fail();
        const requestId = ownedLedger.sent({ name, action: "delete", transport: "rest" });
        ownedLedger.answered({ name, action: "delete", transport: "rest", requestId, kind: "ok" });
      } else if (
        reply?.status !== 404 ||
        reply.ok !== false ||
        reply.code !== "NOT_FOUND" ||
        reply.unknown !== false ||
        reply.body?.error?.status !== "NOT_FOUND" ||
        !ownedLedger.settleAbsent(name, reply)
      )
        fail();
    }
    if (!closed() || JSON.stringify(withoutAt(delta)) !== JSON.stringify(withoutAt(cleanupIssued)))
      fail();
  }
  return { summary, descriptor: originalDescriptor };
}
export function admit(options, now = Date.now()) {
  const descriptorFile = readJson(options.descriptor),
    descriptor = descriptorFile.value;
  verifyDescriptor(descriptor);
  const scope = readJson(options.authority).value;
  verifyScope(scope, descriptor, descriptorFile.sha256, options, now);
  const packet = readJson(options.packet);
  verifyPacket(packet, scope, descriptor, descriptorFile.sha256);
  const main = dirname(git("rev-parse", "--path-format=absolute", "--git-common-dir"));
  const ledgerPath = resolve(main, "docs.local/instructions/owner-decisions.md");
  for (const kind of ["E", "V"]) {
    const file = readJson(options[kind]);
    const row = file.value;
    if (
      scope[kind]?.sha256 !== file.sha256 ||
      !Number.isSafeInteger(row.ledgerLine) ||
      row.ledgerLine < 1 ||
      !/^[a-f0-9]{64}$/.test(row.ledgerLineSha256 ?? "")
    )
      throw new Error("approved ledger export required");
    const line = readFileSync(ledgerPath, "utf8").split("\n")[row.ledgerLine - 1];
    if (typeof line !== "string" || sha256(line) !== row.ledgerLineSha256)
      throw new Error("actual ledger line mismatch");
    verifyProof(row, line, scope, kind);
  }
  const canonical = resolve(main, "docs.local/runs/sandbox-locks", `${PROJECT}.lock`);
  const check = () => {
    if (Date.now() >= Date.parse(scope.expiresAt) || git("rev-parse", "HEAD") !== descriptor.head)
      throw new Error("authority expired or source HEAD changed");
    for (const pin of descriptor.sources)
      if (sha256(readFileSync(resolve(root, pin.path))) !== pin.sha256)
        throw new Error("loaded source pin changed");
    verifyLiveLock(
      { path: options.lock, expectedPath: canonical, cleanupOnly: options.a2 },
      { envelopeId: scope.envelopeId, sourceCommit: descriptor.head },
    );
  };
  check();
  if (!options.a2 && options.runId === scope.runIds[1]) {
    if (
      scope.previousAttempt?.path !==
      resolve(scope.runOutputs[scope.runIds[0]], `summary-${scope.runIds[0]}.json`)
    )
      throw new Error("run2 prior summary path mismatch");
    if (scope.previousAttempt?.record) {
      const binding = scope.previousAttempt.record;
      if (
        binding.runId !== scope.runIds[0] ||
        binding.summary?.path !== scope.previousAttempt.path ||
        binding.summary?.sha256 !== scope.previousAttempt.sha256
      )
        throw new Error("run2 original source binding mismatch");
      verifySourceRecord(binding, scope.plan, descriptor, readFileSync);
    } else {
      const previous = readJson(scope.previousAttempt?.path);
      if (
        previous.sha256 !== scope.previousAttempt?.sha256 ||
        previous.value.runId !== scope.runIds[0] ||
        previous.value.sourceHead !== descriptor.head ||
        previous.value.envelopeId !== scope.envelopeId ||
        previous.value.packetSha256 !== scope.packetSha256 ||
        previous.value.resourcesClosed !== true ||
        previous.value.recordingComplete !== true
      )
        throw new Error("run2 requires complete closed run1");
    }
  }
  return {
    scope,
    descriptor,
    descriptorSha256: descriptorFile.sha256,
    check,
    plan: scope.plan,
    preflightUnusedRun: () =>
      unusedRunPreflight({
        runId: options.runId,
        out: options.out,
        ledgerPath: resolve(main, "docs.local/runs/sandbox-ledger.jsonl"),
        runsRoot: resolve(main, "docs.local/runs"),
      }),
  };
}
