import { baseAttributes, CE_TYPE } from "./cases/support.mjs";

export const H_LIMITS = Object.freeze({
  preflight: 30,
  readiness: 160,
  publish: 48,
  capture: 120,
  cleanup: 50,
  a2: 40,
});

export function hManifest({ project, runId }) {
  if (!/^[a-f0-9]{12}$/.test(runId) || !/^[a-z][a-z0-9-]{4,62}$/.test(project))
    throw new Error("invalid H project or run ID");
  return {
    project,
    runId,
    recording: "h1",
    location: "us-central1",
    observe: `fe${runId}HObserve`,
    filtered: `fe${runId}HFiltered`,
    type: `fireemu.h.${runId}`,
    source: `//fireemu/handler/${runId}`,
    tenant: `h${runId}`,
    channel: `projects/${project}/locations/us-central1/channels/firebase`,
    markerCollection: `fe_h_${runId}`,
    propagationMs: 300_000,
  };
}

/** The frozen H table: no searches, replayed IDs or adaptive extra requests. */
export function hPublishes(m) {
  const requests = [];
  let serial = 0;
  const event = (caseId, overrides = {}) => ({
    "@type": CE_TYPE,
    id: `fe${m.runId}-h-${caseId}-${++serial}`,
    source: m.source,
    specVersion: "1.0",
    type: m.type,
    attributes: {
      ...baseAttributes("application/json", "2026-10-06T00:00:00.123456789Z"),
      subject: { ceString: caseId },
      tenant: { ceString: m.tenant },
    },
    textData: '{"probe":true}',
    ...overrides,
  });
  const add = (caseId, events, extra = {}) =>
    requests.push({ case: caseId, body: { events }, ...extra });
  const control = (caseId) => add(caseId, [event(caseId)], { control: true });
  const bracket = (caseId, events, extra = {}) => {
    control(`${caseId}-before`);
    add(caseId, events, { windowMs: 120_000, ...extra });
    control(`${caseId}-after`);
  };
  control("before-control");
  for (const [name, textData] of [
    ["object", '{"a":1,"b":[true,null]}'],
    ["scalar", "1"],
    ["null", "null"],
    ["array", "[1,2,3]"],
  ])
    add(name, [event(name, { textData })]);
  const binary = event("binary", { binaryData: "AAEC/w==" });
  delete binary.textData;
  binary.attributes.datacontenttype = { ceString: "application/octet-stream" };
  add("binary", [binary]);
  const mixed = [
    event("multi-match"),
    event("multi-source-miss", { source: `${m.source}/miss` }),
    event("multi-tenant-miss"),
  ];
  mixed[2].attributes.tenant.ceString = `${m.tenant}-miss`;
  add("multi", mixed);
  const noTime = event("no-time");
  delete noTime.attributes.time;
  bracket("no-time", [noTime], { negativeHandlers: [m.observe, m.filtered] });
  const bytes = event("ce-bytes");
  bytes.attributes.convbytes = { ceBytes: "AAE=" };
  bracket("ce-bytes", [bytes], { negativeHandlers: [m.observe, m.filtered] });
  for (const [caseId, channel, generated] of [
    ["sdk-default", undefined, false],
    ["sdk-full", m.channel, false],
    ["sdk-relative", "locations/us-central1/channels/firebase", false],
    ["sdk-generated", undefined, true],
    ["sdk-metadata", undefined, false],
  ]) {
    const proto = event(caseId);
    const sdkEvent = {
      id: proto.id,
      type: m.type,
      source: m.source,
      time: "2026-10-06T00:00:00.123Z",
      subject: caseId,
      tenant: m.tenant,
      data: { run: m.runId, recording: "h1", case: caseId },
    };
    if (generated) {
      delete sdkEvent.id;
      delete sdkEvent.time;
      delete sdkEvent.source;
    }
    requests.push({ case: caseId, sdk: true, channel, events: [sdkEvent], source: m.source });
  }
  for (const caseId of ["wrong-type", "wrong-source", "wrong-tenant", "missing-tenant"]) {
    const e = event(caseId);
    if (caseId === "wrong-type") e.type = `${m.type}.miss`;
    if (caseId === "wrong-source") e.source = `${m.source}/miss`;
    if (caseId === "wrong-tenant") e.attributes.tenant.ceString = `${m.tenant}-miss`;
    if (caseId === "missing-tenant") delete e.attributes.tenant;
    bracket(caseId, [e], {
      negativeHandlers: caseId === "wrong-type" ? [m.observe, m.filtered] : [m.filtered],
      positiveHandlers: caseId === "wrong-type" ? [] : [m.observe],
    });
  }
  bracket(
    "refused-101",
    Array.from({ length: 101 }, () => event("refused-101")),
    { refused: true },
  );
  for (const [caseId, invalidIndex] of [
    ["refused-middle", 1],
    ["refused-first", 0],
    ["refused-last", 2],
  ]) {
    const events = Array.from({ length: 3 }, () => event(caseId));
    delete events[invalidIndex].type;
    bracket(caseId, events, { refused: true });
  }
  add(
    "retry",
    [
      event("retry", {
        textData: JSON.stringify({
          fixtureKind: "retry",
          run: m.runId,
          recording: "h1",
          case: "retry",
        }),
      }),
    ],
    { windowMs: 600_000, retry: true },
  );
  for (let i = 1; i <= 4; i++) control(`fresh-control-${i}`);
  control("after-control");
  return requests.map((request, i) => ({ sequence: i + 1, ...request }));
}
