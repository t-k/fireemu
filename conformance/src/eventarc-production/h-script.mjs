import { baseAttributes, CE_TYPE } from "./cases/support.mjs";
import { randomBytes } from "node:crypto";

export const H_LIMITS = Object.freeze({
  preflight: 56,
  readiness: 2035,
  publish: 48,
  capture: 120,
  cleanup: 224,
  a2: 62,
});

export function hManifest({
  project,
  runId = randomBytes(6).toString("hex"),
  recording = "h1",
  segment = "core",
}) {
  if (
    !/^[a-f0-9]{12}$/.test(runId) ||
    !/^[a-z][a-z0-9-]{4,62}$/.test(project) ||
    !["h1", "h2-a", "h2-b"].includes(recording)
  )
    throw new Error("invalid H project or run ID");
  const m = {
    project,
    runId,
    recording,
    location: "us-central1",
    observe: `fe${runId}HObserve`,
    filtered: `fe${runId}HFiltered`,
    type: `fireemu.h.${runId}`,
    filteredType: `fireemu.h.${runId}.filtered`,
    source: `//fireemu/handler/${runId}`,
    tenant: `h${runId}`,
    channel: `projects/${project}/locations/us-central1/channels/firebase`,
    markerCollection: `fe_h_${runId}`,
    propagationMs: 300_000,
  };
  if (recording !== "h1") {
    Object.assign(m, {
      segment,
      fanout: `fe${runId}HFanout`,
      named: `fe${runId}HNamed`,
      extension: `fe${runId}HExtension`,
      multi: `fe${runId}HMulti`,
      sourceProbe: `fe${runId}HSource`,
      namedChannelId: `fe${runId}-h-named`,
      namedChannel: `projects/${project}/locations/us-central1/channels/fe${runId}-h-named`,
      subject: `h${runId}-subject`,
      reserveUsd: recording === "h2-a" ? 7 : 6,
      estimatedUsd: recording === "h2-a" ? 3.5 : 3,
      wallMs: 9 * 60 * 60_000,
      // Reserve thirty minutes for cleanup, bounded operation waits and separately admitted A2.
      cleanupReserveMs: 30 * 60_000,
      limits: {
        preflight: 69,
        readiness: recording === "h2-a" ? 7210 : 6165,
        publish: 97,
        capture: 500,
        cleanup: recording === "h2-a" ? 672 : 591,
        a2: 105,
      },
    });
    m.functions = [
      {
        name: m.observe,
        type: m.type,
        filters: {},
        channel: m.channel,
        retry: true,
        segment: "core",
      },
      {
        name: m.filtered,
        type: m.filteredType,
        filters: {},
        channel: m.channel,
        retry: false,
        segment: "core",
      },
      {
        name: m.fanout,
        type: m.type,
        filters: {},
        channel: m.channel,
        retry: false,
        segment: "core",
      },
      {
        name: m.named,
        type: m.type,
        filters: {},
        channel: m.namedChannel,
        retry: false,
        segment: "core",
      },
      {
        name: m.extension,
        type: `${m.type}.extension`,
        filters: { tenant: m.tenant },
        channel: m.channel,
        retry: false,
        segment: "extension",
      },
      {
        name: m.multi,
        type: `${m.type}.multi`,
        filters: { tenant: m.tenant, subject: m.subject },
        channel: m.channel,
        retry: false,
        segment: "multi",
      },
      // The coordinator binds the complete recorded v4 type/source/tenant construction.
      ...(recording === "h2-a"
        ? [
            {
              name: m.sourceProbe,
              type: m.type,
              filters: { source: m.source, tenant: m.tenant },
              channel: m.channel,
              retry: false,
              segment: "source",
            },
          ]
        : []),
    ];
    if (!m.functions.some((f) => f.segment === segment)) throw new Error("invalid H2 segment");
  }
  return m;
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
  const control = (caseId) =>
    add(caseId, [event(caseId), event(caseId, { type: m.filteredType })], { control: true });
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
    if (m.functions && ["scalar", "null"].includes(name))
      bracket(name, [event(name, { textData })], { shape: true });
    else add(name, [event(name, { textData })]);
  const binary = event("binary", { binaryData: "AAEC/w==" });
  delete binary.textData;
  binary.attributes.datacontenttype = { ceString: "application/octet-stream" };
  if (m.functions) bracket("binary", [binary], { shape: true });
  else add("binary", [binary]);
  const mixed = [
    event("multi-match", { type: m.filteredType }),
    event("multi-source-miss", { source: `${m.source}/miss` }),
    event("multi-tenant-miss"),
  ];
  mixed[2].attributes.tenant.ceString = `${m.tenant}-miss`;
  add("multi", mixed);
  const noTime = event("no-time");
  delete noTime.attributes.time;
  bracket("no-time", [noTime], m.functions ? {} : { negativeHandlers: [m.observe, m.filtered] });
  const bytes = event("ce-bytes");
  bytes.attributes.convbytes = { ceBytes: "AAE=" };
  bracket("ce-bytes", [bytes], m.functions ? {} : { negativeHandlers: [m.observe, m.filtered] });
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
      data: { run: m.runId, recording: m.recording, case: caseId },
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
          recording: m.recording,
          case: "retry",
        }),
      }),
    ],
    { windowMs: 600_000, retry: true },
  );
  for (let i = 1; i <= 4; i++) control(`fresh-control-${i}`);
  control("after-control");
  if (m.functions) {
    const text = event("text", { textData: "H2 text bytes\n" });
    text.attributes.datacontenttype = { ceString: "text/plain" };
    bracket("text", [text], { shape: true });
    for (const channel of [m.channel, m.namedChannel]) {
      const name = channel === m.channel ? "isolation-default" : "isolation-named";
      for (const position of ["before", "after"]) {
        for (const [index, target] of [m.channel, m.namedChannel].entries()) {
          const caseId = `${name}-${position}-${index === 0 ? "default" : "named"}`;
          control(caseId);
          Object.assign(requests.at(-1), {
            channel: target,
            bracket: name,
            position,
            controlWaitMs: index === 0 ? 0 : 120_000,
          });
        }
        if (position === "before")
          add(name, [event(name)], { channel, bracket: name, windowMs: 120_000 });
      }
    }
    for (const segment of ["extension", "multi"]) {
      const f = m.functions.find((f) => f.segment === segment);
      for (const variant of [
        "match",
        "wrong-type",
        "wrong-tenant",
        "missing-tenant",
        ...(segment === "multi" ? ["wrong-subject", "missing-subject"] : []),
      ]) {
        const name = `${segment}-${variant}`;
        for (const position of ["before", "after"]) {
          const caseId = `${name}-${position}`;
          control(caseId);
          const positive = event(caseId, { type: f.type });
          if (segment === "multi") positive.attributes.subject.ceString = m.subject;
          requests.at(-1).body.events.push(positive);
          Object.assign(requests.at(-1), { segment, bracket: name, position });
          if (position === "before") {
            const subject = event(name, { type: f.type });
            if (segment === "multi") subject.attributes.subject.ceString = m.subject;
            if (variant === "wrong-type") subject.type += ".miss";
            if (variant === "wrong-tenant") subject.attributes.tenant.ceString += "-miss";
            if (variant === "missing-tenant") delete subject.attributes.tenant;
            if (variant === "wrong-subject") subject.attributes.subject.ceString += "-miss";
            if (variant === "missing-subject") delete subject.attributes.subject;
            add(name, [subject], { segment, bracket: name, windowMs: 120_000 });
          }
        }
      }
    }
    for (const p of requests) {
      p.segment ??= "core";
      if (!p.sdk) p.channel ??= m.channel;
      if (p.control) p.controlWaitMs ??= 120_000;
      if (!p.bracket && /-(before|after)$/.test(p.case)) {
        p.bracket = p.case.replace(/-(before|after)$/, "");
        p.position = p.case.endsWith("-before") ? "before" : "after";
      }
      if (p.windowMs && !p.retry) p.bracket ??= p.case;
      const forbidden = p.negativeHandlers?.length || p.refused;
      const recipients = (p.body?.events ?? []).flatMap((e) =>
        m.functions
          .filter(
            (f) =>
              f.segment !== "source" &&
              (f.segment === "core" || f.segment === p.segment) &&
              f.channel === p.channel &&
              f.type === e.type &&
              Object.entries(f.filters).every(
                ([key, value]) =>
                  (key === "source" ? e.source : e.attributes[key]?.ceString) === value,
              ),
          )
          .filter(
            (f) =>
              !forbidden ||
              p.positiveHandlers?.includes(f.name) ||
              (f.name === m.fanout && p.positiveHandlers?.includes(m.observe)),
          )
          .map((f) => ({ handler: f.name, id: e.id, source: e.source })),
      );
      p.expectedRecipients = recipients;
      if (p.negativeHandlers?.includes(m.observe)) p.negativeHandlers.push(m.fanout);
    }
  }
  return requests.map((request, i) => ({ sequence: i + 1, ...request }));
}
