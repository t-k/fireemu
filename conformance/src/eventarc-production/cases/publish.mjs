import { acceptance, bisect, bracket } from "../bisect.mjs";
import {
  baseAttributes,
  CE_TYPE,
  cloudEvent,
  requireChannel,
  without,
  withoutAttribute,
} from "./support.mjs";

// The envelope: the shapes of a publish request and of the events in it, on an owned channel that exists
// (the case stops, with the reason, when it cannot be created).

export const publishEnvelope = {
  id: "publish-envelope",
  short: "pe",
  requests: 44,
  async run(ctx) {
    const c = ctx.client;
    const channel = await requireChannel(ctx, "env");
    const event = () => cloudEvent(ctx);
    await c.publishEvents(channel, { events: [event()] });
    await c.publishEvents(channel, { events: [event(), event(), event()] });
    await c.publishEvents(channel, { events: [] });
    await c.publishEvents(channel, {});
    for (const missing of ["id", "type", "source", "specVersion"])
      await c.publishEvents(channel, { events: [without(event(), missing)] });
    await c.publishEvents(channel, { events: [withoutAttribute(event(), "time")] });
    await c.publishEvents(channel, { events: [withoutAttribute(event(), "datacontenttype")] });
    await c.publishEvents(channel, {
      events: [
        {
          ...event(),
          attributes: { ...baseAttributes(), time: { ceString: "2026-10-05T00:00:00Z" } },
        },
      ],
    });
    await c.publishEvents(channel, {
      events: [{ ...event(), attributes: { ...baseAttributes(), extra: { ceFoo: "x" } } }],
    });
    await c.publishEvents(channel, {
      events: [{ ...event(), attributes: { ...baseAttributes("application/json", "not-a-time") } }],
    });
    await c.publishEvents(channel, {
      events: [{ ...event(), "@type": "type.googleapis.com/google.protobuf.Empty" }],
    });
    await c.publishEvents(channel, { events: [without(event(), "@type")] });
    await c.publishEvents(channel, { events: [{ ...event(), noSuchMember: 1 }] });
    // A well-formed event with an extension attribute and a subject.
    await c.publishEvents(channel, {
      events: [
        {
          ...event(),
          attributes: { ...baseAttributes(), subject: { ceString: "s" }, extra: { ceString: "x" } },
        },
      ],
    });
    // The same event published twice (the same id).
    const repeated = event();
    await c.publishEvents(channel, { events: [repeated] });
    await c.publishEvents(channel, { events: [repeated] });
    // The same id twice inside one request, an event that is only its type URL, and the attribute kinds
    // other than a string and a timestamp.
    await c.publishEvents(channel, { events: [repeated, repeated] });
    await c.publishEvents(channel, { events: [{ "@type": CE_TYPE }] });
    await c.publishEvents(channel, {
      events: [
        {
          ...event(),
          attributes: {
            ...baseAttributes(),
            flag: { ceBoolean: true },
            count: { ceInteger: 1 },
            link: { ceUri: "https://example.com/x" },
            relative: { ceUriRef: "/x" },
            bytes: { ceBytes: "AAE=" },
          },
        },
      ],
    });
  },
};

export const publishContent = {
  id: "publish-content",
  short: "pc",
  requests: 24,
  async run(ctx) {
    const c = ctx.client;
    const channel = await requireChannel(ctx, "content");
    const json = (textData) => cloudEvent(ctx, { textData });
    await c.publishEvents(channel, { events: [json('{"a":1,"b":[true,null]}')] });
    await c.publishEvents(channel, { events: [json("1")] });
    await c.publishEvents(channel, { events: [json("null")] });
    await c.publishEvents(channel, { events: [json("[1,2,3]")] });
    await c.publishEvents(channel, { events: [json("{")] });
    await c.publishEvents(channel, {
      events: [
        cloudEvent(ctx, { textData: "plain text", attributes: baseAttributes("text/plain") }),
      ],
    });
    await c.publishEvents(channel, {
      events: [
        cloudEvent(ctx, {
          textData: undefined,
          binaryData: Buffer.from([0, 1, 2, 255]).toString("base64"),
          attributes: baseAttributes("application/octet-stream"),
        }),
      ],
    });
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx, { textData: undefined, binaryData: "***not base64***" })],
    });
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx, { binaryData: Buffer.from("x").toString("base64") })],
    });
    await c.publishEvents(channel, { events: [without(cloudEvent(ctx), "textData")] });
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx, { textData: "", attributes: baseAttributes("text/plain") })],
    });
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx, { textData: "x", attributes: baseAttributes("application/xml") })],
    });
  },
};

// The limits against a channel that exists. Each is a search between a value known to be accepted and one
// known to be refused, with a fixed number of requests (see ../bisect.mjs), so that the boundary is found
// and not assumed. The events are tiny or one large text, to a channel that has no trigger, so nothing is
// delivered. An answer that does not say whether a value was accepted ends its search; nothing is re-sent.
const KiB = 1024;
const MiB = KiB * KiB;
/** Stage A: 256 events were refused (OUT_OF_RANGE) and 8 events reached the channel lookup. */
const COUNT_LADDER = [8, 255, 256];
const COUNT_BISECT_STEPS = 8;
/** Stage A: a 256 KiB text passed the size check; a 1 MiB text was refused. The text length is the unit. */
const SIZE_LADDER = [256 * KiB, MiB, 4 * MiB];
const SIZE_BISECT_STEPS = 10;

export const publishLimits = {
  id: "publish-limits",
  short: "pl",
  requests: 40,
  async run(ctx) {
    const c = ctx.client;
    const channel = await requireChannel(ctx, "limits");
    const many = (n) => Array.from({ length: n }, () => cloudEvent(ctx, { textData: "1" }));
    const big = c.with({ timeoutMs: 120_000 });
    const search = async (name, start, ladder, steps, send) => {
      const accepts = async (value) => acceptance(await send(value));
      const bracketed = await bracket({ start, values: ladder, accepts });
      ctx.note("limit-bracket", { name, ...bracketed });
      if (bracketed.unknown || bracketed.high === null) return;
      const found = await bisect({ low: bracketed.low, high: bracketed.high, accepts, maxSteps: steps });
      ctx.note("limit-boundary", { name, ...found });
    };
    // The count of events in one request: one event is accepted (the envelope case), 256 was refused.
    await search("event-count", 1, COUNT_LADDER, COUNT_BISECT_STEPS, (n) =>
      c.publishEvents(channel, { events: many(n) }),
    );
    // The size of one event, by the length of its text (the request is a little larger: see requestBytes).
    await search("event-text-length", 1, SIZE_LADDER, SIZE_BISECT_STEPS, (size) =>
      big.publishEvents(channel, {
        events: [cloudEvent(ctx, { textData: JSON.stringify("x".repeat(size - 2)) })],
      }),
    );
    // The request size over several events: 8 events of 128 KiB and of 1 MiB.
    for (const each of [128 * KiB, MiB])
      await big.publishEvents(channel, {
        events: Array.from({ length: 8 }, () =>
          cloudEvent(ctx, { textData: JSON.stringify("x".repeat(each - 2)) }),
        ),
      });
    // Attributes: the number of them and the length of a name.
    const extras = (n, name = (i) => `ext${i}`) =>
      Object.fromEntries(Array.from({ length: n }, (_, i) => [name(i), { ceString: "v" }]));
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx, { attributes: { ...baseAttributes(), ...extras(100) } })],
    });
    await c.publishEvents(channel, {
      events: [
        cloudEvent(ctx, {
          attributes: { ...baseAttributes(), [`n${"a".repeat(255)}`]: { ceString: "v" } },
        }),
      ],
    });
    // A batch with one invalid event among valid ones: is the rest delivered?
    await c.publishEvents(channel, {
      events: [cloudEvent(ctx), without(cloudEvent(ctx), "type"), cloudEvent(ctx)],
    });
  },
};
