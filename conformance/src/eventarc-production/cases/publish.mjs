import {
  baseAttributes,
  cloudEvent,
  createOwnedChannel,
  without,
  withoutAttribute,
} from "./support.mjs";

// The envelope: the shapes of a publish request and of the events in it, on an owned channel. If the
// channel cannot be created the publishes go to the owned name anyway, which records the answer for a
// channel that does not exist.
async function channelOrName(ctx, key) {
  return (await createOwnedChannel(ctx, key)) ?? ctx.channel(`${key}-absent`);
}

export const publishEnvelope = {
  id: "publish-envelope",
  short: "pe",
  requests: 32,
  async run(ctx) {
    const c = ctx.client;
    const channel = await channelOrName(ctx, "env");
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
  },
};

export const publishContent = {
  id: "publish-content",
  short: "pc",
  requests: 24,
  async run(ctx) {
    const c = ctx.client;
    const channel = await channelOrName(ctx, "content");
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

// The limits are not known: each is a ladder, so that the first refusal is found and not assumed. The
// events are tiny or one large text, to a channel that has no trigger, so nothing is delivered.
const KiB = 1024;
const MiB = KiB * KiB;

export const publishLimits = {
  id: "publish-limits",
  short: "pl",
  requests: 24,
  async run(ctx) {
    const c = ctx.client;
    const channel = await channelOrName(ctx, "limits");
    const many = (n) => Array.from({ length: n }, () => cloudEvent(ctx, { textData: "1" }));
    for (const n of [256, 257, 1000]) await c.publishEvents(channel, { events: many(n) });
    const big = c.with({ timeoutMs: 120_000 });
    for (const size of [256 * KiB, MiB, 4 * MiB, 10 * MiB])
      await big.publishEvents(channel, {
        events: [cloudEvent(ctx, { textData: JSON.stringify("x".repeat(size - 2)) })],
      });
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
