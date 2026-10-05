import {
  acceptance,
  bisect,
  isAttributeCountRefusal,
  isAttributeKeyRefusal,
  isSizeRefusal,
  stepsNeeded,
} from "../bisect.mjs";
import {
  baseAttributes,
  cloudEvent,
  requireReadyChannel,
  without,
  withoutAttribute,
} from "./support.mjs";

// The boundaries stage B bracketed but did not pin, and the order of the checks when an event has two
// defects at once. Every search starts from the values stage B recorded (a text of 524032 characters
// passed and 524800 was refused; 106 attributes and a key of 259 bytes were refused) and asks again for
// the bracket's ends, so that a bracket that moved ends only its own search (`bracket-moved`) and is
// reported, never assumed. Each search sends at most the steps its interval needs.
const TEXT_LOW = 524_032;
const TEXT_HIGH = 524_800;
const EXTRAS_HIGH = 100;
const NAME_HIGH = 256;

const extras = (count, name = (index) => `ext${index}`) =>
  Object.fromEntries(Array.from({ length: count }, (_, index) => [name(index), { ceString: "v" }]));

export const publishBoundaries = {
  id: "publish-boundaries",
  short: "pb",
  requests: 54,
  async run(ctx) {
    const c = ctx.client;
    const channel = await requireReadyChannel(ctx, "b");
    const big = c.with({ timeoutMs: 120_000 });
    const pin = async (name, { low, high, steps, isRefusal, send, confirmLow }) => {
      const accepts = async (value) => acceptance(await send(value), isRefusal);
      const lowAccepted = confirmLow ? await accepts(low) : true;
      const highAccepted = await accepts(high);
      if (lowAccepted !== true || highAccepted !== false) {
        ctx.note("bracket-moved", { name, low, high, lowAccepted, highAccepted });
        return;
      }
      const found = await bisect({ low, high, accepts, maxSteps: steps });
      ctx.note("limit-boundary", { name, ...found });
    };
    await pin("event-text-length", {
      low: TEXT_LOW,
      high: TEXT_HIGH,
      steps: stepsNeeded(TEXT_HIGH - TEXT_LOW),
      isRefusal: isSizeRefusal,
      confirmLow: true,
      send: (size) =>
        big.publishEvents(channel, {
          events: [cloudEvent(ctx, { textData: JSON.stringify("x".repeat(size - 2)) })],
        }),
    });
    await pin("extra-attributes", {
      low: 0,
      high: EXTRAS_HIGH,
      steps: stepsNeeded(EXTRAS_HIGH),
      isRefusal: isAttributeCountRefusal,
      confirmLow: false,
      send: (count) =>
        c.publishEvents(channel, {
          events: [cloudEvent(ctx, { attributes: { ...baseAttributes(), ...extras(count) } })],
        }),
    });
    await pin("attribute-name-length", {
      low: 1,
      high: NAME_HIGH,
      steps: stepsNeeded(NAME_HIGH - 1),
      isRefusal: isAttributeKeyRefusal,
      confirmLow: false,
      send: (length) =>
        c.publishEvents(channel, {
          events: [
            cloudEvent(ctx, {
              attributes: {
                ...baseAttributes(),
                [`n${"a".repeat(length - 1)}`]: { ceString: "v" },
              },
            }),
          ],
        }),
    });
    // The order of the checks when an event has two defects at once. Each request has exactly the two
    // defects named; which one the answer names says which check comes first.
    const event = () => cloudEvent(ctx);
    const asString = (item) => ({
      ...item,
      attributes: { ...item.attributes, time: { ceString: "2026-10-05T00:00:00Z" } },
    });
    // A missing id and a missing content type.
    await c.publishEvents(channel, {
      events: [withoutAttribute(without(event(), "id"), "datacontenttype")],
    });
    // A missing source and a time that is a string.
    await c.publishEvents(channel, { events: [asString(without(event(), "source"))] });
    // A time that is a string and a content type that is not JSON.
    await c.publishEvents(channel, {
      events: [asString({ ...event(), attributes: baseAttributes("application/xml") })],
    });
    // Over 100 events, each without a type: the count or the events first?
    await c.publishEvents(channel, {
      events: Array.from({ length: 101 }, () =>
        without(cloudEvent(ctx, { textData: "1" }), "type"),
      ),
    });
    // An event that is too large (and has no id), one with too many attributes (no id), one with a key
    // that is too long (no id): the quota or the required attribute first?
    await big.publishEvents(channel, {
      events: [without(cloudEvent(ctx, { textData: JSON.stringify("x".repeat(600_000)) }), "id")],
    });
    await c.publishEvents(channel, {
      events: [
        without(
          cloudEvent(ctx, { attributes: { ...baseAttributes(), ...extras(EXTRAS_HIGH) } }),
          "id",
        ),
      ],
    });
    await c.publishEvents(channel, {
      events: [
        without(
          cloudEvent(ctx, {
            attributes: {
              ...baseAttributes(),
              [`n${"a".repeat(NAME_HIGH - 1)}`]: { ceString: "v" },
            },
          }),
          "id",
        ),
      ],
    });
    // The same source and id twice, the second without a content type: the duplicate or the defect first?
    const first = event();
    await c.publishEvents(channel, { events: [first, withoutAttribute(first, "datacontenttype")] });
  },
};
