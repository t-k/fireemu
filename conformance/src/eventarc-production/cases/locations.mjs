// What a location the service does not serve answers, and what a channel in another real location and an
// operation that was never issued answer. Reads only: nothing is created, so nothing is left behind.
// Stage B knew `europe-west1` (served, empty) and `us-east99` (a 403).
const REAL = ["asia-northeast1", "us-east1", "us-west1", "europe-west4"];
const INVENTED = [
  "us-east99",
  "us-central9",
  "europe-north99",
  "asia-south9",
  "global",
  "US-CENTRAL1",
];

export const locations = {
  id: "locations",
  short: "lc",
  requests: 15,
  async run(ctx) {
    const c = ctx.client;
    for (const location of [...REAL, ...INVENTED]) await c.listChannels(ctx.project, location);
    await c.getChannel(
      `projects/${ctx.project}/locations/asia-northeast1/channels/${ctx.ownership.prefix}lc-none`,
    );
    for (const operation of [
      `projects/${ctx.project}/locations/${ctx.location}/operations/operation-0-0-0-0`,
      `projects/${ctx.project}/locations/europe-west1/operations/operation-0-0-0-0`,
      `projects/${ctx.project}/locations/${ctx.location}/operations/x`,
    ])
      await c.getOperation("eventarc", operation);
  },
};
