// The Admin SDK publish (firebase-admin getEventarc().channel().publish()). The SDK builds the URL and the
// body itself; it is pointed at a loopback forwarder through CLOUD_EVENTARC_EMULATOR_HOST, which is the
// SDK's own switch for another host. The forwarder sends each request on through the recorder's publishing
// transport, so that it is counted against the budget and captured like every other request, and answers
// the SDK with what came back. The SDK's credential is a function returning the gcloud token; its headers
// are not forwarded (the transport sets the authorization itself). A request the SDK refuses before it is
// sent never reaches the forwarder, and the outcome says so.

import { createServer } from "node:http";

export async function createSdk({
  project,
  runId,
  getToken,
  publishing,
  publishPrefix,
  importer = (name) => import(name),
}) {
  const { initializeApp, deleteApp } = await importer("firebase-admin/app");
  const { getEventarc } = await importer("firebase-admin/eventarc");
  let label = { case: "sdk", step: "s00" };
  let forwarded = 0;
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", async () => {
      forwarded += 1;
      let body;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        body = undefined;
      }
      const reply = await publishing.request({
        label: { ...label, step: `${label.step}-${forwarded}` },
        op: "sdk.publishEvents",
        method: request.method,
        path: `${publishPrefix}${request.url}`,
        body,
      });
      response.statusCode = reply.status ?? 502;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(reply.body ?? {}));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const host = `http://127.0.0.1:${server.address().port}`;
  const app = initializeApp(
    {
      projectId: project,
      credential: {
        getAccessToken: async () => ({ access_token: await getToken(), expires_in: 3000 }),
      },
    },
    `fe-${runId}`,
  );
  let counter = 0;
  return Object.freeze({
    host,
    /**
     * Publishes with the SDK and says what happened: whether the SDK threw (and its code and message)
     * and how many requests it sent.
     */
    async publish({ channel, channelOptions, events, source, caseId }) {
      counter += 1;
      label = { case: caseId, step: `s${String(counter).padStart(2, "0")}` };
      forwarded = 0;
      const previousHost = process.env.CLOUD_EVENTARC_EMULATOR_HOST;
      const previousSource = process.env.EVENTARC_CLOUD_EVENT_SOURCE;
      process.env.CLOUD_EVENTARC_EMULATOR_HOST = host;
      if (source === undefined) delete process.env.EVENTARC_CLOUD_EVENT_SOURCE;
      else process.env.EVENTARC_CLOUD_EVENT_SOURCE = source;
      const outcome = { requests: 0, threw: false };
      try {
        const eventarc = getEventarc(app);
        const target =
          channel === undefined ? eventarc.channel() : eventarc.channel(channel, channelOptions);
        await target.publish(events);
      } catch (error) {
        outcome.threw = true;
        outcome.error = {
          name: error?.name ?? "Error",
          code: error?.code ?? null,
          message: String(error?.message ?? error).slice(0, 300),
          status: error?.httpResponse?.status ?? null,
        };
      } finally {
        if (previousHost === undefined) delete process.env.CLOUD_EVENTARC_EMULATOR_HOST;
        else process.env.CLOUD_EVENTARC_EMULATOR_HOST = previousHost;
        if (previousSource === undefined) delete process.env.EVENTARC_CLOUD_EVENT_SOURCE;
        else process.env.EVENTARC_CLOUD_EVENT_SOURCE = previousSource;
      }
      outcome.requests = forwarded;
      return outcome;
    },
    async close() {
      await deleteApp(app);
      await new Promise((resolve) => server.close(resolve));
    },
  });
}
