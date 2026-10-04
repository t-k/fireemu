// The Admin SDK publish (firebase-admin getEventarc().channel().publish()). The SDK builds the URL and the
// body itself; it is pointed at a loopback forwarder through CLOUD_EVENTARC_EMULATOR_HOST, which is the
// SDK's own switch for another host. The forwarder is made for one case and closed right after it:
//
// - it listens on 127.0.0.1 on an ephemeral port, and only under a path token that exists for this
//   forwarder, so another local process cannot use it;
// - it answers only while a `publish()` is in progress, and only `POST` to
//   `/projects/<project>/locations/<location>/channels/<id>:publishEvents`;
// - the channel is checked with `ownership.assertPublishable` before anything is sent;
// - one request is forwarded for each `publish()`: the SDK retries a 503 up to four times, and every
//   retry is answered here with a 409, which it does not retry, and never sent (note
//   `sdk-retry-suppressed`);
// - the request goes through the transport of the case, which counts it against the case's ceiling and the
//   run's budget; a ceiling or budget error ends the `publish()` by being thrown again (the SDK is
//   answered with a 400), so that the runner records it and cleans up.
//
// The SDK's credential is a function returning the gcloud token; its headers are not forwarded (the
// transport sets the authorization itself), so the recorded request carries the recorder's headers and
// not `X-Firebase-Client`.

import { randomBytes } from "node:crypto";
import { createServer } from "node:http";

const PUBLISH_PATH = /^\/projects\/([^/]+)\/locations\/([^/]+)\/channels\/([^/:]+):publishEvents$/;

const answer = (response, status, body) => {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify(body));
};

export async function createSdk({
  project,
  runId,
  caseId,
  getToken,
  transport,
  ownership,
  publishPrefix,
  note = () => {},
  importer = (name) => import(name),
}) {
  const { initializeApp, deleteApp } = await importer("firebase-admin/app");
  const { getEventarc } = await importer("firebase-admin/eventarc");
  const token = randomBytes(12).toString("hex");
  let active = null;
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", async () => {
      const refuse = (status, why) => {
        note("sdk-refused", { why });
        answer(response, status, { error: { status: "FAILED_PRECONDITION", message: why } });
      };
      try {
        if (active === null) return refuse(403, "no publish is in progress");
        const prefix = `/${token}`;
        const url = String(request.url);
        if (request.method !== "POST" || !url.startsWith(`${prefix}/`))
          return refuse(404, "not the publish route of this forwarder");
        const match = PUBLISH_PATH.exec(url.slice(prefix.length));
        if (match === null || match[1] !== project)
          return refuse(404, "not a publish route of the project");
        const channel = `projects/${match[1]}/locations/${match[2]}/channels/${match[3]}`;
        ownership.assertPublishable(channel);
        if (active.forwarded >= 1) {
          // The SDK retried (it does so on a 503): the retry is never sent.
          active.suppressed += 1;
          note("sdk-retry-suppressed", { channel });
          return answer(response, 409, {
            error: { status: "ABORTED", message: "retry suppressed" },
          });
        }
        active.forwarded += 1;
        let body;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          body = undefined;
        }
        const reply = await transport.request({
          label: { case: caseId, step: `s${String(active.number).padStart(2, "0")}-1` },
          op: "sdk.publishEvents",
          method: "POST",
          path: `${publishPrefix}/${channel}:publishEvents`,
          body,
        });
        return answer(response, reply.status ?? 502, reply.body ?? {});
      } catch (error) {
        // The SDK is answered here, and the error is raised again by the publish() that is waiting.
        if (active !== null) active.error = active.error ?? error;
        return answer(response, 400, { error: { status: "INVALID_ARGUMENT", message: "stopped" } });
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const host = `http://127.0.0.1:${server.address().port}/${token}`;
  const app = initializeApp(
    {
      projectId: project,
      credential: {
        getAccessToken: async () => ({ access_token: await getToken(), expires_in: 3000 }),
      },
    },
    `fe-${runId}-${token}`,
  );
  let counter = 0;
  let closed = false;
  return Object.freeze({
    host,
    /**
     * Publishes with the SDK and says what happened: whether the SDK threw (and its code and message),
     * how many requests it sent, and how many retries were suppressed. A ceiling or budget error that
     * stopped the forwarder is thrown here.
     */
    async publish({ channel, channelOptions, events, source }) {
      if (closed) throw new Error("the SDK forwarder of this case is closed");
      counter += 1;
      active = { number: counter, forwarded: 0, suppressed: 0, error: null };
      const previousHost = process.env.CLOUD_EVENTARC_EMULATOR_HOST;
      const previousSource = process.env.EVENTARC_CLOUD_EVENT_SOURCE;
      process.env.CLOUD_EVENTARC_EMULATOR_HOST = host;
      if (source === undefined) delete process.env.EVENTARC_CLOUD_EVENT_SOURCE;
      else process.env.EVENTARC_CLOUD_EVENT_SOURCE = source;
      const outcome = { threw: false };
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
      const finished = active;
      active = null;
      if (finished.error !== null) throw finished.error;
      return { ...outcome, requests: finished.forwarded, suppressed: finished.suppressed };
    },
    async close() {
      if (closed) return;
      closed = true;
      active = null;
      await deleteApp(app);
      await new Promise((resolve) => server.close(resolve));
    },
  });
}
