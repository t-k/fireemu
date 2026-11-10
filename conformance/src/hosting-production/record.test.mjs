import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import test from "node:test";

import { createWorld } from "./world.mjs";

const root = "https://firebasehosting.googleapis.com/v1beta1";
const site = "fireemu-oracle-idp";
const request = (world, method, url, body) =>
  world.http({ method, url, body: body === undefined ? undefined : JSON.stringify(body) });

test("the fake API deploys and deletes a channel and version", async () => {
  const world = createWorld({ run: "123abc", secrets: { apiKey: "private-value" } });
  const channels = `${root}/projects/-/sites/${site}/channels`;
  const channelId = "hst-123abc-v01";
  const channel = JSON.parse(
    (
      await request(world, "POST", `${channels}?channelId=${channelId}`, {
        labels: { "fireemu-run": "123abc" },
      })
    ).text,
  );
  const version = JSON.parse(
    (
      await request(world, "POST", `${root}/projects/-/sites/${site}/versions`, {
        labels: { "fireemu-run": "123abc" },
      })
    ).text,
  );
  const population = JSON.parse(
    (
      await request(world, "POST", `${root}/${version.name}:populateFiles`, {
        files: { "/ready.txt": "hash" },
      })
    ).text,
  );
  assert.deepEqual(population.uploadRequiredHashes, ["hash"]);
  await world.http({
    method: "POST",
    url: `${population.uploadUrl}/hash`,
    body: gzipSync("ready"),
  });
  assert.equal(
    (
      await request(world, "PATCH", `${root}/${version.name}?updateMask=status,config`, {
        status: "FINALIZED",
        config: {},
      })
    ).status,
    200,
  );
  await request(
    world,
    "POST",
    `${channels}/${channelId}/releases?versionName=${encodeURIComponent(version.name)}`,
    {},
  );
  const answer = await world.edge({
    method: "GET",
    host: new URL(channel.url).host,
    target: "/ready.txt",
  });
  assert.equal(answer.status, 200);
  assert.equal(answer.body.toString(), "ready");
  const info = JSON.parse((await request(world, "GET", `${root}/${version.name}`)).text);
  assert.equal(info.fileCount, "3");
  await request(world, "DELETE", `${channels}/${channelId}`);
  await request(world, "DELETE", `${root}/${version.name}`);
  assert.equal(
    (await world.edge({ method: "GET", host: new URL(channel.url).host, target: "/ready.txt" }))
      .status,
    404,
  );
});

test("fault overrides apply to their selected call only", async () => {
  const world = createWorld({
    run: "123abc",
    secrets: {},
    overrides: [{ match: "GET /channels/", nth: 2, answer: "timeout" }],
  });
  const url = `${root}/projects/-/sites/${site}/channels`;
  assert.equal((await request(world, "GET", url)).status, 200);
  assert.equal((await request(world, "GET", url)).status, 0);
  assert.equal((await request(world, "GET", url)).status, 200);
});
