// A table-driven test of the Gen2 source upload helper over the pairwise combinations of the
// factors that decide a deploy's outcome (PICT model gen2-upload-cleanup.pict, pairwise, with the
// mandatory combinations of gen2-upload-cleanup.seed.tsv): object arrived or not, the PUT's own status line, CLI ended by
// itself or was killed, metadata answer, DELETE answer, read-back answer, a new foreign object or a
// bucket grown past the page bound, a failing after-list, a short budget.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  FAKE_BUCKET,
  FAKE_PROJECT_NUMBER,
  FAKE_REGION,
  answer,
  createFakeGcs,
} from "./gen2-source-uploads.fake.mjs";
import { UPLOAD_BOUNDS, openSourceUploads } from "./gen2-source-uploads.mjs";

const OBJECT = "9be229fd-1507-4797-ab4b-69f2fda6e54a.zip";
const OTHER = "11111111-2222-4333-8444-555555555555.zip";
const FOREIGN = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee.zip";

const TABLE = `
object	put	cli	meta	delete	readback	extra	list	budget
present	ok	exited	ok	ok204	absent404	none	ok	ok
present	none	exited	ok	ok204	absent404	none	ok	ok
absent	refused	exited	ok	ok204	absent404	none	ok	ok
absent	none	exited	ok	ok204	absent404	none	ok	ok
absent	ok	exited	ok	ok204	absent404	none	ok	ok
absent	unavailable	killed	ok	ok204	absent404	none	ok	ok
absent	refused	killed	ok	ok204	absent404	none	ok	ok
present	ok	killed	ok	ok204	absent404	none	ok	ok
present	ok	exited	ok	conflict412	absent404	none	ok	ok
present	ok	exited	ok	gone404	absent404	none	ok	ok
present	ok	exited	ok	ok204	present200	none	ok	ok
present	ok	exited	ok	ok204	absent404	foreign	ok	ok
present	ok	exited	ok	ok204	absent404	none	ok	short
present	none	killed	ok	gone404	absent404	foreign	unavailable	ok
present	none	killed	ok	forbidden403	absent404	none	ok	short
present	ok	exited	ok	throws	absent404	foreign	unavailable	ok
present	ok	exited	ok	unavailable503	absent404	grown	unavailable	ok
present	none	killed	ok	stayed204	absent404	grown	ok	ok
present	none	exited	forbidden	ok204	absent404	foreign	unavailable	ok
present	none	killed	ok	unavailable503	absent404	none	ok	short
present	none	killed	ok	conflict412	absent404	grown	unavailable	ok
present	none	exited	wrongname	ok204	absent404	none	ok	short
present	ok	exited	unavailable	ok204	absent404	none	ok	short
present	ok	exited	ok	stayed204	absent404	none	ok	short
present	ok	exited	ok	ok204	unavailable503	grown	unavailable	ok
present	ok	exited	throws	ok204	absent404	none	ok	short
present	none	killed	throws	ok204	absent404	foreign	unavailable	ok
present	ok	exited	ok	gone404	absent404	grown	unavailable	ok
present	none	killed	unavailable	ok204	absent404	grown	unavailable	ok
present	none	exited	ok	unavailable503	absent404	foreign	unavailable	ok
present	ok	exited	throws	ok204	absent404	grown	unavailable	ok
present	none	killed	ok	throws	absent404	none	ok	short
present	ok	exited	ok	forbidden403	absent404	grown	unavailable	ok
present	ok	killed	forbidden	ok204	absent404	none	ok	short
absent	refused	exited	ok	ok204	absent404	grown	unavailable	ok
present	none	killed	ok	ok204	unavailable503	none	ok	short
present	ok	killed	wrongname	ok204	absent404	grown	unavailable	ok
present	none	exited	ok	stayed204	absent404	foreign	unavailable	ok
present	ok	exited	ok	forbidden403	absent404	foreign	unavailable	ok
absent	unavailable	exited	ok	ok204	absent404	foreign	unavailable	ok
present	none	killed	wrongname	ok204	absent404	foreign	unavailable	ok
present	ok	killed	ok	ok204	unavailable503	foreign	ok	ok
present	ok	exited	forbidden	ok204	absent404	grown	unavailable	ok
absent	refused	killed	ok	ok204	absent404	foreign	unavailable	ok
present	none	exited	ok	conflict412	absent404	none	ok	short
present	none	killed	ok	ok204	present200	grown	unavailable	ok
present	none	killed	ok	conflict412	absent404	foreign	ok	ok
absent	refused	killed	ok	ok204	absent404	none	ok	short
present	none	killed	ok	throws	absent404	grown	unavailable	ok
present	none	exited	ok	ok204	present200	foreign	ok	ok
present	ok	killed	ok	ok204	present200	none	ok	short
present	none	exited	unavailable	ok204	absent404	foreign	ok	ok
absent	unavailable	killed	ok	ok204	absent404	grown	ok	ok
absent	unavailable	killed	ok	ok204	absent404	none	ok	short
present	none	exited	ok	gone404	absent404	none	ok	short
present	ok	exited	forbidden	ok204	absent404	none	unavailable	ok
`;

const [HEADER, ...ROWS] = TABLE.trim()
  .split("\n")
  .map((line) => line.split("\t"));

const META = {
  forbidden: answer(403),
  unavailable: answer(503),
  throws: new Error("reset"),
  wrongname: answer(200, { bucket: FAKE_BUCKET, name: OTHER, generation: "1" }),
};

async function runRow(row) {
  const f = Object.fromEntries(HEADER.map((name, index) => [name, row[index]]));
  const dir = mkdtempSync(join(tmpdir(), "gen2-pict-"));
  try {
    const world = createFakeGcs();
    world.put("base-0");
    world.put("base-1");
    let used = 0;
    let left = 1000;
    const uploads = openSourceUploads({
      ledgerPath: join(dir, "l.jsonl"),
      runId: "run-t",
      projectNumber: FAKE_PROJECT_NUMBER,
      region: FAKE_REGION,
      send: (method, url) => {
        used += 1;
        return world.send(method, url);
      },
      requestsLeft: () => left - used,
    });
    const deploy = await uploads.beginDeploy("p:http");
    if (f.object === "present") world.put(OBJECT);
    deploy.receipt({ bucket: FAKE_BUCKET, object: OBJECT });
    const putStatuses = { none: [], ok: [200], refused: [403], unavailable: [503] }[f.put];
    for (const status of putStatuses) {
      deploy.observe({ type: "put-status", bucket: FAKE_BUCKET, object: OBJECT, status });
    }
    if (f.extra === "foreign") world.put(FOREIGN);
    if (f.extra === "grown") {
      for (let i = 0; i < UPLOAD_BOUNDS.pageSize * UPLOAD_BOUNDS.maxPages; i += 1) {
        world.put(`grown-${String(i).padStart(5, "0")}`);
      }
    }
    const get = { method: "GET", url: `/o/${OBJECT}` };
    const del = { method: "DELETE", url: OBJECT };
    if (f.meta !== "ok") world.override(get, META[f.meta]);
    const effect = {
      gone404: () => world.remove(OBJECT),
      conflict412: () => world.put(OBJECT),
    }[f.delete];
    const replies = {
      gone404: answer(404),
      conflict412: answer(412),
      forbidden403: answer(403),
      unavailable503: answer(503),
      throws: new Error("reset"),
      stayed204: { status: 204, bodyReadable: true, value: {}, bytes: 0 },
    };
    if (f.delete !== "ok204") world.override(del, replies[f.delete], { effect });
    if (f.readback !== "absent404") {
      const send = world.send;
      let gets = 0;
      world.send = async (method, url) => {
        if (method === "GET" && url.includes(`/o/${OBJECT}`) && (gets += 1) === 2) {
          return f.readback === "unavailable503"
            ? answer(503)
            : answer(200, { bucket: FAKE_BUCKET, name: OBJECT, generation: "1" });
        }
        return send(method, url);
      };
    }
    if (f.list === "unavailable") world.override({ method: "GET", url: "/o?" }, answer(503));
    if (f.budget === "short") left = used + 1;
    const before = world.requests.length;
    const result = await deploy.finish({
      cliExited: f.cli === "exited",
      exitCode: f.cli === "exited" ? 1 : null,
    });
    const sent = world.requests.slice(before);

    const expectClean =
      f.budget === "ok" &&
      f.list === "ok" &&
      f.extra === "none" &&
      ((f.object === "present" &&
        f.meta === "ok" &&
        f.delete === "ok204" &&
        f.readback === "absent404") ||
        (f.object === "absent" && f.put === "refused"));
    assert.equal(result.clean, expectClean, `${row.join(" ")} -> ${result.reasons}`);
    const deletes = sent.filter((request) => request.method === "DELETE");
    assert.ok(deletes.length <= 1, "a DELETE is never re-sent");
    for (const request of deletes) {
      assert.ok(request.url.includes(OBJECT), "only the receipt object is deleted");
      assert.match(request.url, /ifGenerationMatch=\d+$/);
    }
    if (f.object === "absent" || f.meta !== "ok") assert.equal(deletes.length, 0);
    if (f.budget === "short") assert.equal(sent.length, 0);
    assert.ok(world.objects.has("base-0") && world.objects.has("base-1"));
    if (f.extra === "foreign") assert.ok(world.objects.has(FOREIGN));
    assert.equal(uploads.report().closureReady, expectClean);
    uploads.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("pairwise combinations of the deploy outcome factors", () => {
  for (const row of ROWS) {
    it(row.join(" "), () => runRow(row));
  }
});
