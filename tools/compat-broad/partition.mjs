// Local partition reconstruction: physical split choices are not equality expectations.
import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  partitionRanges,
  verifyPartitionDocuments,
} from "../../conformance/src/firestore-probe/partition-reconstruction.mjs";

export const rangesFor = partitionRanges;
const documents = (rows) => rows.filter((row) => row.document).map((row) => row.document);
const compareReferences = (left, right) => {
  const a = left.split("/"),
    b = right.split("/");
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    const order = Buffer.compare(Buffer.from(a[index]), Buffer.from(b[index]));
    if (order) return order;
  }
  return a.length - b.length;
};

export function verifyOrdered(expected, ranges) {
  const counts = verifyPartitionDocuments(expected, ranges);
  const full = documents(expected),
    merged = documents(ranges.flat());
  for (let index = 1; index < full.length; index++) {
    assert.ok(
      compareReferences(full[index - 1].name, full[index].name) < 0,
      "full query name order differs",
    );
  }
  assert.deepEqual(merged, full, "ordered complete document reconstruction differs");
  return counts;
}

export async function run(output) {
  const origin = process.env.BROAD_ORIGIN;
  const parent = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/databases/(default)/documents`;
  const report = { productionExecuted: false, status: "incomplete", cases: [], requests: 0 };
  const started = performance.now();
  const request = async (path, body, method = "POST") => {
    if (++report.requests >= 800 || performance.now() - started > 110000)
      throw new Error("partition budget exhausted");
    const response = await fetch(`${origin}${path}`, {
      method,
      headers: { authorization: "Bearer owner", "content-type": "application/json" },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const value = await response.json();
    assert.equal(response.status, 200, `HTTP ${response.status}: ${JSON.stringify(value)}`);
    return value;
  };
  try {
    for (const size of [0, 1, 2, 9, 41]) {
      await request(
        `/emulator/v1/projects/${process.env.GOOGLE_CLOUD_PROJECT}/databases/(default)/documents`,
        undefined,
        "DELETE",
      );
      const seed = Array.from({ length: size }, (_, index) => ({
        update: {
          name: `${parent}/groups/g${index % 3}/items/d${String(index).padStart(3, "0")}${index % 2 ? "é" : ""}`,
          fields: {
            ordinal: { integerValue: String(index) },
            nested: { mapValue: { fields: { text: { stringValue: `value-${index}` } } } },
          },
        },
      }));
      if (seed.length) await request(`/v1/${parent}:commit`, { writes: seed });
      const structuredQuery = {
        from: [{ collectionId: "items", allDescendants: true }],
        orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
      };
      const initial = await request(`/v1/${parent}:runQuery`, { structuredQuery });
      assert.equal(documents(initial).length, size, "seed count differs");
      for (const partitionCount of [1, 2, 7])
        for (const pageSize of [1, 3]) {
          const row = {
            id: `size-${size}/count-${partitionCount}/page-${pageSize}`,
            size,
            partitionCount,
            pageSize,
            pages: [],
            rangeRows: [],
            status: "incomplete",
          };
          report.cases.push(row);
          let pageToken = "";
          const tokens = new Set();
          do {
            const page = await request(`/v1/${parent}:partitionQuery`, {
              structuredQuery,
              partitionCount: String(partitionCount),
              pageSize,
              ...(pageToken ? { pageToken } : {}),
            });
            row.pages.push(page);
            pageToken = page.nextPageToken ?? "";
            assert.ok(!pageToken || !tokens.has(pageToken), "pagination cycle");
            tokens.add(pageToken);
            assert.ok(row.pages.length <= partitionCount + 1, "unbounded pagination");
          } while (pageToken);
          const ranges = rangesFor({
            pages: row.pages,
            partitionCount,
            pageSize,
            parent,
            structuredQuery,
          });
          for (const range of ranges)
            row.rangeRows.push(await request(`/v1/${parent}:runQuery`, { structuredQuery: range }));
          row.fullBefore = initial;
          row.fullAfter = await request(`/v1/${parent}:runQuery`, { structuredQuery });
          verifyOrdered(initial, [row.fullAfter]);
          Object.assign(row, verifyOrdered(initial, row.rangeRows), { status: "pass" });
        }
    }
    report.status = "pass";
  } catch (error) {
    report.failure = String(error.message);
    throw error;
  } finally {
    report.elapsedMs = performance.now() - started;
    writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  }
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await run(process.argv[2]);
