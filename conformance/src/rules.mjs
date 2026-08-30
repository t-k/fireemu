// Loading the same Security Rules text into both sides.
//
// This is the one place the two sides are configured differently, and the difference is in
// deployment rather than behaviour: the official suite reads `firestore.rules` and
// `storage.rules` from firebase.json when it starts, while fireemu takes rules text
// through its control API. Both therefore evaluate the same bytes, which is what makes the
// Rules-decision rows comparable at all.

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR } from "./config.mjs";

const put = async (url, source, controlToken) => {
  const headers = { "content-type": "application/json" };
  if (controlToken) headers.authorization = `Bearer ${controlToken}`;
  const response = await fetch(url, { method: "PUT", headers, body: JSON.stringify({ source }) });
  if (!response.ok) {
    throw new Error(`PUT ${url}: ${response.status} ${await response.text()}`);
  }
  return response.status;
};

/**
 * @param {"oracle" | "testd"} side
 * @returns a description of how rules reached the side, recorded with the run.
 */
export async function loadRules(side, hosts) {
  if (side === "oracle") {
    return { via: "firebase.json", firestore: "firestore.rules", storage: "storage.rules" };
  }
  const firestore = await readFile(join(CONFORMANCE_DIR, "firestore.rules"), "utf8");
  const storage = await readFile(join(CONFORMANCE_DIR, "storage.rules"), "utf8");
  const token = process.env.FIREEMU_CONTROL_TOKEN ?? null;
  const firestoreStatus = await put(`http://${hosts.auth}/v1/rules`, firestore, token);
  const storageStatus = await put(`http://${hosts.auth}/v1/storage/rules`, storage, token);
  return { via: "control API", firestoreStatus, storageStatus };
}
