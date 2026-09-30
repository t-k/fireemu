import { googleError, isObject, isTimestamp, jsonBody, result, unexpected } from "./acceptance-core.mjs";

// Closed Firestore REST v1 document schemas. Field values are never read into a fact.
const onlyKeys = (value, allowed) => Object.keys(value).every((key) => allowed.includes(key));
const pathName = (row) => (typeof row.request.path === "string" && row.request.path.startsWith("/v1/") ? row.request.path.slice(4) : null);
const expectedName = (row) => {
  const base = pathName(row);
  if (base === null) return null;
  if (row.request.method !== "POST") return base;
  const id = row.request.query?.documentId;
  return typeof id === "string" && id !== "" ? `${base}/${id}` : null;
};
function documentOf(body, name) {
  if (!isObject(body) || !onlyKeys(body, ["name", "fields", "createTime", "updateTime"]) || body.name !== name || !isTimestamp(body.createTime) || !isTimestamp(body.updateTime)) return null;
  if (body.fields !== undefined && !isObject(body.fields)) return null;
  return { name: body.name, createTime: body.createTime, updateTime: body.updateTime };
}

export const FIRESTORE_CLASSIFIERS = {
  "firestore-read": (row, response) => {
    const name = expectedName(row);
    const document = response.status === 200 && name !== null ? documentOf(jsonBody(response), name) : null;
    if (document) return result("firestore-read", "present", { status: 200, documentName: document.name, createTime: document.createTime, updateTime: document.updateTime });
    if (googleError(response, 404, "NOT_FOUND")) return result("firestore-read", "absent", { status: 404 });
    return unexpected("firestore-read", response);
  },
  "firestore-write": (row, response) => {
    if (row.request.method === "DELETE") {
      const body = response.status === 200 ? jsonBody(response) : undefined;
      return isObject(body) && Object.keys(body).length === 0 ? result("firestore-write", "accepted", { status: 200 }) : unexpected("firestore-write", response);
    }
    const name = expectedName(row);
    const document = response.status === 200 && name !== null ? documentOf(jsonBody(response), name) : null;
    return document ? result("firestore-write", "accepted", { status: 200, documentName: document.name, updateTime: document.updateTime }) : unexpected("firestore-write", response);
  },
};
