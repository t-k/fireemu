import { createHash } from "node:crypto";

const rejected = () => new Error("native Firestore frame rejected");
const requireValue = (condition) => {
  if (!condition) throw rejected();
};
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 2048 &&
  [...value].every((character) => character.codePointAt(0) >= 32);
const segment = (value) => text(value) && value !== "." && value !== ".." && !value.includes("/");
const ownValue = (value, key) => {
  requireValue(object(value));
  const property = Object.getOwnPropertyDescriptor(value, key);
  requireValue(property && Object.hasOwn(property, "value"));
  return property.value;
};
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const kinds = ["created", "updated", "deleted"];
const eventType = (kind) => `google.cloud.firestore.document.v1.${kind}`;

function nativeBytes(raw) {
  const base64 = ownValue(raw, "base64");
  const sha256 = ownValue(raw, "sha256");
  requireValue(typeof base64 === "string" && base64.length > 0 && base64.length <= 1398104);
  requireValue(typeof sha256 === "string" && /^[a-f0-9]{64}$/.test(sha256));
  const bytes = Buffer.from(base64, "base64");
  requireValue(bytes.length > 0 && bytes.length <= 1024 * 1024);
  requireValue(bytes.toString("base64") === base64 && digest(bytes) === sha256);
  return bytes;
}

function validTime(value) {
  if (!text(value)) return false;
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))$/.exec(
      value,
    );
  if (!match) return false;
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    zoneHourText,
    zoneMinuteText,
  ] = match;
  const [year, month, day, hour, minute, second] = [
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
  ].map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= days[month - 1] &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59 &&
    (!zoneHourText || (Number(zoneHourText) <= 23 && Number(zoneMinuteText) <= 59)) &&
    Number.isFinite(Date.parse(value))
  );
}

function allowedTypes(handlerEvent) {
  if (kinds.includes(handlerEvent)) return [eventType(handlerEvent)];
  if (handlerEvent === "written") return [eventType("written")];
  if (handlerEvent === "written-with-auth-context")
    return [`${eventType("written")}.withAuthContext`];
  throw rejected();
}

/** Verify one local v2 Firestore frame against its raw event bytes; capture provenance is outside this contract. */
export function verifyNativeFirestoreV2Frame(frame, operation, row) {
  try {
    requireValue(ownValue(row, "source") === "firestore" && ownValue(row, "generation") === 2);
    const handlerEvent = ownValue(row, "handlerEvent");
    requireValue(ownValue(frame, "source") === "firestore");
    requireValue(
      ownValue(frame, "generation") === 2 && ownValue(frame, "handlerEvent") === handlerEvent,
    );
    const resource = ownValue(operation, "resource");
    const entity = ownValue(operation, "entity");
    requireValue(text(resource) && text(entity));
    requireValue(ownValue(frame, "resource") === resource && ownValue(frame, "entity") === entity);
    const rawBytes = nativeBytes(ownValue(frame, "raw"));
    const source = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
    const native = JSON.parse(source);
    requireValue(JSON.stringify(native) === source);
    requireValue(object(native));
    requireValue(native.specversion === "1.0" && native.datacontenttype === "application/json");
    requireValue(object(native.data));
    requireValue(text(native.id) && validTime(native.time));
    requireValue(text(native.source) && text(native.subject));
    requireValue(segment(native.project) && segment(native.database) && text(native.document));
    requireValue(allowedTypes(handlerEvent).includes(native.type));
    if (handlerEvent === "written-with-auth-context") requireValue(text(native.authtype));
    const path = native.document.split("/");
    requireValue(path.length >= 2 && path.length % 2 === 0 && path.every(segment));
    requireValue(native.subject === `documents/${native.document}`);
    const documentName = `projects/${native.project}/databases/${native.database}/documents/${native.document}`;
    const serviceSource = `//firestore.googleapis.com/projects/${native.project}/databases/${native.database}`;
    requireValue(native.source === documentName || native.source === serviceSource);
    requireValue(documentName === `${resource}/${entity}`);
    requireValue(ownValue(frame, "eventSource") === native.source);
    requireValue(ownValue(frame, "eventId") === native.id);
    requireValue(ownValue(frame, "eventTime") === native.time);
    return Object.freeze({
      nativeFrameConsistent: true,
      documentName,
      eventSource: native.source,
      eventId: native.id,
      eventTime: native.time,
      captureProvenanceVerified: false,
      compatibilityEstablished: false,
      sendAuthorized: false,
    });
  } catch {
    throw rejected();
  }
}
