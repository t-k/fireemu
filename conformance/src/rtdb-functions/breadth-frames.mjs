export const FRAME_MARKER = "G9_FRAME ";
export const INSTANCE = "fireemu-q-rtdb2";
export const LOCATION = "us-central1";
export const PREFIX = "g9-rtdb";
export const ITEM_PATH = `/${PREFIX}/{group}/items/{id}`;
export const FIXTURE_HANDLERS = [
  { name: "g9WrittenV2Retry", generation: 2, event: "write", retry: true },
  { name: "g9WrittenV1Retry", generation: 1, event: "write", retry: true },
  { name: "g9WrittenV2", generation: 2, event: "write", retry: false },
];
export { NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS } from "./frames.mjs";
export const RECORDED_MEMBERS = Object.freeze([]);
export function isRecordedMember() {
  return false;
}
