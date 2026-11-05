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
import { RECORDED_MEMBERS as CV14_MEMBERS, isRecordedMember as cv14Member } from "./frames.mjs";
export const RECORDED_MEMBERS = Object.freeze(
  CV14_MEMBERS.filter((entry) => entry.event === "write"),
);
export function isRecordedMember(handler, generation, member, value) {
  if (!FIXTURE_HANDLERS.some((entry) => entry.name === handler && entry.generation === generation))
    return false;
  return cv14Member(`rtdbWrittenV${generation}`, generation, member, value);
}
