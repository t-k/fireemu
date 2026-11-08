// The entry of the kinds recording: the breadth recorder with the kinds scenario. Run by the launch
// script of the packet; admission, pins, the budget and the private output are breadth-record.mjs's.
import { pathToFileURL } from "node:url";
import { recordBreadth } from "./breadth-record.mjs";
import { KINDS_SCENARIO } from "./kinds-scenario.mjs";

export const recordKinds = () => recordBreadth(KINDS_SCENARIO);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  recordKinds().catch((error) => {
    console.error("kinds recorder failed", error?.constructor?.name ?? "Error");
    process.exitCode = 1;
  });
}
