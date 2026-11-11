// The entry of the second kinds recording (packet v2): the same recorder, fixture and judge as
// kinds-record.mjs, with only the user writes k15 to k21. Admission, pins, the budget and the private
// output are breadth-record.mjs's.
import { pathToFileURL } from "node:url";
import { recordBreadth } from "./breadth-record.mjs";
import { KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";

export const recordKindsV2 = () => recordBreadth(KINDS_V2_SCENARIO);

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  recordKindsV2().catch((error) => {
    console.error("kinds recorder (v2) failed", error?.constructor?.name ?? "Error");
    process.exitCode = 1;
  });
}
