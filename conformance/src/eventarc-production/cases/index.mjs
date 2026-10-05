import { channelBusy } from "./busy.mjs";
import { channelDelete, channelLifecycle } from "./channels.mjs";
import { channelIds } from "./ids.mjs";
import { locations } from "./locations.mjs";
import { channelOrder } from "./order.mjs";
import { publishBoundaries } from "./boundaries.mjs";
import { createProbe } from "./create-probe.mjs";
import { authErrors } from "./errors.mjs";
import { publishContent, publishEnvelope, publishLimits } from "./publish.mjs";
import { adminSdkPublish } from "./sdk.mjs";
import { preconditions } from "./service.mjs";

// The order matters. The preconditions come first (the publishing API is enabled, and the recording does
// not enable it). The create probe is second: it stops the whole run, cleanly, when a creation with a name
// is refused, so that nothing that needs a channel is sent without one.
export const CASES = Object.freeze([
  preconditions,
  createProbe,
  channelLifecycle,
  channelDelete,
  channelOrder,
  channelBusy,
  channelIds,
  locations,
  publishEnvelope,
  publishContent,
  publishLimits,
  publishBoundaries,
  adminSdkPublish,
  authErrors,
]);
