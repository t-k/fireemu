import { channelLifecycle } from "./channels.mjs";
import { authErrors } from "./errors.mjs";
import { publishContent, publishEnvelope, publishLimits } from "./publish.mjs";
import { adminSdkPublish } from "./sdk.mjs";
import { serviceState } from "./service.mjs";

// The order matters: the service-state case is first because it records the answers of the disabled
// publishing API before it enables it, which can only be recorded once.
export const CASES = Object.freeze([
  serviceState,
  channelLifecycle,
  publishEnvelope,
  publishContent,
  publishLimits,
  adminSdkPublish,
  authErrors,
]);
