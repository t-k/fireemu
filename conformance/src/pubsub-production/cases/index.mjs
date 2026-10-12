import { lifecycle, names, paging } from "./lifecycle.mjs";
import { subscriptionConfig, subscriptionUpdate, topicConfig } from "./config.mjs";
import { publishLimits, publishWire } from "./publish.mjs";
import { filtering, nackAndDeadline, ordering, pullAck, retryPolicy } from "./delivery.mjs";
import { snapshotSeek } from "./snapshots.mjs";
import { authErrors, pushConfig } from "./errors.mjs";
import { deadLetterForwarding } from "./deadletter.mjs";

// The order matters twice: the dead-letter forwarding is last because it is the only case that can
// stop the run (a missing service agent), and the slow cases are late so a short run covers the most.
export const CASES = Object.freeze([
  lifecycle,
  names,
  paging,
  topicConfig,
  subscriptionConfig,
  subscriptionUpdate,
  publishWire,
  publishLimits,
  pullAck,
  filtering,
  ordering,
  snapshotSeek,
  authErrors,
  pushConfig,
  nackAndDeadline,
  retryPolicy,
  deadLetterForwarding,
]);
