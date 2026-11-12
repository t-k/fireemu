// What the functions smoke expects to see in the three places where the strict profile and
// the emulator profile deliver different shapes. Each value is the shape that profile is
// specified to deliver, not whatever it delivered last:
//
// - strict follows the recorded production runs. A custom Eventarc event carries no
//   `datacontenttype` (EVENTARC H1 v5: 0 of 69 handler frames). A dispatched task names the bare
//   queue id in `X-CloudTasks-QueueName` (TASK-QUEUE recordings r1 and r2). The Admin SDK's local
//   `owner` credential is named `unknown` with its own id in a withAuthContext event, the form
//   recorded for an operator's credential (FE v5 and v7).
// - emulator follows the official emulator: `datacontenttype: application/json`, the internal
//   queue key `queue:<project>-<location>-<queue>`, and `unknown` with the constant
//   `fake-auth-id@gmail.com` whoever wrote.

export const PROFILES = ["strict", "emulator"];

/** Reads the smoke's profile from the environment; an unknown name fails closed. */
export function profileFromEnv(env) {
  const name = env.FIREEMU_SMOKE_PROFILE ?? "strict";
  if (!PROFILES.includes(name)) {
    throw new Error(`FIREEMU_SMOKE_PROFILE must be one of ${PROFILES.join(", ")}, got ${JSON.stringify(name)}`);
  }
  return name;
}

export function expectedShapes(profile, project) {
  switch (profile) {
    case "strict":
      return {
        customEventDatacontenttype: null,
        taskQueueName: "countJob",
        authType: "unknown",
        authId: "owner",
      };
    case "emulator":
      return {
        customEventDatacontenttype: "application/json",
        taskQueueName: `queue:${project}-us-central1-countJob`,
        authType: "unknown",
        authId: "fake-auth-id@gmail.com",
      };
    default:
      throw new Error(`unknown functions smoke profile ${JSON.stringify(profile)}`);
  }
}
