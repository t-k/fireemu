// Runs inside `fireemu exec`: performs the check's one source operation (an email/password sign-up) against the local Auth
// emulator, the way the recorder does against production, and waits for the blocking function to have printed its frames.
// The frames reach the parent (dry-run.mjs) through fireemu's own output, as Cloud Logging carries them in production.
import { signUpBody } from "../record/script.mjs";

const [runId = "0123456789abcdef", settleSeconds = "10"] = process.argv.slice(2);
const host = process.env.FIREBASE_AUTH_EMULATOR_HOST;
if (!host) throw new Error("FIREBASE_AUTH_EMULATOR_HOST is not set");
const response = await fetch(
  `http://${host}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=local`,
  {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(signUpBody(runId)),
  },
);
const body = await response.json().catch(() => ({}));
console.log(`DRIVE signUp ${response.status} localIdLength=${String(body.localId ?? "").length}`);
await new Promise((resolve) => setTimeout(resolve, Number(settleSeconds) * 1000));
