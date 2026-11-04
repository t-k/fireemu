// The one source operation of the check, as a declared request. Anonymous and custom authentication do not trigger
// blocking functions, so the sign-up is an email and password one, with an address that names the run.
import { ACCOUNTS_URL, SIGN_UP_URL } from "./plan.mjs";

export const emailOf = (runId) => `pcblock-${runId}@example.com`;
/** A password that satisfies any policy the project could have set, and says what it is for. */
export const passwordOf = (runId) => `Pcblock-${runId}-Aa1!`;

export const signUpBody = (runId) => ({
  email: emailOf(runId),
  password: passwordOf(runId),
  returnSecureToken: true,
});

export const signUp = (runId) => ({ method: "POST", url: SIGN_UP_URL, json: signUpBody(runId) });
export const deleteAccount = (localId) => ({
  method: "POST",
  url: `${ACCOUNTS_URL}:delete`,
  json: { localId },
});
export const lookupAccount = (localId) => ({
  method: "POST",
  url: `${ACCOUNTS_URL}:lookup`,
  json: { localId: [localId] },
});
export const countAccounts = () => ({
  method: "POST",
  url: `${ACCOUNTS_URL}:query`,
  json: { returnUserInfo: false },
});
