// The AUTH-TENANT-BLOCKING blocking-function fixture (owner decision TB1): one codebase deployed
// to the Identity Platform sandbox for a recording and deleted after it, and served unchanged by
// fireemu's Functions runtime for the comparison. It has no side effect and holds no secret: it
// only answers the event it receives.
//
// What each function does is chosen by the request, so one deployment serves every program. The
// directives are words of the account's address (`fireemu-aa-<run>-<word>-<word>@example.com`);
// a word starting with `c` acts in beforeCreate, `s` in beforeSignIn, `e` in beforeSendEmail:
//
//   cdeny<code>, sdeny<code>, edeny<code>      refuse with an HttpsError of that code (CODES)
//   cthrow, sthrow                             throw an unhandled error
//   cslow, sslow                               answer after the eight-second deadline
//   cdisable, sdisable                         answer disabled: true
//   cprofile                                   set displayName, photoURL, emailVerified
//   cbig, sbig                                 claims over the 1000-character limit
//   creserved, sreserved                       a reserved claim name
//   eblock                                     recaptchaActionOverride BLOCK
//
// Without a refusing directive, beforeCreate saves an echo of its event in customClaims.atbC and
// beforeSignIn puts an echo of its event in sessionClaims.atbS, so the ID token shows which
// events ran, in which order, and what they saw (TB5: the decoded event is compared). The echo
// names members and shapes, never an id, a time or a credential. beforeSendEmail and
// beforeSendSms refuse with their echo as the message when asked to (`eecho`, and the last test
// phone number for SMS), which is the only way their event can be observed.

const {
  HttpsError,
  beforeEmailSent,
  beforeSmsSent,
  beforeUserCreated,
  beforeUserSignedIn,
} = require("firebase-functions/v2/identity");

const OPTIONS = { region: "us-central1" };
/** The test phone number whose SMS event is refused with its echo. */
const ECHO_PHONE = "+16505550106";
const CODES = {
  pd: "permission-denied",
  ia: "invalid-argument",
  un: "unavailable",
  nf: "not-found",
  ae: "already-exists",
  rx: "resource-exhausted",
  in: "internal",
  ua: "unauthenticated",
};

/** The directive words of an address, or none. */
function directives(email) {
  const local = String(email ?? "").split("@")[0];
  const match = /^fireemu-aa-\d+-(.+)$/.exec(local);
  return new Set(match ? match[1].split("-") : []);
}

function codeAfter(words, prefix) {
  for (const word of words) {
    if (word.startsWith(prefix)) return CODES[word.slice(prefix.length)] ?? "internal";
  }
  return undefined;
}

/** The members an object carries a value for, in order. */
const sorted = (object) =>
  object && typeof object === "object"
    ? Object.keys(object)
        .filter((key) => object[key] !== undefined)
        .toSorted()
    : [];
const kind = (value) => (value === undefined ? "u" : value === null ? "n" : typeof value);

/** What an event looked like, without ids, times or credentials. */
function echo(event) {
  const user = event.data;
  return {
    t: event.eventType,
    at: event.authType,
    rn: event.resource?.name,
    au: sorted(event.additionalUserInfo),
    nu: event.additionalUserInfo?.isNewUser,
    pi: event.additionalUserInfo?.providerId,
    cr: event.credential ? sorted(event.credential) : null,
    cx: ["ipAddress", "userAgent", "locale", "eventId", "timestamp"].map((k) => kind(event[k])),
    et: event.emailType,
    st: event.smsType,
    u: user ? sorted(user) : null,
    ev: user?.emailVerified,
    dn: user?.displayName,
    dis: user?.disabled,
    pd: user ? (user.providerData ?? []).map((p) => p.providerId).toSorted() : null,
    mf: user?.multiFactor?.enrolledFactors?.map((f) => f.factorId) ?? null,
    cc: user ? sorted(user.customClaims) : null,
    tn: kind(user?.tenantId),
  };
}

function refuse(words, phase) {
  const code = codeAfter(words, `${phase}deny`);
  if (code) throw new HttpsError(code, `atb ${phase} refused`);
  if (words.has(`${phase}throw`)) throw new Error(`atb ${phase} unhandled`);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

exports.atbBeforeCreate = beforeUserCreated(OPTIONS, async (event) => {
  const words = directives(event.data?.email);
  refuse(words, "c");
  if (words.has("cslow")) await sleep(8000);
  if (words.has("cdisable")) return { disabled: true };
  if (words.has("cbig")) return { customClaims: { atbBig: "x".repeat(1001) } };
  if (words.has("creserved")) return { customClaims: { aud: "atb" } };
  const answer = { customClaims: { atbC: echo(event) } };
  if (words.has("cprofile")) {
    answer.displayName = "ATB Profile";
    answer.photoURL = "https://example.com/atb.png";
    answer.emailVerified = true;
  }
  return answer;
});

exports.atbBeforeSignIn = beforeUserSignedIn(OPTIONS, async (event) => {
  const words = directives(event.data?.email);
  refuse(words, "s");
  if (words.has("sslow")) await sleep(8000);
  if (words.has("sdisable")) return { disabled: true };
  if (words.has("sbig")) return { sessionClaims: { atbBig: "x".repeat(1001) } };
  if (words.has("sreserved")) return { sessionClaims: { iss: "atb" } };
  return { sessionClaims: { atbS: echo(event) } };
});

exports.atbBeforeSendEmail = beforeEmailSent(OPTIONS, async (event) => {
  const words = directives(event.additionalUserInfo?.email);
  refuse(words, "e");
  if (words.has("eecho")) throw new HttpsError("failed-precondition", JSON.stringify(echo(event)));
  if (words.has("eblock")) return { recaptchaActionOverride: "BLOCK" };
  return {};
});

exports.atbBeforeSendSms = beforeSmsSent(OPTIONS, async (event) => {
  if (event.additionalUserInfo?.phoneNumber === ECHO_PHONE)
    throw new HttpsError("failed-precondition", JSON.stringify(echo(event)));
  return {};
});
