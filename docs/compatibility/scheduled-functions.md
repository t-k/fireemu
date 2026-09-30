# Scheduled Functions Closure Scope

SCHEDULED-FUNCTIONS is IMPLEMENTING. Its frozen inventory does not establish production compatibility. The inventory covers first-generation `pubsub.schedule` and second-generation `onSchedule`, their Cloud Scheduler declaration/calendar/delivery/retry behavior, and separately classified Fireemu-only scheduler and virtual-clock properties.

Task queue functions are a candidate for a future TASK-QUEUE-FUNCTIONS parent; no task queue work is included here. Generic Pub/Sub APIs, custom Eventarc and ordinary Firebase source events belong to other parents. General Cloud Scheduler resource-management APIs, arbitrary external targets, App Engine HTTP application targets, billing, scaling and IAM management parity are outside this claim. English-like schedule syntax is included independently of App Engine HTTP target support.

## Evidence obligations

The frozen inventory is `spec/compatibility/closure/SCHEDULED-FUNCTIONS.json`. Fourteen conditions require two genuine production recordings of the same corpus, followed by comparison of every exact case on the final Fireemu artifact and runner. Nine conditions require local property/regression evidence; these must never be represented as production recordings. Two conditions bind the final artifact and independent closure review. All 25 remain pending.

Production calendar observations use Cloud Scheduler's recorded responses. A timezone library is not a substitute for a production recording. Future next-time metadata across a DST transition proves only the exposed next-time result; it does not prove repeated-hour dispatch behavior. First-generation deployment also depends on the existing App Engine location. Creating an App Engine application is a separate owner decision and is not implied by API enablement.

## Fireemu-only clock policy

The approved closure policy retains fail-closed verification after explicit clock rewind: a token issued after the rewound logical time is invalid. This is a Fireemu-only property and remains pending local test evidence. Scheduler capacity repairs are limited to scheduled and manual invocations; Auth and control-Pub/Sub admission obligations remain with their owners.

## Checking the closure

Run `node --test conformance/src/scheduled-functions-closure.test.mjs` to check frozen inventory integrity and promotion guards. Run `FIREEMU_REQUIRE_SCHEDULED_CLOSURE=1 node --test conformance/src/scheduled-functions-closure.test.mjs` to require a reviewed COMPAT_VERIFIED parent. The latter intentionally fails while any closure evidence is missing.
