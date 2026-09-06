# Functions SDK export inventory

What happens to every trigger namespace the `firebase-functions` Node SDK exports when a codebase that uses it is loaded by fireemu. The runner (`tools/runner-node/index.mjs`) discovers a codebase with the SDK's own manifest, then serves each endpoint or reports it as ignored with a scope and a reason; nothing is dropped silently. This table is checked against the installed SDK by `tools/runner-node/inventory.test.mjs`: every trigger namespace the SDK exports must have a row here, and every row must carry one of the statuses below.

Statuses:

- `served`: discovered, registered and invoked by fireemu; the evidence column names a test or fixture that executes a real handler.
- `deferred`: the product has no emulator in fireemu's active surface yet; the endpoint is reported as ignored with that reason and discovery continues.
- `not-planned`: the product has no local emulator anywhere; reported as ignored with that reason.
- `unsupported`: a shape neither the official emulator nor the runner recognises; reported as ignored (`Unsupported trigger`) exactly as the official emulator does.

Non-trigger exports (`params`, `logger`, `config`, `app`, `onInit`, `runWith`, `region`, `setGlobalOptions`) are not triggers and are not rows: they shape endpoints the rows below describe.

## v1 (`firebase-functions/v1`)

| namespace | status | fireemu trigger | evidence | notes |
| --- | --- | --- | --- | --- |
| `https` (`onRequest`, `onCall`) | served | `http`, `http` callable | `crates/fireemu/tests/functions_discovery.rs`, `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`, `callable-auth-context.json` | CORS, timeouts, callable auth and App Check context are gated by the conformance fixtures |
| `firestore` (`document().onCreate/onUpdate/onDelete/onWrite`) | served | `firestore` (v1 event types mapped from `google.cloud.firestore.document.v1.*`) | `crates/fireemu-adapter-functions/tests/runtime.rs` (`ok`, `fail`, `withAuth` fixtures), `conformance/src/corpus/functions.mjs` | Named databases and `withAuthContext` are mapped from the resource |
| `storage` (`object().onFinalize/onDelete/onMetadataUpdate/onArchive`) | served | `storage` | `crates/fireemu-adapter-functions/tests/runtime.rs` (`slow` fixture), `conformance/storage-matrix.json#triggers` | `onArchive` is mapped; fireemu never archives because versioning is not emulated, so the handler is registered and never fires |
| `pubsub` (`topic().onPublish`, `schedule()`) | served | `pubsub`, `schedule` | `crates/fireemu-adapter-functions/tests/runtime.rs` (`onJob`, `tick`, `nightly`, `failSchedule`), `conformance/pubsub-matrix.json` | Schedules run on the virtual clock |
| `auth` (`user().onCreate/onDelete`, `beforeCreate`, `beforeSignIn`) | served | `auth`, blocking `auth` | `crates/fireemu-adapter-functions/tests/runtime.rs` (`onUser`, `onGone`), `crates/fireemu/tests/functions_discovery.rs`, `crates/fireemu-adapter-http/tests/auth_flows.rs` | Blocking functions run synchronously inside the Identity Toolkit request; credential forwarding follows `auth.forwardInboundCredentials` |
| `tasks` (`taskQueue().onDispatch`) | served | `tasks` | `crates/fireemu-adapter-functions/tests/runtime.rs` (task queue scenarios) | Rate limits and retry config are enforced on the virtual clock |
| `database` (`ref().onCreate/...`) | deferred | none (`ignored.triggerType: database`) | `tools/runner-node/index.mjs` `DEFERRED_TRIGGER_PRODUCTS` | The Realtime Database emulator is not in the active supported surface |
| `remoteConfig` (`onUpdate`) | deferred | none (`ignored.triggerType: remoteConfig`) | same | Remote Config has no emulator in the active surface |
| `analytics` (`event().onLog`) | not-planned | none (`ignored.triggerType: analytics`) | same | Google Analytics triggers have no local emulator |
| `testLab` (`testMatrix().onComplete`) | not-planned | none (`ignored.triggerType: testLab`) | same | Test Lab triggers have no local emulator |

## v2 (`firebase-functions/v2/*`)

| module | status | fireemu trigger | evidence | notes |
| --- | --- | --- | --- | --- |
| `https` (`onRequest`, `onCall`, `onCallGenkit`) | served | `http`, `http` callable | as v1 `https`; streaming callables in `crates/fireemu-adapter-functions/tests/runtime.rs` | `onCallGenkit` is a callable and is served as one |
| `firestore` (`onDocumentCreated/Updated/Deleted/Written` and the `WithAuthContext` variants) | served | `firestore` | as v1 `firestore` | |
| `storage` (`onObjectFinalized/Deleted/MetadataUpdated/Archived`) | served | `storage` | as v1 `storage` | |
| `pubsub` (`onMessagePublished`) | served | `pubsub` | `crates/fireemu-adapter-functions/tests/runtime.rs` (`onJob`), `conformance/pubsub-matrix.json` | |
| `scheduler` (`onSchedule`) | served | `schedule` | as v1 `schedule` | |
| `identity` (`beforeUserCreated`, `beforeUserSignedIn`, `beforeEmailSent`, `beforeSmsSent`) | served for `beforeUserCreated` and `beforeUserSignedIn`; `unsupported` for `beforeEmailSent` and `beforeSmsSent` | blocking `auth` | `crates/fireemu/tests/functions_discovery.rs` | The email and SMS blocking events are reported as `blocking identity event ... is not served`, the official emulator does not serve them either |
| `tasks` (`onTaskDispatched`) | served | `tasks` | as v1 `tasks` | |
| `eventarc` (`onCustomEventPublished`) | served | `eventarc` | `crates/fireemu-adapter-functions/tests/runtime.rs` (`customEvent`), `crates/fireemu-adapter-functions/src/eventarc.rs` tests | Channels and filters are matched; publication goes through the Eventarc listener |
| `alerts` (`onAlertPublished` and the per-product `onNew*` helpers) | served | `eventarc` (Firebase alerts channel) | `ui/e2e/alerts.spec.ts`, `crates/fireemu-adapter-functions/tests/runtime.rs` | Alerts are published through the official `google/publishEvents` mechanism |
| `database` (`onValueCreated/...`) | deferred | none | `DEFERRED_TRIGGER_PRODUCTS` | Realtime Database is deferred |
| `dataconnect` (`onMutationExecuted`) | deferred | none (`ignored.triggerType: dataconnect`) | `DEFERRED_TRIGGER_PRODUCTS` | The Data Connect emulator is not in the active supported surface |
| `ai` (`beforeGenerateContent`, `afterGenerateContent`) | not-planned | none (`ignored.triggerType: ai`) | `DEFERRED_TRIGGER_PRODUCTS` | Firebase AI Logic blocking triggers have no local emulator; the official emulator does not serve them either |
| `remoteConfig` (`onConfigUpdated`) | deferred | none | `DEFERRED_TRIGGER_PRODUCTS` | Remote Config is deferred |
| `testLab` (`onTestMatrixCompleted`) | not-planned | none | `DEFERRED_TRIGGER_PRODUCTS` | Test Lab has no local emulator |

## Anything else

An endpoint whose manifest entry has none of `httpsTrigger`, `callableTrigger`, `eventTrigger`, `blockingTrigger`, `scheduleTrigger` or `taskQueueTrigger`, or an event type the tables above do not name, is reported as `unsupported` with the official emulator's own wording (`unsupported function type: expected either an httpsTrigger, eventTrigger, or blockingTrigger`). `GET /v1/sessions/default/functions` lists every ignored export with its trigger type, scope and reason, so a codebase author can see what fireemu declined and why.
