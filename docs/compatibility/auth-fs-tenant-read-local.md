# Local tenant identity, Firestore reads and active listeners

Parent: `AUTH-FS-CROSS`. This is local regression coverage; the parent remains `WAITING_ORACLE`.

`crates/fireemu-adapter-grpc/tests/auth_tenant_rules.rs` passes Auth-issued local tokens through `RulesEnforcer` with `TokenAcceptance::Verified`. The default namespace and two tenants deliberately contain the same UID and email. Each issues tokens with both values of a `reader` custom claim. The Rules policy requires that the token's tenant and UID match the document's tenant and owner, and that `reader` is true.

| Obligation | Local check | Positive control |
| --- | --- | --- |
| Tenant and custom claims govern each read | All six identities attempt gets and constrained queries for both tenants; the default namespace and wrong tenant cannot reuse the matching UID | Each tenant's reader can get and query its own data |
| Anonymous requests remain denied | Anonymous get and fully constrained query | Verified matching tenant reader |
| A query must prove tenant and owner restrictions | Missing either constraint, an incorrect owner, and a disjunction spanning both tenants are denied | Exact tenant and owner equality constraints for each tenant |
| Every document in a batch must be authorized | A mixed-tenant batch is denied in both document orders despite the shared UID | A batch containing only the caller's tenant document |
| Removed tenants cannot authenticate via the parent namespace | Fresh principal construction rejects both previously issued tokens of the removed tenant | Default and sibling credentials still authenticate; the sibling can still read |
| An active document listener reauthenticates on the next database refresh | After initial snapshots and live updates, deleting one tenant then committing to the database produces target REMOVE with cause 16, stream Unauthenticated and EOF; no post-deletion document is delivered | The same-UID sibling listener continues receiving its own updated document |

The query checks call the shared authorization method used for query targets. They do not exercise SDK token refresh, reconnection, cache or pending writes. A separate in-memory test calls the public `listen_stream` with real `LocalBackend` commits and Tokio channels, without binding a TCP socket. It checks initial snapshot and live document frames, target-specific and global snapshot barriers, tenant deletion followed by native reauthentication failure, REMOVE/error/EOF ordering and a live sibling control. The multi-document checks verify the authorization decision, not a wire response or storage mutation. Tenant deletion is tested both on fresh principal construction and on the next backend refresh of an already authenticated document listener. Auth deletion itself does not emit a Firestore commit notification; this does not establish immediate disconnection after deletion. Query listener wire frames, SDK behavior and production timing remain untested. The channel/task helper closes and awaits tasks on normal completion and aborts owned tasks on assertion failure; timeout is only a hang guard, never positive evidence of absence. Tokens are local unsigned Auth fixtures; these checks do not verify production signatures or establish production revocation/deletion timing.

Run the socket-free target with `cargo nextest run -p fireemu-adapter-grpc --profile pr --test auth_tenant_rules`. Cross-tenant SDK listener recordings and the corresponding bounded production observations remain separate requirements.
