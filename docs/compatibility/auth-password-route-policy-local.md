# Auth password policy route coverage (local)

The finite `AUTH-U12-local-route-policy` slice exercises the shared password policy through the Admin `accounts:create` route in addition to the existing sign-up, end-user `accounts:update`, OOB `resetPassword`, Admin update and batch import coverage.

The Admin create matrix accepts 4095 and 4096 UTF-16 units and refuses 4097 units. It also refuses a control-character password, a five-character password and a non-string password. Refused requests leave the requested UID and email unallocated; accepted boundary values preserve the requested profile fields. The regression is `password_policy_admin_create_covers_maximum_and_invalid_password_inputs_atomically` in `crates/fireemu-adapter-http/tests/identity_toolkit.rs`.

This is local safety and route-consistency evidence. It does not establish production error wording or policy behavior for unobserved settings, custom policies, tenants or SDK paths. The parent `AUTH-U12` gap remains open until its required production comparison is completed.
