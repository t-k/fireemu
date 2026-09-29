// The authorized domains the sandbox answers with (read 2026-09-24): its Firebase Hosting
// domains, without `localhost`. Production is checked against them; fireemu is given them.
//
// A module of its own, with no side effects, because the AUTH-ACTION and AUTH-MFA runners and the
// harness registry (which puts the value into their harness digests) all read it.

export const AUTHORIZED_DOMAINS = ["{project}.firebaseapp.com", "{project}.web.app"];
