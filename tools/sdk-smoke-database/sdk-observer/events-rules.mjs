// Exact temporary Rules of the events and admin suites (packet 1 of the RTDB closure). Same shape and safety as
// rules.mjs packetRules: everything outside the profile scopes stays `.read:false/.write:false`.
//   events: each profile scope is readable and writable by the anonymous client, with the indexes its queries use.
//   admin:  each profile scope is denied to every client; only the Admin SDK's bypass can read and write it.
export const EVENTS_PROFILES = ['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'];
export const ADMIN_PROFILES = ['r1-admin', 'r2-admin'];
export const SUITE_AREAS = { events: 'sdk-events', admin: 'sdk-admin' };

const eventsScope = () => ({ '.read': true, '.write': true, vr: { '.indexOn': '.value' }, eq: { '.indexOn': 't' }, cp: { '.indexOn': 's' } });
const adminScope = () => ({ '.read': false, '.write': false, w: { '.indexOn': 's' }, deny: { '.read': false, '.write': false } });

/** `suites` is a list of 'events' and/or 'admin'; the result is the whole Rules document to install. */
export function suiteRules(suites, prefix) {
  if (!Array.isArray(suites) || suites.length === 0 || suites.some(s => !Object.hasOwn(SUITE_AREAS, s)) || new Set(suites).size !== suites.length) throw Error('Invalid suites');
  if (typeof prefix !== 'string' || prefix.length > 256 || !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw Error('Invalid rules prefix');
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const part of prefix.slice(1).split('/')) target = target[part] = {};
  if (suites.includes('events')) target[SUITE_AREAS.events] = Object.fromEntries(EVENTS_PROFILES.map(name => [name, eventsScope()]));
  if (suites.includes('admin')) target[SUITE_AREAS.admin] = Object.fromEntries(ADMIN_PROFILES.map(name => [name, adminScope()]));
  return { rules };
}
