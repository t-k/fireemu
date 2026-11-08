// Exact temporary rules for the four finite SDK profiles.
export function packetRules(prefix) {
  if (typeof prefix !== 'string' || prefix.length > 256 || !/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(prefix)) throw Error('Invalid rules prefix');
  if (prefix.slice(1).split('/').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw Error('Invalid rules prefix');
  const rules = { '.read': false, '.write': false }; let target = rules;
  for (const part of prefix.slice(1).split('/')) target = target[part] = {};
  target['sdk-next'] = Object.fromEntries(['r1-ws', 'r1-lp', 'r2-ws', 'r2-lp'].map(name => [name, { '.read': true, '.write': true, values: { '.indexOn': '.value' } }]));
  return { rules };
}
