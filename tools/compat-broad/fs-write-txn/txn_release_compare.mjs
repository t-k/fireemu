/** Semantic expectations are distinct from complete native acquisition receipts. */
import { isDeepStrictEqual } from 'node:util';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { scenarioComplete } from './web_sdk_retry.mjs';
import { projectAdminReceipt, projectArchivedAdminReceipt, compareAdminProjections } from './admin_sdk_retry.mjs';
import { canonicalRow, filterSites, isUnfinished, recordingProblems, erroredPrograms, classifyRow } from '../../../conformance/src/fs-listen/compare.mjs';

export function projectWeb(receipt, local = false) {
  if (receipt.complete !== true || (local && (receipt.localOnly !== true || receipt.projectId !== 'demo-web-retry'))) throw new Error('Web acquisition incomplete');
  return (local ? [['node-sdk', 'node'], ['browser', 'browser']] : [['node', 'node'], ['browser', 'browser']]).flatMap(([label, transport]) => {
    const report = receipt.transports.find(item => item.transport === label);
    if (report?.closed !== true || report.scenarios.length !== 2) throw new Error('Web report incomplete');
    return ['control', 'conflict'].map(scenario => {
      const row = report.scenarios.find(item => item.scenario === scenario);
      if (!row || row.complete !== true || !scenarioComplete(row)) throw new Error('Web scenario incomplete');
      return { transport, scenario, semantic: { attempts: row.answer.attempts, finalValue: row.final.value,
        wire: row.events.filter(event => event.event === 'transaction-wire').toSorted((a, b) => a.n - b.n).map(event => ({ method: event.method ?? null, status: event.status ?? null, grpcCode: event.grpcCode ?? null, complete: event.complete ?? null, refusal: event.response?.error ?? null })) } };
    });
  });
}

export function projectListen(recording, ids) {
  if (recordingProblems(recording).length) throw new Error('Listen recording incomplete');
  return ids.map(id => {
    const row = recording.rows[id];
    if (!row || isUnfinished(row) || erroredPrograms(recording).has(row.program) || classifyRow(row, row) !== 'MATCH') throw new Error('Listen row missing or unfinished');
    const places = {};
    for (const site of filterSites(row)) if (!site.redundant) places[site.place] = [...new Set([...(places[site.place] ?? []), site.key])].toSorted();
    return { id, canonical: canonicalRow(row), places };
  });
}

export function compareListenProjection(first, actual, second = first) {
  if (first.id !== second.id || first.id !== actual.id || !isDeepStrictEqual(first.canonical, second.canonical) || !isDeepStrictEqual(first.canonical, actual.canonical)) return false;
  const informative = row => Object.entries(row.places).flatMap(([place, keys]) => keys.map(key => JSON.stringify([place, key])));
  const [firstSites, secondSites, actualSites] = [first, second, actual].map(informative);
  const required = firstSites.filter(site => secondSites.includes(site));
  const allowed = new Set([...firstSites, ...secondSites]);
  return required.every(site => actualSites.includes(site)) && actualSites.every(site => allowed.has(site));
}

export function comparisonRows(kind, expectations, local) {
  const rows = [];
  if (kind === 'listen' && expectations.length !== 2) throw new Error('Listen requires two production projections');
  for (const [recording, expected] of expectations.entries()) {
    if (kind === 'p17') {
      const result = compareAdminProjections(expected, projectAdminReceipt(local));
      if (result.mismatches) throw new Error('SDK semantic responses differ');
      rows.push(...result.attempts.map(row => ({ row: `p17/r${recording + 1}/${row.caseId}/callback${row.callbackCount}`, status: 'MATCH' })));
    } else if (kind === 'web') {
      const actual = projectWeb(local, true);
      if (!isDeepStrictEqual(expected, actual)) throw new Error('Web semantic responses differ');
      rows.push(...actual.map(row => ({ row: `web/r${recording + 1}/${row.transport}/${row.scenario}`, status: 'MATCH' })));
    } else if (kind === 'listen') {
      const actual = projectListen(local, expected.map(row => row.id));
      if (expected.length !== 4 || expected.some((row, i) => !compareListenProjection(row, actual[i], expectations[1 - recording][i]))) throw new Error('Listen semantic responses differ');
      rows.push(...actual.map(row => ({ row: `listen/r${recording + 1}/${row.id}`, status: 'MATCH' })));
    } else throw new Error('unknown semantic recipe');
  }
  return rows;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [mode, input, local, output] = process.argv.slice(2);
  const read = path => JSON.parse(readFileSync(path, 'utf8'));
  if (mode === 'compare') {
    const expected = read(input);
    writeFileSync(output, JSON.stringify(comparisonRows(expected.kind, expected.recordings.map(row => row.projection), read(local)), null, 2) + '\n');
  } else if (mode === 'publish') {
    const packet = read(input);
    const value = packet.kind === 'p17' ? projectArchivedAdminReceipt(read(packet.raw), packet.sources) : packet.kind === 'web' ? projectWeb(read(packet.raw)) : projectListen(read(packet.raw), packet.ids);
    writeFileSync(local, JSON.stringify(value, null, 2) + '\n');
  } else throw new Error('usage: txn_release_compare.mjs compare expectation local output | publish packet output');
}
