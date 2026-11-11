import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sdkLatestRows } from './sdk-latest.mjs';

const light = {
	schemaVersion: 1,
	suite: 'light',
	recordedOn: '2026-02-28',
	runId: '12345',
	versions: { fireemu: '1.2.3', firebase: '12.3.4', firebaseAdmin: '13.4.5', firebaseFunctions: null },
	smokes: ['storage', 'client'],
};
const broad = {
	...light,
	suite: 'broad',
	recordedOn: '2024-02-29',
	runId: null,
	versions: { ...light.versions, firebaseFunctions: '7.0.0-beta.1' },
	smokes: ['auth', 'firestore-listen-transaction', 'functions'],
};

test('returns no rows for an empty record list', () => {
	assert.deepEqual(sdkLatestRows({ schemaVersion: 1, records: [] }), []);
});

test('orders suites and formats all row fields', () => {
	assert.deepEqual(sdkLatestRows({ schemaVersion: 1, records: [broad, light] }), [
		{ suite: 'light', label: 'Daily: light', recordedOn: '2026-02-28', runId: '12345', fireemu: '1.2.3', firebase: '12.3.4', firebaseAdmin: '13.4.5', firebaseFunctions: 'not installed', smokes: 'storage, client' },
		{ suite: 'broad', label: 'Weekly: broad', recordedOn: '2024-02-29', runId: null, fireemu: '1.2.3', firebase: '12.3.4', firebaseAdmin: '13.4.5', firebaseFunctions: '7.0.0-beta.1', smokes: 'auth, firestore-listen-transaction, functions' },
	]);
});

test('rejects invalid records and unknown keys', () => {
	const cases = [
		{ schemaVersion: 1, records: [], extra: true },
		{ schemaVersion: 2, records: [] },
		{ schemaVersion: 1, records: [{ ...light, schemaVersion: 2 }] },
		{ schemaVersion: 1, records: [{ ...light, extra: true }] },
		{ schemaVersion: 1, records: [{ ...light, versions: { ...light.versions, extra: '1.0.0' } }] },
		{ schemaVersion: 1, records: [{ ...light, suite: 'nightly' }] },
		{ schemaVersion: 1, records: [{ ...light, recordedOn: '2026-02-30' }] },
		{ schemaVersion: 1, records: [{ ...light, runId: '12a' }] },
		{ schemaVersion: 1, records: [{ ...light, versions: { ...light.versions, firebase: '1.2' } }] },
		{ schemaVersion: 1, records: [{ ...light, smokes: ['pubsub'] }] },
		{ schemaVersion: 1, records: [{ ...light, smokes: [] }] },
		{ schemaVersion: 1, records: [{ ...light, smokes: ['storage', 'storage'] }] },
		{ schemaVersion: 1, records: [light, light] },
	];
	for (const value of cases) assert.throws(() => sdkLatestRows(value));
});
