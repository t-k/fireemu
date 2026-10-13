import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
	AREAS,
	productSurfaceRows,
	productionAreaRows,
	capabilityRows,
	loadRepositoryData,
} from './compat.mjs';

const surface = (overrides) => ({
	id: 'firestore',
	title: 'Cloud Firestore',
	scope: 'active',
	state: 'claimed',
	official: true,
	officialDefaultPort: 8080,
	...overrides,
});

test('product rows describe each scope and state in user terms', () => {
	const rows = productSurfaceRows({
		surfaces: [
			surface({}),
			surface({ id: 'appcheck', title: 'Firebase App Check', state: 'addition', official: false, officialDefaultPort: undefined }),
			surface({ id: 'database', title: 'Firebase Realtime Database', scope: 'deferred', state: 'none', officialDefaultPort: 9000 }),
			surface({ id: 'extensions', title: 'Firebase Extensions', scope: 'not-planned', state: 'none' }),
		],
	});
	assert.deepEqual(
		rows.map((r) => [r.id, r.status, r.port]),
		[
			['firestore', 'Supported', 8080],
			['appcheck', 'Supported (Fireemu addition)', null],
			['database', 'Not yet supported', 9000],
			['extensions', 'Not planned', 8080],
		],
	);
});

test('an active surface without a claim is reported as a gap, never as supported', () => {
	const [row] = productSurfaceRows({ surfaces: [surface({ state: 'gap' })] });
	assert.equal(row.status, 'Partially supported');
});

test('an unknown scope or state fails the build instead of being shown as supported', () => {
	assert.throws(() => productSurfaceRows({ surfaces: [surface({ state: 'mystery' })] }), /mystery/);
	assert.throws(() => productSurfaceRows({ surfaces: [surface({ scope: 'mystery' })] }), /mystery/);
});

const closure = (parent, statuses, extra = {}) => ({
	parent,
	parentStatus: 'COMPAT_VERIFIED',
	conditions: statuses.map((status, i) => ({ conditionId: `${parent}/c${i}`, status })),
	...extra,
});

test('production area rows count verified conditions and approved differences', () => {
	const rows = productionAreaRows([
		closure('FS-DATA-WRITE', ['VERIFIED', 'VERIFIED', 'KNOWN_DIFFERENCE_APPROVED'], {
			approvedKnownDifferences: [{ conditionId: 'FS-DATA-WRITE/c2', reason: 'Estimated bound.' }],
		}),
		closure('PUBSUB', ['VERIFIED'], {
			knownDifferences: { cache: { statement: 'Negative cache is not emulated.' } },
		}),
	]);
	const fs = rows.find((r) => r.parent === 'FS-DATA-WRITE');
	assert.equal(fs.verified, 2);
	assert.equal(fs.total, 3);
	assert.equal(fs.status, 'Verified against production');
	assert.deepEqual(fs.knownDifferences, ['Estimated bound.']);
	assert.equal(fs.product, AREAS['FS-DATA-WRITE'].product);
	const pubsub = rows.find((r) => r.parent === 'PUBSUB');
	assert.deepEqual(pubsub.knownDifferences, ['Negative cache is not emulated.']);
});

test('rows are ordered by product and then by area', () => {
	const rows = productionAreaRows([
		closure('PUBSUB', ['VERIFIED']),
		closure('FS-RULES', ['VERIFIED']),
		closure('AUTH-MFA', ['VERIFIED']),
		closure('FS-DATA-WRITE', ['VERIFIED']),
	]);
	assert.deepEqual(
		rows.map((r) => r.parent),
		['FS-DATA-WRITE', 'FS-RULES', 'AUTH-MFA', 'PUBSUB'],
	);
});

test('an area that is not verified is never labelled verified', () => {
	const [row] = productionAreaRows([{ ...closure('FS-RULES', ['VERIFIED']), parentStatus: 'IN_PROGRESS' }]);
	assert.equal(row.status, 'In progress');
});

test('an unmapped production area fails the build so it gets a description', () => {
	assert.throws(() => productionAreaRows([closure('NEW-AREA', ['VERIFIED'])]), /NEW-AREA/);
});

test('an unknown condition status fails the build', () => {
	assert.throws(() => productionAreaRows([closure('FS-RULES', ['MAYBE'])]), /MAYBE/);
});

test('capability rows group by product and keep the manifest status', () => {
	const rows = capabilityRows({
		'FS-QRY-1': { status: 'implemented' },
		'APPCHECK-REPLAY-1': { status: 'unsupported', notes: ['no replay'] },
		'ST-OBJ-1': { status: 'partial', implemented: ['a'], unimplemented: ['b'] },
	});
	assert.deepEqual(
		rows.map((r) => [r.id, r.product, r.status]),
		[
			['FS-QRY-1', 'Cloud Firestore', 'Implemented'],
			['ST-OBJ-1', 'Cloud Storage', 'Partial'],
			['APPCHECK-REPLAY-1', 'App Check', 'Not supported'],
		],
	);
	assert.deepEqual(rows[1].unimplemented, ['b']);
});

test('an unknown capability prefix fails the build', () => {
	assert.throws(() => capabilityRows({ 'ZZZ-1': { status: 'implemented' } }), /ZZZ-1/);
});

test('the repository data maps completely', async () => {
	const data = await loadRepositoryData();
	assert.ok(productSurfaceRows(data.contract).length > 0);
	const areas = productionAreaRows(data.closures);
	assert.equal(areas.length, data.closures.length);
	assert.ok(capabilityRows(data.capabilities).length > 0);
});

test('the repository root is found from a nested directory and refused outside a checkout', async () => {
	const { findRepoRoot } = await import('./compat.mjs');
	const root = findRepoRoot();
	assert.equal(findRepoRoot(`${root}/site/src/data`), root);
	assert.throws(() => findRepoRoot('/'), /no repository checkout/);
});
