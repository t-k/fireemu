// Turns the machine-readable compatibility records of the repository into the
// rows the compatibility pages render. Every lookup is exhaustive: a scope,
// state, status or area this module does not know fails the build, so a new
// record can never be shown with a wrong or missing label.

import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

const PRODUCT_ORDER = [
	'Cloud Firestore',
	'Authentication',
	'Cloud Storage',
	'Cloud Functions',
	'Cloud Pub/Sub',
	'Eventarc',
	'App Check',
	'Tooling',
];

/** Production verification areas, as named by spec/compatibility/closure/<parent>.json. */
export const AREAS = {
	'FS-DATA-WRITE': {
		product: 'Cloud Firestore',
		title: 'Writes, batches and limits',
		covers: 'Batched writes, malformed and undecodable values, document, field and index-entry size limits, and request size limits over gRPC, REST and WebChannel.',
	},
	'FS-QUERY-INDEX': {
		product: 'Cloud Firestore',
		title: 'Queries and indexes',
		covers: 'Filters, ordering, cursors, collection groups, aggregations, vector search, partition queries, explain, index selection and read-time queries.',
	},
	'FS-TRANSACTION': {
		product: 'Cloud Firestore',
		title: 'Transactions',
		covers: 'Read-write and read-only transactions, conflicts and locks, expiry, retries in the Web and Admin SDKs, and atomic visibility of commits.',
	},
	'FS-LISTEN-SDK': {
		product: 'Cloud Firestore',
		title: 'Real-time listeners',
		covers: 'Snapshot listener event order, pending writes, reconnect and resume, existence filters and browser tab lifecycle.',
	},
	'FS-RULES': {
		product: 'Cloud Firestore',
		title: 'Firestore Security Rules',
		covers: 'Principals and token fields, tenants, request and resource data, query proofs, access budgets, compile and runtime limits, and refusal shapes.',
	},
	'FS-CONFIG-LIFECYCLE': {
		product: 'Cloud Firestore',
		title: 'Databases and administration',
		covers: 'Named databases, index and field configuration, TTL, long-running operations, export, import and bulk delete.',
	},
	'FS-TEXT-SEARCH': {
		product: 'Cloud Firestore',
		title: 'Enterprise full-text search',
		covers: 'Search stage membership and result order by score and by creation time, recorded search refusals and response frames, and the text index lifecycle, failed builds and repair state.',
	},
	'AUTH-ACCOUNT': {
		product: 'Authentication',
		title: 'Accounts',
		covers: 'Sign-up and profile updates, anonymous accounts, email handling, Admin account management, import with password hashes, and provider linking.',
	},
	'AUTH-CREDENTIAL': {
		product: 'Authentication',
		title: 'Tokens and sessions',
		covers: 'ID and refresh tokens, custom tokens, claim precedence, revocation, session cookies and token expiry.',
	},
	'AUTH-ACTION': {
		product: 'Authentication',
		title: 'Email actions',
		covers: 'Password reset, email verification, email change and email link sign-in, including action-code ownership and expiry.',
	},
	'AUTH-CONFIG-SDK': {
		product: 'Authentication',
		title: 'Project configuration and SDKs',
		covers: 'Project configuration reads and updates, password policies, provider switches, email enumeration protection, and the Admin and Web SDK flows that use them.',
	},
	'AUTH-FEDERATION': {
		product: 'Authentication',
		title: 'OIDC and SAML providers',
		covers: 'Provider configuration, OIDC and SAML assertion checks, account creation and collisions, linking and claims from identity providers.',
	},
	'AUTH-MFA': {
		product: 'Authentication',
		title: 'Multi-factor authentication',
		covers: 'Project MFA configuration, TOTP enrollment and sign-in, SMS factors, withdrawal and second-factor claims.',
	},
	'AUTH-TENANT-BLOCKING': {
		product: 'Authentication',
		title: 'Multi-tenancy and blocking functions',
		covers: 'Tenant management and isolation, tenant settings, and blocking functions before account creation, sign-in and email sending.',
	},
	'AUTH-FS-CROSS': {
		product: 'Authentication',
		title: 'Authentication with Firestore',
		covers: 'How tokens, tenants, sign-out, token refresh and revocation affect Firestore transactions and listeners.',
	},
	'STORAGE-OBJECT': {
		product: 'Cloud Storage',
		title: 'Objects',
		covers: 'Uploads, downloads, download tokens, metadata, listing, copy and rewrite, preconditions, checksums and errors, in both the Firebase and Cloud Storage JSON APIs.',
	},
	'STORAGE-RULES': {
		product: 'Cloud Storage',
		title: 'Storage Security Rules',
		covers: 'Method grants, request and stored resources, token claims, path matching, Firestore lookups from Storage rules, denial shapes and rules releases.',
	},
	'FUNCTIONS-HTTP': {
		product: 'Cloud Functions',
		title: 'HTTP and callable functions',
		covers: 'Request and response handling, streaming, CORS, timeouts, callable envelopes and errors, and callable authentication.',
	},
	'FUNCTIONS-EVENTS': {
		product: 'Cloud Functions',
		title: 'Event triggers',
		covers: 'Firestore, Storage, Authentication and Pub/Sub triggers: which events fire, their payloads and routing, and delivery retries.',
	},
	'SCHEDULED-FUNCTIONS': {
		product: 'Cloud Functions',
		title: 'Scheduled functions',
		covers: 'Schedule grammars, time zones and daylight saving time, delivery to v1 and v2 functions, retries, deadlines and overlap.',
	},
	PUBSUB: {
		product: 'Cloud Pub/Sub',
		title: 'Pub/Sub',
		covers: 'Topics and subscriptions, publish, pull and acknowledgement, redelivery, filters, ordering, dead-letter topics, StreamingPull, snapshots and seek.',
	},
	EVENTARC: {
		product: 'Eventarc',
		title: 'Eventarc',
		covers: 'Channels, publishing through REST and the Admin SDK, publish limits, custom event handlers, trigger filters and delivery retries.',
	},
};

const SURFACE_STATUS = {
	active: { claimed: 'Supported', addition: 'Supported (Fireemu addition)', gap: 'Partially supported' },
	deferred: { none: 'Not yet supported' },
	'not-planned': { none: 'Not planned' },
};

/** @param {{ surfaces: Array<Record<string, any>> }} contract */
export function productSurfaceRows(contract) {
	return contract.surfaces.map((surface) => {
		const byState = SURFACE_STATUS[surface.scope];
		if (!byState) throw new Error(`unknown surface scope "${surface.scope}" on ${surface.id}`);
		const status = byState[surface.state];
		if (!status) throw new Error(`unknown surface state "${surface.state}" for scope ${surface.scope} on ${surface.id}`);
		return {
			id: surface.id,
			title: surface.title,
			status,
			official: surface.official === true,
			inSuite: surface.official === true ? 'Yes' : surface.state === 'addition' ? 'No (Fireemu addition)' : '—',
			port: surface.officialDefaultPort ?? null,
		};
	});
}

const AREA_STATUS = { COMPAT_VERIFIED: 'Verified against production', IN_PROGRESS: 'In progress' };
const CONDITION_STATUSES = new Set(['VERIFIED', 'KNOWN_DIFFERENCE_APPROVED']);

function differenceTexts(record) {
	const texts = [];
	for (const entry of record.approvedKnownDifferences ?? []) texts.push(entry.reason);
	for (const entry of Object.values(record.knownDifferences ?? {})) texts.push(entry.statement);
	return texts.filter((text) => typeof text === 'string' && text.length > 0);
}

const productRank = (product) => {
	const rank = PRODUCT_ORDER.indexOf(product);
	if (rank < 0) throw new Error(`product "${product}" has no place in PRODUCT_ORDER`);
	return rank;
};

/** @param {Array<Record<string, any>>} closures */
export function productionAreaRows(closures) {
	const rows = closures.map((record) => {
		const area = AREAS[record.parent];
		if (!area) throw new Error(`production area ${record.parent} has no entry in AREAS`);
		const status = AREA_STATUS[record.parentStatus];
		if (!status) throw new Error(`unknown parent status "${record.parentStatus}" on ${record.parent}`);
		for (const condition of record.conditions) {
			if (!CONDITION_STATUSES.has(condition.status)) {
				throw new Error(`unknown condition status "${condition.status}" on ${condition.conditionId}`);
			}
		}
		return {
			parent: record.parent,
			...area,
			status,
			total: record.conditions.length,
			verified: record.conditions.filter((c) => c.status === 'VERIFIED').length,
			conditions: record.conditions.map((c) => ({
				id: c.conditionId.startsWith(`${record.parent}/`) ? c.conditionId.slice(record.parent.length + 1) : c.conditionId,
				status: c.status,
			})),
			knownDifferences: differenceTexts(record),
		};
	});
	const order = Object.keys(AREAS);
	return rows.sort(
		(a, b) => productRank(a.product) - productRank(b.product) || order.indexOf(a.parent) - order.indexOf(b.parent),
	);
}

const CAPABILITY_PRODUCTS = [
	['APPCHECK-', 'App Check'],
	['AUTH-', 'Authentication'],
	['FS-', 'Cloud Firestore'],
	['RULES-', 'Cloud Firestore'],
	['ST-', 'Cloud Storage'],
	['STORAGE-', 'Cloud Storage'],
	['FN-', 'Cloud Functions'],
	['PUBSUB-', 'Cloud Pub/Sub'],
	['CTL-', 'Tooling'],
	['CLI-', 'Tooling'],
	['LOG-', 'Tooling'],
	['DATA-', 'Tooling'],
];

// Manifest notes may point at the private issue tracker under docs.local/,
// which is never published.
const PRIVATE_PATH = /\s*\(docs\.local\/[^)\s]*\)|docs\.local\/\S*/g;
const publicText = (texts) => texts.map((text) => text.replace(PRIVATE_PATH, (m) => (m.trimStart().startsWith('(') ? '' : '(private note)')));

const CAPABILITY_STATUS = { implemented: 'Implemented', partial: 'Partial', unsupported: 'Not supported' };

/** @param {Record<string, Record<string, any>>} manifest */
export function capabilityRows(manifest) {
	const rows = Object.entries(manifest).map(([id, entry]) => {
		const match = CAPABILITY_PRODUCTS.find(([prefix]) => id.startsWith(prefix));
		if (!match) throw new Error(`capability ${id} has no product in CAPABILITY_PRODUCTS`);
		const status = CAPABILITY_STATUS[entry.status];
		if (!status) throw new Error(`unknown capability status "${entry.status}" on ${id}`);
		return {
			id,
			product: match[1],
			status,
			implemented: publicText(entry.implemented ?? []),
			unimplemented: publicText([...(entry.unimplemented ?? []), ...(entry.unsupported ?? [])]),
			notes: publicText(entry.notes ?? []),
		};
	});
	return rows.sort((a, b) => productRank(a.product) - productRank(b.product));
}

/**
 * The repository checkout the site is built in: the nearest directory, from the
 * working directory up, that holds the compatibility contract. The build runs
 * bundled code, so a path relative to this module would not survive it.
 */
export function findRepoRoot(start = process.cwd()) {
	for (let dir = path.resolve(start); ; dir = path.dirname(dir)) {
		if (existsSync(path.join(dir, 'spec/compatibility/contract.json'))) return dir;
		if (path.dirname(dir) === dir) throw new Error(`no repository checkout above ${start}`);
	}
}

const readJson = async (relative) => JSON.parse(await readFile(path.join(findRepoRoot(), relative), 'utf8'));

/** Reads the records from the repository checkout the site is built in. */
export async function loadRepositoryData() {
	const closureDir = 'spec/compatibility/closure';
	const names = (await readdir(path.join(findRepoRoot(), closureDir)))
		.filter((name) => /^[A-Z][A-Z-]*\.json$/.test(name))
		.sort();
	return {
		contract: await readJson('spec/compatibility/contract.json'),
		capabilities: await readJson('crates/fireemu/src/capabilities.json'),
		closures: await Promise.all(names.map((name) => readJson(path.join(closureDir, name)))),
	};
}
