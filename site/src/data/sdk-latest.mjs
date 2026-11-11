export function sdkLatestRows(file) {
	if (!file || typeof file !== 'object' || Array.isArray(file) ||
		(Object.keys(file).length !== 2 || Object.keys(file).sort().join(',') !== 'records,schemaVersion') ||
		file.schemaVersion !== 1 || !Array.isArray(file.records)) {
		throw new Error('Invalid sdk-latest file');
	}

	const rows = [];
	for (const record of file.records) {
		if (!record || typeof record !== 'object' || Array.isArray(record) ||
			(Object.keys(record).length !== 6 || Object.keys(record).sort().join(',') !== 'recordedOn,runId,schemaVersion,smokes,suite,versions') ||
			record.schemaVersion !== 1 || !['light', 'broad'].includes(record.suite) ||
			rows.some((row) => row.suite === record.suite) ||
			typeof record.recordedOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(record.recordedOn) ||
			Number.isNaN(Date.parse(record.recordedOn)) || new Date(record.recordedOn).toISOString().slice(0, 10) !== record.recordedOn ||
			(record.runId !== null && (typeof record.runId !== 'string' || !/^\d+$/.test(record.runId)))) {
			throw new Error('Invalid sdk-latest record');
		}
		const versions = record.versions;
		if (!versions || typeof versions !== 'object' || Array.isArray(versions) ||
			(Object.keys(versions).length !== 4 || Object.keys(versions).sort().join(',') !== 'firebase,firebaseAdmin,firebaseFunctions,fireemu') ||
			!['fireemu', 'firebase', 'firebaseAdmin'].every((key) => typeof versions[key] === 'string' && /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(versions[key])) ||
			(versions.firebaseFunctions !== null && (typeof versions.firebaseFunctions !== 'string' || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(versions.firebaseFunctions))) ||
			!Array.isArray(record.smokes) || record.smokes.length === 0 || new Set(record.smokes).size !== record.smokes.length ||
			!record.smokes.every((smoke) => ['storage', 'client', 'auth', 'firestore-listen-transaction', 'functions'].includes(smoke))) {
			throw new Error('Invalid sdk-latest versions or smokes');
		}
		rows.push({
			suite: record.suite,
			label: record.suite === 'light' ? 'Daily: light' : 'Weekly: broad',
			recordedOn: record.recordedOn,
			runId: record.runId,
			fireemu: versions.fireemu,
			firebase: versions.firebase,
			firebaseAdmin: versions.firebaseAdmin,
			firebaseFunctions: versions.firebaseFunctions ?? 'not installed',
			smokes: record.smokes.join(', '),
		});
	}
	return rows.sort((a, b) => (a.suite === b.suite ? 0 : a.suite === 'light' ? -1 : 1));
}
