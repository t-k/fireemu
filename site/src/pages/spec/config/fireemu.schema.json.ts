// Serves the configuration JSON Schema from the repository, unchanged.
import type { APIRoute } from 'astro';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { findRepoRoot } from '../../../data/compat.mjs';

export const GET: APIRoute = async () => {
	const schema = await readFile(path.join(findRepoRoot(), 'spec/config/fireemu.schema.json'), 'utf8');
	return new Response(schema, { headers: { 'Content-Type': 'application/schema+json' } });
};
