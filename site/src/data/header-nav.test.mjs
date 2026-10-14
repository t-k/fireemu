import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { headerNav, currentNavSlug } from './header-nav.mjs';

const docs = new URL('../content/docs/', import.meta.url);

test('every header link points at an existing docs page', () => {
	for (const { slug } of headerNav) {
		const found = ['.md', '.mdx', '/index.md', '/index.mdx'].some((ext) =>
			existsSync(new URL(`${slug}${ext}`, docs)),
		);
		assert.ok(found, `no docs page for header link ${slug}`);
	}
});

test('the most specific section is current', () => {
	assert.equal(currentNavSlug('/getting-started/why-fireemu/'), 'getting-started/why-fireemu');
	assert.equal(currentNavSlug('/getting-started/connect/'), 'getting-started/install');
	assert.equal(currentNavSlug('/compatibility/limitations/'), 'compatibility');
	assert.equal(currentNavSlug('/guides/time/'), 'guides/configuration');
	assert.equal(currentNavSlug('/'), undefined);
	assert.equal(currentNavSlug('/products/firestore/'), undefined);
	assert.equal(currentNavSlug('/compatibility-other/'), undefined);
});
