// Links shown in the site header on every page, including the splash landing
// page, which has no sidebar. Each `slug` is a docs page; `section` marks the
// path prefix that highlights the link as current.
export const headerNav = [
	{ label: 'Why Fireemu', slug: 'getting-started/why-fireemu', section: 'getting-started/why-fireemu' },
	{ label: 'Docs', slug: 'getting-started/install', section: 'getting-started' },
	{ label: 'Guides', slug: 'guides/configuration', section: 'guides' },
	{ label: 'Compatibility', slug: 'compatibility', section: 'compatibility' },
	{ label: 'Reference', slug: 'reference/cli', section: 'reference' },
];

/** The link whose section is the longest prefix of `path` (relative to the site base). */
export function currentNavSlug(path) {
	const clean = path.replace(/^\/+|\/+$/g, '');
	let best;
	for (const item of headerNav) {
		if (clean === item.section || clean.startsWith(`${item.section}/`)) {
			if (!best || item.section.length > best.section.length) best = item;
		}
	}
	return best?.slug;
}
