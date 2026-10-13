// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { fileURLToPath } from 'node:url';

// The deployment target is set by the Pages workflow. The defaults build for
// https://t-k.github.io/fireemu/, the project page of the repository.
const site = process.env.FIREEMU_SITE_URL ?? 'https://t-k.github.io';
const base = process.env.FIREEMU_SITE_BASE ?? '/fireemu';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
	site,
	base,
	trailingSlash: 'always',
	vite: {
		// The compatibility pages read spec/ and crates/ from the repository root.
		server: { fs: { allow: [repoRoot] } },
	},
	integrations: [
		starlight({
			title: 'Fireemu',
			description:
				'A local Firebase emulator for tests and CI that follows production Firebase behavior.',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/t-k/fireemu' }],
			editLink: { baseUrl: 'https://github.com/t-k/fireemu/edit/main/site/' },
			lastUpdated: false,
			logo: { src: './src/assets/logo.svg' },
			customCss: ['./src/styles/custom.css'],
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Why Fireemu', slug: 'getting-started/why-fireemu' },
						{ label: 'Install and run', slug: 'getting-started/install' },
						{ label: 'Connect your app', slug: 'getting-started/connect' },
						{ label: 'Migrate from the Local Emulator Suite', slug: 'getting-started/migrate' },
					],
				},
				{
					label: 'Products',
					items: [
						{ label: 'Cloud Firestore', slug: 'products/firestore' },
						{ label: 'Authentication', slug: 'products/auth' },
						{ label: 'Cloud Storage', slug: 'products/storage' },
						{ label: 'Cloud Functions', slug: 'products/functions' },
						{ label: 'Pub/Sub and Eventarc', slug: 'products/pubsub-eventarc' },
						{ label: 'App Check', slug: 'products/app-check' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Configuration files', slug: 'guides/configuration' },
						{ label: 'Profiles and productionExact', slug: 'guides/profiles' },
						{ label: 'Security Rules', slug: 'guides/security-rules' },
						{ label: 'Time and scheduled functions', slug: 'guides/time' },
						{ label: 'Export and import data', slug: 'guides/data' },
						{ label: 'Emulator UI', slug: 'guides/ui' },
						{ label: 'CI and containers', slug: 'guides/ci-and-containers' },
						{ label: 'Troubleshooting', slug: 'guides/troubleshooting' },
					],
				},
				{
					label: 'Compatibility',
					items: [
						{ label: 'Compatibility tables', slug: 'compatibility' },
						{ label: 'Limitations', slug: 'compatibility/limitations' },
						{ label: 'Performance', slug: 'compatibility/performance' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI', slug: 'reference/cli' },
						{ label: 'Configuration schema', slug: 'reference/configuration' },
					],
				},
			],
		}),
	],
});
