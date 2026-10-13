# Fireemu documentation site

The documentation site for Fireemu, built with [Astro Starlight](https://starlight.astro.build/) and published to GitHub Pages by `.github/workflows/pages.yml`.

```sh
pnpm -C site install --frozen-lockfile
pnpm -C site test      # checks the compatibility data mapping
pnpm -C site build     # writes site/dist
pnpm -C site preview   # serves site/dist locally
```

The compatibility pages are generated at build time from `spec/compatibility/contract.json`, `spec/compatibility/closure/*.json` and `crates/fireemu/src/capabilities.json`. A new production area, surface state or capability prefix fails the build until `src/data/compat.mjs` describes it.

`FIREEMU_SITE_URL` and `FIREEMU_SITE_BASE` override the deployment URL (default `https://t-k.github.io` and `/fireemu`).
