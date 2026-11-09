# Hosting production observation proposal

Status: unsent, awaiting owner approval of an exact executable packet. This document grants no sending authority. Use one disposable preview channel and never release to the live channel. No credentials or project identifiers belong in this packet.

Observe the shared static, redirect, rewrite, header, cleanUrls, trailingSlash, i18n, reserved-path and 404 conditions under three bounded configuration versions. Record request target, method, status, selected headers, body bytes and content digest. Follow no redirect automatically. Production Functions/Run provisioning and invocations need a separate approved packet; they are not concealed in this budget.

| Operation | Maximum requests |
| --- | ---: |
| Service/site/channel prechecks | 3 |
| Create preview channel | 1 |
| Three versions: create, populate, up to twelve uploads, finalize, release | 48 |
| Serving observations, 24 per version | 72 |
| Version metadata readback | 3 |
| Version files listing, one page per version | 3 |
| Delete channel and three versions | 4 |
| Cleanup readbacks | 4 |
| Reserved resolution or cleanup requests | 12 |
| Total hard cap | 150 |

Each request, including a failed request or cleanup request, consumes the cap. Pagination beyond the single allowed files-list page stops collection rather than increasing the bound. The exact packet must specify how ambiguous creation/deletion responses remain unresolved and how later cleanup verification is performed. Automatic retries, unknown upstream requests and unbounded polling are prohibited.

Upload at most 1 MiB per version and receive at most 8 MiB overall. Estimate cost as stored GB-month multiplied by the applicable storage price plus transferred GB multiplied by the applicable transfer price. Free allowances apply project-wide; do not assume unused allowance or claim a zero-dollar run. Illustrative estimate, using prices checked on 2026-11-07: using USD0.026/GB storage and USD0.15/GB transfer, a full monthly-bill illustration with 3 MiB of stored user payload and 8 MiB transferred is about USD0.00134 before any allowance. The monthly storage assumption is illustrative; the cited pages do not establish precise prorating for this packet. This excludes unknown reserved-file storage, protocol overhead, taxes and other project activity; it is neither a billing cap nor a zero-cost promise. The owner must review current prices and project usage before sending. The twelve reserved requests do not authorize Functions or Run deployment.

Record the API's string `fileCount` independently from the uploaded manifest. Enumerate returned file paths to distinguish reserved files from user files, without assuming equality of their counts. Historical metadata statements and the public REST schema are not production evidence for this parent.

References: [Hosting Version API](https://firebase.google.com/docs/reference/hosting/rest/v1beta1/sites.versions), [Hosting usage and pricing](https://firebase.google.com/docs/hosting/usage-quotas-pricing), and [Firebase pricing](https://firebase.google.com/pricing).
