import type { ResultAsync } from "neverthrow";
import { request, type ApiError } from "./client";

/** One entry of `rewrites`, `redirects` or `headers`, as written in `firebase.json`. */
export type HostingRule = Record<string, unknown>;

/** The routing keys of the served site (the server returns no other key). */
export type HostingSite = {
  public?: string;
  cleanUrls?: boolean;
  trailingSlash?: boolean;
  rewrites?: HostingRule[];
  redirects?: HostingRule[];
  headers?: HostingRule[];
  i18n?: { root?: string };
  ignore?: string[];
  appAssociation?: string;
};

export type HostingInfo =
  | { served: false }
  | {
      served: true;
      /** The local URL of the site, with a trailing slash. */
      url: string;
      /** The public directory as the server resolved it. */
      publicRoot: string;
      /** False when the directory did not exist at start: every file lookup misses. */
      publicExists: boolean;
      site: HostingSite;
    };

/** The served Hosting site and the rules in effect (read-only). */
export const hostingInfo = (): ResultAsync<HostingInfo, ApiError> =>
  request<HostingInfo>("GET", "hosting");
