import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@solidjs/testing-library";
import { errAsync, okAsync } from "neverthrow";
import Hosting from "./Hosting";
import * as hosting from "../api/hosting";
import type { HostingInfo } from "../api/hosting";

vi.mock("../api/hosting", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/hosting")>()),
  hostingInfo: vi.fn(),
}));

const served: HostingInfo = {
  served: true,
  url: "http://127.0.0.1:5000/",
  publicRoot: "/work/app/dist",
  publicExists: true,
  site: {
    public: "dist",
    cleanUrls: true,
    trailingSlash: false,
    rewrites: [
      { source: "/api/**", function: { functionId: "api", region: "europe-west1" } },
      { regex: "^/legacy/(.*)$", run: { serviceId: "web", region: "us-central1" } },
      { source: "**", destination: "/index.html" },
    ],
    redirects: [
      { source: "/old", destination: "/new", type: 302 },
      { source: "/gone", destination: "/" },
    ],
    headers: [
      {
        source: "**/*.js",
        headers: [
          { key: "Cache-Control", value: "max-age=3600" },
          { key: "X-A", value: "1" },
        ],
      },
    ],
    i18n: { root: "/locales" },
    ignore: ["**/.*", "**/node_modules/**"],
    appAssociation: "AUTO",
  },
};

beforeEach(() => {
  vi.mocked(hosting.hostingInfo).mockReset();
  vi.mocked(hosting.hostingInfo).mockReturnValue(okAsync(served));
});
afterEach(cleanup);

describe("Hosting", () => {
  it("shows the site: local URL, public directory, flags, i18n, app association and ignore globs", async () => {
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-url")).toBeTruthy());
    const link = ui.getByTestId("hosting-url") as HTMLAnchorElement;
    expect(link.getAttribute("href")).toBe("http://127.0.0.1:5000/");
    expect(link.textContent).toBe("http://127.0.0.1:5000/");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(ui.getByTestId("hosting-public").textContent).toBe("dist");
    expect(ui.getByTestId("hosting-public-root").textContent).toBe("/work/app/dist");
    expect(ui.queryByTestId("hosting-public-missing")).toBeNull();
    expect(ui.getByTestId("hosting-clean-urls").textContent).toBe("yes");
    expect(ui.getByTestId("hosting-trailing-slash").textContent).toContain("removed");
    expect(ui.getByTestId("hosting-i18n-root").textContent).toBe("/locales");
    expect(ui.getByTestId("hosting-app-association").textContent).toBe("AUTO");
    expect(ui.getByTestId("hosting-ignore").textContent).toContain("**/node_modules/**");
  });

  it("describes trailingSlash true, unset and the absent optional keys", async () => {
    vi.mocked(hosting.hostingInfo).mockReturnValue(
      okAsync({ ...served, site: { public: "dist", trailingSlash: true } } as HostingInfo),
    );
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-url")).toBeTruthy());
    expect(ui.getByTestId("hosting-trailing-slash").textContent).toContain("added");
    expect(ui.getByTestId("hosting-clean-urls").textContent).toBe("no");
    expect(ui.queryByTestId("hosting-i18n-root")).toBeNull();
    expect(ui.queryByTestId("hosting-app-association")).toBeNull();
    cleanup();
    vi.mocked(hosting.hostingInfo).mockReturnValue(
      okAsync({ ...served, site: { public: "dist" } } as HostingInfo),
    );
    const unset = render(() => <Hosting />);
    await waitFor(() => expect(unset.getByTestId("hosting-url")).toBeTruthy());
    expect(unset.getByTestId("hosting-trailing-slash").textContent).toContain("unchanged");
  });

  it("lists rewrites in order with their matcher kind and target", async () => {
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-rewrites")).toBeTruthy());
    const rows = ui.getByTestId("hosting-rewrites").querySelectorAll("tbody tr");
    expect(rows.length).toBe(3);
    expect(rows[0]!.textContent).toContain("/api/**");
    expect(rows[0]!.textContent).toContain("glob");
    expect(rows[0]!.textContent).toContain("function api (europe-west1)");
    expect(rows[1]!.textContent).toContain("^/legacy/(.*)$");
    expect(rows[1]!.textContent).toContain("regex");
    expect(rows[1]!.textContent).toContain("Cloud Run web (us-central1)");
    expect(rows[2]!.textContent).toContain("/index.html");
  });

  it("lists redirects with the status (301 when unset) and headers with their pairs", async () => {
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-redirects")).toBeTruthy());
    const redirects = ui.getByTestId("hosting-redirects").querySelectorAll("tbody tr");
    expect(redirects.length).toBe(2);
    expect(redirects[0]!.textContent).toContain("/old");
    expect(redirects[0]!.textContent).toContain("/new");
    expect(redirects[0]!.textContent).toContain("302");
    expect(redirects[1]!.textContent).toContain("301");
    const headers = ui.getByTestId("hosting-headers").querySelectorAll("tbody tr");
    expect(headers.length).toBe(1);
    expect(headers[0]!.textContent).toContain("**/*.js");
    expect(headers[0]!.textContent).toContain("Cache-Control: max-age=3600");
    expect(headers[0]!.textContent).toContain("X-A: 1");
  });

  it("says when a rule list is empty", async () => {
    vi.mocked(hosting.hostingInfo).mockReturnValue(
      okAsync({ ...served, site: { public: "dist" } } as HostingInfo),
    );
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-url")).toBeTruthy());
    for (const kind of ["rewrites", "redirects", "headers"]) {
      expect(ui.queryByTestId(`hosting-${kind}`), kind).toBeNull();
      expect(ui.getByTestId(`hosting-${kind}-none`).textContent, kind).toContain("No ");
    }
  });

  it("warns that every request misses when the public directory did not exist", async () => {
    vi.mocked(hosting.hostingInfo).mockReturnValue(
      okAsync({ ...served, publicExists: false } as HostingInfo),
    );
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-public-missing")).toBeTruthy());
  });

  it("says Hosting is not served, without a link or tables", async () => {
    vi.mocked(hosting.hostingInfo).mockReturnValue(okAsync({ served: false }));
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-not-served")).toBeTruthy());
    expect(ui.getByTestId("hosting-not-served").textContent).toContain("firebase.json");
    expect(ui.queryByTestId("hosting-url")).toBeNull();
    expect(ui.queryByTestId("hosting-rewrites")).toBeNull();
  });

  it("shows a failed read with a retry that reads again", async () => {
    vi.mocked(hosting.hostingInfo).mockReturnValue(errAsync({ status: 503, message: "hub down" }));
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByRole("alert").textContent).toContain("hub down"));
    vi.mocked(hosting.hostingInfo).mockReturnValue(okAsync(served));
    fireEvent.click(ui.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(ui.getByTestId("hosting-url")).toBeTruthy());
  });

  it("refreshes with a guarded button that cannot be double-clicked", async () => {
    const ui = render(() => <Hosting />);
    await waitFor(() => expect(ui.getByTestId("hosting-url")).toBeTruthy());
    expect(vi.mocked(hosting.hostingInfo)).toHaveBeenCalledTimes(1);
    const button = ui.getByTestId("hosting-refresh") as HTMLButtonElement;
    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => expect(vi.mocked(hosting.hostingInfo)).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(button.disabled).toBe(false));
    expect(vi.mocked(hosting.hostingInfo)).toHaveBeenCalledTimes(2);
  });
});
