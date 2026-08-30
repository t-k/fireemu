import { describe, expect, it } from "vitest";
import { render } from "@solidjs/testing-library";

// The app renders untrusted content -- log lines, object names, rule text, user metadata --
// only through Solid's text interpolation, never through innerHTML. These tests lock that
// guarantee for the exact JSX patterns the pages use: a crafted string must appear as text,
// producing no elements of its own.
const HOSTILE = '<script>window.__pwned = 1</script><img src=x onerror="window.__pwned=1">';

describe("untrusted content is escaped, never parsed as HTML", () => {
  it("renders a hostile log line inside a <pre> as text", () => {
    const { container, unmount } = render(() => <pre>{[HOSTILE, "info ok"].join("\n")}</pre>);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
    unmount();
  });

  it("renders a hostile value inside a table cell as text", () => {
    const { container, unmount } = render(() => (
      <table>
        <tbody>
          <tr>
            <td>{HOSTILE}</td>
          </tr>
        </tbody>
      </table>
    ));
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("td")?.textContent).toBe(HOSTILE);
    unmount();
  });
});
