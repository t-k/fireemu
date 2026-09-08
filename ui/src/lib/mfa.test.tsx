import { afterEach, expect, it } from "vitest";
import { cleanup, render } from "@solidjs/testing-library";
import { MfaSummary } from "../pages/Auth";

afterEach(cleanup);
it("shows absent and empty enrollment states", () => {
  const ui = render(() => (
    <>
      <span>
        <MfaSummary />
      </span>
      <span>
        <MfaSummary enrollments={[]} />
      </span>
    </>
  ));
  expect(ui.getAllByText("No second factors")).toHaveLength(2);
});
it("shows factor types without exposing enrollment details or secrets", () => {
  const ui = render(() => (
    <MfaSummary
      enrollments={[
        { mfaEnrollmentId: "phone-id", phoneInfo: "+15555550123" },
        { mfaEnrollmentId: "totp-id", totpInfo: { secret: "hidden-secret" } },
        { mfaEnrollmentId: "unknown-id", displayName: "private-label" },
      ]}
    />
  ));
  expect(ui.container.textContent).toBe("Phone, TOTP, Unknown factor");
});
