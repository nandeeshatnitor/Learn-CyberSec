import { describe, expect, it } from "vitest";

import { safeHttpUrl } from "@/lib/url";

describe("safeHttpUrl", () => {
  it("allows http and https", () => {
    expect(safeHttpUrl("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")).toBe(
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    );
    expect(safeHttpUrl("http://example.com/a")).toBe("http://example.com/a");
  });

  it.each([
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "vbscript:x",
    "//example.com",
    "/relative",
    "https://exa mple.com",
    "https://example.com/\u0000",
    " https://example.com",
    "",
    null,
    undefined,
  ])("rejects %j", (value) => {
    expect(safeHttpUrl(value)).toBeNull();
  });
});
