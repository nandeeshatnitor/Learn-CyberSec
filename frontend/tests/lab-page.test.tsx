import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  notFound: vi.fn(() => {
    throw new Error("NEXT_NOT_FOUND");
  }),
}));
vi.mock("@/components/lab/lab-workspace", () => ({
  LabWorkspace: ({ instanceId, backHref }: { instanceId: string; backHref: string | null }) => (
    <div data-testid="workspace-stub" data-back={backHref ?? ""}>{instanceId}</div>
  ),
}));

import LabPage from "@/app/lab/[instanceId]/page";

const ID = "22222222-2222-4222-8222-222222222222";
const page = async (instanceId: string, from?: string | string[]) =>
  render(await LabPage({ params: Promise.resolve({ instanceId }), searchParams: Promise.resolve({ from }) }));

describe("/lab/[instanceId]", () => {
  it("renders the workspace for a lab id", async () => {
    await page(ID);
    expect(screen.getByTestId("workspace-stub")).toHaveTextContent(ID);
    expect(screen.getByTestId("workspace-stub")).toHaveAttribute("data-back", "");
  });

  it.each(["not-a-uuid", "../etc/passwd", "22222222-2222-4222-8222-22222222222", ""])("404s for %j", async (bad) => {
    await expect(page(bad)).rejects.toThrow("NEXT_NOT_FOUND");
  });

  it("accepts a link back into this site's own lessons", async () => {
    await page(ID, "/learn/CVE-2099-12345");
    expect(screen.getByTestId("workspace-stub")).toHaveAttribute("data-back", "/learn/CVE-2099-12345");
  });

  it.each(["https://evil.example/", "//evil.example", "/learn/../admin", "/learn/CVE-2099-12345/../../x", "javascript:alert(1)", "/cves/CVE-2099-12345", ["/learn/CVE-2099-12345", "x"]])(
    "never uses %j as a link back",
    async (from) => {
      await page(ID, from as string);
      expect(screen.getByTestId("workspace-stub")).toHaveAttribute("data-back", "");
    },
  );
});
