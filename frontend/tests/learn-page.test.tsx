import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { makeDetail } from "./fixtures";

vi.mock("@/lib/api", () => ({ getCve: vi.fn(), searchCves: vi.fn(), getHealth: vi.fn() }));
vi.mock("next/navigation", () => ({
  notFound: vi.fn(() => {
    throw new Error("NEXT_NOT_FOUND");
  }),
  redirect: vi.fn(),
}));
vi.mock("@/components/learn/learning-workspace", () => ({
  LearningWorkspace: ({ cveId }: { cveId: string }) => <div data-testid="workspace-stub">{cveId}</div>,
}));

import LearnPage from "@/app/learn/[cveId]/page";
import { getCve } from "@/lib/api";

const getCveMock = vi.mocked(getCve);
const renderPage = async (cveId: string) => render(await LearnPage({ params: Promise.resolve({ cveId }) }));

beforeEach(() => vi.clearAllMocks());

describe("/learn/[cveId]", () => {
  it("renders the lesson shell with the CVE's severity and the workspace", async () => {
    getCveMock.mockResolvedValue({ ok: true, data: makeDetail() });
    await renderPage("cve-2021-44228");
    expect(getCveMock).toHaveBeenCalledWith("CVE-2021-44228");
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent("CVE-2021-44228");
    expect(screen.getByRole("link", { name: /Back to CVE-2021-44228/ })).toHaveAttribute("href", "/cves/CVE-2021-44228");
    expect(screen.getByTestId("workspace-stub")).toHaveTextContent("CVE-2021-44228");
    expect(screen.getByText(/education and authorized testing only/i)).toBeInTheDocument();
  });

  it("still works when the CVE lookup fails (the workspace loads its own data)", async () => {
    getCveMock.mockResolvedValue({ ok: false, kind: "unavailable", message: "down" });
    await renderPage("CVE-2021-44228");
    expect(screen.getByTestId("workspace-stub")).toBeInTheDocument();
  });

  it.each(["nope", "%E0%A4%A", "CVE-2021-44228%00", "CVE-2021-1"])("404s malformed id %j without calling the API", async (id) => {
    await expect(renderPage(id)).rejects.toThrow("NEXT_NOT_FOUND");
    expect(getCveMock).not.toHaveBeenCalled();
  });
});
