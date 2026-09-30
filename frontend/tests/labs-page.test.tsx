import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LabsCatalog } from "@/components/lab/labs-catalog";
import { SiteHeader } from "@/components/site-header";

import { INSTANCE_ID, NEW_INSTANCE_ID, installFakeSandbox, instance, lab } from "./sandbox-fixtures";

const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => router, notFound: () => { throw new Error("NEXT_NOT_FOUND"); } }));

beforeEach(() => router.push.mockReset());
afterEach(() => vi.unstubAllGlobals());

describe("labs catalogue", () => {
  it("lists the labs with what they are and starts one", async () => {
    const api = installFakeSandbox();
    render(<LabsCatalog />);
    const list = await screen.findByTestId("lab-list");
    expect(list).toHaveTextContent("Path traversal in a document portal");
    expect(list).toHaveTextContent("CWE-22");
    expect(list).toHaveTextContent(/Lasts 45 minutes · no network access · 2 objectives/);
    await userEvent.setup().click(screen.getByRole("button", { name: "Start lab" }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith(`/lab/${NEW_INSTANCE_ID}`));
    expect(api.calls.find((c) => c.method === "POST")!.body).toEqual({ lab_id: "path-traversal-101" }); // no session
  });

  it("offers to resume a lab that is already running instead of starting a second", async () => {
    const api = installFakeSandbox();
    api.state.current = instance();
    render(<LabsCatalog />);
    expect(await screen.findByTestId("resume-lab")).toHaveTextContent(/lab running/);
    expect(screen.getByRole("link", { name: "Resume it" })).toHaveAttribute("href", `/lab/${INSTANCE_ID}`);
    expect(screen.getByRole("button", { name: "Start lab" })).toBeDisabled();
  });

  it("says plainly when labs are not enabled on the server", async () => {
    vi.stubGlobal("fetch", async () => ({ ok: false, status: 503, headers: new Headers(), json: async () => ({ error: { code: "sandbox_disabled", message: "Labs are not enabled on this server." } }) }) as unknown as Response);
    render(<LabsCatalog />);
    expect(await screen.findByTestId("labs-unavailable")).toHaveTextContent("Hands-on labs are not enabled on this server.");
  });

  it("shows why a lab could not be started", async () => {
    installFakeSandbox({ labs: [lab()], startError: { status: 503, code: "lab_capacity", message: "All lab slots are in use right now. Try again in a few minutes." } });
    render(<LabsCatalog />);
    await userEvent.setup().click(await screen.findByRole("button", { name: "Start lab" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/All lab slots are in use/);
    expect(router.push).not.toHaveBeenCalled();
  });

  it("is reachable from the header", () => {
    render(<SiteHeader />);
    expect(screen.getByRole("link", { name: "Labs" })).toHaveAttribute("href", "/labs");
  });
});
