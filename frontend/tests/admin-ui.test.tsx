import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  notFound: () => {
    throw new Error("NEXT_NOT_FOUND");
  },
}));

import ReviewPage from "@/app/admin/labs/[id]/page";
import CandidateLabsPage from "@/app/admin/labs/page";
import { AdminGate } from "@/components/admin/admin-gate";
import { CandidateList } from "@/components/admin/candidate-list";
import { CandidateReview } from "@/components/admin/candidate-review";

import { CAND_ID, detail, installFakeAdmin, summary, version } from "./admin-fixtures";

const TOKEN = "good-reviewer-token-0123456789abc";
afterEach(() => vi.unstubAllGlobals());

const renderList = () =>
  render(<AdminGate>{(_r, out) => <CandidateList onSignedOut={out} />}</AdminGate>);
const renderReview = () =>
  render(<AdminGate>{(_r, out) => <CandidateReview id={CAND_ID} onSignedOut={out} />}</AdminGate>);

describe("sign-in", () => {
  it("asks for a token when nobody is signed in, and rejects a wrong one", async () => {
    installFakeAdmin({ signedIn: false });
    renderList();
    expect(await screen.findByTestId("admin-sign-in")).toBeInTheDocument();
    const field = screen.getByLabelText("Reviewer token");
    expect(field).toHaveAttribute("type", "password");
    await userEvent.setup().type(field, "wrong-token-0123456789abcdef");
    await userEvent.setup().click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("That token was not accepted.");
    expect(screen.queryByTestId("reviewer-name")).toBeNull();
  });

  it("signs in with a good token, shows who the reviewer is and never keeps the token on screen", async () => {
    const api = installFakeAdmin({ signedIn: false });
    renderList();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Reviewer token"), TOKEN);
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByTestId("reviewer-name")).toHaveTextContent("alice");
    expect(document.body.innerHTML).not.toContain(TOKEN);
    expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/admin/session")).toBe(
      true,
    );
  });

  it("signs out", async () => {
    installFakeAdmin();
    renderList();
    await userEvent.setup().click(await screen.findByRole("button", { name: /Sign out/ }));
    expect(await screen.findByTestId("admin-sign-in")).toBeInTheDocument();
  });

  it("says so when the feature is off on the server", async () => {
    vi.stubGlobal(
      "fetch",
      async () =>
        ({
          ok: false,
          status: 503,
          headers: new Headers(),
          json: async () => ({ error: { code: "labgen_disabled", message: "x" } }),
        }) as unknown as Response,
    );
    renderList();
    expect(await screen.findByTestId("admin-unavailable")).toHaveTextContent("not enabled");
  });

  it("returns to the sign-in form when the session ends", async () => {
    const api = installFakeAdmin();
    renderList();
    await screen.findByTestId("candidate-table");
    api.state.signedIn = false;
    await userEvent.setup().selectOptions(screen.getByLabelText("Status"), "approved");
    expect(await screen.findByTestId("admin-sign-in")).toBeInTheDocument();
  });
});

describe("Candidate Labs list", () => {
  it("shows the columns a reviewer needs", async () => {
    installFakeAdmin({
      list: [
        summary(),
        summary({
          id: "66666666-6666-4666-8666-666666666666",
          cve_id: "CVE-2099-5",
          status: "approved",
          reviewer: "bob",
          lab_id: "cve-2099-5-v1",
          source_count: 3,
          security_status: "failed",
        }),
      ],
    });
    renderList();
    const table = await screen.findByTestId("candidate-table");
    for (const header of [
      "CVE",
      "Status",
      "Sources",
      "Build Status",
      "Security Validation",
      "Reviewer",
    ]) {
      expect(within(table).getByRole("columnheader", { name: header })).toBeInTheDocument();
    }
    const [first, second] = screen.getAllByTestId("candidate-row");
    expect(first).toHaveTextContent("CVE-2099-12345");
    expect(first).toHaveTextContent("Awaiting review");
    expect(first).toHaveTextContent("7");
    expect(within(first!).getByRole("link", { name: "CVE-2099-12345" })).toHaveAttribute(
      "href",
      `/admin/labs/${CAND_ID}`,
    );
    expect(second).toHaveTextContent("bob");
    expect(second).toHaveTextContent("published as cve-2099-5-v1");
    expect(second).toHaveTextContent("Failed");
  });

  it("filters by status", async () => {
    const api = installFakeAdmin({
      list: [
        summary(),
        summary({ id: "66666666-6666-4666-8666-666666666666", status: "rejected" }),
      ],
    });
    renderList();
    await screen.findByTestId("candidate-table");
    await userEvent.setup().selectOptions(screen.getByLabelText("Status"), "rejected");
    await waitFor(() => expect(screen.getAllByTestId("candidate-row")).toHaveLength(1));
    expect(api.calls.some((c) => c.path === "/api/admin/labs/candidates?status=rejected")).toBe(
      true,
    );
  });

  it("says when there are none", async () => {
    installFakeAdmin({ list: [] });
    renderList();
    expect(await screen.findByTestId("no-candidates")).toHaveTextContent("No candidate labs yet");
  });

  it("requests a candidate for a CVE, normalising the ID, and says it is queued", async () => {
    const api = installFakeAdmin();
    renderList();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("CVE ID"), " cve-2099-7777 ");
    await user.click(screen.getByRole("button", { name: "Generate candidate" }));
    expect(await screen.findByTestId("generate-notice")).toHaveTextContent("CVE-2099-7777");
    expect(
      api.calls.find((c) => c.method === "POST" && c.path.endsWith("/candidates"))!.body,
    ).toEqual({ cve_id: "CVE-2099-7777", overrides: {} });
  });

  it("refuses an invalid CVE ID without calling the server", async () => {
    const api = installFakeAdmin();
    renderList();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("CVE ID"), "not-a-cve");
    await user.click(screen.getByRole("button", { name: "Generate candidate" }));
    expect(await screen.findByTestId("generate-notice")).toHaveTextContent("Enter a CVE ID");
    expect(api.calls.some((c) => c.method === "POST" && c.path.endsWith("/candidates"))).toBe(
      false,
    );
  });

  it("shows the server's reason when a candidate cannot be requested", async () => {
    const api = installFakeAdmin();
    renderList();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("CVE ID"), "CVE-2099-1111");
    api.state.failNext = {
      status: 422,
      code: "invalid_input",
      message: "There is no learning guide for this CVE yet.",
    };
    await user.click(screen.getByRole("button", { name: "Generate candidate" }));
    expect(await screen.findByTestId("generate-notice")).toHaveTextContent("no learning guide");
  });

  it("refreshes itself while a candidate is being worked on", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const api = installFakeAdmin({
        list: [summary({ status: "building", progress: "Build succeeds: passed" })],
      });
      renderList();
      expect(await screen.findByText("Build succeeds: passed")).toBeInTheDocument();
      api.state.list = [summary({ status: "awaiting_review" })];
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4500);
      });
      await waitFor(() => expect(screen.getByTestId("status-badge")).toHaveTextContent("Awaiting review"));
    } finally {
      vi.useRealTimers();
    }
  });

  it("lists published versions and stops offering one with a reason", async () => {
    const api = installFakeAdmin({ versions: [version()] });
    renderList();
    const user = userEvent.setup();
    const list = await screen.findByTestId("version-list");
    expect(list).toHaveTextContent("cve-2099-12345-v1");
    await user.click(within(list).getByRole("button", { name: "Stop offering" }));
    const withdraw = within(list).getByRole("button", { name: "Withdraw" });
    expect(withdraw).toBeDisabled();
    await user.type(within(list).getByLabelText(/Reason for withdrawing/), "Hints were wrong");
    await user.click(withdraw);
    await waitFor(() => expect(list).toHaveTextContent("withdrawn: Hints were wrong"));
    expect(api.calls.some((c) => c.path.endsWith("/withdraw"))).toBe(true);
  });
});

describe("candidate review", () => {
  it("shows the whole specification, sources, checks, files and gates", async () => {
    installFakeAdmin();
    renderReview();
    expect(await screen.findByTestId("review-title")).toHaveTextContent("revision 1");
    expect(screen.getByTestId("vulnerable-version")).toHaveTextContent("4.2.3");
    expect(
      screen.getByText("Understand how a header can be evaluated as an expression, and fix it."),
    ).toBeInTheDocument();
    expect(screen.getByText(/The header value is evaluated/)).toBeInTheDocument();
    expect(screen.getByText(/Escape the header/)).toBeInTheDocument();
    expect(screen.getAllByTestId("validation-checks")[0]!.querySelectorAll("li")).toHaveLength(10);
    expect(screen.getByTestId("static-findings")).toHaveTextContent("plain text files");
    expect(screen.getByTestId("runtime-findings")).toHaveTextContent("egress");
    expect(screen.getByTestId("gates")).toHaveTextContent("All automated gates passed");
    expect(screen.getByTestId("build-log")).toHaveTextContent("Successfully built");
    expect(screen.getByText("acme/docs:4.2.3")).toBeInTheDocument();
  });

  it("renders source links safely and shows generated files as text, never as markup", async () => {
    installFakeAdmin();
    renderReview();
    const sources = await screen.findByTestId("source-list");
    expect(within(sources).getByRole("link", { name: /Acme advisory/ })).toHaveAttribute(
      "href",
      "https://advisories.acme-vendor.test/a",
    );
    expect(within(sources).queryByRole("link", { name: /Sneaky/ })).toBeNull(); // javascript: is inert text
    const user = userEvent.setup();
    await user.click(screen.getByRole("tab", { name: "app/server.py" }));
    expect(screen.getByTestId("file-view")).toHaveTextContent("<script>alert(1)</script>");
    expect(document.querySelector("script")).toBeNull();
  });

  it("approves only after an explicit confirmation", async () => {
    const api = installFakeAdmin();
    renderReview();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Approve" }));
    expect(api.calls.some((c) => c.path.endsWith("/approve"))).toBe(false);
    expect(screen.getByText(/Publish this to students as the next version/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Yes, publish" }));
    expect(await screen.findByTestId("published-as")).toHaveTextContent("cve-2099-12345-v1");
    expect(screen.getByTestId("decision-message")).toHaveTextContent("Approved and published.");
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });

  it("cancelling the confirmation does nothing", async () => {
    const api = installFakeAdmin();
    renderReview();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Approve" }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(api.calls.some((c) => c.path.endsWith("/approve"))).toBe(false);
  });

  it("will not offer approval while a gate has not passed, and lists why", async () => {
    installFakeAdmin({
      detail: detail({
        status: "awaiting_review",
        can_approve: false,
        blockers: ["not all ten automated validation checks passed"],
      }),
    });
    renderReview();
    expect(await screen.findByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByTestId("gates")).toHaveTextContent(
      "not all ten automated validation checks passed",
    );
  });

  it("requires notes to reject or request changes", async () => {
    const api = installFakeAdmin();
    renderReview();
    const user = userEvent.setup();
    const reject = await screen.findByRole("button", { name: "Reject" });
    const changes = screen.getByRole("button", { name: "Request Changes" });
    expect(reject).toBeDisabled();
    expect(changes).toBeDisabled();
    await user.type(screen.getByLabelText(/Notes/), "Use the documented header.");
    expect(changes).toBeEnabled();
    await user.click(changes);
    expect(await screen.findByTestId("decision-message")).toHaveTextContent("Changes requested.");
    expect(api.calls.find((c) => c.path.endsWith("/request-changes"))!.body).toEqual({
      notes: "Use the documented header.",
    });
  });

  it("rejects with the notes", async () => {
    const api = installFakeAdmin();
    renderReview();
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText(/Notes/), "Out of scope");
    await user.click(screen.getByRole("button", { name: "Reject" }));
    expect(await screen.findByTestId("decision-message")).toHaveTextContent("Rejected.");
    expect(api.calls.find((c) => c.path.endsWith("/reject"))!.body).toEqual({
      notes: "Out of scope",
    });
  });

  it("shows the server's refusal, for example a gate that no longer holds", async () => {
    const api = installFakeAdmin();
    renderReview();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Approve" }));
    api.state.failNext = {
      status: 409,
      code: "conflict",
      message: "Cannot approve: the built image changed since it was validated.",
    };
    await user.click(screen.getByRole("button", { name: "Yes, publish" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("the built image changed");
    expect(screen.queryByTestId("published-as")).toBeNull();
  });

  it("generates a new revision with the reviewer's corrections", async () => {
    const api = installFakeAdmin({
      detail: detail({ status: "changes_requested", can_approve: false }),
    });
    renderReview();
    const user = userEvent.setup();
    await user.click(await screen.findByText("Generate a new revision"));
    await user.type(screen.getByLabelText("Endpoint path"), "/render");
    await user.type(screen.getByLabelText("Vulnerable version"), "4.1.0");
    await user.click(screen.getByRole("button", { name: /Generate revision/ }));
    expect(await screen.findByTestId("decision-message")).toHaveTextContent(
      "A new revision is being generated.",
    );
    expect(api.calls.find((c) => c.path.endsWith("/regenerate"))!.body).toEqual({
      overrides: { endpoint: "/render", vulnerable_version: "4.1.0" },
    });
  });

  it("offers no decision on an approved candidate, only a new revision", async () => {
    installFakeAdmin({
      detail: detail({
        status: "approved",
        can_approve: false,
        lab_id: "cve-2099-12345-v1",
        reviewer: "alice",
      }),
    });
    renderReview();
    expect(await screen.findByTestId("published-as")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reject" })).toBeNull();
    expect(screen.getByTestId("regenerate")).toBeInTheDocument();
  });

  it("shows the review history", async () => {
    installFakeAdmin({
      detail: detail({
        status: "changes_requested",
        can_approve: false,
        reviews: [
          {
            reviewer: "bob",
            action: "request_changes",
            from_status: "awaiting_review",
            to_status: "changes_requested",
            notes: "Use /render",
            at: "2026-10-01T08:00:00Z",
          },
        ],
      }),
    });
    renderReview();
    expect(await screen.findByTestId("review-history")).toHaveTextContent("bob — request changes");
    expect(screen.getByTestId("review-history")).toHaveTextContent("Use /render");
  });

  it("reports an unknown candidate", async () => {
    installFakeAdmin();
    render(
      <AdminGate>
        {(_r, out) => (
          <CandidateReview id="99999999-9999-4999-8999-999999999999" onSignedOut={out} />
        )}
      </AdminGate>,
    );
    expect(await screen.findByTestId("review-problem")).toHaveTextContent("does not exist");
  });
});

describe("admin pages", () => {
  it("lists candidate labs from the page", async () => {
    installFakeAdmin();
    render(<CandidateLabsPage />);
    expect(screen.getByRole("heading", { name: "Candidate labs" })).toBeInTheDocument();
    expect(await screen.findByTestId("candidate-table")).toBeInTheDocument();
  });

  it("404s for a review id that is not a UUID", async () => {
    for (const bad of ["not-a-uuid", "../x", "3333"]) {
      await expect(ReviewPage({ params: Promise.resolve({ id: bad }) })).rejects.toThrow(
        "NEXT_NOT_FOUND",
      );
    }
    installFakeAdmin();
    render(await ReviewPage({ params: Promise.resolve({ id: CAND_ID }) }));
    expect(await screen.findByTestId("review-title")).toBeInTheDocument();
  });
});
