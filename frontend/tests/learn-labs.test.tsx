import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LearningWorkspace } from "@/components/learn/learning-workspace";

import { CVE, installFakeLearningApi } from "./learning-fixtures";
import { INSTANCE_ID, NEW_INSTANCE_ID, SESSION_ID, instance, makeFakeSandbox, sessionLabs } from "./sandbox-fixtures";

const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => router }));

beforeEach(() => router.push.mockReset());
afterEach(() => vi.unstubAllGlobals());

const setup = () => userEvent.setup();
const FROM = "%2Flearn%2FCVE-2099-12345";

async function openLesson(sandbox: ReturnType<typeof makeFakeSandbox>) {
  const learning = installFakeLearningApi({ existing: "in_progress", sandbox: sandbox.handler });
  render(<LearningWorkspace cveId={CVE} />);
  await screen.findByTestId("workspace");
  return learning;
}

describe("hands-on lab in the learning workspace", () => {
  it("offers a lab that fits the vulnerability, with its objectives and no progress yet", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(0) });
    await openLesson(sandbox);
    const card = await screen.findByTestId("labs-card");
    expect(within(card).getByRole("heading", { name: "Path traversal in a document portal" })).toBeInTheDocument();
    expect(within(card).getByTestId("lab-progress-text")).toHaveTextContent("0 of 2 objectives verified");
    expect(within(card).getByRole("progressbar", { name: /objectives/ })).toHaveAttribute("aria-valuenow", "0");
    expect(within(card).getByText("Fix the vulnerability")).toBeInTheDocument();
    expect(within(card).getByText(/no network access/)).toBeInTheDocument();
    expect(screen.getByRole("complementary", { name: "Objectives and progress" })).toContainElement(card);
  });

  it("starts the lab inside this learning session and opens it", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(0) });
    await openLesson(sandbox);
    await setup().click(await screen.findByRole("button", { name: "Start lab" }));
    const start = sandbox.calls.find((c) => c.method === "POST" && c.path === "/api/sandbox/instances")!;
    expect(start.body).toEqual({ lab_id: "path-traversal-101", session_id: SESSION_ID });
    await vi.waitFor(() => expect(router.push).toHaveBeenCalledWith(`/lab/${NEW_INSTANCE_ID}?from=${FROM}`));
  });

  it("shows the student's verified objectives as progress", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(1, { last_instance_id: INSTANCE_ID }) });
    await openLesson(sandbox);
    const card = await screen.findByTestId("labs-card");
    expect(within(card).getByTestId("lab-progress-text")).toHaveTextContent("1 of 2 objectives verified");
    expect(within(card).getByRole("progressbar")).toHaveAttribute("aria-valuenow", "50");
    expect(within(card).getByText("(verified)")).toBeInTheDocument();
    expect(within(card).getByRole("button", { name: "Start a fresh lab" })).toBeInTheDocument();
  });

  it("keeps an earlier version's progress visible but does not offer to start it", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(2, { retired: true, last_instance_id: INSTANCE_ID }) });
    await openLesson(sandbox);
    const card = await screen.findByTestId("labs-card");
    expect(within(card).getByTestId("lab-retired")).toHaveTextContent(/earlier version/i);
    expect(within(card).getByTestId("lab-progress-text")).toHaveTextContent("2 of 2 objectives verified");
    expect(within(card).queryByRole("button", { name: /Start/ })).toBeNull();
  });

  it("lets the student resume a lab that is still running", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(1, { instance_id: INSTANCE_ID, last_instance_id: INSTANCE_ID }) });
    await openLesson(sandbox);
    const link = await screen.findByRole("link", { name: "Resume lab" });
    expect(link).toHaveAttribute("href", `/lab/${INSTANCE_ID}?from=${FROM}`);
    expect(screen.queryByRole("button", { name: /Start/ })).toBeNull();
  });

  it("explains a refusal and points to the lab that is already running", async () => {
    const sandbox = makeFakeSandbox({
      session: sessionLabs(0),
      startError: { status: 409, code: "conflict", message: "You already have a lab running. Stop or reset it first." },
    });
    sandbox.state.current = instance();
    await openLesson(sandbox);
    await setup().click(await screen.findByRole("button", { name: "Start lab" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/already have a lab running/);
    expect(within(alert).getByRole("link", { name: "Open it" })).toHaveAttribute("href", `/lab/${INSTANCE_ID}?from=${FROM}`);
    expect(router.push).not.toHaveBeenCalled();
  });

  it("shows other start failures as fixed messages", async () => {
    const sandbox = makeFakeSandbox({
      session: sessionLabs(0),
      startError: { status: 502, code: "lab_start_failed", message: "The lab was not started because its network isolation could not be verified." },
    });
    await openLesson(sandbox);
    await setup().click(await screen.findByRole("button", { name: "Start lab" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/network isolation could not be verified/);
  });

  it("shows nothing when no lab fits this CVE", async () => {
    const sandbox = makeFakeSandbox({ session: { session_id: SESSION_ID, labs: [] } });
    await openLesson(sandbox);
    await new Promise((r) => setTimeout(r, 30));
    expect(screen.queryByTestId("labs-card")).toBeNull();
  });

  it("includes the lab progress in the summary once the session is complete", async () => {
    const sandbox = makeFakeSandbox({ session: sessionLabs(1) });
    installFakeLearningApi({ existing: "in_progress", sandbox: sandbox.handler });
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await screen.findByTestId("workspace");
    const answers = ["The template engine", "The X-Template-Hint header", "The renderer does not sanitize it"];
    for (const text of answers) {
      await user.clear(screen.getByLabelText("Your answer"));
      await user.type(screen.getByLabelText("Your answer"), text);
      await user.click(screen.getByRole("button", { name: "Submit answer" }));
      const next = screen.queryByRole("button", { name: /Next task|Continue/ });
      if (next) await user.click(next);
    }
    await user.click(await screen.findByRole("button", { name: "Complete session" }));
    const summary = await screen.findByTestId("summary");
    const labs = within(summary).getByTestId("summary-labs");
    expect(labs).toHaveTextContent("Path traversal in a document portal");
    expect(labs).toHaveTextContent("1 of 2 objectives verified");
  });
});
