import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LearningWorkspace } from "@/components/learn/learning-workspace";

import { CVE, installFakeLearningApi } from "./learning-fixtures";

afterEach(() => vi.unstubAllGlobals());

const setup = () => userEvent.setup();

async function start(user: ReturnType<typeof setup>) {
  await user.click(await screen.findByRole("button", { name: "Start learning session" }));
  await screen.findByTestId("workspace");
}
async function answer(user: ReturnType<typeof setup>, text: string) {
  await user.clear(screen.getByLabelText("Your answer"));
  await user.type(screen.getByLabelText("Your answer"), text);
  await user.click(screen.getByRole("button", { name: "Submit answer" }));
}

describe("learning workspace", () => {
  it("points to the CVE page when no guide has been generated", async () => {
    installFakeLearningApi({ guideAvailable: false });
    render(<LearningWorkspace cveId={CVE} />);
    expect(await screen.findByText("Generate the learning guide first")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Go to the CVE page" })).toHaveAttribute("href", `/cves/${CVE}#learning-guide`);
  });

  it("introduces the exercise and starts a session", async () => {
    const api = installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    expect(await screen.findByTestId("intro")).toHaveTextContent(/full solution stays hidden/);
    expect(screen.getByTestId("intro")).toHaveTextContent(/−5, −10 and −15/);
    await start(setup());
    expect(api.count("POST", /\/api\/learning$/)).toBe(1);
    expect(api.count("POST", /\/start$/)).toBe(1);
    expect(screen.getByRole("heading", { name: "Identify the vulnerable component" })).toBeInTheDocument();
  });

  it("lays out objectives and progress (left), the task (centre), tutor, hints and sources (right)", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    await start(setup());
    const left = screen.getByRole("complementary", { name: "Objectives and progress" });
    const right = screen.getByRole("complementary", { name: "Tutor, hints and sources" });
    expect(within(left).getByRole("progressbar", { name: "Learning progress" })).toHaveAttribute("aria-valuenow", "0");
    expect(within(left).getByTestId("objectives").querySelectorAll("li")).toHaveLength(3);
    expect(within(left).getByTestId("prerequisites")).toHaveTextContent(/local or authorized lab/);
    expect(within(screen.getByRole("main")).getByTestId("task-panel")).toBeInTheDocument();
    expect(within(right).getByRole("heading", { name: "AI tutor" })).toBeInTheDocument();
    expect(within(right).getByRole("heading", { name: "Hints" })).toBeInTheDocument();
    expect(within(right).getByRole("heading", { name: "Sources" })).toBeInTheDocument();
    expect(screen.getByTestId("research-context")).toHaveTextContent(/Investigate first/);
    expect(screen.getByTestId("score")).toHaveTextContent("100");
  });

  it("gives feedback on a wrong and a partial answer without revealing the answer", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);
    await answer(user, "the http request parser");
    expect(await screen.findByTestId("feedback")).toHaveTextContent("Not yet");
    expect(screen.getByTestId("feedback")).not.toHaveTextContent(/template engine/i);
    await answer(user, "something in AcmeDocs");
    expect(screen.getByTestId("feedback")).toHaveTextContent("Partly correct");
    expect(screen.getByTestId("feedback")).toHaveTextContent(/Still missing/);
    expect(screen.queryByTestId("solution")).toBeNull();
  });

  it("shows hints one at a time with their cost, in a log with evidence", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);
    await user.click(screen.getByRole("button", { name: "Get Hint 1 (−5 points)" }));
    expect(await screen.findByText("Follow the data.")).toBeInTheDocument();
    expect(screen.getByTestId("score")).toHaveTextContent("95");
    await user.click(screen.getByRole("button", { name: "Get Hint 2 (−10 points)" }));
    await user.click(screen.getByRole("button", { name: "Get Hint 3 (−15 points)" }));
    const log = screen.getByTestId("hint-log");
    expect(log.querySelectorAll(":scope > li")).toHaveLength(3);
    expect(log).toHaveTextContent("Hint 3");
    expect(log).toHaveTextContent(/The sources state: template engine/);
    expect(within(log).getAllByRole("link", { name: /AcmeDocs Security Advisory/ }).length).toBe(3);
    expect(within(log).getByText("Show the excerpt")).toBeInTheDocument(); // only hint 3 has one
    expect(screen.getByTestId("hints-used")).toHaveTextContent("3");
    expect(screen.getByRole("button", { name: "All hints shown" })).toBeDisabled();
  });

  it("only allows the solution after an attempt, and asks for confirmation", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);
    expect(screen.getByRole("button", { name: /Reveal solution/ })).toBeDisabled();
    expect(screen.getByText(/available after your first answer/)).toBeInTheDocument();
    await answer(user, "no idea at all");
    await user.click(screen.getByRole("button", { name: "Reveal solution (−30)" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent(/costs 30 points/);
    await user.click(screen.getByRole("button", { name: "Keep trying" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.queryByTestId("solution")).toBeNull();
    await user.click(screen.getByRole("button", { name: "Reveal solution (−30)" }));
    await user.click(screen.getByRole("button", { name: "Yes, reveal it" }));
    // the student stays on the task to read the solution, then chooses to continue
    expect(await screen.findByTestId("solution")).toHaveTextContent("AcmeDocs template engine expression injection");
    expect(screen.getByText(/finished with the solution revealed/)).toBeInTheDocument();
    expect(screen.getByTestId("score")).toHaveTextContent("70");
    expect(screen.getByText("A solution was revealed")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Continue to the next task" }));
    expect(await screen.findByRole("heading", { name: "Identify the vulnerable input" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Identify the vulnerable component/ }));
    expect(screen.getByTestId("solution")).toBeInTheDocument(); // still readable from the objectives list
  });

  it("walks the whole journey: answer, hint, tutor, solution, complete, summary", async () => {
    const api = installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);

    await answer(user, "It is the template engine");
    expect(await screen.findByTestId("solution")).toBeInTheDocument();
    expect(screen.getByTestId("progress-text")).toHaveTextContent("1 of 3");
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "33");
    await user.click(screen.getByRole("button", { name: "Continue to the next task" }));

    await user.click(await screen.findByRole("button", { name: "Get Hint 1 (−5 points)" }));
    await user.type(screen.getByLabelText("Ask the tutor"), "Which versions are affected?");
    await user.click(screen.getByRole("button", { name: "Send" }));
    const claim = await screen.findByTestId("tutor-claim");
    expect(claim).toHaveTextContent("Versions 4.0.0 through 4.2.3 are affected.");
    expect(within(claim).getByRole("link", { name: /AcmeDocs Security Advisory/ })).toBeInTheDocument();

    await answer(user, "The X-Template-Hint header");
    await user.click(await screen.findByRole("button", { name: "Continue to the next task" }));
    await screen.findByRole("heading", { name: "Explain why the behavior occurs" });
    await answer(user, "no clue whatsoever here");
    await user.click(screen.getByRole("button", { name: "Reveal solution (−30)" }));
    await user.click(screen.getByRole("button", { name: "Yes, reveal it" }));

    await user.click(await screen.findByRole("button", { name: "Complete session" }));
    const summary = await screen.findByTestId("summary");
    expect(summary).toHaveTextContent("Session complete");
    expect(screen.getByTestId("final-score")).toHaveTextContent("65");
    expect(summary).toHaveTextContent(/Solution shown/);
    expect(api.count("POST", /\/complete$/)).toBe(1);
    expect(screen.getByLabelText("Ask the tutor")).toBeDisabled(); // the session has ended
  });

  it("shows the tutor's guidance, no-evidence and refusal replies distinctly", async () => {
    installFakeLearningApi({
      existing: "in_progress",
      tutor: (question) => {
        const base = { parts: [], next_step: null, safety_reminder: null, model_version: null, created_at: "2026-09-30T08:10:00Z" };
        if (/exploit/i.test(question)) return { ...base, outcome: "refused", message: "I can only help you learn about this vulnerability in a local or authorized lab." };
        if (/france/i.test(question)) return { ...base, outcome: "no_evidence", message: "The sources I retrieved don't say enough about that for me to answer without guessing." };
        return { ...base, outcome: "guided", message: "That is the question for Task 1, so I won't answer it for you.", safety_reminder: "Only try this in a local or authorized lab that you control." };
      },
    });
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    const ask = async (text: string) => {
      await user.type(await screen.findByLabelText("Ask the tutor"), text);
      await user.click(screen.getByRole("button", { name: "Send" }));
    };
    await ask("How do I exploit my school's server?");
    expect(await screen.findByText("Outside this tutor's scope")).toBeInTheDocument();
    await ask("What is the capital of France?");
    expect(await screen.findByText("Not in the sources")).toBeInTheDocument();
    await ask("What component is responsible?");
    expect(await screen.findByText("A nudge, not the answer")).toBeInTheDocument();
    expect(screen.getByText(/Only try this in a local or authorized lab/)).toBeInTheDocument();
  });

  it("offers the suggested questions", async () => {
    installFakeLearningApi({ existing: "in_progress" });
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    for (const q of ["Why does this happen?", "What should I investigate next?", "What does this parameter mean?", "Can you explain the vulnerability?"]) {
      expect(await screen.findByRole("button", { name: q })).toBeInTheDocument();
    }
    await user.click(screen.getByRole("button", { name: "Why does this happen?" }));
    expect(await screen.findByTestId("tutor-claim")).toBeInTheDocument();
  });

  it("resumes a session in progress, with hints and the conversation reloaded", async () => {
    const api = installFakeLearningApi({ existing: "in_progress" });
    api.state.hints.push({ task_id: "t1", number: 1, label: "Hint 1", text: "Follow the data.", penalty: 5, revealed_at: "2026-09-30T08:05:00Z", evidence: [] });
    api.state.turns.push({ role: "student", task_id: "t1", content: "Earlier question", reply: null, created_at: "2026-09-30T08:06:00Z" });
    render(<LearningWorkspace cveId={CVE} />);
    expect(await screen.findByTestId("workspace")).toBeInTheDocument();
    expect(await screen.findByText("Follow the data.")).toBeInTheDocument();
    expect(await screen.findByText("Earlier question")).toBeInTheDocument();
    expect(screen.queryByTestId("intro")).toBeNull();
  });

  it("begins a session that was created but not started", async () => {
    const api = installFakeLearningApi({ existing: "not_started" });
    render(<LearningWorkspace cveId={CVE} />);
    await userEvent.click(await screen.findByRole("button", { name: "Begin the session" }));
    await screen.findByTestId("workspace");
    expect(api.count("POST", /\/api\/learning$/)).toBe(0); // reuses the existing session
    expect(api.count("POST", /\/start$/)).toBe(1);
  });

  it("shows server messages when an action is refused, and keeps working", async () => {
    installFakeLearningApi({ fail: { "POST /api/learning/:id/hints": { status: 409, code: "conflict", message: "Hints are revealed in order." } } });
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);
    await user.click(screen.getByRole("button", { name: /Get Hint 1/ }));
    expect(await screen.findByTestId("learn-error")).toHaveTextContent("Hints are revealed in order.");
    expect(screen.getByRole("button", { name: /Get Hint 1/ })).toBeEnabled();
  });

  it("rejects too-short answers before or after the server, without losing the text", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    const user = setup();
    await start(user);
    await user.type(screen.getByLabelText("Your answer"), "hm");
    expect(screen.getByRole("button", { name: "Submit answer" })).toBeDisabled();
    await user.type(screen.getByLabelText("Your answer"), "mm");
    await user.click(screen.getByRole("button", { name: "Submit answer" }));
    expect(await screen.findByTestId("learn-error")).toHaveTextContent(/at least a few words/);
    expect(screen.getByLabelText("Your answer")).toHaveValue("hmmm");
  });

  it("renders untrusted text as text only", async () => {
    installFakeLearningApi({
      existing: "in_progress",
      tutor: () => ({
        outcome: "answered", message: "<img src=x onerror=alert(1)>", next_step: "<script>alert(2)</script>", safety_reminder: null, model_version: null, created_at: "2026-09-30T08:10:00Z",
        parts: [{ text: "<b onmouseover=alert(3)>x</b>", source_ids: ["S3"], evidence_level: "DOCUMENTED", evidence: [{ source_id: "S3", title: "t", url: "javascript:alert(4)", excerpt: "<iframe src=//evil.test></iframe>" }] }],
      }),
    });
    const { container } = render(<LearningWorkspace cveId={CVE} />);
    await userEvent.click(await screen.findByRole("button", { name: "Why does this happen?" }));
    await screen.findByTestId("tutor-claim");
    expect(container.querySelector("script, iframe, img[onerror], b[onmouseover]")).toBeNull();
    for (const a of container.querySelectorAll("a[href]")) expect(a.getAttribute("href")).toMatch(/^(https?:\/\/|\/|#)/);
  });

  it("does not flash an error in strict mode", async () => {
    installFakeLearningApi({ existing: "in_progress" });
    render(
      <StrictMode>
        <LearningWorkspace cveId={CVE} />
      </StrictMode>,
    );
    expect(await screen.findByTestId("workspace")).toBeInTheDocument();
    expect(screen.queryByTestId("learn-error")).toBeNull();
  });

  it("shows no lab card when labs are not enabled on the server", async () => {
    installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    await start(setup());
    expect(screen.queryByTestId("labs-card")).toBeNull();
    expect(screen.getByTestId("workspace")).toBeInTheDocument(); // the lesson itself is unaffected
  });

  it("only talks to this site's own learning routes", async () => {
    const api = installFakeLearningApi();
    render(<LearningWorkspace cveId={CVE} />);
    await start(setup());
    for (const call of api.calls) expect(call.path).toMatch(/^\/api\/(learning|sandbox|cves\/CVE-2099-12345\/research\/status)/);
  });
});
