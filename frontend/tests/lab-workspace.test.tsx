import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LabWorkspace, formatRemaining } from "@/components/lab/lab-workspace";

import { FakeSocket, INSTANCE_ID, NEW_INSTANCE_ID, SESSION_ID, TOKEN, installFakeSandbox, instance } from "./sandbox-fixtures";
import { FakeTerminal } from "./xterm-mocks";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xterm-mocks")).FakeTerminal }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xterm-mocks")).FakeFit }));
const router = vi.hoisted(() => ({ push: vi.fn(), replace: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => router }));

beforeEach(() => {
  FakeSocket.instances = [];
  FakeTerminal.instances = [];
  router.push.mockReset();
  router.replace.mockReset();
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const setup = () => userEvent.setup();
const open = async (back: string | null = null) => {
  render(<LabWorkspace instanceId={INSTANCE_ID} backHref={back} />);
  await screen.findByTestId("lab-status");
};

describe("formatRemaining", () => {
  it.each([[2700, "45:00"], [59, "00:59"], [0, "00:00"], [-5, "00:00"], [3725, "1:02:05"], [61.9, "01:01"]])("%s s -> %s", (s, text) => {
    expect(formatRemaining(s)).toBe(text);
  });
});

describe("lab workspace", () => {
  it("shows the lab, its state, the time left, the objectives and the rules of the sandbox", async () => {
    installFakeSandbox();
    await open();
    expect(screen.getByRole("heading", { name: "Path traversal in a document portal" })).toBeInTheDocument();
    expect(screen.getByTestId("lab-status")).toHaveTextContent("running");
    expect(screen.getByTestId("lab-timer")).toHaveTextContent("45:00");
    expect(within(screen.getByTestId("lab-objectives")).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByTestId("lab-instructions").querySelectorAll("li")).toHaveLength(3);
    expect(screen.getByText(/0.5 CPU · 128 MB/)).toBeInTheDocument();
    expect(screen.getByText(/cannot reach the internet, other labs or the platform/)).toBeInTheDocument();
    expect(screen.getByTestId("lab-safety")).toHaveTextContent(/intentionally vulnerable toy application/);
    expect(screen.getByRole("tab", { name: "Terminal", selected: true })).toBeInTheDocument();
  });

  it("only ever talks to this site's own sandbox routes", async () => {
    const api = installFakeSandbox();
    await open();
    await setup().click(screen.getByRole("button", { name: "Verify" }));
    for (const call of api.calls) expect(call.path).toMatch(/^\/api\/sandbox\//);
  });

  it("opens the terminal on the running lab", async () => {
    const api = installFakeSandbox();
    await open();
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    expect(api.count("POST", new RegExp(`${INSTANCE_ID}/terminal-ticket$`))).toBe(1);
    expect(screen.getByTestId("terminal")).toBeInTheDocument();
  });

  it("counts down and warns when little time is left", async () => {
    installFakeSandbox({ instance: { seconds_remaining: 301 } });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await open();
    expect(screen.queryByText(/Less than five minutes left/)).toBeNull();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(screen.getByTestId("lab-timer")).toHaveTextContent("04:59");
    expect(screen.getByText(/Less than five minutes left/)).toBeInTheDocument();
  });

  it("asks the server again when the time runs out, and shows the lab as ended", async () => {
    const api = installFakeSandbox({ instance: { seconds_remaining: 2 } });
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await open();
    api.state.instance = { ...api.state.instance, status: "stopped", can_use: false, stop_reason: "expired", seconds_remaining: 0, app_path: null };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3100);
    });
    expect(await screen.findByTestId("lab-ended")).toHaveTextContent(/time ran out and it was removed/);
    expect(screen.queryByTestId("lab-timer")).toBeNull();
    expect(screen.getByRole("button", { name: "Start a fresh lab" })).toBeInTheDocument();
  });

  it("keeps in step with the server by polling", async () => {
    const api = installFakeSandbox();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await open();
    const before = api.count("GET", new RegExp(`${INSTANCE_ID}$`));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_500);
    });
    expect(api.count("GET", new RegExp(`${INSTANCE_ID}$`))).toBeGreaterThan(before);
  });

  it("links back to the lesson only when it came from one", async () => {
    installFakeSandbox();
    await open("/learn/CVE-2099-12345");
    expect(screen.getByRole("link", { name: /Back to your lesson/ })).toHaveAttribute("href", "/learn/CVE-2099-12345");
  });
});

describe("objectives", () => {
  it("verifies an exploit by sending the request path, and shows the result", async () => {
    const api = installFakeSandbox();
    await open();
    const user = setup();
    await user.type(screen.getByLabelText("Request path"), "/download?name=../private/canary.txt");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByTestId("objective-exploit-outcome")).toHaveTextContent("return its private secret");
    expect(screen.getByTestId("objective-exploit-state")).toHaveTextContent("Verified");
    const call = api.calls.find((c) => c.path.endsWith("/verify"))!;
    expect(call.body).toEqual({ check_id: "exploit", payload: "/download?name=../private/canary.txt" });
  });

  it("does not mark a miss as verified and shows why", async () => {
    installFakeSandbox();
    await open();
    const user = setup();
    await user.type(screen.getByLabelText("Request path"), "/download?name=welcome.txt");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByTestId("objective-exploit-outcome")).toHaveTextContent(/without this lab’s secret/);
    expect(screen.getByTestId("objective-exploit-state")).toHaveTextContent("Not yet");
  });

  it("locks the fix until the exploit is verified, then lets the student restart and verify it", async () => {
    const api = installFakeSandbox();
    await open();
    const user = setup();
    const fix = () => screen.getByRole("button", { name: "Restart the app and verify my fix" });
    expect(fix()).toBeDisabled();
    expect(screen.getByText(/Complete “Read a file outside the documents folder” first/)).toBeInTheDocument();
    await user.type(screen.getByLabelText("Request path"), "/download?name=../x");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    await screen.findByTestId("objective-exploit-outcome");
    await waitFor(() => expect(fix()).toBeEnabled());
    await user.click(fix());
    await waitFor(() => expect(screen.getByTestId("objective-remediate-outcome")).toBeInTheDocument());
    expect(api.calls.filter((c) => c.path.endsWith("/verify"))[1]!.body).toEqual({ check_id: "remediate" }); // nothing but the id
  });

  it("shows a server refusal instead of failing silently", async () => {
    const api = installFakeSandbox();
    await open();
    const original = api.handler;
    api.handler = async (url, init) => (url.pathname.endsWith("/verify") ? ({ ok: false, status: 429, headers: new Headers(), json: async () => ({ error: { code: "rate_limited", message: "You have verified many times. Please wait." } }) } as unknown as Response) : original(url, init));
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => api.handler(new URL(String(input), "http://localhost"), init));
    await setup().click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("You have verified many times");
  });
});

describe("reset, stop, start again", () => {
  it("asks before resetting, then replaces the lab with a fresh one", async () => {
    const api = installFakeSandbox({ instance: { session_id: SESSION_ID } });
    await open("/learn/CVE-2099-12345");
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Reset lab" }));
    expect(screen.getByText(/deletes everything you changed/)).toBeInTheDocument();
    expect(api.count("POST", /reset$/)).toBe(0); // nothing happens until confirmed
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.count("POST", /reset$/)).toBe(0);
    await user.click(screen.getByRole("button", { name: "Reset lab" }));
    await user.click(screen.getByRole("button", { name: "Yes, reset" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith(`/lab/${NEW_INSTANCE_ID}?from=%2Flearn%2FCVE-2099-12345`));
    expect(api.count("POST", new RegExp(`${INSTANCE_ID}/reset$`))).toBe(1);
  });

  it("stops the lab and offers a fresh one in the same session", async () => {
    const api = installFakeSandbox({ instance: { session_id: SESSION_ID } });
    await open();
    const user = setup();
    await user.click(screen.getByRole("button", { name: "Stop lab" }));
    expect(await screen.findByTestId("lab-ended")).toHaveTextContent(/You stopped this lab/);
    expect(screen.getByTestId("lab-ended")).toHaveTextContent(/Everything inside it has been deleted/);
    await user.click(screen.getByRole("button", { name: "Start a fresh lab" }));
    await waitFor(() => expect(router.replace).toHaveBeenCalledWith(`/lab/${NEW_INSTANCE_ID}`));
    expect(api.calls.find((c) => c.method === "POST" && c.path === "/api/sandbox/instances")!.body).toEqual({ lab_id: "path-traversal-101", session_id: SESSION_ID });
  });

  it("says what happened to an expired, failed or replaced lab, and that progress is kept", async () => {
    installFakeSandbox({
      instance: {
        status: "stopped", can_use: false, stop_reason: "expired", seconds_remaining: 0, app_path: null,
        objectives: [{ ...instance().objectives[0]!, verified: true }, instance().objectives[1]!],
      },
    });
    await open();
    expect(screen.getByTestId("lab-ended")).toHaveTextContent(/time ran out/);
    expect(screen.getByTestId("lab-ended")).toHaveTextContent(/verified are kept \(1 of 2\)/);
    expect(screen.queryByRole("button", { name: "Reset lab" })).toBeNull();
  });

  it("shows the fixed failure message when a lab could not be started", async () => {
    installFakeSandbox({ instance: { status: "failed", can_use: false, seconds_remaining: 0, app_path: null, failure_message: "The lab was not started because its network isolation could not be verified." } });
    await open();
    expect(screen.getByTestId("lab-status")).toHaveTextContent("failed");
    expect(screen.getByTestId("lab-ended")).toHaveTextContent(/network isolation could not be verified/);
  });

  it("shows a start error from starting again", async () => {
    installFakeSandbox({ instance: { status: "stopped", can_use: false, stop_reason: "student", app_path: null }, startError: { status: 409, code: "conflict", message: "You already have a lab running. Stop or reset it first." } });
    await open();
    await setup().click(screen.getByRole("button", { name: "Start a fresh lab" }));
    expect(await screen.findByTestId("lab-error")).toHaveTextContent(/already have a lab running/);
    expect(router.replace).not.toHaveBeenCalled();
  });

  it("says so when the lab does not exist or is someone else's", async () => {
    const api = installFakeSandbox();
    api.handler = async () => ({ ok: false, status: 404, headers: new Headers(), json: async () => ({ error: { code: "not_found", message: "Lab not found." } }) }) as unknown as Response;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => api.handler(new URL(String(input), "http://localhost"), init));
    render(<LabWorkspace instanceId={INSTANCE_ID} backHref={null} />);
    expect(await screen.findByTestId("lab-error")).toHaveTextContent(/could not be found/);
    expect(screen.getByRole("link", { name: "See the labs" })).toHaveAttribute("href", "/labs");
  });
});

describe("lab tools", () => {
  it("shows the lab's web app in a sandboxed frame that cannot reach the platform", async () => {
    installFakeSandbox();
    await open();
    await setup().click(screen.getByRole("tab", { name: "Lab app" }));
    const frame = screen.getByTestId("lab-app-frame") as HTMLIFrameElement;
    expect(frame).toHaveAttribute("src", `/lab-app/${INSTANCE_ID}/${TOKEN}/`);
    expect(frame.getAttribute("sandbox")).toBe("allow-forms allow-scripts"); // never allow-same-origin
    expect(frame.getAttribute("referrerpolicy")).toBe("no-referrer");
    const link = screen.getByRole("link", { name: /Open in a new tab/ });
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("keeps the terminal running while another tab is open", async () => {
    installFakeSandbox();
    await open();
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(1));
    const user = setup();
    await user.click(screen.getByRole("tab", { name: "Lab app" }));
    expect(document.getElementById("panel-terminal")).toHaveAttribute("hidden");
    expect(document.getElementById("panel-terminal")!.querySelector("[data-testid=terminal]")).not.toBeNull(); // still mounted
    await user.click(screen.getByRole("tab", { name: "Terminal" }));
    expect(FakeSocket.instances).toHaveLength(1); // the same session, not a new one
  });

  it("runs the isolation proof and reports what was blocked", async () => {
    installFakeSandbox();
    await open();
    const user = setup();
    await user.click(screen.getByRole("tab", { name: "Isolation" }));
    await user.click(screen.getByRole("button", { name: "Run isolation check" }));
    const report = await screen.findByTestId("isolation-report");
    expect(report).toHaveTextContent("Isolated: nothing was reachable.");
    expect(report).toHaveTextContent("The internet (1.1.1.1)");
    expect(within(report).getAllByText("Blocked")).toHaveLength(2);
  });

  it("flags anything that was reachable", async () => {
    installFakeSandbox({ isolation: { passed: false, results: [{ target: "The internet (1.1.1.1)", blocked: false }] } });
    await open();
    const user = setup();
    await user.click(screen.getByRole("tab", { name: "Isolation" }));
    await user.click(screen.getByRole("button", { name: "Run isolation check" }));
    const report = await screen.findByTestId("isolation-report");
    expect(report).toHaveTextContent(/Something was reachable/);
    expect(report).toHaveTextContent("REACHABLE");
  });
});
