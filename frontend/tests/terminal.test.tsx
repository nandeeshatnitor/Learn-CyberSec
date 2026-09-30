import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LabTerminal, socketUrl } from "@/components/lab/terminal";

import { FakeSocket, INSTANCE_ID, installFakeSandbox } from "./sandbox-fixtures";
import { FakeTerminal } from "./xterm-mocks";

vi.mock("@xterm/xterm", async () => ({ Terminal: (await import("./xterm-mocks")).FakeTerminal }));
vi.mock("@xterm/addon-fit", async () => ({ FitAddon: (await import("./xterm-mocks")).FakeFit }));

beforeEach(() => {
  FakeSocket.instances = [];
  FakeTerminal.instances = [];
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} unobserve() {} });
});
afterEach(() => vi.unstubAllGlobals());

const socket = async () => {
  await waitFor(() => expect(FakeSocket.instances.length).toBeGreaterThan(0));
  return FakeSocket.instances[FakeSocket.instances.length - 1]!;
};
const term = () => FakeTerminal.instances[FakeTerminal.instances.length - 1]!;

describe("socketUrl", () => {
  const loc = (protocol: string, host: string) => ({ protocol, host }) as Location;
  it("uses this site's own address by default, secure when the page is", () => {
    const t = { ticket: "a b", path: "/api/sandbox/terminal/ws", url: null };
    expect(socketUrl(t, loc("http:", "localhost:3000"))).toBe("ws://localhost:3000/api/sandbox/terminal/ws?ticket=a%20b");
    expect(socketUrl(t, loc("https:", "learn.example.com"))).toBe("wss://learn.example.com/api/sandbox/terminal/ws?ticket=a%20b");
  });
  it("uses the gateway's own public address when it has one", () => {
    expect(socketUrl({ ticket: "t", path: "/p", url: "wss://labs.example.com" }, loc("http:", "x"))).toBe("wss://labs.example.com/p?ticket=t");
  });
});

describe("lab terminal", () => {
  it("gets a single-use ticket, opens a WebSocket with it and shows the connection state", async () => {
    const api = installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    expect(screen.getByTestId("terminal-state")).toHaveTextContent("Connecting");
    const ws = await socket();
    expect(ws.url).toBe("ws://localhost:3000/api/sandbox/terminal/ws?ticket=ticket-0123456789abcdefghij");
    expect(ws.binaryType).toBe("arraybuffer");
    expect(api.count("POST", /terminal-ticket$/)).toBe(1);
    act(() => ws.open());
    expect(screen.getByTestId("terminal-state")).toHaveTextContent("Connected to your lab");
    expect(JSON.parse(ws.sent[0]!)).toEqual({ type: "resize", cols: 80, rows: 24 });
    expect(term().focused).toBe(true);
  });

  it("sends what the student types and the window size, and nothing else", async () => {
    installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    act(() => ws.open());
    act(() => term().type("ls -la\r"));
    act(() => term().resize(120, 40));
    expect(ws.sent.map((m) => JSON.parse(m))).toEqual([
      { type: "resize", cols: 80, rows: 24 },
      { type: "input", data: "ls -la\r" },
      { type: "resize", cols: 120, rows: 40 },
    ]);
  });

  it("writes the lab's output to the screen", async () => {
    installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    act(() => ws.open());
    act(() => ws.serverBytes("/lab $ "));
    act(() => ws.serverBytes("welcome.txt"));
    expect(term().text).toBe("/lab $ welcome.txt");
  });

  it("does not send while the socket is not open", async () => {
    installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    await waitFor(() => expect(term()).toBeDefined());
    act(() => term().type("early"));
    expect(ws.sent).toEqual([]);
  });

  it.each([
    ["lab_ended", /expired, was stopped or was reset/],
    ["idle", /inactivity/],
    ["shell_exited", /shell exited/],
    ["busy", /maximum number of terminals/],
    ["unauthorized", /could not be authorised/],
    ["unavailable", /not available right now/],
    ["something_new", /session ended/],
  ])("explains why the session ended: %s", async (reason, text) => {
    installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    act(() => ws.open());
    act(() => ws.serverText({ type: "closed", reason }));
    act(() => ws.serverClose());
    expect(screen.getByTestId("terminal-notice")).toHaveTextContent(text);
    expect(screen.getByTestId("terminal-state")).toHaveTextContent("Disconnected");
  });

  it("offers to reconnect with a fresh ticket", async () => {
    const api = installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const first = await socket();
    act(() => first.open());
    act(() => first.serverClose());
    await userEvent.setup().click(screen.getByRole("button", { name: /Reconnect/ }));
    await waitFor(() => expect(FakeSocket.instances).toHaveLength(2));
    expect(api.count("POST", /terminal-ticket$/)).toBe(2);
    expect(screen.queryByTestId("terminal-notice")).toBeNull();
  });

  it("shows the reason when no ticket can be issued, without opening a socket", async () => {
    installFakeSandbox({ ticketError: true });
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    expect(await screen.findByTestId("terminal-notice")).toHaveTextContent("This lab is not running.");
    expect(FakeSocket.instances).toHaveLength(0);
    expect(screen.getByTestId("terminal-state")).toHaveTextContent("Disconnected");
  });

  it("stays idle for a lab that is not running", async () => {
    const api = installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active={false} />);
    await new Promise((r) => setTimeout(r, 30));
    expect(api.calls).toHaveLength(0);
    expect(FakeSocket.instances).toHaveLength(0);
  });

  it("closes the socket and disposes the terminal when it goes away", async () => {
    installFakeSandbox();
    const { unmount } = render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    act(() => ws.open());
    unmount();
    expect(ws.readyState).toBe(3);
    expect(term().disposed).toBe(true);
  });

  it("ignores malformed control frames", async () => {
    installFakeSandbox();
    render(<LabTerminal instanceId={INSTANCE_ID} active />);
    const ws = await socket();
    act(() => ws.open());
    act(() => ws.onmessage?.({ data: "not json" }));
    expect(screen.queryByTestId("terminal-notice")).toBeNull();
  });
});
