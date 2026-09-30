import { vi } from "vitest";

import type {
  InstanceView,
  LabProgressView,
  LabView,
  ObjectiveView,
  OutcomeView,
  SessionLabs,
} from "@/lib/sandbox-types";

export const INSTANCE_ID = "22222222-2222-4222-8222-222222222222";
export const NEW_INSTANCE_ID = "33333333-3333-4333-8333-333333333333";
export const SESSION_ID = "11111111-1111-4111-8111-111111111111";
export const TOKEN = "tokentokentokentoken0123";

export const objectives = (verified: boolean[] = [false, false]): ObjectiveView[] => [
  {
    id: "exploit", title: "Read a file outside the documents folder", kind: "payload_replay",
    description: "Submit a request path that makes the portal return this lab's private secret.",
    input_label: "Request path", input_hint: "/download?name=...", requires: [], verified: verified[0]!, attempts: 0, last_detail: null,
  },
  {
    id: "remediate", title: "Fix the vulnerability", kind: "regression",
    description: "After your fix, the portal must refuse the attack and still serve real documents.",
    input_label: null, input_hint: null, requires: ["exploit"], verified: verified[1]!, attempts: 0, last_detail: null,
  },
];

export const lab = (over: Partial<LabView> = {}): LabView => ({
  id: "path-traversal-101", title: "Path traversal in a document portal",
  summary: "A tiny document portal serves files from one folder.",
  cve_id: null, cwe_ids: ["CWE-22"], difficulty: "beginner",
  instructions: ["Open the portal.", "Read `read_document`.", "Find a request that returns the secret."],
  safety_notes: ["Intentionally vulnerable toy application."],
  objectives: objectives(),
  resources: { cpus: 0.5, memory_mb: 128, processes: 64, scratch_mb: 16, timeout_minutes: 45 },
  network: "No network access: the lab cannot reach the internet, other labs or the platform.",
  ...over,
});

export const instance = (over: Partial<InstanceView> = {}): InstanceView => ({
  id: INSTANCE_ID, lab: lab(), status: "running", session_id: null,
  created_at: "2026-09-30T09:00:00Z", started_at: "2026-09-30T09:00:05Z", expires_at: "2026-09-30T09:45:00Z",
  seconds_remaining: 2700, stop_reason: null, failure_message: null, reset_of: null,
  ports: [{ name: "app", protocol: "http" }], objectives: objectives(), can_use: true,
  app_path: `/lab-app/${INSTANCE_ID}/${TOKEN}/`,
  safety_notice: "This lab runs an intentionally vulnerable toy application in a sealed, disposable container with no network access.",
  ...over,
});

export const progress = (verified = 0, over: Partial<LabProgressView> = {}): LabProgressView => ({
  lab: lab(), objectives: objectives([verified >= 1, verified >= 2]), verified, total: 2, instance_id: null, last_instance_id: null, ...over,
});

export const sessionLabs = (verified = 0, over: Partial<LabProgressView> = {}): SessionLabs => ({
  session_id: SESSION_ID, labs: [progress(verified, over)],
});

const reply = (code: number, body: unknown, headers: Record<string, string> = {}) =>
  ({ ok: code >= 200 && code < 300, status: code, headers: new Headers(headers), json: async () => body }) as unknown as Response;
const err = (code: number, c: string, message: string) => reply(code, { error: { code: c, message } });

type Body = { lab_id?: string; session_id?: string | null; check_id?: string; payload?: string };

export interface FakeSandbox {
  calls: { method: string; path: string; body: Body | undefined }[];
  state: { instance: InstanceView; verified: boolean[]; current: InstanceView | null };
  count: (method: string, pattern: RegExp) => number;
  handler: (url: URL, init?: RequestInit) => Promise<Response>;
}

/** A stateful stand-in for /api/sandbox/*, served through fetch. */
export function makeFakeSandbox(
  options: {
    instance?: Partial<InstanceView>;
    labs?: LabView[];
    startError?: { status: number; code: string; message: string };
    verify?: (checkId: string, payload: string | undefined) => OutcomeView["status"];
    isolation?: { passed: boolean; results: { target: string; blocked: boolean }[] };
    ticketError?: boolean;
    session?: SessionLabs;
  } = {},
): FakeSandbox {
  const calls: FakeSandbox["calls"] = [];
  const state: FakeSandbox["state"] = {
    instance: instance(options.instance),
    verified: options.instance?.objectives ? options.instance.objectives.map((o) => o.verified) : [false, false],
    current: null,
  };
  const view = (over: Partial<InstanceView> = {}): InstanceView => ({ ...state.instance, objectives: objectives(state.verified), ...over });
  const handler = async (url: URL, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    const body = (init?.body ? JSON.parse(String(init.body)) : {}) as Body;
    calls.push({ method, path: url.pathname, body: init?.body ? body : undefined });
    const path = url.pathname.replace("/api/sandbox", "").replace(/^\//, "").replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, ":id");
    if (path === "labs") return reply(200, options.labs ?? [lab()]);
    if (path === "instances/current") return reply(200, { instance: state.current });
    if (path === "instances" && method === "POST") {
      if (options.startError) return err(options.startError.status, options.startError.code, options.startError.message);
      state.instance = instance({ id: NEW_INSTANCE_ID, session_id: body.session_id ?? null, app_path: `/lab-app/${NEW_INSTANCE_ID}/${TOKEN}/` });
      return reply(200, view());
    }
    if (path === "instances/:id" && method === "GET") return reply(200, view());
    if (path === "instances/:id/reset") {
      state.verified = [...state.verified];
      state.instance = instance({ id: NEW_INSTANCE_ID, reset_of: INSTANCE_ID, app_path: `/lab-app/${NEW_INSTANCE_ID}/${TOKEN}/` });
      return reply(200, view());
    }
    if (path === "instances/:id/stop") {
      state.instance = { ...state.instance, status: "stopped", can_use: false, stop_reason: "student", seconds_remaining: 0, app_path: null };
      return reply(200, view());
    }
    if (path === "instances/:id/verify") {
      const status = options.verify?.(body.check_id ?? "", body.payload) ?? (body.check_id === "exploit" && String(body.payload ?? "").includes("..") ? "passed" : "failed");
      if (status === "passed") state.verified[body.check_id === "exploit" ? 0 : 1] = true;
      const detail = status === "passed" ? "Your request made the lab return its private secret." : "The lab answered with status 200, without this lab’s secret.";
      state.instance = { ...state.instance };
      return reply(200, { outcome: { check_id: body.check_id, status, detail }, instance: view() });
    }
    if (path === "instances/:id/network-check")
      return reply(200, { checked_at: "2026-09-30T09:10:00Z", ...(options.isolation ?? { passed: true, results: [{ target: "The internet (1.1.1.1)", blocked: true }, { target: "Cloud metadata (169.254.169.254)", blocked: true }] }) });
    if (path === "instances/:id/terminal-ticket") return options.ticketError ? err(409, "conflict", "This lab is not running.") : reply(200, { ticket: "ticket-0123456789abcdefghij", expires_in: 30, path: "/api/sandbox/terminal/ws", url: null });
    if (path === "sessions/:id/labs") return reply(200, options.session ?? sessionLabs());
    return err(404, "not_found", "Not found.");
  };
  return { calls, state, handler, count: (m, p) => calls.filter((c) => c.method === m && p.test(c.path)).length };
}

export function installFakeSandbox(options: Parameters<typeof makeFakeSandbox>[0] = {}): FakeSandbox {
  const fake = makeFakeSandbox(options);
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => fake.handler(new URL(String(input), "http://localhost"), init));
  return fake;
}

/** A WebSocket stand-in that records what the terminal sends and lets a test push server frames. */
export class FakeSocket {
  static instances: FakeSocket[] = [];
  static OPEN = 1;
  static CONNECTING = 0;
  static CLOSED = 3;
  readyState = 0;
  binaryType = "blob";
  sent: string[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(public url: string) {
    FakeSocket.instances.push(this);
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = 3;
    this.onclose?.();
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  serverText(message: object) {
    this.onmessage?.({ data: JSON.stringify(message) });
  }
  serverBytes(text: string) {
    this.onmessage?.({ data: new TextEncoder().encode(text).buffer });
  }
  serverClose() {
    this.readyState = 3;
    this.onclose?.();
  }
}
