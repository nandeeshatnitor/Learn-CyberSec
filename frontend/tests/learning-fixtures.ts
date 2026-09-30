import { vi } from "vitest";

import type {
  AnswerResult,
  EvidenceRef,
  HintView,
  SessionView,
  SolutionView,
  SourceRef,
  TaskView,
  TutorReplyView,
  TutorTurn,
} from "@/lib/learning-types";

export const CVE = "CVE-2099-12345";

export const sources: SourceRef[] = [
  { id: "S1", title: "NVD record for CVE-2099-12345", url: "https://nvd.nist.gov/vuln/detail/CVE-2099-12345", publisher: "NVD", source_type: "nvd", reliability_level: "official", kind: "provider_record" },
  { id: "S3", title: "AcmeDocs Security Advisory", url: "https://advisories.acme-vendor.test/ACME-SA-2099-01", publisher: "acme", source_type: "vendor_advisory", reliability_level: "high", kind: "document" },
];

interface FakeTask {
  id: string;
  title: string;
  prompt: string;
  objective: string;
  answer: RegExp; // what counts as correct
  partial?: RegExp;
  hints: string[];
  solution: string;
}

const TASKS: FakeTask[] = [
  { id: "t1", title: "Identify the vulnerable component", prompt: "Which component is responsible?", objective: "Identify the vulnerable component.", answer: /template engine/i, partial: /acmedocs/i, hints: ["Follow the data.", "A source says: █████ █████ injection.", "The sources state: template engine."], solution: "AcmeDocs template engine expression injection" },
  { id: "t2", title: "Identify the vulnerable input", prompt: "Which input can an attacker control?", objective: "Identify the vulnerable input.", answer: /x-template-hint/i, hints: ["What does the attacker send?", "A header.", "The X-Template-Hint header."], solution: "The X-Template-Hint header is evaluated." },
  { id: "t3", title: "Explain why the behavior occurs", prompt: "Why does it happen?", objective: "Explain why the behavior occurs.", answer: /sanitiz/i, hints: ["What should happen first?", "Something is missing.", "The renderer does not sanitize the value."], solution: "The renderer does not sanitize the header." },
];

const PENALTY = [5, 10, 15];

export interface FakeOptions {
  /** Start with no session; whether a guide exists decides the "no guide" screen. */
  guideAvailable?: boolean;
  existing?: "none" | "not_started" | "in_progress";
  tutor?: (question: string, taskId: string | null) => TutorReplyView;
  fail?: Partial<Record<string, { status: number; code: string; message: string }>>;
  /** Serves /api/sandbox/*; by default labs are "not enabled", exactly like a server without Docker. */
  sandbox?: (url: URL, init?: RequestInit) => Promise<Response>;
}

export interface FakeApi {
  state: { session: SessionView | null; hints: HintView[]; turns: TutorTurn[]; solutions: Record<string, SolutionView> };
  calls: { method: string; path: string; body: unknown }[];
  count: (method: string, pattern: RegExp) => number;
}

function taskViews(progress: Record<string, { status: TaskView["status"]; attempts: number; hints: number }>, requireAttempt = true): TaskView[] {
  const currentIndex = TASKS.findIndex((t) => progress[t.id]!.status === "open" || progress[t.id]!.status === "locked");
  return TASKS.map((t, index) => {
    const p = progress[t.id]!;
    const status: TaskView["status"] = p.status === "correct" || p.status === "revealed" ? p.status : index === currentIndex ? "open" : "locked";
    return {
      id: t.id, order: index + 1, kind: "explain_cause", title: t.title, prompt: t.prompt, objective: t.objective,
      verification_criteria: ["Names the specific thing, not just the product"], status, attempts: p.attempts,
      hints_revealed: p.hints, next_hint_penalty: p.hints < 3 ? PENALTY[p.hints]! : null, solution_penalty: 30,
      solution_available: status === "open" && (p.attempts >= 1 || !requireAttempt), context_sources: sources.slice(1),
    };
  });
}

/** A small stateful stand-in for /api/learning and /api/cves/.../research/status, served via fetch. */
export function installFakeLearningApi(options: FakeOptions = {}): FakeApi {
  const progress: Record<string, { status: TaskView["status"]; attempts: number; hints: number }> = Object.fromEntries(
    TASKS.map((t) => [t.id, { status: "open" as TaskView["status"], attempts: 0, hints: 0 }]),
  );
  const state: FakeApi["state"] = { session: null, hints: [], turns: [], solutions: {} };
  const calls: FakeApi["calls"] = [];
  let score = 100;
  let hintsUsed = 0;
  let solutionRevealed = false;
  let status: SessionView["status"] = "not_started";
  let completedAt: string | null = null;

  const build = (): SessionView => {
    const tasks = taskViews(progress);
    const resolved = tasks.filter((t) => t.status === "correct" || t.status === "revealed").length;
    return {
      id: "11111111-1111-4111-8111-111111111111", cve_id: CVE, status, started_at: status === "not_started" ? null : "2026-09-30T08:00:00Z",
      completed_at: completedAt, hints_used: hintsUsed, solution_revealed: solutionRevealed, score, max_score: 100,
      progress: { resolved, total: tasks.length, percent: Math.round((100 * resolved) / tasks.length) },
      learning_objectives: TASKS.map((t) => t.objective),
      prerequisites: [{ text: "A local or authorized lab environment that you control.", source_ids: [] }],
      tasks, current_task_id: tasks.find((t) => t.status === "open")?.id ?? null,
      can_complete: status === "in_progress" && resolved === tasks.length, sources,
      cve: { cve_id: CVE, description: "AcmeDocs evaluates expressions from a request header.", severity: "CRITICAL", cvss_score: 9.8, affected: ["Acme AcmeDocs"] },
      scoring: { start: 100 }, notes: [], guide_generated_at: "2026-09-30T07:00:00Z",
      safety_notice: "Practise only on systems you own or have explicit permission to test.",
    };
  };
  const evidence = (id: string, excerpt: string | null): EvidenceRef[] => [{ source_id: id, title: sources[1]!.title, url: sources[1]!.url, excerpt }];
  const solutionOf = (t: FakeTask): SolutionView => ({ task_id: t.id, parts: [{ text: t.solution, command: null, source_ids: ["S3"], evidence_level: "DOCUMENTED" }], evidence: evidence("S3", t.solution) });
  const current = () => TASKS.find((t) => progress[t.id]!.status === "open")!;

  if (options.existing === "not_started") state.session = build();
  if (options.existing === "in_progress") {
    status = "in_progress";
    state.session = build();
  }

  const reply = (code: number, body: unknown, headers: Record<string, string> = {}) =>
    ({ ok: code >= 200 && code < 300, status: code, headers: new Headers(headers), json: async () => body }) as unknown as Response;
  const err = (code: number, c: string, message: string) => reply(code, { error: { code: c, message } });

  const handler = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), "http://localhost");
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path: url.pathname, body });
    const key = `${method} ${url.pathname.replace(/[0-9a-f-]{36}/, ":id")}`;
    const forced = options.fail?.[key];
    if (forced) return err(forced.status, forced.code, forced.message);

    if (url.pathname.startsWith("/api/sandbox")) {
      return options.sandbox ? options.sandbox(url, init) : err(503, "sandbox_disabled", "Labs are not enabled on this server.");
    }
    if (url.pathname.endsWith("/research/status")) {
      const guide = options.guideAvailable ?? true;
      return reply(200, { cve_id: CVE, status: guide ? "ready" : "not_started", stage: guide ? "Ready" : "No learning guide", guide_available: guide });
    }
    const path = url.pathname.replace("/api/learning", "").replace(/^\//, "");
    if (method === "GET" && path.startsWith("by-cve/")) return state.session ? reply(200, state.session) : err(404, "not_found", "No learning session for this CVE yet.");
    if (method === "POST" && path === "") {
      state.session = build();
      return reply(200, state.session);
    }
    const [, rest = ""] = /^[0-9a-f-]{36}\/?(.*)$/.exec(path) ?? [];
    if (method === "GET" && rest === "") return reply(200, build());
    if (method === "POST" && rest === "start") {
      status = "in_progress";
      state.session = build();
      return reply(200, state.session);
    }
    if (rest === "hints" && method === "GET") return reply(200, { hints: [...state.hints], next: null });
    if (rest === "hints" && method === "POST") {
      const t = TASKS.find((x) => x.id === body.task_id)!;
      const p = progress[t.id]!;
      if (body.number !== p.hints + 1) return err(409, "conflict", `Hints are revealed in order. The next one is Hint ${p.hints + 1}.`);
      p.hints = body.number;
      hintsUsed += 1;
      score -= PENALTY[body.number - 1]!;
      const hint: HintView = { task_id: t.id, number: body.number, label: `Hint ${body.number}`, text: t.hints[body.number - 1]!, penalty: PENALTY[body.number - 1]!, revealed_at: "2026-09-30T08:05:00Z", evidence: evidence("S3", body.number === 3 ? "an excerpt" : null) };
      state.hints.push(hint);
      state.session = build();
      return reply(200, { hint, session: state.session });
    }
    const task = /^tasks\/(t\d+)\/(answer|solution)$/.exec(rest);
    if (task && method === "POST" && task[2] === "answer") {
      const t = TASKS.find((x) => x.id === task[1])!;
      const p = progress[t.id]!;
      const text = String(body.answer);
      if (text.trim().split(/\s+/).length < 2) return err(422, "invalid_input", "Write at least a few words so your answer can be checked.");
      p.attempts += 1;
      const result: AnswerResult = t.answer.test(text) ? "correct" : t.partial?.test(text) ? "partially_correct" : "incorrect";
      if (result === "correct") {
        p.status = "correct";
        state.solutions[t.id] = solutionOf(t);
      }
      state.session = build();
      const feedback = result === "correct" ? "Correct. Your answer covers the specific component." : result === "partially_correct" ? "You are partly there: you have covered the affected product. Still missing: the specific module." : "That does not match what the sources describe for this task.";
      return reply(200, { result, feedback, solution: result === "correct" ? solutionOf(t) : null, attempts: p.attempts, session: state.session });
    }
    if (task && method === "POST" && task[2] === "solution") {
      const t = TASKS.find((x) => x.id === task[1])!;
      const p = progress[t.id]!;
      if (p.attempts < 1) return err(409, "conflict", "Try the task first: submit an answer, then ask for hints or the solution.");
      p.status = "revealed";
      solutionRevealed = true;
      score -= 30;
      state.solutions[t.id] = solutionOf(t);
      state.session = build();
      return reply(200, { solution: solutionOf(t), penalty: 30, session: state.session });
    }
    if (task && method === "GET") return state.solutions[task[1]!] ? reply(200, state.solutions[task[1]!]) : err(409, "conflict", "Finish this task first.");
    if (rest === "tutor" && method === "GET") return reply(200, { messages: [...state.turns] });
    if (rest === "tutor" && method === "POST") {
      const t = options.tutor?.(body.question, body.task_id) ?? {
        outcome: "answered" as const, message: "Here is what the sources say:",
        parts: [{ text: "Versions 4.0.0 through 4.2.3 are affected.", source_ids: ["S3"], evidence_level: "DOCUMENTED", evidence: evidence("S3", "AcmeDocs versions 4.0.0 through 4.2.3 are affected.") }],
        next_step: null, safety_reminder: null, model_version: null, created_at: "2026-09-30T08:10:00Z",
      };
      state.turns.push({ role: "student", task_id: body.task_id, content: body.question, reply: null, created_at: "2026-09-30T08:10:00Z" });
      state.turns.push({ role: "tutor", task_id: body.task_id, content: t.message, reply: t, created_at: t.created_at });
      return reply(200, t);
    }
    if (rest === "complete" && method === "POST") {
      const s = build();
      if (!s.can_complete) return err(409, "conflict", "Finish every task (answer it or reveal its solution) first.");
      status = "completed";
      completedAt = "2026-09-30T08:30:00Z";
      state.session = build();
      return reply(200, state.session);
    }
    void current;
    return err(404, "not_found", "Not found.");
  };
  vi.stubGlobal("fetch", vi.fn(handler));
  return { state, calls, count: (m, p) => calls.filter((c) => c.method === m && p.test(c.path)).length };
}
