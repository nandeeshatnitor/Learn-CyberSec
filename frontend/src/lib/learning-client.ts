import { call, type Outcome } from "@/lib/research-client";
import type {
  AnswerResponse,
  HintRevealResponse,
  HintsResponse,
  SessionView,
  SolutionResponse,
  SolutionView,
  TutorReplyView,
  TutorTurn,
} from "@/lib/learning-types";

/**
 * Browser-side calls to this site's own learning route handlers (never to the backend). The learner
 * identity is an HttpOnly cookie the browser sends automatically; script never sees it.
 */
export type { Outcome };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isSession = (v: unknown): v is SessionView =>
  isRecord(v) &&
  typeof v.id === "string" &&
  typeof v.score === "number" &&
  Array.isArray(v.tasks) &&
  isRecord(v.progress);
const isHints = (v: unknown): v is HintsResponse => isRecord(v) && Array.isArray(v.hints);
const isHintReveal = (v: unknown): v is HintRevealResponse =>
  isRecord(v) && isRecord(v.hint) && isSession(v.session);
const isAnswer = (v: unknown): v is AnswerResponse =>
  isRecord(v) && typeof v.result === "string" && typeof v.feedback === "string" && isSession(v.session);
const isSolutionResponse = (v: unknown): v is SolutionResponse =>
  isRecord(v) && isRecord(v.solution) && isSession(v.session);
const isSolution = (v: unknown): v is SolutionView => isRecord(v) && Array.isArray(v.parts);
const isTutorReply = (v: unknown): v is TutorReplyView =>
  isRecord(v) && typeof v.outcome === "string" && typeof v.message === "string" && Array.isArray(v.parts);
const isTutorHistory = (v: unknown): v is { messages: TutorTurn[] } =>
  isRecord(v) && Array.isArray(v.messages);

const base = "/api/learning";
const post = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body ?? {}),
});

export const createSession = (cveId: string, signal?: AbortSignal) =>
  call(base, isSession, post({ cve_id: cveId }), signal);
export const sessionForCve = (cveId: string, signal?: AbortSignal) =>
  call(`${base}/by-cve/${encodeURIComponent(cveId)}`, isSession, {}, signal);
export const getSession = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}`, isSession, {}, signal);
export const startSession = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}/start`, isSession, post(), signal);
export const completeSession = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}/complete`, isSession, post(), signal);
export const abandonSession = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}/abandon`, isSession, post(), signal);
export const listHints = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}/hints`, isHints, {}, signal);
export const revealHint = (id: string, taskId: string, number: number, signal?: AbortSignal) =>
  call(`${base}/${id}/hints`, isHintReveal, post({ task_id: taskId, number }), signal);
export const submitAnswer = (id: string, taskId: string, answer: string, signal?: AbortSignal) =>
  call(`${base}/${id}/tasks/${taskId}/answer`, isAnswer, post({ answer }), signal);
export const revealSolution = (id: string, taskId: string, signal?: AbortSignal) =>
  call(`${base}/${id}/tasks/${taskId}/solution`, isSolutionResponse, post(), signal);
export const getSolution = (id: string, taskId: string, signal?: AbortSignal) =>
  call(`${base}/${id}/tasks/${taskId}/solution`, isSolution, {}, signal);
export const askTutor = (id: string, question: string, taskId: string | null, signal?: AbortSignal) =>
  call(`${base}/${id}/tutor`, isTutorReply, post({ question, task_id: taskId }), signal);
export const tutorHistory = (id: string, signal?: AbortSignal) =>
  call(`${base}/${id}/tutor`, isTutorHistory, {}, signal);
