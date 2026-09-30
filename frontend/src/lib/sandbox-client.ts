import { call, type Outcome } from "@/lib/research-client";
import type {
  CurrentInstance,
  InstanceView,
  IsolationView,
  LabView,
  SessionLabs,
  TicketView,
  VerifyResponse,
} from "@/lib/sandbox-types";

/**
 * Browser-side calls to this site's own sandbox route handlers (never to the backend). The learner
 * identity is an HttpOnly cookie the browser sends automatically; script never sees it.
 */
export type { Outcome };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isInstance = (v: unknown): v is InstanceView =>
  isRecord(v) &&
  typeof v.id === "string" &&
  typeof v.status === "string" &&
  typeof v.seconds_remaining === "number" &&
  isRecord(v.lab) &&
  Array.isArray(v.objectives);
const isCurrent = (v: unknown): v is CurrentInstance =>
  isRecord(v) && (v.instance === null || isInstance(v.instance));
const isLabList = (v: unknown): v is LabView[] => Array.isArray(v) && v.every((l) => isRecord(l) && typeof l.id === "string");
const isVerify = (v: unknown): v is VerifyResponse =>
  isRecord(v) && isRecord(v.outcome) && typeof v.outcome.status === "string" && isInstance(v.instance);
const isIsolation = (v: unknown): v is IsolationView =>
  isRecord(v) && typeof v.passed === "boolean" && Array.isArray(v.results);
const isTicket = (v: unknown): v is TicketView =>
  isRecord(v) && typeof v.ticket === "string" && typeof v.path === "string";
const isSessionLabs = (v: unknown): v is SessionLabs => isRecord(v) && Array.isArray(v.labs);

const base = "/api/sandbox";
const post = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body ?? {}),
});

export const listLabs = (signal?: AbortSignal) => call(`${base}/labs`, isLabList, {}, signal);
export const currentInstance = (signal?: AbortSignal) =>
  call(`${base}/instances/current`, isCurrent, {}, signal);
export const startLab = (labId: string, sessionId?: string | null, signal?: AbortSignal) =>
  call(
    `${base}/instances`,
    isInstance,
    post({ lab_id: labId, ...(sessionId ? { session_id: sessionId } : {}) }),
    signal,
  );
export const getInstance = (id: string, signal?: AbortSignal) =>
  call(`${base}/instances/${id}`, isInstance, {}, signal);
export const resetInstance = (id: string, signal?: AbortSignal) =>
  call(`${base}/instances/${id}/reset`, isInstance, post(), signal);
export const stopInstance = (id: string, signal?: AbortSignal) =>
  call(`${base}/instances/${id}/stop`, isInstance, post(), signal);
export const verifyObjective = (id: string, checkId: string, payload?: string, signal?: AbortSignal) =>
  call(
    `${base}/instances/${id}/verify`,
    isVerify,
    post({ check_id: checkId, ...(payload !== undefined ? { payload } : {}) }),
    signal,
  );
export const networkCheck = (id: string, signal?: AbortSignal) =>
  call(`${base}/instances/${id}/network-check`, isIsolation, post(), signal);
export const terminalTicket = (id: string, signal?: AbortSignal) =>
  call(`${base}/instances/${id}/terminal-ticket`, isTicket, post(), signal);
export const sessionLabs = (sessionId: string, signal?: AbortSignal) =>
  call(`${base}/sessions/${sessionId}/labs`, isSessionLabs, {}, signal);
