import { call, type Outcome } from "@/lib/research-client";
import type {
  CandidateDetail,
  CandidateStatusName,
  CandidateSummary,
  Reviewer,
  VersionView,
} from "@/lib/admin-types";

/** Browser-side calls to this site's own admin route handlers (never to the backend). */
export type { Outcome };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const isSummary = (v: unknown): v is CandidateSummary =>
  isRecord(v) &&
  typeof v.id === "string" &&
  typeof v.cve_id === "string" &&
  typeof v.status === "string";
const isDetail = (v: unknown): v is CandidateDetail =>
  isSummary(v) &&
  Array.isArray((v as unknown as Record<string, unknown>).checks) &&
  isRecord((v as unknown as Record<string, unknown>).files) &&
  typeof (v as unknown as Record<string, unknown>).can_approve === "boolean";
const isList = (v: unknown): v is { candidates: CandidateSummary[] } =>
  isRecord(v) && Array.isArray(v.candidates) && v.candidates.every(isSummary);
const isVersions = (v: unknown): v is { versions: VersionView[] } =>
  isRecord(v) && Array.isArray(v.versions);
const isVersion = (v: unknown): v is VersionView =>
  isRecord(v) && typeof v.lab_id === "string" && typeof v.status === "string";
const isReviewer = (v: unknown): v is Reviewer => isRecord(v) && typeof v.name === "string";
const isOk = (v: unknown): v is { ok: true } => isRecord(v) && v.ok === true;

const labs = "/api/admin/labs";
const post = (body?: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body ?? {}),
});

export const signIn = (token: string, signal?: AbortSignal) =>
  call("/api/admin/session", isReviewer, post({ token }), signal);
export const signOut = (signal?: AbortSignal) =>
  call("/api/admin/session", isOk, { method: "DELETE" }, signal);
export const whoami = (signal?: AbortSignal) => call("/api/admin/session", isReviewer, {}, signal);

export const listCandidates = (status?: CandidateStatusName | "", signal?: AbortSignal) =>
  call(`${labs}/candidates${status ? `?status=${status}` : ""}`, isList, {}, signal);
export const requestCandidate = (
  cveId: string,
  overrides: Record<string, string> = {},
  signal?: AbortSignal,
) => call(`${labs}/candidates`, isSummary, post({ cve_id: cveId, overrides }), signal);
export const getCandidate = (id: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}`, isDetail, {}, signal);

export const approve = (id: string, notes: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}/approve`, isDetail, post({ notes }), signal);
export const reject = (id: string, notes: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}/reject`, isDetail, post({ notes }), signal);
export const requestChanges = (id: string, notes: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}/request-changes`, isDetail, post({ notes }), signal);
export const regenerate = (
  id: string,
  overrides: Record<string, string>,
  notes?: string,
  signal?: AbortSignal,
) => call(`${labs}/candidates/${id}/regenerate`, isSummary, post({ overrides, notes }), signal);
export const rebuild = (id: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}/rebuild`, isSummary, post(), signal);
export const release = (id: string, signal?: AbortSignal) =>
  call(`${labs}/candidates/${id}/release`, isSummary, post(), signal);

export const listVersions = (family?: string, signal?: AbortSignal) =>
  call(
    `${labs}/versions${family ? `?family=${encodeURIComponent(family)}` : ""}`,
    isVersions,
    {},
    signal,
  );
export const withdrawVersion = (id: string, notes: string, signal?: AbortSignal) =>
  call(`${labs}/versions/${id}/withdraw`, isVersion, post({ notes }), signal);
