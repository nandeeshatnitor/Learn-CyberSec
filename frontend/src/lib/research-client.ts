import type {
  ResearchGuideResponse,
  ResearchProblem,
  ResearchStatus,
  ResearchStatusName,
} from "@/lib/research-types";

/**
 * Browser-side calls to this site's own research route handlers (never to the backend). Every
 * response is checked for the shape the UI relies on; anything else becomes a generic problem.
 */
export type Outcome<T> = { ok: true; data: T } | { ok: false; problem: ResearchProblem };

const STATUS_NAMES: readonly ResearchStatusName[] = [
  "not_started", "queued", "researching", "synthesizing", "ready", "failed",
];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export function isResearchStatus(value: unknown): value is ResearchStatus {
  return (
    isRecord(value) &&
    typeof value.cve_id === "string" &&
    typeof value.status === "string" &&
    (STATUS_NAMES as readonly string[]).includes(value.status) &&
    typeof value.stage === "string"
  );
}

export function isGuideResponse(value: unknown): value is ResearchGuideResponse {
  return (
    isResearchStatus(value) &&
    isRecord((value as unknown as Record<string, unknown>).guide) &&
    Array.isArray((value as unknown as { research_sources?: unknown }).research_sources) &&
    isRecord(((value as unknown as { guide: Record<string, unknown> }).guide).reproduction)
  );
}

function problemFrom(status: number, body: unknown, retryAfter: string | null): ResearchProblem {
  const error = isRecord(body) && isRecord(body.error) ? body.error : {};
  const code = typeof error.code === "string" ? error.code : "";
  const message = typeof error.message === "string" ? error.message : "";
  if (status === 404) return { kind: "not_found", message: message || "Not found." };
  if (status === 401) return { kind: "unauthorized", message: "Please sign in." };
  if (status === 403) return { kind: "forbidden", message: "This request was refused." };
  if (status === 422) {
    // "invalid_input" messages are written for the user; framework validation errors are not.
    const friendly = code === "invalid_input" && message ? message : "The request was rejected as invalid.";
    return { kind: "invalid", message: friendly };
  }
  if (status === 409 && message) return { kind: "invalid", message };
  if (status === 429) {
    const seconds = Number(retryAfter);
    return {
      kind: "rate_limited",
      message: message || "Too many requests. Please try again later.",
      retryAfter: Number.isFinite(seconds) && seconds > 0 ? seconds : undefined,
    };
  }
  if (code === "labgen_disabled" || code === "admin_disabled") {
    return { kind: "disabled", message: "The review interface is not enabled on this server." };
  }
  if (code === "sandbox_disabled") return { kind: "disabled", message: "Labs are not enabled on this server." };
  if (code === "research_disabled") return { kind: "disabled", message: "Learning-guide generation is turned off on this server." };
  return { kind: "unavailable", message: message || "The service is not available right now." };
}

export async function call<T>(
  url: string,
  isValid: (value: unknown) => value is T,
  init: RequestInit = {},
  signal?: AbortSignal,
): Promise<Outcome<T>> {
  let response: Response;
  try {
    response = await fetch(url, { ...init, cache: "no-store", credentials: "same-origin", signal });
  } catch {
    return { ok: false, problem: { kind: "unavailable", message: "The service could not be reached." } };
  }
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // handled below
  }
  if (!response.ok) return { ok: false, problem: problemFrom(response.status, body, response.headers.get("retry-after")) };
  if (!isValid(body)) {
    return { ok: false, problem: { kind: "unavailable", message: "The service returned an unexpected response." } };
  }
  return { ok: true, data: body };
}

const base = (cveId: string) => `/api/cves/${encodeURIComponent(cveId)}/research`;

export const fetchStatus = (cveId: string, signal?: AbortSignal) =>
  call(`${base(cveId)}/status`, isResearchStatus, {}, signal);

export const fetchGuide = (cveId: string, signal?: AbortSignal) =>
  call(base(cveId), isGuideResponse, {}, signal);

export const startResearch = (cveId: string, refresh = false, signal?: AbortSignal) =>
  call(
    base(cveId),
    isResearchStatus,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh }) },
    signal,
  );
