import "server-only";

import type { Cve, CveSearchResponse, HealthResponse } from "@/lib/types";

/**
 * Server-side client for the FastAPI backend.
 *
 * `import "server-only"` makes the build fail if this module is ever pulled into a client
 * component, so the backend URL (and any future credentials) can never reach the browser.
 */

const REQUEST_TIMEOUT_MS = 5000;

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; kind: "not_found" | "invalid" | "unavailable"; message: string };

function backendUrl(): string {
  return (process.env.BACKEND_URL ?? "http://localhost:8000").replace(/\/+$/, "");
}

async function request<T>(path: string): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(`${backendUrl()}${path}`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    return { ok: false, kind: "unavailable", message: "The API could not be reached." };
  }

  if (response.status === 404) {
    return { ok: false, kind: "not_found", message: "Not found." };
  }
  if (response.status === 422) {
    return { ok: false, kind: "invalid", message: "The request was rejected as invalid." };
  }
  if (!response.ok && !(path === "/api/health" && response.status === 503)) {
    return { ok: false, kind: "unavailable", message: `The API returned HTTP ${response.status}.` };
  }
  try {
    return { ok: true, data: (await response.json()) as T };
  } catch {
    return { ok: false, kind: "unavailable", message: "The API returned an unreadable response." };
  }
}

export function getHealth() {
  return request<HealthResponse>("/api/health");
}

export function getCve(cveId: string) {
  return request<Cve>(`/api/cves/${encodeURIComponent(cveId)}`);
}

export function searchCves(query: string, limit = 20, offset = 0) {
  const params = new URLSearchParams({ q: query, limit: String(limit), offset: String(offset) });
  return request<CveSearchResponse>(`/api/cves/search?${params}`);
}
