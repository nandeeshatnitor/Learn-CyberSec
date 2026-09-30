import type { ProviderStatus } from "@/lib/types";

/** Result shapes of the server-side API client. Kept separate so client components can import
 * the types without pulling in the server-only client itself. */
export type ApiError = {
  ok: false;
  kind: "not_found" | "invalid" | "rate_limited" | "unavailable";
  message: string;
  /** Seconds, for rate_limited. */
  retryAfter?: number;
  /** Per-provider outcome, when the backend could not reach any provider. */
  providers?: ProviderStatus[];
};
export type ApiResult<T> = { ok: true; data: T } | ApiError;

