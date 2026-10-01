import { vi } from "vitest";

import type {
  CandidateDetail,
  CandidateSpec,
  CandidateSummary,
  VersionView,
} from "@/lib/admin-types";

export const CAND_ID = "33333333-3333-4333-8333-333333333333";
export const OTHER_ID = "44444444-4444-4444-8444-444444444444";

const CHECK_TITLES = [
  "Build succeeds",
  "Application starts",
  "A student can connect",
  "Verification works",
  "The expected vulnerable behaviour exists",
  "Remediation removes the behaviour",
  "The sandbox has no unauthorized network access",
  "Resource limits work",
  "Cleanup works",
  "Reset works",
];

export const spec = (): CandidateSpec => ({
  cve_id: "CVE-2099-12345",
  title: "AcmeDocs 4.2.3: expression injection (CVE-2099-12345)",
  affected_software: {
    vendor: "acme",
    product: "AcmeDocs",
    vulnerable_version: "4.2.3",
    vulnerable_version_basis: "The highest version the sources state as affected.",
    affected_ranges: ["4.0.0 ≤ version ≤ 4.2.3"],
    fixed_version: "4.2.4",
    evidence: [],
  },
  safe_objective: "Understand how a header can be evaluated as an expression, and fix it.",
  prerequisites: ["A sandboxed lab only"],
  learning_tasks: [{ id: "t1", title: "Find the input", description: "Read the app source." }],
  expected_behavior: {
    vulnerable: "The header value is evaluated.",
    after_fix: "The header is escaped.",
  },
  verification_method: {
    summary: "Two checks run against the live lab.",
    checks: [
      { id: "exploit", title: "Reveal the secret", kind: "payload_replay", description: "d" },
    ],
  },
  remediation_task: { description: "Escape the header.", documented_fix: "Upgrade to 4.2.4." },
  source_references: [
    {
      id: "s1",
      title: "Acme advisory",
      url: "https://advisories.acme-vendor.test/a",
      publisher: "Acme",
      source_type: "vendor_advisory",
      reliability_level: "OFFICIAL",
    },
    {
      id: "s2",
      title: "Sneaky",
      url: "javascript:alert(1)",
      publisher: null,
      source_type: "blog",
      reliability_level: "COMMUNITY",
    },
  ],
  documented_artifacts: [{ kind: "docker_image", value: "acme/docs:4.2.3", note: "not used" }],
  blueprint: { id: "expression_injection", version: "1", params: {} },
  generation: {
    method: "blueprint",
    generator_version: "1",
    model: null,
    llm_fallback: null,
    overrides: {},
    change_notes: null,
  },
  caveats: [],
  safety_notice: "A candidate lab …",
});

export const summary = (over: Partial<CandidateSummary> = {}): CandidateSummary => ({
  id: CAND_ID,
  cve_id: "CVE-2099-12345",
  family: "cve-2099-12345",
  revision: 1,
  title: "AcmeDocs 4.2.3: expression injection (CVE-2099-12345)",
  status: "awaiting_review",
  build_status: "passed",
  validation_status: "passed",
  security_status: "passed",
  progress: null,
  source_count: 7,
  product: "AcmeDocs",
  vulnerable_version: "4.2.3",
  reviewer: null,
  reviewed_at: null,
  requested_by: "alice",
  created_at: "2026-10-01T06:00:00Z",
  updated_at: "2026-10-01T06:05:00Z",
  lab_id: null,
  error: null,
  ...over,
});

export const detail = (over: Partial<CandidateDetail> = {}): CandidateDetail => ({
  ...summary(),
  parent_id: null,
  spec: spec(),
  files: {
    Dockerfile: "FROM python:3.12-alpine\nUSER 10001:10001\n",
    "app/server.py": "print('<script>alert(1)</script>')\n",
  },
  build_log: "Successfully built",
  image_tag: "cvelearn-candidate/cve-2099-12345:abc",
  checks: CHECK_TITLES.map((title, i) => ({
    id: `c${i}`,
    title,
    status: "passed",
    detail: "ok",
    seconds: 1,
    evidence: [],
  })),
  static_findings: [
    {
      id: "file_set",
      title: "The build context is a small set of plain text files",
      passed: true,
      detail: "",
    },
  ],
  runtime_findings: [
    {
      id: "egress",
      title: "egress",
      status: "passed",
      detail: "no route",
      seconds: 1,
      evidence: [],
    },
  ],
  reviews: [],
  can_approve: true,
  blockers: [],
  generator: {},
  review_notes: null,
  ...over,
});

export const version = (over: Partial<VersionView> = {}): VersionView => ({
  id: "55555555-5555-4555-8555-555555555555",
  lab_id: "cve-2099-12345-v1",
  family: "cve-2099-12345",
  version: 1,
  cve_id: "CVE-2099-12345",
  status: "published",
  published_at: "2026-10-01T07:00:00Z",
  published_by: "alice",
  superseded_by: null,
  withdrawn_at: null,
  withdrawn_by: null,
  withdrawn_reason: null,
  content_hash: "0".repeat(64),
  candidate_id: CAND_ID,
  ...over,
});

type Call = { method: string; path: string; body: unknown };
export type FakeAdmin = {
  calls: Call[];
  state: {
    signedIn: boolean;
    list: CandidateSummary[];
    detail: CandidateDetail;
    versions: VersionView[];
    failNext: { status: number; code: string; message: string } | null;
  };
};

/** A fake of this site's admin route handlers (the only thing the browser talks to). */
export function installFakeAdmin(init: Partial<FakeAdmin["state"]> = {}): FakeAdmin {
  const api: FakeAdmin = {
    calls: [],
    state: {
      signedIn: true,
      list: [summary()],
      detail: detail(),
      versions: [],
      failNext: null,
      ...init,
    },
  };
  const json = (status: number, body: unknown) =>
    ({
      ok: status < 400,
      status,
      headers: new Headers(),
      json: async () => body,
    }) as unknown as Response;
  const error = (status: number, code: string, message: string) =>
    json(status, { error: { code, message } });

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, options: RequestInit = {}) => {
      const url = new URL(String(input), "http://localhost");
      const method = options.method ?? "GET";
      const body = options.body ? JSON.parse(String(options.body)) : undefined;
      api.calls.push({ method, path: url.pathname + url.search, body });
      const { state } = api;
      if (url.pathname === "/api/admin/session") {
        if (method === "DELETE") {
          state.signedIn = false;
          return json(200, { ok: true });
        }
        if (method === "POST") {
          if (body?.token !== "good-reviewer-token-0123456789abc")
            return error(401, "unauthorized", "no");
          state.signedIn = true;
        }
        return state.signedIn
          ? json(200, { name: "alice", labgen_enabled: true })
          : error(401, "unauthorized", "Please sign in.");
      }
      if (!state.signedIn) return error(401, "unauthorized", "Please sign in.");
      if (state.failNext) {
        const f = state.failNext;
        state.failNext = null;
        return error(f.status, f.code, f.message);
      }
      const path = url.pathname.replace("/api/admin/labs", "");
      if (method === "GET" && path === "/candidates") {
        const status = url.searchParams.get("status");
        return json(200, {
          candidates: status ? state.list.filter((c) => c.status === status) : state.list,
        });
      }
      if (method === "POST" && path === "/candidates")
        return json(202, summary({ id: OTHER_ID, cve_id: body.cve_id, status: "generating" }));
      if (method === "GET" && path === "/versions") return json(200, { versions: state.versions });
      if (method === "GET" && path === `/candidates/${CAND_ID}`) return json(200, state.detail);
      const act = new RegExp(`^/candidates/${CAND_ID}/([a-z-]+)$`).exec(path);
      if (method === "POST" && act) {
        const name = act[1]!;
        if (name === "approve") {
          state.detail = detail({
            status: "approved",
            reviewer: "alice",
            lab_id: "cve-2099-12345-v1",
            can_approve: false,
          });
          return json(200, state.detail);
        }
        if (name === "reject")
          return json(
            200,
            (state.detail = detail({ status: "rejected", can_approve: false, reviewer: "alice" })),
          );
        if (name === "request-changes")
          return json(
            200,
            (state.detail = detail({
              status: "changes_requested",
              can_approve: false,
              reviewer: "alice",
            })),
          );
        return json(202, summary({ id: OTHER_ID, status: "generating" }));
      }
      const withdraw = /^\/versions\/([0-9a-f-]{36})\/withdraw$/.exec(path);
      if (method === "POST" && withdraw) {
        state.versions = state.versions.map((v) => ({
          ...v,
          status: "withdrawn",
          withdrawn_reason: body.notes,
        }));
        return json(200, state.versions[0]);
      }
      return error(404, "not_found", "Not found.");
    }),
  );
  return api;
}
