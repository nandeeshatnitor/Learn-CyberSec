"use client";

import { Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";

import { StageBadge, StatusBadge } from "@/components/admin/status";
import { VersionsPanel } from "@/components/admin/versions-panel";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import * as api from "@/lib/admin-client";
import {
  STATUS_LABELS,
  WORKING,
  type CandidateStatusName,
  type CandidateSummary,
} from "@/lib/admin-types";
import { normalizeCveId } from "@/lib/cve";
import { formatDateTime } from "@/lib/format";
import type { ResearchProblem } from "@/lib/research-types";

const POLL_MS = 4000;

/** The "Candidate Labs" table: one row per revision, newest first. */
export function CandidateList({ onSignedOut }: { onSignedOut: () => void }) {
  const [rows, setRows] = useState<CandidateSummary[] | null>(null);
  const [filter, setFilter] = useState<CandidateStatusName | "">("");
  const [problem, setProblem] = useState<ResearchProblem | null>(null);
  const [cve, setCve] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const refresh = () => setReload((n) => n + 1);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      const result = await api.listCandidates(filter, controller.signal);
      if (controller.signal.aborted) return;
      if (result.ok) {
        setRows(result.data.candidates);
        setProblem(null);
      } else if (result.problem.kind === "unauthorized") onSignedOut();
      else setProblem(result.problem);
    })();
    return () => controller.abort();
  }, [filter, reload, onSignedOut]);

  const working = rows?.some((r) => WORKING.includes(r.status)) ?? false;
  useEffect(() => {
    if (!working) return;
    const timer = setInterval(() => setReload((n) => n + 1), POLL_MS);
    return () => clearInterval(timer);
  }, [working]);

  async function generate(event: FormEvent) {
    event.preventDefault();
    const id = normalizeCveId(cve);
    if (!id) {
      setNotice("Enter a CVE ID such as CVE-2021-44228.");
      return;
    }
    setBusy(true);
    setNotice(null);
    const result = await api.requestCandidate(id);
    setBusy(false);
    if (result.ok) {
      setCve("");
      setNotice(
        `Candidate ${result.data.cve_id} (revision ${result.data.revision}) is being generated.`,
      );
      refresh();
    } else if (result.problem.kind === "unauthorized") onSignedOut();
    else setNotice(result.problem.message);
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Generate a candidate lab</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Builds a <strong>candidate</strong> from a CVE&apos;s researched learning guide
            (generate the guide first). It is built and tested offline and then waits here for a
            person. Nothing is published until you approve it.
          </p>
          <form onSubmit={(e) => void generate(e)} className="flex flex-wrap items-end gap-3">
            <div className="grow space-y-1 sm:max-w-xs">
              <label htmlFor="candidate-cve" className="text-sm font-medium">
                CVE ID
              </label>
              <Input
                id="candidate-cve"
                value={cve}
                onChange={(e) => setCve(e.target.value)}
                placeholder="CVE-2021-44228"
                maxLength={40}
                className="h-10"
              />
            </div>
            <Button type="submit" disabled={busy || !cve.trim()}>
              {busy && <Loader2 aria-hidden className="size-4 animate-spin" />} Generate candidate
            </Button>
          </form>
          {notice && (
            <p role="status" className="text-sm" data-testid="generate-notice">
              {notice}
            </p>
          )}
        </CardContent>
      </Card>

      <section aria-labelledby="candidates-title" className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="candidates-title" className="text-xl font-semibold">
            Candidate Labs
          </h2>
          <div className="flex items-center gap-2 text-sm">
            <label htmlFor="status-filter">Status</label>
            <select
              id="status-filter"
              value={filter}
              onChange={(e) => setFilter(e.target.value as CandidateStatusName | "")}
              className="h-9 rounded-lg border border-input bg-card px-2 text-sm"
            >
              <option value="">All</option>
              {(Object.keys(STATUS_LABELS) as CandidateStatusName[]).map((s) => (
                <option key={s} value={s}>
                  {STATUS_LABELS[s]}
                </option>
              ))}
            </select>
          </div>
        </div>
        {problem && (
          <p role="alert" className="text-sm text-destructive">
            {problem.message}
          </p>
        )}
        {!rows && !problem && (
          <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 aria-hidden className="size-4 animate-spin" /> Loading candidates…
          </p>
        )}
        {rows && rows.length === 0 && (
          <p className="text-sm text-muted-foreground" data-testid="no-candidates">
            No candidate labs{filter ? " with that status" : " yet"}.
          </p>
        )}
        {rows && rows.length > 0 && (
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm" data-testid="candidate-table">
              <caption className="sr-only">Candidate labs and their review state</caption>
              <thead className="bg-muted/50 text-xs uppercase text-muted-foreground">
                <tr>
                  <th scope="col" className="px-3 py-2">
                    CVE
                  </th>
                  <th scope="col" className="px-3 py-2">
                    Status
                  </th>
                  <th scope="col" className="px-3 py-2">
                    Sources
                  </th>
                  <th scope="col" className="px-3 py-2">
                    Build Status
                  </th>
                  <th scope="col" className="px-3 py-2">
                    Security Validation
                  </th>
                  <th scope="col" className="px-3 py-2">
                    Reviewer
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id} className="border-t align-top" data-testid="candidate-row">
                    <td className="px-3 py-2">
                      <Link
                        href={`/admin/labs/${row.id}`}
                        className="font-medium text-primary underline-offset-4 hover:underline"
                      >
                        {row.cve_id}
                      </Link>
                      <div className="text-xs text-muted-foreground">
                        revision {row.revision}
                        {row.lab_id ? ` · published as ${row.lab_id}` : ""}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {formatDateTime(row.updated_at) ?? ""}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge status={row.status} />
                      {row.progress && (
                        <div className="mt-1 text-xs text-muted-foreground">{row.progress}</div>
                      )}
                      {row.error && (
                        <div className="mt-1 text-xs text-destructive">{row.error}</div>
                      )}
                    </td>
                    <td className="px-3 py-2">{row.source_count}</td>
                    <td className="px-3 py-2">
                      <StageBadge stage={row.build_status} />
                    </td>
                    <td className="px-3 py-2">
                      <StageBadge stage={row.security_status} />
                    </td>
                    <td className="px-3 py-2">
                      {row.reviewer ?? <span className="text-muted-foreground">—</span>}
                      {row.reviewed_at && (
                        <div className="text-xs text-muted-foreground">
                          {formatDateTime(row.reviewed_at)}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <VersionsPanel refreshKey={rows?.map((r) => `${r.id}:${r.status}`).join(",")} />
    </div>
  );
}
