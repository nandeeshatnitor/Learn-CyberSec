"use client";

import { ArrowLeft, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { StageBadge, StatusBadge } from "@/components/admin/status";
import { SafeLink } from "@/components/safe-link";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import * as api from "@/lib/admin-client";
import {
  OVERRIDE_FIELDS,
  WORKING,
  type CandidateDetail,
  type CandidateStatusName,
  type CheckView,
} from "@/lib/admin-types";
import { formatDateTime } from "@/lib/format";
import type { ResearchProblem } from "@/lib/research-types";

const POLL_MS = 4000;
const REGENERABLE: readonly CandidateStatusName[] = [
  "changes_requested",
  "rejected",
  "approved",
  "spec_only",
  "generation_failed",
  "validation_failed",
  "build_failed",
];
const DECIDABLE: readonly CandidateStatusName[] = [
  "awaiting_review",
  "spec_only",
  "validation_failed",
  "build_failed",
  "generation_failed",
];

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} aria-labelledby={`${id}-title`}>
      <Card>
        <CardHeader>
          <CardTitle id={`${id}-title`} className="text-lg">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">{children}</CardContent>
      </Card>
    </section>
  );
}

function CheckList({ items, testId }: { items: CheckView[]; testId: string }) {
  return (
    <ol className="space-y-2" data-testid={testId}>
      {items.map((c, i) => (
        <li key={c.id} className="flex items-start gap-3">
          <span className="w-5 shrink-0 pt-0.5 text-xs text-muted-foreground">{i + 1}.</span>
          <div className="min-w-0 grow">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium">{c.title}</span>
              <Badge
                variant={
                  c.status === "passed"
                    ? "default"
                    : c.status === "failed"
                      ? "destructive"
                      : "outline"
                }
              >
                {c.status}
              </Badge>
            </div>
            {c.detail && <p className="text-xs text-muted-foreground">{c.detail}</p>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function CandidateReview({ id, onSignedOut }: { id: string; onSignedOut: () => void }) {
  const [c, setC] = useState<CandidateDetail | null>(null);
  const [problem, setProblem] = useState<ResearchProblem | null>(null);
  const [notes, setNotes] = useState("");
  const [overrides, setOverrides] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{
    tone: "ok" | "error";
    text: string;
  } | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [file, setFile] = useState<string | null>(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      const result = await api.getCandidate(id, controller.signal);
      if (controller.signal.aborted) return;
      if (result.ok) {
        setC(result.data);
        setProblem(null);
      } else if (result.problem.kind === "unauthorized") onSignedOut();
      else setProblem(result.problem);
    })();
    return () => controller.abort();
  }, [id, reload, onSignedOut]);

  const working = c ? WORKING.includes(c.status) : false;
  useEffect(() => {
    if (!working) return;
    const timer = setInterval(() => setReload((n) => n + 1), POLL_MS);
    return () => clearInterval(timer);
  }, [working]);

  const names = c ? Object.keys(c.files).sort() : [];
  const shownFile = file && names.includes(file) ? file : (names[0] ?? null);

  async function act(
    name: string,
    run: () => Promise<{ ok: true; data: unknown } | { ok: false; problem: ResearchProblem }>,
    done: string,
    after?: (data: unknown) => void,
  ) {
    setBusy(name);
    setMessage(null);
    const result = await run();
    setBusy(null);
    setConfirming(false);
    if (result.ok) {
      setMessage({ tone: "ok", text: done });
      setNotes("");
      after?.(result.data);
      setReload((n) => n + 1);
    } else if (result.problem.kind === "unauthorized") onSignedOut();
    else setMessage({ tone: "error", text: result.problem.message });
  }

  if (problem) {
    return (
      <div className="space-y-3">
        <BackLink />
        <p role="alert" className="text-sm text-destructive" data-testid="review-problem">
          {problem.kind === "not_found" ? "That candidate does not exist." : problem.message}
        </p>
      </div>
    );
  }
  if (!c) {
    return (
      <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 aria-hidden className="size-4 animate-spin" /> Loading candidate…
      </p>
    );
  }

  const trimmed = notes.trim();
  const canDecide = DECIDABLE.includes(c.status);
  const spec = c.spec;
  const overridesToSend = Object.fromEntries(Object.entries(overrides).filter(([, v]) => v.trim()));

  return (
    <div className="space-y-6">
      <BackLink />
      <header className="space-y-2">
        <h1 className="flex flex-wrap items-center gap-3 text-2xl font-bold tracking-tight">
          {c.cve_id} <StatusBadge status={c.status} />
        </h1>
        <p className="text-sm text-muted-foreground" data-testid="review-title">
          {c.title ?? "No title"} · revision {c.revision}
          {c.parent_id ? " (replaces an earlier revision)" : ""} · requested by {c.requested_by} ·{" "}
          {formatDateTime(c.created_at)}
        </p>
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="flex items-center gap-1">
            Build <StageBadge stage={c.build_status} />
          </span>
          <span className="flex items-center gap-1">
            Validation <StageBadge stage={c.validation_status} />
          </span>
          <span className="flex items-center gap-1">
            Security <StageBadge stage={c.security_status} />
          </span>
        </div>
        {working && (
          <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 aria-hidden className="size-4 animate-spin" /> {c.progress ?? "Working…"}
          </p>
        )}
        {c.error && <p className="text-sm text-destructive">{c.error}</p>}
        {c.lab_id && (
          <p className="text-sm" data-testid="published-as">
            Published to students as <strong>{c.lab_id}</strong>. Published labs never change: a
            change is a new version.
          </p>
        )}
      </header>

      <Section id="decision" title="Decision">
        <p className="text-muted-foreground">
          Nothing reaches students until a person approves it here. Approval re-checks every
          automated gate, then publishes this exact content as the next immutable version.
        </p>
        {c.status === "awaiting_review" && (
          <div className="rounded-lg border p-3" data-testid="gates">
            {c.can_approve ? (
              <p>
                All automated gates passed: build, ten validation checks and security validation.
              </p>
            ) : (
              <>
                <p className="font-medium text-destructive">
                  This candidate cannot be approved yet:
                </p>
                <ul className="list-disc pl-5">
                  {c.blockers.map((b) => (
                    <li key={b}>{b}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
        {(canDecide || REGENERABLE.includes(c.status)) && (
          <div className="space-y-2">
            <label htmlFor="decision-notes" className="font-medium">
              Notes{" "}
              {canDecide && (
                <span className="font-normal text-muted-foreground">
                  (required to reject or request changes)
                </span>
              )}
            </label>
            <Textarea
              id="decision-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              maxLength={2000}
              className="min-h-20 text-sm"
            />
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {c.status === "awaiting_review" &&
            (confirming ? (
              <>
                <span className="text-sm">Publish this to students as the next version?</span>
                <Button
                  onClick={() =>
                    void act("approve", () => api.approve(c.id, trimmed), "Approved and published.")
                  }
                  disabled={busy !== null}
                >
                  {busy === "approve" && <Loader2 aria-hidden className="size-4 animate-spin" />}{" "}
                  Yes, publish
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setConfirming(false)}
                  disabled={busy !== null}
                >
                  Cancel
                </Button>
              </>
            ) : (
              <Button
                onClick={() => setConfirming(true)}
                disabled={!c.can_approve || busy !== null}
              >
                Approve
              </Button>
            ))}
          {canDecide && (
            <>
              <Button
                variant="outline"
                disabled={trimmed.length < 3 || busy !== null}
                onClick={() => void act("reject", () => api.reject(c.id, trimmed), "Rejected.")}
              >
                Reject
              </Button>
              <Button
                variant="outline"
                disabled={trimmed.length < 3 || busy !== null}
                onClick={() =>
                  void act("changes", () => api.requestChanges(c.id, trimmed), "Changes requested.")
                }
              >
                Request Changes
              </Button>
            </>
          )}
          {["build_failed", "validation_failed"].includes(c.status) &&
            Object.keys(c.files).length > 0 && (
              <Button
                variant="ghost"
                disabled={busy !== null}
                onClick={() => void act("rebuild", () => api.rebuild(c.id), "Rebuild queued.")}
              >
                Re-run build and tests
              </Button>
            )}
          {working && (
            <Button
              variant="ghost"
              disabled={busy !== null}
              onClick={() => void act("release", () => api.release(c.id), "Released.")}
            >
              Release stalled job
            </Button>
          )}
        </div>
        {message && (
          <p
            role={message.tone === "error" ? "alert" : "status"}
            className={message.tone === "error" ? "text-destructive" : "text-primary"}
            data-testid="decision-message"
          >
            {message.text}
          </p>
        )}
        {REGENERABLE.includes(c.status) && (
          <details className="rounded-lg border p-3" data-testid="regenerate">
            <summary className="cursor-pointer font-medium">Generate a new revision</summary>
            <div className="mt-3 space-y-3">
              <p className="text-muted-foreground">
                Builds a fresh candidate from the same sources. You can correct what the sources
                said; leave a field empty to keep it. Only fields the generator recognises are used,
                and each is validated.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                {OVERRIDE_FIELDS.map(([key, label]) => (
                  <div key={key} className="space-y-1">
                    <label htmlFor={`ov-${key}`} className="text-xs font-medium">
                      {label}
                    </label>
                    <Input
                      id={`ov-${key}`}
                      className="h-9 text-sm"
                      value={overrides[key] ?? ""}
                      maxLength={200}
                      onChange={(e) => setOverrides({ ...overrides, [key]: e.target.value })}
                    />
                  </div>
                ))}
              </div>
              <Button
                disabled={busy !== null}
                onClick={() =>
                  void act(
                    "regenerate",
                    () => api.regenerate(c.id, overridesToSend, trimmed || undefined),
                    "A new revision is being generated.",
                  )
                }
              >
                {busy === "regenerate" && <Loader2 aria-hidden className="size-4 animate-spin" />}{" "}
                Generate revision
              </Button>
            </div>
          </details>
        )}
      </Section>

      {spec && (
        <Section id="spec" title="Candidate specification">
          <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">CVE</dt>
            <dd>{spec.cve_id}</dd>
            <dt className="text-muted-foreground">Affected software</dt>
            <dd>
              {[spec.affected_software.vendor, spec.affected_software.product]
                .filter(Boolean)
                .join(" ") || "Unknown"}
              {spec.affected_software.affected_ranges.length > 0 && (
                <span className="text-muted-foreground">
                  {" "}
                  — {spec.affected_software.affected_ranges.join("; ")}
                </span>
              )}
            </dd>
            <dt className="text-muted-foreground">Vulnerable version</dt>
            <dd data-testid="vulnerable-version">
              {spec.affected_software.vulnerable_version ?? "Not established"}
              {spec.affected_software.vulnerable_version_basis && (
                <span className="block text-xs text-muted-foreground">
                  {spec.affected_software.vulnerable_version_basis}
                </span>
              )}
              {spec.affected_software.fixed_version && (
                <span className="block text-xs text-muted-foreground">
                  Fixed in {spec.affected_software.fixed_version}
                </span>
              )}
            </dd>
            <dt className="text-muted-foreground">Safe lab objective</dt>
            <dd>{spec.safe_objective}</dd>
            <dt className="text-muted-foreground">Prerequisites</dt>
            <dd>
              <ul className="list-disc pl-5">
                {spec.prerequisites.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </dd>
            <dt className="text-muted-foreground">Learning tasks</dt>
            <dd>
              <ol className="list-decimal space-y-1 pl-5">
                {spec.learning_tasks.map((t) => (
                  <li key={t.id}>
                    <strong>{t.title}.</strong> {t.description}
                  </li>
                ))}
              </ol>
            </dd>
            {spec.expected_behavior && (
              <>
                <dt className="text-muted-foreground">Expected behaviour</dt>
                <dd>
                  <p>
                    <strong>Vulnerable:</strong> {spec.expected_behavior.vulnerable}
                  </p>
                  <p>
                    <strong>After the fix:</strong> {spec.expected_behavior.after_fix}
                  </p>
                </dd>
              </>
            )}
            {spec.verification_method && (
              <>
                <dt className="text-muted-foreground">Verification method</dt>
                <dd>
                  <p>{spec.verification_method.summary}</p>
                  <ul className="list-disc pl-5">
                    {spec.verification_method.checks.map((v) => (
                      <li key={v.id}>
                        {v.title} <span className="text-xs text-muted-foreground">({v.kind})</span>
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            <dt className="text-muted-foreground">Remediation task</dt>
            <dd>
              <p>{spec.remediation_task.description}</p>
              {spec.remediation_task.documented_fix && (
                <p className="text-xs text-muted-foreground">
                  Documented fix: {spec.remediation_task.documented_fix}
                </p>
              )}
            </dd>
          </dl>
          {spec.caveats.length > 0 && (
            <div className="rounded-lg border border-warning/40 p-3" data-testid="caveats">
              <p className="font-medium">Caveats</p>
              <ul className="list-disc pl-5">
                {spec.caveats.map((v) => (
                  <li key={v}>{v}</li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-xs text-muted-foreground">
            Generated{" "}
            {spec.generation.method === "spec_only"
              ? "as a specification only"
              : `from the ${spec.blueprint?.id ?? "vetted"} blueprint`}
            {spec.generation.model ? ` with wording polished by ${spec.generation.model}` : ""}
            {spec.generation.llm_fallback
              ? ` (model wording rejected: ${spec.generation.llm_fallback})`
              : ""}
            . The platform never copies vendor code; documented images and commands are recorded,
            not run.
          </p>
          {spec.generation.change_notes && (
            <p className="text-xs">
              Reviewer request this revision answers: {spec.generation.change_notes}
            </p>
          )}
          {Object.keys(spec.generation.overrides).length > 0 && (
            <p className="text-xs">
              Reviewer corrections applied:{" "}
              {Object.entries(spec.generation.overrides)
                .map(([k, v]) => `${k} = ${v}`)
                .join(", ")}
            </p>
          )}
        </Section>
      )}

      {spec && (
        <Section id="sources" title={`Sources (${spec.source_references.length})`}>
          <ul className="space-y-1" data-testid="source-list">
            {spec.source_references.map((s) => (
              <li key={s.id} className="flex flex-wrap items-center gap-2">
                <SafeLink href={s.url}>{s.title}</SafeLink>
                <Badge variant="outline">{s.source_type}</Badge>
                <Badge variant="muted">{s.reliability_level}</Badge>
                {s.publisher && (
                  <span className="text-xs text-muted-foreground">{s.publisher}</span>
                )}
              </li>
            ))}
          </ul>
          {spec.documented_artifacts.length > 0 && (
            <div>
              <p className="font-medium">Documented in the sources, not used or run</p>
              <ul className="list-disc pl-5">
                {spec.documented_artifacts.map((a) => (
                  <li key={`${a.kind}:${a.value}`}>
                    <code className="break-all text-xs">{a.value}</code>{" "}
                    <span className="text-xs text-muted-foreground">({a.kind})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Section>
      )}

      <Section id="validation" title="Automated validation">
        {c.checks.length === 0 ? (
          <p className="text-muted-foreground">Not run yet.</p>
        ) : (
          <CheckList items={c.checks} testId="validation-checks" />
        )}
      </Section>

      <Section id="security" title="Security validation">
        {c.static_findings.length === 0 && c.runtime_findings.length === 0 ? (
          <p className="text-muted-foreground">Not run yet.</p>
        ) : (
          <>
            <div>
              <p className="mb-1 font-medium">Static scan of the generated files</p>
              <ul className="space-y-1" data-testid="static-findings">
                {c.static_findings.map((f) => (
                  <li key={f.id} className="flex flex-wrap items-center gap-2">
                    <Badge variant={f.passed ? "default" : "destructive"}>
                      {f.passed ? "passed" : "failed"}
                    </Badge>
                    <span>{f.title}</span>
                    {f.detail && <span className="text-xs text-muted-foreground">{f.detail}</span>}
                  </li>
                ))}
              </ul>
            </div>
            {c.runtime_findings.length > 0 && (
              <div>
                <p className="mb-1 font-medium">Inspection of the running sandbox</p>
                <CheckList items={c.runtime_findings} testId="runtime-findings" />
              </div>
            )}
          </>
        )}
      </Section>

      {names.length > 0 && (
        <Section id="files" title={`Generated files (${names.length})`}>
          <p className="text-muted-foreground">
            Read these before approving: this is exactly what would be built.
          </p>
          <div className="flex flex-wrap gap-2" role="tablist" aria-label="Generated files">
            {names.map((n) => (
              <Button
                key={n}
                size="sm"
                role="tab"
                aria-selected={n === shownFile}
                variant={n === shownFile ? "default" : "outline"}
                onClick={() => setFile(n)}
              >
                {n}
              </Button>
            ))}
          </div>
          {shownFile && (
            <pre
              className="max-h-96 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs"
              data-testid="file-view"
            >
              {c.files[shownFile]}
            </pre>
          )}
        </Section>
      )}

      {c.build_log && (
        <Section id="build" title="Build log">
          <pre
            className="max-h-72 overflow-auto rounded-lg border bg-muted/40 p-3 text-xs"
            data-testid="build-log"
          >
            {c.build_log}
          </pre>
        </Section>
      )}

      <Section id="history" title="Review history">
        {c.reviews.length === 0 ? (
          <p className="text-muted-foreground">No decisions yet.</p>
        ) : (
          <ul className="space-y-2" data-testid="review-history">
            {c.reviews.map((r) => (
              <li key={`${r.at}-${r.action}`}>
                <strong>{r.reviewer}</strong> — {r.action.replace("_", " ")} ({formatDateTime(r.at)}
                ){r.notes && <p className="text-muted-foreground">{r.notes}</p>}
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      href="/admin/labs"
      className="inline-flex items-center gap-1 text-sm text-primary underline-offset-4 hover:underline"
    >
      <ArrowLeft aria-hidden className="size-4" /> All candidate labs
    </Link>
  );
}
