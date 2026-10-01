"use client";

import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import * as api from "@/lib/admin-client";
import type { VersionView } from "@/lib/admin-types";
import { formatDateTime } from "@/lib/format";

/** Published versions. They cannot be edited; the only action is to stop offering one. */
export function VersionsPanel({ refreshKey }: { refreshKey?: unknown }) {
  const [versions, setVersions] = useState<VersionView[] | null>(null);
  const [target, setTarget] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const [reload, setReload] = useState(0);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const result = await api.listVersions();
      if (alive && result.ok) setVersions(result.data.versions);
    })();
    return () => {
      alive = false;
    };
  }, [reload, refreshKey]);

  async function withdraw(id: string) {
    setError(null);
    const result = await api.withdrawVersion(id, reason.trim());
    if (result.ok) {
      setTarget(null);
      setReason("");
      setReload((n) => n + 1);
    } else setError(result.problem.message);
  }

  if (!versions || versions.length === 0) return null;
  return (
    <section aria-labelledby="versions-title" className="space-y-3">
      <h2 id="versions-title" className="text-xl font-semibold">
        Published versions
      </h2>
      <p className="text-sm text-muted-foreground">
        A published version never changes. A newer version replaces it for new learners; learners
        who used it keep their record against it.
      </p>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <ul className="space-y-2" data-testid="version-list">
        {versions.map((v) => (
          <li
            key={v.id}
            className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-sm"
          >
            <strong>{v.lab_id}</strong>
            <Badge
              variant={
                v.status === "published"
                  ? "default"
                  : v.status === "withdrawn"
                    ? "destructive"
                    : "muted"
              }
            >
              {v.status}
            </Badge>
            <span className="text-muted-foreground">
              {v.cve_id} · published by {v.published_by} {formatDateTime(v.published_at)}
              {v.superseded_by ? ` · replaced by ${v.superseded_by}` : ""}
              {v.withdrawn_reason ? ` · withdrawn: ${v.withdrawn_reason}` : ""}
            </span>
            {v.status !== "withdrawn" &&
              (target === v.id ? (
                <span className="flex flex-wrap items-center gap-2">
                  <label htmlFor={`why-${v.id}`} className="sr-only">
                    Reason for withdrawing {v.lab_id}
                  </label>
                  <Input
                    id={`why-${v.id}`}
                    className="h-8 w-64 text-sm"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="Reason"
                    maxLength={2000}
                  />
                  <Button
                    size="sm"
                    disabled={reason.trim().length < 3}
                    onClick={() => void withdraw(v.id)}
                  >
                    Withdraw
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setTarget(null)}>
                    Cancel
                  </Button>
                </span>
              ) : (
                <Button size="sm" variant="outline" onClick={() => setTarget(v.id)}>
                  Stop offering
                </Button>
              ))}
          </li>
        ))}
      </ul>
    </section>
  );
}
