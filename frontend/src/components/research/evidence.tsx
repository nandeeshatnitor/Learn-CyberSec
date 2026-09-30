import { Badge } from "@/components/ui/badge";
import type { EvidenceLevel, EvidencePassage, LearningGuide } from "@/lib/research-types";

const LEVELS: Record<
  EvidenceLevel,
  { label: string; variant: "default" | "muted" | "warning" | "outline"; help: string }
> = {
  DOCUMENTED: {
    label: "Documented",
    variant: "default",
    help: "A retrieved source states this.",
  },
  SUPPORTED_BY_MULTIPLE_SOURCES: {
    label: "Multiple sources",
    variant: "default",
    help: "Independent sources each contain this.",
  },
  SYNTHESIZED: {
    label: "Synthesized",
    variant: "muted",
    help: "Drawn from the cited sources but not stated outright by them.",
  },
  UNCERTAIN: {
    label: "Uncertain",
    variant: "warning",
    help: "Weakly supported. Treat as unconfirmed.",
  },
};

export function EvidenceBadge({ level }: { level: EvidenceLevel }) {
  const info = LEVELS[level] ?? LEVELS.UNCERTAIN;
  return (
    <Badge variant={info.variant} title={info.help} data-evidence={level}>
      {info.label}
    </Badge>
  );
}

export function EvidenceLegend() {
  return (
    <dl className="grid gap-x-6 gap-y-1 text-xs text-muted-foreground sm:grid-cols-2">
      {(Object.keys(LEVELS) as EvidenceLevel[]).map((level) => (
        <div key={level} className="flex items-baseline gap-2">
          <dt>
            <EvidenceBadge level={level} />
          </dt>
          <dd>{LEVELS[level].help}</dd>
        </div>
      ))}
    </dl>
  );
}

// Source IDs are assigned by the backend as "S<number>"; anything else is not turned into an
// anchor or element ID.
const SID = /^S\d{1,3}$/;

export function Citations({ ids, guide }: { ids: string[]; guide: LearningGuide }) {
  const valid = ids.filter((id) => SID.test(id));
  if (valid.length === 0) return null;
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-baseline" data-testid="citations">
      {valid.map((id) => {
        const source = guide.sources.find((s) => s.id === id);
        return (
          <a
            key={id}
            href={`#guide-source-${id}`}
            title={source ? `${source.title}${source.publisher ? ` (${source.publisher})` : ""}` : id}
            aria-label={`Source ${id}${source ? `: ${source.title}` : ""}`}
            className="rounded border px-1 font-mono text-[11px] leading-5 text-primary hover:bg-accent"
          >
            [{id}]
          </a>
        );
      })}
    </span>
  );
}

/** The exact excerpts a claim rests on, so a reader can check it against the source. */
export function EvidenceDetails({ passageIds, guide }: { passageIds: string[]; guide: LearningGuide }) {
  const passages = passageIds
    .map((id) => guide.evidence.find((p) => p.id === id))
    .filter((p): p is EvidencePassage => p !== undefined);
  if (passages.length === 0) return null;
  return (
    <details className="mt-1 text-xs text-muted-foreground">
      <summary className="cursor-pointer select-none">Show evidence ({passages.length})</summary>
      <ul className="mt-1 space-y-1">
        {passages.map((passage) => (
          <li key={passage.id} className="border-l-2 pl-2">
            {/* Plain text: excerpts come from third-party pages and are never injected as HTML. */}
            <q className="whitespace-pre-line">{passage.text}</q>
            <span className="ml-1 font-mono">[{SID.test(passage.source_id) ? passage.source_id : "?"}]</span>
          </li>
        ))}
      </ul>
    </details>
  );
}
