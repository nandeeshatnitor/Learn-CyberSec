/** Mirrors backend/app/schemas/learning.py. */

export type SessionStatus = "not_started" | "in_progress" | "completed" | "abandoned";
export type TaskStatus = "locked" | "open" | "correct" | "revealed";
export type AnswerResult = "correct" | "partially_correct" | "incorrect";
export type TutorOutcome = "answered" | "guided" | "no_evidence" | "refused";

export interface SourceRef {
  id: string;
  title: string;
  url: string | null;
  publisher: string | null;
  source_type: string;
  reliability_level: string;
  kind: string;
}

export interface EvidenceRef {
  source_id: string;
  title: string;
  url: string | null;
  /** Present only for evidence the student has earned (hint 3, a solution) or the tutor cites. */
  excerpt: string | null;
}

export interface TaskView {
  id: string;
  order: number;
  kind: string;
  title: string;
  prompt: string;
  objective: string;
  verification_criteria: string[];
  status: TaskStatus;
  attempts: number;
  hints_revealed: number;
  next_hint_penalty: number | null;
  solution_penalty: number;
  solution_available: boolean;
  context_sources: SourceRef[];
}

export interface SessionView {
  id: string;
  cve_id: string;
  status: SessionStatus;
  started_at: string | null;
  completed_at: string | null;
  hints_used: number;
  solution_revealed: boolean;
  score: number;
  max_score: number;
  progress: { resolved: number; total: number; percent: number };
  learning_objectives: string[];
  prerequisites: { text: string; source_ids: string[] }[];
  tasks: TaskView[];
  current_task_id: string | null;
  can_complete: boolean;
  sources: SourceRef[];
  cve: {
    cve_id: string;
    description: string | null;
    severity: string | null;
    cvss_score: number | null;
    affected: string[];
  };
  scoring: Record<string, unknown>;
  notes: string[];
  guide_generated_at: string | null;
  safety_notice: string;
}

export interface HintView {
  task_id: string;
  number: number;
  label: string;
  text: string;
  penalty: number;
  revealed_at: string;
  evidence: EvidenceRef[];
}

export interface HintsResponse {
  hints: HintView[];
  next: { task_id: string; number: number; penalty: number } | null;
}

export interface SolutionView {
  task_id: string;
  parts: { text: string; command: string | null; source_ids: string[]; evidence_level: string }[];
  evidence: EvidenceRef[];
}

export interface AnswerResponse {
  result: AnswerResult;
  feedback: string;
  solution: SolutionView | null;
  attempts: number;
  session: SessionView;
}

export interface HintRevealResponse {
  hint: HintView;
  session: SessionView;
}

export interface SolutionResponse {
  solution: SolutionView;
  penalty: number;
  session: SessionView;
}

export interface TutorReplyView {
  outcome: TutorOutcome;
  message: string;
  parts: { text: string; source_ids: string[]; evidence_level: string; evidence: EvidenceRef[] }[];
  next_step: string | null;
  safety_reminder: string | null;
  model_version: string | null;
  created_at: string;
}

export interface TutorTurn {
  role: "student" | "tutor";
  task_id: string | null;
  content: string;
  reply: TutorReplyView | null;
  created_at: string;
}
