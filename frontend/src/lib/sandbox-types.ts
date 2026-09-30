/** Shapes of the sandbox (lab) API. Nothing here carries the lab's secret or any runtime detail. */

export type ObjectiveView = {
  id: string;
  title: string;
  description: string;
  kind: "payload_replay" | "regression";
  input_label: string | null;
  input_hint: string | null;
  requires: string[];
  verified: boolean;
  attempts: number;
  last_detail: string | null;
};

export type ResourceView = {
  cpus: number;
  memory_mb: number;
  processes: number;
  scratch_mb: number;
  timeout_minutes: number;
};

export type LabView = {
  id: string;
  title: string;
  summary: string;
  cve_id: string | null;
  cwe_ids: string[];
  difficulty: string;
  instructions: string[];
  safety_notes: string[];
  objectives: ObjectiveView[];
  resources: ResourceView;
  network: string;
};

export type InstanceStatus = "starting" | "running" | "expired" | "stopping" | "stopped" | "failed";

export type InstanceView = {
  id: string;
  lab: LabView;
  status: InstanceStatus;
  session_id: string | null;
  created_at: string;
  started_at: string | null;
  expires_at: string;
  seconds_remaining: number;
  stop_reason: string | null;
  failure_message: string | null;
  reset_of: string | null;
  ports: { name: string; protocol: string }[];
  objectives: ObjectiveView[];
  can_use: boolean;
  app_path: string | null;
  safety_notice: string;
};

export type CurrentInstance = { instance: InstanceView | null };

export type OutcomeView = {
  check_id: string;
  status: "passed" | "failed" | "blocked" | "error";
  detail: string;
};

export type VerifyResponse = { outcome: OutcomeView; instance: InstanceView };

export type IsolationView = {
  passed: boolean;
  results: { target: string; blocked: boolean }[];
  checked_at: string;
};

export type TicketView = { ticket: string; expires_in: number; path: string; url: string | null };

export type LabProgressView = {
  lab: LabView;
  objectives: ObjectiveView[];
  verified: number;
  total: number;
  instance_id: string | null;
  last_instance_id: string | null;
};

export type SessionLabs = { session_id: string; labs: LabProgressView[] };
