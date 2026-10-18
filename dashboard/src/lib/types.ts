export type Verdict = "malicious" | "suspicious" | "likely_safe";
export type CaseStatus = "open" | "in_review" | "resolved" | "auto_closed";
export type Resolution = "confirmed_phish" | "false_positive" | "";

export interface CaseSummary {
  id: string;
  ref: string;
  created_at: string;
  subject: string;
  sender: string;
  sender_domain: string;
  verdict: Verdict;
  score: number;
  status: CaseStatus;
  resolution: Resolution | null;
  assignee: string | null;
  report_count: number;
  top_finding: string | null;
  finding_count: number;
  attack: string[];
  has_attachments: boolean;
  link_count: number;
}

export interface Finding {
  rule_id: string;
  title: string;
  group: string;
  confidence: number;
  evidence: string[];
  attack: string[];
  lesson: string;
}

export interface UrlTrace {
  hops: { url: string; status: number | null; note: string }[];
  final_url: string;
  final_host: string;
  title: string;
  password_form: boolean;
}

export interface UrlInfo {
  url: string;
  defanged: string;
  host: string;
  domain: string;
  text: string;
  source: string;
  flags: string[];
  wrapped: boolean;
  age_days: number | null;
  intel: { source: string; kind: string; detail: string; reference?: string }[];
  trace?: UrlTrace;
}

export interface AttachmentInfo {
  filename: string;
  size: number;
  sha256: string;
  md5: string;
  declared_type: string;
  sniffed: string;
  extension: string;
  flags: string[];
  intel: { source: string; detail: string }[];
}

export interface Contribution {
  feature: string;
  label: string;
  value: number;
  contribution: number;
}

export interface Analysis {
  message: {
    subject: string;
    from: { display: string; address: string; domain: string };
    reply_to: { display: string; address: string; domain: string } | null;
    to_count: number;
    date: string;
    message_id: string;
    sha256: string;
    size: number;
    received_hops: number;
    inline_forward: boolean;
    excerpt: string;
  };
  auth: {
    present: boolean;
    authserv: string;
    spf: string;
    dkim: string;
    dmarc: string;
    dmarc_policy: string;
    spf_aligned: boolean | null;
    dkim_aligned: boolean | null;
  };
  urls: UrlInfo[];
  attachments: AttachmentInfo[];
  findings: Finding[];
  rules: { score: number; groups: Record<string, number> };
  model: { score: number; baseline: number; contributions: Contribution[]; version: string } | null;
  verdict: {
    label: Verdict;
    score: number;
    rules_score: number;
    model_score: number | null;
    floor: number | null;
    thresholds: { suspicious: number; malicious: number };
  };
  attack: { id: string; name: string; rules: string[]; url: string }[];
  notes: string[];
  timings_ms: Record<string, number>;
  indicators: { kind: string; value: string; reason: string }[];
}

export interface CaseNote {
  source: "template" | "llm";
  verdict: Verdict;
  summary: string;
  claims: { text: string; evidence: string[] }[];
  actions: string[];
  evidence: { id: string; kind: string; text: string }[];
  rejected_draft: { violations: { kind: string; detail: string }[] } | null;
}

export interface CaseDetail extends CaseSummary {
  analysis: Analysis;
  note: CaseNote | null;
  analyst_minutes: number;
  resolved_at: string | null;
  reports: { id: string; reporter: string; received_at: string; verdict_at: string | null }[];
  indicators: { id: string; kind: string; value: string; reason: string; state: string }[];
}

export interface Overview {
  totals: Record<"reports" | "cases" | "malicious" | "suspicious" | "likely_safe" | "open" | "resolved" | "auto_closed", number>;
  auto_resolved_pct: number;
  time_to_verdict: { median_s: number; p95_s: number } | null;
  analyst_minutes: { manual_baseline: number; actual: number; saved: number };
  daily: { date: string; malicious: number; suspicious: number; likely_safe: number }[];
  top_rules: { rule_id: string; title: string; count: number }[];
  attack: { id: string; name: string; count: number }[];
}

export interface RuleInfo {
  id: string;
  title: string;
  group: string;
  confidence: number;
  lesson: string;
  attack: { id: string; name: string }[];
}

export interface Indicator {
  id: string;
  kind: string;
  value: string;
  reason: string;
  state: string;
  case: string;
  created_at: string;
}

export interface BlocklistItem {
  kind: string;
  value: string;
  reason: string;
  case: string;
  added: string;
}

export interface Rates {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  fpr: number;
  f1: number;
  ci95?: Record<string, [number, number]>;
}

export interface CostAssumptions {
  manual_minutes: number;
  triaged_review_minutes: number;
  malicious_review_minutes: number;
  miss_minutes: number;
  block_error_minutes: number;
  prevalence: number;
}

export interface EvalReport {
  schema: number;
  generated_at: string;
  corpus: {
    name: string;
    kind: "real" | "synthetic";
    sources: { name: string; label: string; count: number }[];
    messages_read: number;
    unparseable: number;
    duplicates_removed: number;
    label_conflicts_removed: number;
    splits: Record<"train" | "val" | "test", { phish: number; ham: number }>;
    split_by: string;
    seed: number;
    notes: string[];
    licenses?: Record<string, string>;
  };
  assumptions: CostAssumptions;
  operating_point: { alpha: number; suspicious: number; malicious: number };
  metrics: {
    flag: Rates;
    block: Rates;
    auc_roc: number;
    auc_pr: number;
    at_prevalence: { prevalence: number; precision: number; recall: number; fpr: number };
  };
  economics: {
    per_1000: {
      baseline_minutes: number;
      triage_minutes: number;
      minutes_saved: number;
      net_minutes_saved: number;
      missed_phish: number;
      false_blocks: number;
      total_cost_minutes: number;
    };
  };
  ablation: { name: string; auc: number; precision: number; recall: number; fpr: number; net_saved_per_1000: number; missed_per_1000: number }[];
  per_rule: { rule_id: string; title: string; group: string; confidence: number; phish_hits: number; ham_hits: number; precision: number | null; coverage: number }[];
  per_source: { source: string; n: number; flagged: number; blocked: number }[];
  model: { version: string; C: number; n_features: number; top_features: { feature: string; label: string; coef: number }[] };
  curves: { roc: [number, number][]; pr: [number, number][]; cost: { t: number; cost: number; net_saved: number; missed: number }[] };
  scores: { phish: number[]; ham: number[] };
  limitations: string[];
}

export interface DemoMeta {
  generated_at: string;
  kind: string;
  cases: number;
  reports: number;
  notes: string;
}
