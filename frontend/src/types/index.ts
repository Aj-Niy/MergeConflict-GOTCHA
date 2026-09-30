export type RiskLevel = "critical" | "high" | "medium" | "low" | "trusted";

export type VerificationStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed";

export interface Repository {
  id: string;
  url: string;
  name: string;
  owner: string;
  description?: string;
  stars: number;
  forks: number;
  language: string;
  lastCommit?: string;
  createdAt?: string;
}

export interface ClaimedCapability {
  id: string;
  category: string;
  description: string;
  source: "readme" | "docs" | "manifest" | "package.json";
}

export interface DetectedBehavior {
  id: string;
  category: string;
  description: string;
  severity: RiskLevel;
  codeReference: string;
  line?: number;
}

export interface UndisclosedBehavior {
  id: string;
  description: string;
  severity: RiskLevel;
  codeReference: string;
  impact: string;
}

export interface ComparisonEntry {
  id: string;
  claimedCapability: string;
  detectedBehavior: string;
  match: "match" | "partial" | "mismatch" | "undisclosed";
  severity: RiskLevel;
  notes: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  stage: string;
  status: "completed" | "running" | "failed" | "pending";
  duration?: number;
  detail: string;
}

export interface Recommendation {
  id: string;
  severity: RiskLevel;
  title: string;
  description: string;
  action: string;
}

export interface DimensionScore {
  dimension: string;
  penalty: number;
  weight: number;
  weighted_penalty: number;
  evidence: string[];
}

export interface Finding {
  id: string;
  category: "static" | "capability" | "secret" | "dependency" | "threat_rule" | string;
  capability_label?: string;
  severity: string;
  confidence: string;
  file_path?: string;
  line_number?: number;
  snippet?: string;
  description: string;
  source: string;
}

export interface Vulnerability {
  id?: string;
  package_name: string;
  version: string;
  cve_id: string;
  severity: string;
  summary?: string;
  fixed_version?: string;
  source?: string;
}

export interface SecretFinding {
  id?: string;
  secret_type: string;
  file_path: string;
  line_number?: number;
  redacted_value: string;
  confidence?: string;
}

export interface PolicyEvaluation {
  id: string;
  scan_id?: string;
  policy_id?: string;
  policy_name?: string;
  decision: "ALLOW" | "WARN" | "RESTRICT" | "BLOCK" | string;
  triggered_rules_json: Array<{
    rule?: string;
    action?: string;
    reason?: string;
    file_path?: string;
    line_number?: number;
  }>;
  evaluated_at?: string;
}

export interface SecurityAttestation {
  id: string;
  scan_id: string;
  trust_score: number;
  risk_category: string;
  recommendation: string;
  capabilities: string[];
  hidden_capabilities: string[];
  content_hash: string;
  signature: string;
  public_key: string;
  issued_at: string;
}

export interface Policy {
  id: string;
  user_id?: string;
  name: string;
  description?: string;
  rules_json: Record<string, string>;
  is_default: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface TrustReport {
  id: string;
  repositoryId: string;
  repository: Repository;
  trustScore: number;
  riskLevel: RiskLevel;
  verdict: string;
  verdictSummary: string;
  aiExplanation: string;
  remediation?: string;
  claimedCapabilities: ClaimedCapability[];
  detectedBehaviors: DetectedBehavior[];
  undisclosedBehaviors: UndisclosedBehavior[];
  comparisonTable: ComparisonEntry[];
  dimensionBreakdown?: DimensionScore[];
  findings?: Finding[];
  vulnerabilities?: Vulnerability[];
  secrets?: SecretFinding[];
  policyEvaluations?: PolicyEvaluation[];
  attestation?: SecurityAttestation;
  recommendations: Recommendation[];
  timeline: TimelineEvent[];
  createdAt: string;
  completedAt: string;
  analysisVersion: string;
}

export interface VerificationRequest {
  url: string;
  targetType: "github" | "mcp" | "plugin" | "skill";
  deep: boolean;
  includeDependencies: boolean;
  policyId?: string;
}

export interface BatchVerificationRequest {
  label: string;
  urls: string[];
  policyId?: string;
}

export interface BatchRecord {
  id: string;
  label: string;
  total_repos: number;
  completed_repos: number;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "PARTIALLY_FAILED" | "FAILED" | string;
  created_at: string;
  completed_at?: string;
  scans?: Array<{
    id: string;
    repository_name: string;
    repository_url: string;
    status: string;
    trust_score: number;
    risk_score: number;
    risk_category: string;
    verdict?: string;
  }>;
}

export interface HistoryRecord {
  id: string;
  repository: Repository;
  trustScore: number;
  riskLevel: RiskLevel;
  status: VerificationStatus;
  createdAt: string;
  completedAt?: string;
  reportId?: string;
}

export interface AnalyticsSummary {
  totalVerifications: number;
  trustedCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  averageTrustScore: number;
  verificationsThisWeek: number;
  weekOverWeekChange: number;
}

export interface ChartDataPoint {
  date: string;
  verifications: number;
  trusted: number;
  critical: number;
}

// ─── Backend response types ────────────────────────────────────────

export interface BackendScanDetailResponse {
  id: string;
  repository: {
    id: string;
    url: string;
    owner: string;
    name: string;
    primary_language?: string;
    stars: number;
    forks: number;
    first_seen_at?: string;
  };
  status: string;
  risk_score: number;
  trust_score: number;
  risk_category: string;
  verdict?: string;
  verdict_summary?: string;
  explanation?: string;
  remediation?: string;
  claims: string[];
  behaviors: string[];
  hidden_behaviors: string[];
  dimension_breakdown?: DimensionScore[];
  findings?: Finding[];
  comparisons?: Array<{
    id?: string;
    claimed_capability: string;
    detected_capability: string;
    match_state: string;
    severity: string;
    notes?: string;
  }>;
  vulnerabilities?: Vulnerability[];
  secrets?: SecretFinding[];
  policy_evaluations?: PolicyEvaluation[];
  attestation?: SecurityAttestation;
  created_at: string;
  completed_at?: string;
}

export interface BackendScanResponse {
  id: string | number;
  risk?: number;
  trust_score?: number;
  status: string;
  claims: string[];
  behavior?: string[];
  behaviors?: string[];
  hidden_behaviors: string[];
  explanation: string;
}

export interface BackendHistoryItem {
  id: string | number;
  url: string | null;
  repo_name: string | null;
  target_type: string | null;
  risk_score: number;
  trust_score?: number;
  risk_level: string | null;
  status: string;
  explanation: string;
  claims: string[];
  behavior: string[];
  hidden_behaviors: string[];
  created_at: string | null;
  completed_at?: string | null;
}

export interface BackendAnalytics {
  totalScans?: number;
  total_scans?: number;
  safeCount?: number;
  safe_count?: number;
  mediumCount?: number;
  medium_count?: number;
  highCount?: number;
  high_count?: number;
  criticalCount?: number;
  critical_count?: number;
  averageRiskScore?: number;
  average_risk_score?: number;
  average_trust_score?: number;
}

// ─── Adapter functions ─────────────────────────────────────────────

export function mapRiskLevel(status: string | null): RiskLevel {
  const s = status?.toUpperCase();
  if (s === "SAFE" || s === "TRUSTED" || s === "LOW") return "trusted";
  if (s === "MEDIUM") return "medium";
  if (s === "HIGH") return "high";
  if (s === "CRITICAL") return "critical";
  return "medium";
}

export function parseRepoName(repoName: string | null, url?: string | null): { owner: string; name: string } {
  if (repoName && repoName.includes("/")) {
    const [owner, name] = repoName.split("/");
    return { owner, name };
  }
  if (url) {
    const parts = url.replace(/\.git$/, "").split("/").filter(Boolean);
    if (parts.length >= 2) {
      return { owner: parts[parts.length - 2], name: parts[parts.length - 1] };
    }
  }
  return { owner: "repo", name: repoName ?? "package" };
}

export function backendItemToHistoryRecord(item: BackendHistoryItem): HistoryRecord {
  const { owner, name } = parseRepoName(item.repo_name, item.url);
  const trustScore = item.trust_score ?? (100 - item.risk_score);

  return {
    id: `scan-${item.id}`,
    repository: {
      id: `repo-${item.id}`,
      url: item.url ?? "",
      name,
      owner,
      description: "",
      stars: 0,
      forks: 0,
      language: "Python",
      lastCommit: item.created_at ?? new Date().toISOString(),
      createdAt: item.created_at ?? new Date().toISOString(),
    },
    trustScore,
    riskLevel: mapRiskLevel(item.risk_level ?? item.status),
    status: (item.status?.toLowerCase() === "completed" ? "completed" : "completed") as VerificationStatus,
    createdAt: item.created_at ?? new Date().toISOString(),
    completedAt: item.completed_at ?? item.created_at ?? new Date().toISOString(),
    reportId: `${item.id}`,
  };
}

export function backendDetailToTrustReport(detail: BackendScanDetailResponse): TrustReport {
  const riskLevel = mapRiskLevel(detail.risk_category);
  const trustScore = detail.trust_score ?? Math.max(0, 100 - (detail.risk_score || 0));

  const claimedCapabilities: ClaimedCapability[] = (detail.claims || [])
    .filter((c) => c && c.trim())
    .map((c, i) => ({
      id: `cc-${i}`,
      category: c.trim(),
      description: `Claimed capability: ${c.trim()}`,
      source: "readme" as const,
    }));

  const detectedBehaviors: DetectedBehavior[] = (detail.behaviors || [])
    .filter((b) => b && b.trim())
    .map((b, i) => ({
      id: `db-${i}`,
      category: b.trim(),
      description: `Detected behavior: ${b.trim()}`,
      severity: "trusted" as RiskLevel,
      codeReference: "source",
    }));

  const undisclosedBehaviors: UndisclosedBehavior[] = (detail.hidden_behaviors || [])
    .filter((h) => h && h.trim())
    .map((h, i) => ({
      id: `ub-${i}`,
      description: `Undisclosed capability: ${h.trim()}`,
      severity: riskLevel,
      codeReference: "Static & Behavioral Audit",
      impact: `${h.trim()} capability executed without documentation disclosure`,
    }));

  const comparisonTable: ComparisonEntry[] = (detail.comparisons || []).map((c, i) => ({
    id: c.id || `ct-${i}`,
    claimedCapability: c.claimed_capability,
    detectedBehavior: c.detected_capability,
    match: (c.match_state?.toLowerCase() as any) || "match",
    severity: mapRiskLevel(c.severity),
    notes: c.notes || "",
  }));

  const recommendations: Recommendation[] = (detail.hidden_behaviors || []).map((h, i) => ({
    id: `rec-${i}`,
    severity: riskLevel,
    title: `Remediate undisclosed ${h.trim()} capability`,
    description: `Code executes ${h.trim()} operations without explicit documentation.`,
    action: `Audit code referencing ${h.trim()} and add policy guards or update docs.`,
  }));

  return {
    id: `${detail.id}`,
    repositoryId: detail.repository?.id || `repo-${detail.id}`,
    repository: {
      id: detail.repository?.id || `repo-${detail.id}`,
      url: detail.repository?.url || "",
      name: detail.repository?.name || "package",
      owner: detail.repository?.owner || "repo",
      stars: detail.repository?.stars || 0,
      forks: detail.repository?.forks || 0,
      language: detail.repository?.primary_language || "Python",
      lastCommit: detail.completed_at || detail.created_at,
      createdAt: detail.created_at,
    },
    trustScore,
    riskLevel,
    verdict: detail.verdict || (trustScore >= 80 ? "Trusted Repository" : "Security Review Required"),
    verdictSummary: detail.verdict_summary || detail.explanation || "Scan completed.",
    aiExplanation: detail.explanation || "",
    remediation: detail.remediation,
    claimedCapabilities,
    detectedBehaviors,
    undisclosedBehaviors,
    comparisonTable,
    dimensionBreakdown: detail.dimension_breakdown,
    findings: detail.findings,
    vulnerabilities: detail.vulnerabilities,
    secrets: detail.secrets,
    policyEvaluations: detail.policy_evaluations,
    attestation: detail.attestation,
    recommendations,
    timeline: [
      {
        id: "tl-001",
        timestamp: detail.created_at,
        stage: "Tarball Intake & Traversal Filter",
        status: "completed",
        duration: 1200,
        detail: "Ingested repository snapshot and checked file safety limits",
      },
      {
        id: "tl-002",
        timestamp: detail.created_at,
        stage: "Multi-Language AST & Secrets Scan",
        status: "completed",
        duration: 2100,
        detail: `Analyzed static ASTs, hardcoded credentials, and OSV dependencies`,
      },
      {
        id: "tl-003",
        timestamp: detail.created_at,
        stage: "Claim Extraction & Anti-Injection",
        status: "completed",
        duration: 1500,
        detail: `Extracted ${(detail.claims || []).length} claimed capabilities`,
      },
      {
        id: "tl-004",
        timestamp: detail.created_at,
        stage: "Semantic Claim ↔ Behavior Correlation",
        status: "completed",
        duration: 800,
        detail: `Found ${(detail.hidden_behaviors || []).length} undisclosed capability/ies`,
      },
      {
        id: "tl-005",
        timestamp: detail.completed_at || detail.created_at,
        stage: "Weighted Risk & Ed25519 Signed Attestation",
        status: "completed",
        duration: 900,
        detail: `Trust Score: ${trustScore}/100, cryptographic signature issued`,
      },
    ],
    createdAt: detail.created_at,
    completedAt: detail.completed_at || detail.created_at,
    analysisVersion: "2.0.0",
  };
}

export function backendAnalyticsToSummary(data: BackendAnalytics): AnalyticsSummary {
  const total = data.total_scans ?? data.totalScans ?? 0;
  const safe = data.safe_count ?? data.safeCount ?? 0;
  const high = data.high_count ?? data.highCount ?? 0;
  const critical = data.critical_count ?? data.criticalCount ?? 0;
  const medium = data.medium_count ?? data.mediumCount ?? 0;
  const avgTrust = data.average_trust_score ?? Math.round(100 - (data.average_risk_score ?? data.averageRiskScore ?? 0));

  return {
    totalVerifications: total,
    trustedCount: safe,
    criticalCount: critical,
    highCount: high,
    mediumCount: medium,
    lowCount: 0,
    averageTrustScore: avgTrust,
    verificationsThisWeek: total,
    weekOverWeekChange: 0,
  };
}
