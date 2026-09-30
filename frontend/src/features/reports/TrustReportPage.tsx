import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams, Link } from "@tanstack/react-router";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  Lock,
  Key,
  Package,
  Layers,
  Sparkles,
  ArrowLeft,
  ExternalLink,
  Code2,
  Terminal,
  FileText,
  Clock,
  EyeOff,
  Scale,
  RefreshCw,
  Check,
} from "lucide-react";
import { reportsApi, attestationApi } from "../../services/api";
import { Header } from "../../components/layout/Header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/card";
import { Badge } from "../../components/ui/badge";
import { Button } from "../../components/ui/button";
import { Skeleton } from "../../components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "../../components/ui/tabs";
import { TrustScoreRing } from "../../components/ui/trust-score-ring";
import { cn, formatDateTime, riskLevelBg, riskLevelDot, matchBadgeStyle } from "../../lib/utils";
import type { TimelineEvent, ComparisonEntry, DimensionScore, Finding, Vulnerability, SecretFinding } from "../../types";

function MatchIcon({ match }: { match: string }) {
  if (match === "match") return <CheckCircle2 className="h-4 w-4 text-emerald-500" />;
  if (match === "partial") return <AlertTriangle className="h-4 w-4 text-amber-500" />;
  if (match === "mismatch") return <XCircle className="h-4 w-4 text-red-500" />;
  return <EyeOff className="h-4 w-4 text-rose-500" />;
}

function PolicyBadge({ decision }: { decision: string }) {
  const d = decision?.toUpperCase();
  if (d === "ALLOW") return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">ALLOW</span>;
  if (d === "WARN") return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">WARN</span>;
  if (d === "RESTRICT") return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200">RESTRICT</span>;
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">BLOCK</span>;
}

export default function TrustReportPage() {
  const { reportId } = useParams({ from: "/app/reports/$reportId" });
  const [activeTab, setActiveTab] = useState("synthesis");
  const [verifyResult, setVerifyResult] = useState<any>(null);

  const { data: report, isLoading, error } = useQuery({
    queryKey: ["report", reportId],
    queryFn: () => reportsApi.getById(reportId),
  });

  const verifyMutation = useMutation({
    mutationFn: () => attestationApi.verifyById(reportId),
    onSuccess: (res) => {
      setVerifyResult(res);
    },
  });

  if (isLoading) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <Header title="Trust Verification Report" />
        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-5xl mx-auto space-y-4">
            <Skeleton className="h-48 w-full" />
            <Skeleton className="h-64 w-full" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex flex-col h-full">
        <Header title="Trust Verification Report" />
        <div className="flex-1 p-6 flex items-center justify-center">
          <Card className="max-w-md w-full text-center p-6">
            <AlertTriangle className="h-10 w-10 text-amber-500 mx-auto mb-3" />
            <h3 className="text-lg font-semibold text-zinc-900">Report Not Found</h3>
            <p className="text-sm text-zinc-500 mt-1 mb-4">Could not retrieve scan report for ID: {reportId}</p>
            <Link to="/reports">
              <Button variant="outline">Back to Reports</Button>
            </Link>
          </Card>
        </div>
      </div>
    );
  }

  const { repository, trustScore, riskLevel } = report;

  return (
    <div className="flex flex-col h-full overflow-hidden bg-zinc-50/50">
      <Header
        title="Trust Verification Report"
        actions={
          <Link to="/reports">
            <Button variant="outline" size="sm" className="gap-1.5 text-xs">
              <ArrowLeft className="h-3.5 w-3.5" />
              All Reports
            </Button>
          </Link>
        }
      />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        <div className="max-w-6xl mx-auto space-y-6">
          {/* Header Card */}
          <Card className="border-zinc-200 bg-white shadow-sm overflow-hidden">
            <div className="p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-zinc-100 rounded-xl">
                    <Code2 className="h-7 w-7 text-zinc-700" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2.5">
                      <h1 className="text-xl font-bold text-zinc-900">{repository.owner}/{repository.name}</h1>
                      <Badge className={cn("capitalize text-xs font-semibold px-2 py-0.5", riskLevelBg(riskLevel))}>
                        {report.riskLevel} risk
                      </Badge>
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-zinc-500 mt-1.5">
                      <span>Language: <strong className="text-zinc-700">{repository.language}</strong></span>
                      <span>•</span>
                      <span>Scan ID: <code className="font-mono text-zinc-600">{report.id}</code></span>
                      <span>•</span>
                      <span>Scanned: {formatDateTime(report.createdAt)}</span>
                    </div>
                    {repository.url && (
                      <a
                        href={repository.url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-indigo-600 hover:text-indigo-700 font-medium mt-2"
                      >
                        {repository.url}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-6 border-t md:border-t-0 md:border-l border-zinc-100 pt-4 md:pt-0 md:pl-6">
                  <TrustScoreRing score={trustScore} size={84} strokeWidth={7} />
                  <div>
                    <p className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Overall Verdict</p>
                    <p className="text-base font-bold text-zinc-900 mt-0.5">{report.verdict}</p>
                    <p className="text-xs text-zinc-500 max-w-xs mt-1 leading-relaxed">{report.verdictSummary}</p>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Main Navigation Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
            <TabsList className="bg-white border border-zinc-200 p-1 rounded-lg">
              <TabsTrigger value="synthesis" className="text-xs gap-1.5">
                <Scale className="h-3.5 w-3.5" />
                5D Risk Breakdown
              </TabsTrigger>
              <TabsTrigger value="correlation" className="text-xs gap-1.5">
                <Layers className="h-3.5 w-3.5" />
                Claim ↔ Behavior Matrix
              </TabsTrigger>
              <TabsTrigger value="findings" className="text-xs gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />
                Findings & CVEs ({((report.findings?.length || 0) + (report.secrets?.length || 0) + (report.vulnerabilities?.length || 0))})
              </TabsTrigger>
              <TabsTrigger value="policy" className="text-xs gap-1.5">
                <Lock className="h-3.5 w-3.5" />
                Policy Decision
              </TabsTrigger>
              <TabsTrigger value="ai-explanation" className="text-xs gap-1.5">
                <Sparkles className="h-3.5 w-3.5" />
                AI Intelligence & Fixes
              </TabsTrigger>
              <TabsTrigger value="attestation" className="text-xs gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5" />
                Signed Attestation
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: 5-Dimensional Risk Breakdown */}
            <TabsContent value="synthesis" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {report.dimensionBreakdown && report.dimensionBreakdown.length > 0 ? (
                  report.dimensionBreakdown.map((dim) => (
                    <Card key={dim.dimension} className="border-zinc-200 bg-white">
                      <CardHeader className="pb-2">
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-sm font-semibold text-zinc-900">{dim.dimension}</CardTitle>
                          <Badge variant="outline" className="text-[11px] font-mono">
                            Weight {(dim.weight * 100).toFixed(0)}%
                          </Badge>
                        </div>
                        <CardDescription className="text-xs text-zinc-500">
                          Penalty: <strong className="text-zinc-800">{dim.penalty.toFixed(1)}</strong> → Weighted: <strong className="text-rose-600">-{dim.weighted_penalty.toFixed(1)} pts</strong>
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-1.5 pt-1">
                          <p className="text-[11px] font-medium text-zinc-400 uppercase">Evidence Signals</p>
                          {dim.evidence && dim.evidence.length > 0 ? (
                            <ul className="space-y-1">
                              {dim.evidence.slice(0, 3).map((ev, i) => (
                                <li key={i} className="text-xs text-zinc-600 flex items-start gap-1.5 bg-zinc-50 p-1.5 rounded border border-zinc-100">
                                  <span className="text-rose-500 shrink-0">•</span>
                                  <span className="truncate">{ev}</span>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-xs text-emerald-600 flex items-center gap-1">
                              <CheckCircle2 className="h-3.5 w-3.5" /> Clean (No violation detected)
                            </p>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))
                ) : (
                  <div className="col-span-3 text-center py-8 text-zinc-400 text-sm">
                    Standard risk metrics computed. Check correlation matrix for detailed signals.
                  </div>
                )}
              </div>

              {/* Timeline Card */}
              <Card className="border-zinc-200 bg-white">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold text-zinc-900 flex items-center gap-2">
                    <Clock className="h-4 w-4 text-indigo-600" />
                    Verification Pipeline Execution
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
                    {report.timeline?.map((event) => (
                      <div key={event.id} className="p-3 bg-zinc-50 rounded-lg border border-zinc-100">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-semibold text-zinc-800">{event.stage}</span>
                          <span className="text-[10px] font-mono text-zinc-400">{(event.duration ? (event.duration / 1000).toFixed(1) + 's' : 'done')}</span>
                        </div>
                        <p className="text-[11px] text-zinc-500 leading-snug">{event.detail}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 2: Claim ↔ Behavior Correlation Matrix */}
            <TabsContent value="correlation" className="space-y-4">
              <Card className="border-zinc-200 bg-white">
                <CardHeader>
                  <CardTitle className="text-base font-semibold text-zinc-900">Semantic Claim vs Code Behavior Correlation</CardTitle>
                  <CardDescription className="text-xs text-zinc-500">
                    Compares declared capabilities from documentation against observed execution in the AST analyzer.
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse">
                      <thead>
                        <tr className="border-b border-zinc-100 bg-zinc-50/75 text-[11px] uppercase tracking-wider text-zinc-500 font-semibold">
                          <th className="py-3 px-4">Documentation Claim</th>
                          <th className="py-3 px-4">Detected Code Behavior</th>
                          <th className="py-3 px-4">Correlation State</th>
                          <th className="py-3 px-4">Security Analysis Notes</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-100 text-sm">
                        {report.comparisonTable && report.comparisonTable.length > 0 ? (
                          report.comparisonTable.map((entry) => (
                            <tr key={entry.id} className="hover:bg-zinc-50/50 transition-colors">
                              <td className="py-3 px-4 font-medium text-zinc-800">{entry.claimedCapability}</td>
                              <td className="py-3 px-4 text-zinc-700 font-mono text-xs">{entry.detectedBehavior}</td>
                              <td className="py-3 px-4">
                                <span className={cn("inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded capitalize", matchBadgeStyle(entry.match))}>
                                  <MatchIcon match={entry.match} />
                                  {entry.match}
                                </span>
                              </td>
                              <td className="py-3 px-4 text-xs text-zinc-600 max-w-md">{entry.notes}</td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan={4} className="py-6 text-center text-zinc-400 text-xs">No correlation records available.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 3: Findings & CVEs */}
            <TabsContent value="findings" className="space-y-4">
              {/* Hardcoded Secrets */}
              {report.secrets && report.secrets.length > 0 && (
                <Card className="border-rose-200 bg-rose-50/30">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-semibold text-rose-900 flex items-center gap-2">
                      <Key className="h-4 w-4 text-rose-600" />
                      Exposed Secrets & API Keys ({report.secrets.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {report.secrets.map((sec, i) => (
                      <div key={i} className="p-2.5 bg-white rounded border border-rose-200 flex items-center justify-between">
                        <div>
                          <p className="text-xs font-semibold text-zinc-900">{sec.secret_type}</p>
                          <p className="text-[11px] font-mono text-zinc-500">{sec.file_path}:{sec.line_number || 1}</p>
                        </div>
                        <code className="text-xs font-mono bg-rose-100/70 text-rose-800 px-2 py-1 rounded">
                          {sec.redacted_value}
                        </code>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Vulnerabilities */}
              {report.vulnerabilities && report.vulnerabilities.length > 0 && (
                <Card className="border-amber-200 bg-amber-50/30">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-semibold text-amber-900 flex items-center gap-2">
                      <Package className="h-4 w-4 text-amber-600" />
                      Vulnerable Third-Party Dependencies ({report.vulnerabilities.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {report.vulnerabilities.map((vuln, i) => (
                      <div key={i} className="p-3 bg-white rounded border border-amber-200 flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <strong className="text-xs text-zinc-900">{vuln.cve_id}</strong>
                            <span className="text-[11px] font-mono bg-zinc-100 text-zinc-700 px-1.5 py-0.5 rounded">
                              {vuln.package_name}@{vuln.version}
                            </span>
                          </div>
                          <p className="text-xs text-zinc-600 mt-1">{vuln.summary}</p>
                        </div>
                        <Badge className="bg-amber-100 text-amber-800 border-amber-200 text-[10px] uppercase">{vuln.severity}</Badge>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Static & Threat Findings */}
              <Card className="border-zinc-200 bg-white">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold text-zinc-900">Static AST & Threat Pattern Findings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {report.findings && report.findings.length > 0 ? (
                    report.findings.map((f, i) => (
                      <div key={i} className="p-3 bg-zinc-50 rounded-lg border border-zinc-100 flex items-start justify-between gap-4">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-zinc-900">{f.description}</span>
                            {f.capability_label && (
                              <Badge variant="outline" className="text-[10px] font-mono">{f.capability_label}</Badge>
                            )}
                          </div>
                          {f.file_path && (
                            <p className="text-[11px] font-mono text-zinc-500">
                              {f.file_path}{f.line_number ? `:${f.line_number}` : ''}
                            </p>
                          )}
                          {f.snippet && (
                            <pre className="text-[11px] font-mono bg-zinc-900 text-zinc-100 p-2 rounded overflow-x-auto max-w-2xl">
                              {f.snippet}
                            </pre>
                          )}
                        </div>
                        <Badge className={cn("text-[10px] uppercase font-semibold", riskLevelBg(f.severity as any))}>
                          {f.severity}
                        </Badge>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-zinc-400 py-4 text-center">No static anomalies detected.</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 4: Policy Decision */}
            <TabsContent value="policy" className="space-y-4">
              <Card className="border-zinc-200 bg-white">
                <CardHeader>
                  <CardTitle className="text-base font-semibold text-zinc-900">Zero-Trust Policy Enforcement</CardTitle>
                  <CardDescription className="text-xs text-zinc-500">
                    Deterministic policy gate evaluation (100% deterministic, no non-deterministic hallucinations).
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {report.policyEvaluations && report.policyEvaluations.length > 0 ? (
                    report.policyEvaluations.map((pe) => (
                      <div key={pe.id} className="p-4 bg-zinc-50 rounded-lg border border-zinc-200 space-y-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="text-sm font-bold text-zinc-900">{pe.policy_name || "Default Security Policy"}</h4>
                            <p className="text-xs text-zinc-500">Evaluated deterministically against repository findings</p>
                          </div>
                          <PolicyBadge decision={pe.decision} />
                        </div>

                        {pe.triggered_rules_json && pe.triggered_rules_json.length > 0 && (
                          <div className="space-y-1.5 pt-2 border-t border-zinc-200">
                            <p className="text-[11px] font-semibold text-zinc-700 uppercase">Triggered Rules</p>
                            {pe.triggered_rules_json.map((tr, idx) => (
                              <div key={idx} className="text-xs bg-white p-2 rounded border border-zinc-200 flex items-center justify-between">
                                <div>
                                  <span className="font-semibold text-zinc-800">{tr.rule || "Policy Violation"}: </span>
                                  <span className="text-zinc-600">{tr.reason}</span>
                                </div>
                                <span className="text-[10px] font-bold text-rose-700 uppercase">{tr.action}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  ) : (
                    <div className="p-4 bg-emerald-50 text-emerald-800 rounded-lg border border-emerald-200 text-xs">
                      Policy Decision: <strong>ALLOW</strong>. Repository adheres to all zero-trust criteria.
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 5: AI Explanation & Remediation */}
            <TabsContent value="ai-explanation" className="space-y-4">
              <Card className="border-indigo-100 bg-indigo-50/20">
                <CardHeader>
                  <CardTitle className="text-sm font-semibold text-indigo-900 flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-indigo-600" />
                    AI Intelligence Synthesis
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="p-4 bg-white rounded-lg border border-indigo-100 text-xs text-zinc-700 leading-relaxed whitespace-pre-line">
                    {report.aiExplanation || "Audit completed."}
                  </div>

                  {report.remediation && (
                    <div className="p-4 bg-white rounded-lg border border-emerald-200 space-y-2">
                      <h4 className="text-xs font-bold text-emerald-900 uppercase">Recommended Remediation Steps</h4>
                      <div className="text-xs text-zinc-700 whitespace-pre-line leading-relaxed">
                        {report.remediation}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 6: Ed25519 Signed Attestation */}
            <TabsContent value="attestation" className="space-y-4">
              <Card className="border-zinc-200 bg-white">
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-base font-semibold text-zinc-900 flex items-center gap-2">
                      <ShieldCheck className="h-5 w-5 text-indigo-600" />
                      Cryptographically Signed Attestation
                    </CardTitle>
                    <CardDescription className="text-xs text-zinc-500">
                      Ed25519 signature over SHA-256 canonical hash of verified repository claims and behaviors.
                    </CardDescription>
                  </div>
                  <Button
                    size="sm"
                    className="gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-xs"
                    onClick={() => verifyMutation.mutate()}
                    disabled={verifyMutation.isPending}
                  >
                    <RefreshCw className={cn("h-3.5 w-3.5", verifyMutation.isPending && "animate-spin")} />
                    Verify Signature
                  </Button>
                </CardHeader>
                <CardContent className="space-y-4">
                  {verifyResult && (
                    <div className={cn(
                      "p-3 rounded-lg border text-xs flex items-center gap-2",
                      verifyResult.valid ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-rose-50 border-rose-200 text-rose-800"
                    )}>
                      {verifyResult.valid ? <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" /> : <XCircle className="h-4 w-4 text-rose-600 shrink-0" />}
                      <span>{verifyResult.message}</span>
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-3 bg-zinc-50 rounded border border-zinc-200 space-y-1">
                      <span className="text-[11px] font-semibold text-zinc-500 uppercase">SHA-256 Content Hash</span>
                      <p className="font-mono text-xs text-zinc-900 break-all select-all">
                        {report.attestation?.content_hash || "Computing..."}
                      </p>
                    </div>
                    <div className="p-3 bg-zinc-50 rounded border border-zinc-200 space-y-1">
                      <span className="text-[11px] font-semibold text-zinc-500 uppercase">Ed25519 Public Key</span>
                      <p className="font-mono text-xs text-zinc-900 break-all select-all">
                        {report.attestation?.public_key || "Published Key"}
                      </p>
                    </div>
                  </div>

                  <div className="p-3 bg-zinc-50 rounded border border-zinc-200 space-y-1">
                    <span className="text-[11px] font-semibold text-zinc-500 uppercase">Ed25519 Cryptographic Signature</span>
                    <p className="font-mono text-xs text-zinc-800 break-all select-all bg-white p-2 rounded border border-zinc-200">
                      {report.attestation?.signature || "Awaiting signature generation"}
                    </p>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}
