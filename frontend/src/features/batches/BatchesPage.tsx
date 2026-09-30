import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  Layers,
  Plus,
  ExternalLink,
  CheckCircle2,
  Clock,
  AlertTriangle,
  FolderGit2,
  ShieldCheck,
  RefreshCw,
} from "lucide-react";
import { Header } from "../../components/layout/Header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Input } from "../../components/ui/input";
import { batchApi } from "../../services/api";
import { formatDateTime, riskLevelBg } from "../../lib/utils";
import type { BatchRecord } from "../../types";

export default function BatchesPage() {
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [label, setLabel] = useState("");
  const [urlsText, setUrlsText] = useState("");

  const { data: batches, isLoading } = useQuery({
    queryKey: ["batches"],
    queryFn: batchApi.getAll,
  });

  const createBatchMutation = useMutation({
    mutationFn: (data: { label: string; urls: string[] }) => batchApi.getAll().then(() => {
      return fetch("/api/scan/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }).then((res) => res.json());
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["batches"] });
      setShowModal(false);
      setLabel("");
      setUrlsText("");
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const urls = urlsText
      .split("\n")
      .map((u) => u.trim())
      .filter((u) => u.length > 0);
    if (!label.trim() || urls.length === 0) return;

    createBatchMutation.mutate({ label, urls });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-zinc-50/50">
      <Header
        title="Batch & Multi-Repo Scanning"
        actions={
          <Button
            size="sm"
            className="gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-xs text-white"
            onClick={() => setShowModal(true)}
          >
            <Plus className="h-3.5 w-3.5" />
            New Batch Scan
          </Button>
        }
      />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-5xl mx-auto space-y-6">
          {showModal && (
            <Card className="border-indigo-200 bg-white shadow-md p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-zinc-900">Start Multi-Repository Batch Verification</h3>
                  <p className="text-xs text-zinc-500">Scan multiple tools, skills, or repositories concurrently</p>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setShowModal(false)}>Cancel</Button>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="text-xs font-semibold text-zinc-700">Batch Name / Label</label>
                  <Input
                    placeholder="e.g. Q4 Security Audit / Agent Tools Suite"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    className="mt-1"
                    required
                  />
                </div>

                <div>
                  <label className="text-xs font-semibold text-zinc-700">Repository URLs (one per line)</label>
                  <textarea
                    className="w-full mt-1 p-3 text-xs font-mono bg-zinc-50 border border-zinc-200 rounded-lg focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    rows={5}
                    placeholder={`https://github.com/fastapi/fastapi\nhttps://github.com/tiangolo/sqlmodel`}
                    value={urlsText}
                    onChange={(e) => setUrlsText(e.target.value)}
                    required
                  />
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => setShowModal(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" size="sm" className="bg-indigo-600 hover:bg-indigo-700 text-white" disabled={createBatchMutation.isPending}>
                    {createBatchMutation.isPending ? "Queuing Batch..." : "Launch Batch Verification"}
                  </Button>
                </div>
              </form>
            </Card>
          )}

          <div className="space-y-4">
            <h2 className="text-sm font-bold text-zinc-900 uppercase tracking-wider">Active & Recent Batches</h2>
            <div className="grid grid-cols-1 gap-4">
              {batches && batches.length > 0 ? (
                batches.map((b) => (
                  <Card key={b.id} className="border-zinc-200 bg-white">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Layers className="h-4 w-4 text-indigo-600" />
                          <CardTitle className="text-base font-bold text-zinc-900">{b.label}</CardTitle>
                          <Badge variant="outline" className="text-[11px]">
                            {b.completed_repos} / {b.total_repos} Completed
                          </Badge>
                        </div>
                        <Badge className={`text-[10px] uppercase font-semibold ${
                          b.status === "COMPLETED" ? "bg-emerald-100 text-emerald-800" : "bg-indigo-100 text-indigo-800"
                        }`}>
                          {b.status}
                        </Badge>
                      </div>
                      <CardDescription className="text-xs text-zinc-500">
                        Created {formatDateTime(b.created_at)}
                      </CardDescription>
                    </CardHeader>
                    {b.scans && b.scans.length > 0 && (
                      <CardContent>
                        <div className="space-y-2 pt-1 border-t border-zinc-100">
                          {b.scans.map((s) => (
                            <div key={s.id} className="flex items-center justify-between p-2.5 bg-zinc-50 rounded border border-zinc-100">
                              <div className="flex items-center gap-2.5">
                                <FolderGit2 className="h-3.5 w-3.5 text-zinc-500" />
                                <span className="text-xs font-semibold text-zinc-800">{s.repository_name}</span>
                                <span className="text-[11px] text-zinc-400">Score: {s.trust_score}/100</span>
                              </div>
                              <Link to={`/reports/${s.id}`}>
                                <Button variant="ghost" size="sm" className="h-7 text-xs text-indigo-600 gap-1">
                                  View Report <ExternalLink className="h-3 w-3" />
                                </Button>
                              </Link>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    )}
                  </Card>
                ))
              ) : (
                <div className="text-center py-12 bg-white rounded-lg border border-dashed border-zinc-200">
                  <Layers className="h-8 w-8 text-zinc-300 mx-auto mb-2" />
                  <p className="text-sm font-semibold text-zinc-700">No batch runs yet</p>
                  <p className="text-xs text-zinc-400 mt-0.5">Submit multiple repositories to track org-wide security posture.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
