import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ShieldCheck,
  Plus,
  Trash2,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Scale,
  Settings2,
} from "lucide-react";
import { Header } from "../../components/layout/Header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { Input } from "../../components/ui/input";
import { policiesApi } from "../../services/api";
import type { Policy } from "../../types";

const RULE_CAPABILITIES = [
  { key: "Shell", label: "Shell / System Command Execution" },
  { key: "Subprocess", label: "Subprocess Spawning" },
  { key: "CredentialExfiltrationRisk", label: "Secret + Outbound Network Co-occurrence" },
  { key: "SecretExposure", label: "Hardcoded Secrets & API Tokens" },
  { key: "NativeCodeExecution", label: "Native Code / ctypes Execution" },
  { key: "DynamicBackdoorRisk", label: "Dynamic Code Evaluation (eval/exec)" },
  { key: "Environment", label: "Environment Variable Inspection" },
  { key: "Network", label: "Outbound Network Requests" },
  { key: "Filesystem", label: "Filesystem Read / Write" },
  { key: "Database", label: "Database Driver Execution" },
];

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [rules, setRules] = useState<Record<string, string>>({
    Shell: "BLOCK",
    Subprocess: "WARN",
    CredentialExfiltrationRisk: "BLOCK",
    SecretExposure: "BLOCK",
    NativeCodeExecution: "RESTRICT",
    DynamicBackdoorRisk: "RESTRICT",
    Environment: "ALLOW",
    Network: "ALLOW",
    Filesystem: "ALLOW",
    Database: "ALLOW",
  });

  const { data: policies, isLoading } = useQuery({
    queryKey: ["policies"],
    queryFn: policiesApi.getAll,
  });

  const createMutation = useMutation({
    mutationFn: (newPolicy: Partial<Policy>) => policiesApi.create(newPolicy),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      setShowCreateModal(false);
      setName("");
      setDescription("");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => policiesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
    },
  });

  const handleRuleChange = (cap: string, action: string) => {
    setRules((prev) => ({ ...prev, [cap]: action }));
  };

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    createMutation.mutate({
      name,
      description,
      rules_json: rules,
      is_default: false,
    });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-zinc-50/50">
      <Header
        title="Security Policy Builder"
        actions={
          <Button
            size="sm"
            className="gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-xs text-white"
            onClick={() => setShowCreateModal(true)}
          >
            <Plus className="h-3.5 w-3.5" />
            Create Policy
          </Button>
        }
      />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-5xl mx-auto space-y-6">
          {showCreateModal && (
            <Card className="border-indigo-200 bg-white shadow-md p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-zinc-900">Define Custom Security Policy</h3>
                  <p className="text-xs text-zinc-500">Specify explicit action gates for every detected capability</p>
                </div>
                <Button variant="ghost" size="sm" onClick={() => setShowCreateModal(false)}>Cancel</Button>
              </div>

              <form onSubmit={handleCreate} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-semibold text-zinc-700">Policy Name</label>
                    <Input
                      placeholder="e.g. Strict Production Gate"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="mt-1"
                      required
                    />
                  </div>
                  <div>
                    <label className="text-xs font-semibold text-zinc-700">Description</label>
                    <Input
                      placeholder="e.g. Blocks any high risk signals before deployment"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      className="mt-1"
                    />
                  </div>
                </div>

                <div className="space-y-2 pt-2 border-t border-zinc-100">
                  <p className="text-xs font-semibold text-zinc-800 uppercase">Capability Enforcement Rules</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                    {RULE_CAPABILITIES.map((cap) => (
                      <div key={cap.key} className="flex items-center justify-between p-2.5 bg-zinc-50 rounded border border-zinc-200">
                        <span className="text-xs font-medium text-zinc-800">{cap.label}</span>
                        <select
                          className="text-xs font-semibold px-2 py-1 bg-white border border-zinc-300 rounded focus:outline-none focus:ring-1 focus:ring-indigo-500"
                          value={rules[cap.key] || "ALLOW"}
                          onChange={(e) => handleRuleChange(cap.key, e.target.value)}
                        >
                          <option value="ALLOW">ALLOW</option>
                          <option value="WARN">WARN</option>
                          <option value="RESTRICT">RESTRICT</option>
                          <option value="BLOCK">BLOCK</option>
                        </select>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => setShowCreateModal(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" size="sm" className="bg-indigo-600 hover:bg-indigo-700 text-white" disabled={createMutation.isPending}>
                    Save Security Policy
                  </Button>
                </div>
              </form>
            </Card>
          )}

          <div className="space-y-4">
            <h2 className="text-sm font-bold text-zinc-900 uppercase tracking-wider">Active Security Policies</h2>
            <div className="grid grid-cols-1 gap-4">
              {policies?.map((policy) => (
                <Card key={policy.id} className="border-zinc-200 bg-white">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Lock className="h-4 w-4 text-indigo-600" />
                        <CardTitle className="text-base font-bold text-zinc-900">{policy.name}</CardTitle>
                        {policy.is_default && (
                          <Badge className="bg-indigo-50 text-indigo-700 border-indigo-200 text-[10px]">
                            Default Zero-Trust Policy
                          </Badge>
                        )}
                      </div>
                      {!policy.is_default && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-rose-600 hover:text-rose-700 hover:bg-rose-50"
                          onClick={() => deleteMutation.mutate(policy.id)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </div>
                    {policy.description && (
                      <CardDescription className="text-xs text-zinc-500 mt-1">{policy.description}</CardDescription>
                    )}
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-2 pt-1">
                      {Object.entries(policy.rules_json || {}).map(([key, val]) => (
                        <div key={key} className="p-2 bg-zinc-50 rounded border border-zinc-100 flex flex-col justify-between">
                          <span className="text-[11px] font-medium text-zinc-600 truncate">{key}</span>
                          <span className={`text-[10px] font-bold uppercase mt-1 ${
                            val === "BLOCK" ? "text-rose-700" : val === "RESTRICT" ? "text-orange-700" : val === "WARN" ? "text-amber-700" : "text-emerald-700"
                          }`}>
                            {val}
                          </span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
