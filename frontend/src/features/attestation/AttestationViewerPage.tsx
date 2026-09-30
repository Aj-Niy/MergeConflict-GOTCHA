import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  ShieldCheck,
  Search,
  CheckCircle2,
  XCircle,
  Key,
  Hash,
  FileCheck2,
} from "lucide-react";
import { Header } from "../../components/layout/Header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { attestationApi } from "../../services/api";

export default function AttestationViewerPage() {
  const [queryId, setQueryId] = useState("");
  const [result, setResult] = useState<any>(null);

  const verifyMutation = useMutation({
    mutationFn: (id: string) => attestationApi.verifyById(id),
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (err: any) => {
      setResult({
        valid: false,
        message: err?.response?.data?.detail || "Attestation record not found or signature invalid.",
      });
    },
  });

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryId.trim()) return;
    verifyMutation.mutate(queryId.trim());
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-zinc-50/50">
      <Header title="Cryptographic Attestation Verifier" />

      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-4xl mx-auto space-y-6">
          <Card className="border-zinc-200 bg-white shadow-sm p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-lg">
                <FileCheck2 className="h-6 w-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-zinc-900">Verify Ed25519 Digital Attestation</h3>
                <p className="text-xs text-zinc-500">
                  Verify canonical hash integrity and cryptographic signatures issued by GOTCHA Trust Verification Engine.
                </p>
              </div>
            </div>

            <form onSubmit={handleVerify} className="flex gap-2">
              <Input
                placeholder="Enter Scan ID or Attestation ID (e.g. 1 or uuid-123)"
                value={queryId}
                onChange={(e) => setQueryId(e.target.value)}
                className="text-xs font-mono"
                required
              />
              <Button type="submit" size="sm" className="bg-indigo-600 hover:bg-indigo-700 text-white text-xs gap-1.5 shrink-0" disabled={verifyMutation.isPending}>
                <Search className="h-3.5 w-3.5" />
                {verifyMutation.isPending ? "Verifying..." : "Verify Attestation"}
              </Button>
            </form>
          </Card>

          {result && (
            <Card className="border-zinc-200 bg-white shadow-sm p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-zinc-100 pb-4">
                <div className="flex items-center gap-2.5">
                  {result.valid ? (
                    <CheckCircle2 className="h-6 w-6 text-emerald-500" />
                  ) : (
                    <XCircle className="h-6 w-6 text-rose-500" />
                  )}
                  <div>
                    <h4 className="text-sm font-bold text-zinc-900">
                      {result.valid ? "Cryptographic Signature Verified" : "Verification Failed"}
                    </h4>
                    <p className="text-xs text-zinc-500">{result.message}</p>
                  </div>
                </div>
              </div>

              {result.content_hash && (
                <div className="space-y-3 pt-2">
                  <div className="p-3 bg-zinc-50 rounded border border-zinc-200 space-y-1">
                    <span className="text-[11px] font-semibold text-zinc-500 uppercase flex items-center gap-1">
                      <Hash className="h-3.5 w-3.5" /> Canonical SHA-256 Hash
                    </span>
                    <p className="font-mono text-xs text-zinc-900 break-all select-all">
                      {result.content_hash}
                    </p>
                  </div>

                  <div className="p-3 bg-zinc-50 rounded border border-zinc-200 space-y-1">
                    <span className="text-[11px] font-semibold text-zinc-500 uppercase flex items-center gap-1">
                      <Key className="h-3.5 w-3.5" /> Recomputed Integrity Hash
                    </span>
                    <p className="font-mono text-xs text-zinc-900 break-all select-all">
                      {result.recomputed_hash}
                    </p>
                  </div>
                </div>
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
