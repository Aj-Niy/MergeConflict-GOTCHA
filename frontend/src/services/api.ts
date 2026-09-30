import axios from "axios";
import type {
  TrustReport,
  HistoryRecord,
  AnalyticsSummary,
  ChartDataPoint,
  VerificationRequest,
  BatchVerificationRequest,
  BatchRecord,
  Policy,
  BackendScanDetailResponse,
  BackendHistoryItem,
  BackendAnalytics,
} from "../types";
import {
  backendItemToHistoryRecord,
  backendDetailToTrustReport,
  backendAnalyticsToSummary,
} from "../types";
import { MOCK_CHART_DATA } from "./mockData";

const BASE_URL = import.meta.env.VITE_API_URL ?? "/api";

export const apiClient = axios.create({
  baseURL: BASE_URL,
  headers: { "Content-Type": "application/json" },
  timeout: 120000,
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("gotcha_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const verificationApi = {
  async submit(req: VerificationRequest): Promise<BackendScanDetailResponse> {
    const { data } = await apiClient.post<BackendScanDetailResponse>("/scan", {
      url: req.url,
      target_type: req.targetType,
      deep: req.deep,
      include_dependencies: req.includeDependencies,
      policy_id: req.policyId,
    });
    return data;
  },

  async submitBatch(req: BatchVerificationRequest): Promise<BatchRecord> {
    const { data } = await apiClient.post<BatchRecord>("/scan/batch", {
      label: req.label,
      urls: req.urls,
      policy_id: req.policyId,
    });
    return data;
  },

  async getStatus(scanId: string): Promise<BackendScanDetailResponse> {
    const { data } = await apiClient.get<BackendScanDetailResponse>(`/scan/${scanId}`);
    return data;
  },
};

export const reportsApi = {
  async getAll(): Promise<TrustReport[]> {
    const { data } = await apiClient.get<BackendHistoryItem[]>("/scan/history");
    return data.map((item) => {
      return backendDetailToTrustReport({
        id: String(item.id),
        repository: {
          id: `repo-${item.id}`,
          url: item.url ?? "",
          owner: (item.repo_name ?? "repo/package").split("/")[0] ?? "repo",
          name: (item.repo_name ?? "repo/package").split("/")[1] ?? "package",
          stars: 0,
          forks: 0,
        },
        status: item.status,
        risk_score: item.risk_score,
        trust_score: item.trust_score ?? (100 - item.risk_score),
        risk_category: item.risk_level ?? item.status,
        explanation: item.explanation,
        claims: item.claims ?? [],
        behaviors: item.behavior ?? [],
        hidden_behaviors: item.hidden_behaviors ?? [],
        created_at: item.created_at ?? new Date().toISOString(),
        completed_at: item.completed_at ?? item.created_at ?? new Date().toISOString(),
      });
    });
  },

  async getById(id: string): Promise<TrustReport> {
    const { data } = await apiClient.get<BackendScanDetailResponse>(`/scan/${id}`);
    return backendDetailToTrustReport(data);
  },
};

export const historyApi = {
  async getAll(): Promise<HistoryRecord[]> {
    const { data } = await apiClient.get<BackendHistoryItem[]>("/scan/history");
    return data.map(backendItemToHistoryRecord);
  },
};

export const policiesApi = {
  async getAll(): Promise<Policy[]> {
    const { data } = await apiClient.get<Policy[]>("/policy");
    return data;
  },
  async create(policy: Partial<Policy>): Promise<Policy> {
    const { data } = await apiClient.post<Policy>("/policy", policy);
    return data;
  },
  async update(id: string, policy: Partial<Policy>): Promise<Policy> {
    const { data } = await apiClient.put<Policy>(`/policy/${id}`, policy);
    return data;
  },
  async delete(id: string): Promise<void> {
    await apiClient.delete(`/policy/${id}`);
  },
};

export const batchApi = {
  async getAll(): Promise<BatchRecord[]> {
    const { data } = await apiClient.get<BatchRecord[]>("/scan/batches");
    return data;
  },
  async getById(id: string): Promise<BatchRecord> {
    const { data } = await apiClient.get<BatchRecord>(`/scan/batch/${id}`);
    return data;
  },
};

export const attestationApi = {
  async verifyById(attestationOrScanId: string): Promise<{
    valid: boolean;
    scan_id: string;
    content_hash: string;
    recomputed_hash: string;
    match: boolean;
    signature_valid: boolean;
    message: string;
  }> {
    const { data } = await apiClient.get(`/attestation/${attestationOrScanId}/verify`);
    return data;
  },
};

export const analyticsApi = {
  async getSummary(): Promise<AnalyticsSummary> {
    const { data } = await apiClient.get<BackendAnalytics>("/scan/analytics");
    return backendAnalyticsToSummary(data);
  },

  async getChartData(): Promise<ChartDataPoint[]> {
    return MOCK_CHART_DATA;
  },
};
