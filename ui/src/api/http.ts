// Real backend client. Method signatures are what the pages import (via
// src/api). The Vite dev proxy forwards /api → http://localhost:8000.
import type {
  Alert,
  AppSettings,
  CanaryAccessLog,
  CanarySecret,
  CanaryTemplate,
  CredentialSource,
  DashboardStats,
  Deployment,
  Endpoint,
  EndpointDetail,
  InstallCommand,
  Integration,
  IntegrationTestResult,
  PluginManifest,
  TokenType,
  TokenTypeInfo,
  Tripwire,
  TripwireDetail,
  VaultConnection,
  VaultConnectionTestResult,
  VersionInfo,
} from "./types";

import { clearAdminToken, getAdminToken } from "./auth";

const BASE = "/api";

// Carries the HTTP status so callers can distinguish a 404 (show a not-found
// state) from a transient 5xx/network failure (show an error). The message keeps
// the `${status}: ${detail}` shape existing call sites already surface.
export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const { headers: initHeaders, ...rest } = init ?? {};
  const token = getAdminToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...initHeaders,
    },
    ...rest,
  });
  // 401 = missing/expired admin token → drop it and re-prompt via AdminGate.
  if (res.status === 401) {
    clearAdminToken();
    window.location.reload();
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const httpApi = {
  getStats: () => req<DashboardStats>("/stats"),
  getSettings: () => req<AppSettings>("/settings"),
  getVersion: () => req<VersionInfo>("/version"),

  // Tripwire definitions
  listTripwires: () => req<Tripwire[]>("/tripwires"),
  getTripwire: (id: string) => req<TripwireDetail>(`/tripwires/${id}`),
  createTripwire: (input: {
    name: string;
    token_type: TokenType;
    path: string;
    source?: CredentialSource;
    custom_content?: string;
    token?: string;
  }) => req<Tripwire>("/tripwires", { method: "POST", body: JSON.stringify(input) }),
  renameTripwire: (id: string, name: string) =>
    req<Tripwire>(`/tripwires/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  deleteTripwire: (id: string) =>
    req<{ status: string }>(`/tripwires/${id}`, { method: "DELETE" }),
  distributeTripwire: (id: string) =>
    req<{ results: { plugin: string; state: string; deployed_count: number; message: string }[] }>(
      `/tripwires/${id}/distribute`, { method: "POST" }),
  // One install command for a set of tripwires (multi-select build flow).
  buildInstall: (ids: string[]) =>
    req<InstallCommand>(
      "/install?" + ids.map((id) => `tripwire=${encodeURIComponent(id)}`).join("&")),

  // Endpoints
  listEndpoints: () => req<Endpoint[]>("/endpoints"),
  getEndpoint: (id: string) => req<EndpointDetail>(`/endpoints/${id}`),
  // Assign / unassign a tripwire on an already-enrolled endpoint. The live
  // agent plants / unplants on its next re-pull.
  assignTripwire: (eid: string, tripwireId: string) =>
    req<Deployment>(`/endpoints/${eid}/tripwires`,
      { method: "POST", body: JSON.stringify({ tripwire_id: tripwireId }) }),
  unassignTripwire: (eid: string, tripwireId: string) =>
    req<{ status: string }>(`/endpoints/${eid}/tripwires/${tripwireId}`,
      { method: "DELETE" }),
  // Flag the endpoint to self-destruct (agent unplants + removes itself on its
  // next heartbeat); or force-remove a dead one outright.
  decommissionEndpoint: (eid: string) =>
    req<Endpoint>(`/endpoints/${eid}/decommission`, { method: "POST" }),
  removeEndpoint: (eid: string) =>
    req<{ status: string }>(`/endpoints/${eid}`, { method: "DELETE" }),

  // Alerts
  listAlerts: (status?: "open" | "resolved") =>
    req<Alert[]>(`/alerts${status ? `?status=${status}` : ""}`),
  resolveAlert: (id: string) => req<Alert>(`/alerts/${id}/resolve`, { method: "POST" }),
  resolveDeploymentAlerts: (deploymentId: string) =>
    req<{ resolved: number }>("/alerts/resolve", {
      method: "POST",
      body: JSON.stringify({ deployment_id: deploymentId }),
    }),
  resolveAllAlerts: () =>
    req<{ resolved: number }>("/alerts/resolve-all", { method: "POST" }),

  // Plugins / integrations
  listManifests: () => req<PluginManifest[]>("/manifests"),
  listIntegrations: () => req<Integration[]>("/integrations"),
  saveIntegration: (plugin: string, config: Record<string, string | boolean>) =>
    req<Integration>(`/integrations/${plugin}`, { method: "POST", body: JSON.stringify(config) }),
  testIntegration: (plugin: string) =>
    req<IntegrationTestResult>(`/integrations/${plugin}/test`, { method: "POST" }),
  deleteIntegration: (plugin: string) =>
    req<{ status: string }>(`/integrations/${plugin}`, { method: "DELETE" }),

  // Vault / secret-manager canaries
  listVaultConnections: () => req<VaultConnection[]>("/vault/connections"),
  createVaultConnection: (input: {
    name: string;
    plugin: string;
    config: Record<string, string | boolean>;
  }) => req<VaultConnection>("/vault/connections", { method: "POST", body: JSON.stringify(input) }),
  updateVaultConnection: (id: string, input: {
    name: string;
    config: Record<string, string | boolean>;
  }) => req<VaultConnection>(`/vault/connections/${id}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteVaultConnection: (id: string) =>
    req<{ status: string }>(`/vault/connections/${id}`, { method: "DELETE" }),
  testVaultConnection: (id: string) =>
    req<VaultConnectionTestResult>(`/vault/connections/${id}/test`, { method: "POST" }),

  listCanaryTemplates: () => req<CanaryTemplate[]>("/vault/templates"),
  listCanarySecrets: () => req<CanarySecret[]>("/vault/secrets"),
  createCanarySecret: (input: {
    vault_connection_id: string;
    template: string;
    path: string;
  }) => req<CanarySecret>("/vault/secrets", { method: "POST", body: JSON.stringify(input) }),
  deleteCanarySecret: (id: string) =>
    req<{ status: string }>(`/vault/secrets/${id}`, { method: "DELETE" }),
  listCanaryAccessLogs: (id: string) =>
    req<CanaryAccessLog[]>(`/vault/secrets/${id}/access-logs`),

  // Token catalog + preview (generation lives on the server)
  getTokenTypes: () => req<TokenTypeInfo[]>("/token-types"),
  previewToken: (token_type: TokenType, source: CredentialSource = "template", custom_content?: string) =>
    req<{ content: string }>("/tokens/preview", {
      method: "POST",
      body: JSON.stringify({ token_type, source, custom_content }),
    }),
};

export type Api = typeof httpApi;
