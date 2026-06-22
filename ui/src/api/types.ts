// These types mirror the FastAPI backend's response models. Keep them in sync
// with server/thumper/models.py - this is the contract between UI and server.

export type TokenType = "aws" | "github" | "gcp" | "azure" | "ssh";

/** Where the bait content comes from. Only "template" is active in v1; the
 *  others are wired in the UI as coming-soon. */
export type CredentialSource = "template" | "custom" | "managed";

/** Per-endpoint instance lifecycle. */
export type DeploymentState = "pending" | "planted" | "failed";

export type EndpointStatus = "online" | "stale" | "inactive" | "decommissioning";

export interface TokenTypeInfo {
  type: TokenType;
  display_name: string;
  /** Top recommended path for this credential, per attacker TTPs. */
  default_path: string;
  /** Other realistic, attacker-inspected locations. Operators may also type any path. */
  suggested_paths: string[];
  description: string;
}

/** A tripwire DEFINITION (a canary recipe). It lives on no machine; deploying it
 *  mints one unique Deployment per endpoint. */
export interface Tripwire {
  id: string;
  name: string;
  token_type: TokenType;
  path: string;
  source: CredentialSource;
  token: string | null;
  created_at: string;
  active: boolean;
  /** Number of endpoints this tripwire is planted on. */
  deployed_count: number;
  /** Number of alerts across those endpoints. */
  triggered_count: number;
}

/** The per-(tripwire × endpoint) instance - unique content + secret server-side. */
export interface Deployment {
  id: string;
  tripwire_id: string;
  endpoint_id: string;
  endpoint_hostname: string;
  state: DeploymentState;
  created_at: string;
  last_triggered: string | null;
  triggered_count: number;
  endpoint_status: EndpointStatus;
}

/** What the operator distributes (via MDM/SSH/etc) to put this tripwire on
 *  machines. Each machine that runs it self-enrolls and gets its own instance. */
export interface InstallSpec {
  tripwire_id: string;
  server_url: string;
  enroll_token: string;
  command: string;
}

/** One install command for a chosen SET of tripwires (multi-select build flow). */
export interface InstallCommand {
  tripwire_ids: string[];
  command: string;
}

export interface TripwireDetail extends Tripwire {
  deployments: Deployment[];
  install: InstallSpec;
}

export interface Endpoint {
  id: string;
  hostname: string;
  platform: string | null;
  enrolled_at: string;
  last_seen: string | null;
  status: EndpointStatus;
  deployment_count: number;
  triggered_count: number;
}

export interface EndpointDetail extends Endpoint {
  deployments: Deployment[];
}

/** A fired tripwire - enriched by the endpoint monitor (fs_usage). */
export interface Alert {
  id: string;
  deployment_id: string;
  tripwire_id: string;
  tripwire_name: string;
  endpoint_id: string;
  endpoint_hostname: string; // the endpoint's hostname, for display
  token_type: TokenType;
  accessed_path: string | null;
  process: string | null;
  pid: number | null;
  os_user: string | null;
  event_type: string | null;
  timestamp: string;
  triggered_by: string | null;
  status: AlertStatus;
  resolved_at: string | null;
}

export type AlertStatus = "open" | "resolved";

export interface ConfigField {
  key: string;
  label: string;
  type: "string" | "secret" | "boolean";
  required: boolean;
  placeholder?: string;
  help?: string;
  generate?: boolean; // offer a "Generate" button (e.g. a signing secret you create yourself)
}

export type PluginKind = "deploy" | "alert";

export interface PluginManifest {
  name: string;
  kind: PluginKind;
  display_name: string;
  version: string;
  author: string;
  description: string;
  config_schema: ConfigField[];
}

export interface Integration {
  plugin: string;
  kind: PluginKind;
  configured: boolean;
  config: Record<string, string | boolean>;
  last_test_status?: "ok" | "failed" | null;
  last_test_at?: string | null;
  last_test_error?: string | null;
}

export interface IntegrationTestResult {
  ok: boolean;
  error: string | null;
  tested_at: string;
}

export interface AppSettings {
  database: { backend: string; location: string };
  thresholds: { stale_minutes: number; inactive_hours: number };
  dashboard: { refresh_seconds: number };
}

export interface DashboardStats {
  tripwires: number;
  endpoints: number;
  alerts_24h: number;
  active_triggers: number;
}
