import { useEffect, useState } from "react";
import { api } from "../api";
import type { Integration, IntegrationTestResult, PluginManifest } from "../api";
import { Topbar, timeAgo } from "../components/ui.tsx";

export default function Integrations() {
  const [manifests, setManifests] = useState<PluginManifest[]>([]);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, IntegrationTestResult>>({});

  const load = () =>
    Promise.all([api.listManifests(), api.listIntegrations()]).then(([m, i]) => {
      setManifests(m);
      setIntegrations(i);
    });
  useEffect(() => {
    load();
  }, []);

  async function test(name: string) {
    setTesting((t) => ({ ...t, [name]: true }));
    try {
      const res = await api.testIntegration(name);
      setResults((r) => ({ ...r, [name]: res }));
    } catch (e) {
      setResults((r) => ({ ...r, [name]: { ok: false, error: (e as Error).message, tested_at: "" } }));
    } finally {
      setTesting((t) => ({ ...t, [name]: false }));
      await load(); // refresh the persisted badge
    }
  }

  async function remove(name: string, label: string) {
    if (!window.confirm(`Remove the ${label} integration? Its saved config will be deleted.`)) return;
    await api.deleteIntegration(name);
    setResults((r) => {
      const next = { ...r };
      delete next[name];
      return next;
    });
    await load();
  }

  const deploy = manifests.filter((m) => m.kind === "deploy");
  const alert = manifests.filter((m) => m.kind === "alert");
  const stateOf = (name: string) => integrations.find((i) => i.plugin === name);
  const COMING_SOON = new Set(["mdm", "ssh", "splunk"]);

  function StatusBadge({ st }: { st?: Integration }) {
    if (!st?.configured) {
      return (
        <span className="badge pending">
          <span className="dot" /> not configured
        </span>
      );
    }
    const when = st.last_test_at ? ` · ${timeAgo(st.last_test_at)}` : "";
    if (st.last_test_status === "ok") {
      return (
        <span className="badge deployed">
          <span className="dot" /> connected{when}
        </span>
      );
    }
    if (st.last_test_status === "failed") {
      return (
        <span className="badge failed" title={st.last_test_error ?? undefined}>
          <span className="dot" /> connection failed{when}
        </span>
      );
    }
    return (
      <span className="badge pending">
        <span className="dot" /> configured · not tested
      </span>
    );
  }

  function Section({ title, sub, plugins }: { title: string; sub: string; plugins: PluginManifest[] }) {
    return (
      <div className="card">
        <div className="card-head">
          <h2>{title}</h2>
          <span className="muted">{sub}</span>
        </div>
        {plugins.map((m) => {
          const st = stateOf(m.name);
          const soon = COMING_SOON.has(m.name);
          return (
            <div className={`integration-row ${soon ? "disabled" : ""}`} key={m.name} title={soon ? "Coming soon" : ""}>
              <div>
                <div className="row" style={{ gap: 8 }}>
                  <strong>{m.display_name}</strong>
                  {soon ? <span className="soon">soon</span> : <StatusBadge st={st} />}
                </div>
                <div className="muted" style={{ marginTop: 4 }}>
                  {m.description}
                </div>
                {st?.configured && (
                  <div className="path" style={{ marginTop: 6 }}>
                    {Object.entries(st.config).map(([k, v]) => `${k}=${v}`).join("  ")}
                  </div>
                )}
                {results[m.name] && (
                  <div
                    className={results[m.name].ok ? "muted" : "danger-text"}
                    style={{ marginTop: 6 }}
                  >
                    {results[m.name].ok ? "✓ Connected" : `✗ ${results[m.name].error}`}
                  </div>
                )}
              </div>
              <div className="row" style={{ gap: 8 }}>
                {st?.configured && m.kind === "alert" && (
                  <button
                    className="btn"
                    disabled={testing[m.name]}
                    onClick={() => test(m.name)}
                  >
                    {testing[m.name] ? "Testing…" : "Test"}
                  </button>
                )}
                <button className="btn" onClick={() => setEditing(m.name)}>
                  {st?.configured ? "Edit" : "Configure"}
                </button>
                {st?.configured && (
                  <button className="btn danger" onClick={() => remove(m.name, m.display_name)}>
                    Remove
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  const editingManifest = manifests.find((m) => m.name === editing);

  return (
    <>
      <Topbar title="Integrations" />
      <div className="content">
        <p className="muted" style={{ marginTop: 0 }}>
          Plugins are auto-loaded from <span className="path">/plugins/deploy</span> and{" "}
          <span className="path">/plugins/alert</span>. Each renders its own config form from its
          manifest - drop in a module to add Ansible, Splunk, PagerDuty, and more. See{" "}
          <span className="path">docs/plugins.md</span>.
        </p>
        <Section
          title="Deployment integrations"
          sub="distribute the agent install to endpoints"
          plugins={deploy}
        />
        <Section title="Alert integrations" sub="SIEM · EDR · webhook" plugins={alert} />
      </div>

      {editingManifest && (
        <ConfigModal
          manifest={editingManifest}
          current={stateOf(editingManifest.name)}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await load();
          }}
        />
      )}
    </>
  );
}

// A representative alert event - mirrors the payload the server fans out to alert
// plugins (see services/alerting deliver_alert). Shown so users can build a
// receiver against the real shape.
const SAMPLE_ALERT = {
  alert_id: "al_3f9c1e0a",
  tripwire_id: "tw_aws_prod",
  tripwire_name: "aws-creds",
  endpoint_id: "ep_a1b2c3d4",
  endpoint_hostname: "alice-mbp",
  token_type: "aws",
  accessed_path: "~/.aws/credentials",
  process: "cat",
  pid: 4242,
  os_user: "alice",
  event_type: "openat",
  timestamp: "2026-06-09T12:33:30Z",
  triggered_by: "cat (pid 4242)",
};

function ConfigModal({
  manifest,
  current,
  onClose,
  onSaved,
}: {
  manifest: PluginManifest;
  current?: Integration;
  onClose: () => void;
  onSaved: () => void;
}) {
  // Pre-fill non-secret fields from the saved config so editing shows the current
  // values. Secrets stay blank (they're masked server-side) and - per the API's
  // merge_config - a blank field is left untouched on save, so re-saving without
  // re-typing a secret keeps it.
  const [values, setValues] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    for (const f of manifest.config_schema) {
      const v = current?.config?.[f.key];
      if (f.type !== "secret" && v != null) init[f.key] = String(v);
    }
    return init;
  });
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});

  const isSet = (f: PluginManifest["config_schema"][number]) =>
    Boolean(values[f.key]?.trim()) || Boolean(current?.config?.[f.key]);
  const missingRequired = manifest.config_schema.some((f) => f.required && !isSet(f));

  function generateSecret(key: string) {
    // 256 bits of CSPRNG, base64url - a strong HMAC signing secret.
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const secret = btoa(String.fromCharCode(...bytes))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    setValues((v) => ({ ...v, [key]: secret }));
    setRevealed((r) => ({ ...r, [key]: true })); // show what was just generated
  }

  async function copyKey(key: string) {
    const value = values[key];
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      setTimeout(() => setCopied((c) => (c === key ? null : c)), 1500);
    } catch {
      /* clipboard blocked (non-secure context) - leave the value visible to copy by hand */
      setRevealed((r) => ({ ...r, [key]: true }));
    }
  }

  async function save() {
    setSaving(true);
    await api.saveIntegration(manifest.name, values);
    onSaved();
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="card modal-card"
        style={{ width: 480 }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-head">
          <h2>Configure {manifest.display_name}</h2>
          <span className="type-tag">{manifest.kind}</span>
        </div>
        <p className="modal-intro">{manifest.description}</p>
        {manifest.config_schema.map((f) => {
          const secretKept = f.type === "secret" && Boolean(current?.config?.[f.key]);
          return (
            <div className="field" key={f.key}>
              <label>
                <span>{f.label}</span>
                <span className={`field-tag ${f.required ? "required" : "optional"}`}>
                  {f.required ? "Required" : "Optional"}
                </span>
              </label>
              <input
                type={f.type === "secret" && !revealed[f.key] ? "password" : "text"}
                placeholder={secretKept ? "•••••• - leave blank to keep current" : f.placeholder}
                value={values[f.key] ?? ""}
                onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
              />
              {f.generate && (
                <div className="row field-actions">
                  <button type="button" className="btn small" onClick={() => generateSecret(f.key)}>
                    Generate
                  </button>
                  <button
                    type="button"
                    className="btn small"
                    disabled={!values[f.key]}
                    onClick={() => copyKey(f.key)}
                  >
                    {copied === f.key ? "Copied ✓" : "Copy"}
                  </button>
                  {f.type === "secret" && values[f.key] && (
                    <button
                      type="button"
                      className="btn small"
                      onClick={() => setRevealed((r) => ({ ...r, [f.key]: !r[f.key] }))}
                    >
                      {revealed[f.key] ? "Hide" : "Show"}
                    </button>
                  )}
                </div>
              )}
              {f.help && <div className="help">{f.help}</div>}
            </div>
          );
        })}
        {manifest.kind === "alert" && (
          <div className="field">
            <label>
              <span>Example alert</span>
              <span className="field-tag optional">JSON</span>
            </label>
            <pre className="code-block">{JSON.stringify(SAMPLE_ALERT, null, 2)}</pre>
            <div className="help">
              The event every alert integration receives when a tripwire fires - the
              webhook delivers exactly this as the POST body (HMAC-signed when a
              signing secret is set).
            </div>
          </div>
        )}
        <div className="row" style={{ marginTop: 6 }}>
          <button className="btn primary" disabled={saving || missingRequired} onClick={save}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
