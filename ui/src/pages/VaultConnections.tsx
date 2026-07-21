import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import type {
  PluginManifest,
  VaultConnection,
  VaultConnectionTestResult,
} from "../api";
import { api } from "../api";
import { TimeAgo, Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";

const PAGE_TITLE = "Secret Managers";

// Shared tabs between the two vault pages. Kept identical in CanarySecrets.tsx.
export function VaultTabs() {
  const cls = ({ isActive }: { isActive: boolean }) => (isActive ? "active" : "");
  return (
    <nav className="nav-tabs">
      <NavLink to="/vault" end className={cls}>Connections</NavLink>
      <NavLink to="/vault/secrets" className={cls}>Canary Secrets</NavLink>
    </nav>
  );
}

export default function VaultConnections() {
  const [connections, setConnections] = useState<VaultConnection[]>([]);
  const [manifests, setManifests] = useState<PluginManifest[]>([]);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<VaultConnection | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, VaultConnectionTestResult>>({});

  const load = () =>
    Promise.all([api.listVaultConnections(), api.listManifests()]).then(([c, m]) => {
      setConnections(c);
      setManifests(m.filter((x) => x.kind === "vault"));
    });
  useEffect(() => {
    load();
  }, []);

  async function test(id: string) {
    setTesting((t) => ({ ...t, [id]: true }));
    try {
      const res = await api.testVaultConnection(id);
      setResults((r) => ({ ...r, [id]: res }));
    } catch (e) {
      setResults((r) => ({ ...r, [id]: { ok: false, error: (e as Error).message } }));
    } finally {
      setTesting((t) => ({ ...t, [id]: false }));
      await load(); // refresh the persisted "configured" badge
    }
  }

  async function remove(c: VaultConnection) {
    if (!window.confirm(
      `Remove "${c.name}"? Its canary secrets are deleted from Thumper (they are ` +
      `NOT removed from the secrets manager - delete those first if you want them gone).`
    )) return;
    await api.deleteVaultConnection(c.id);
    setResults((r) => {
      const next = { ...r };
      delete next[c.id];
      return next;
    });
    await load();
  }

  const manifestOf = (plugin: string) => manifests.find((m) => m.name === plugin);

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <Topbar
        title={PAGE_TITLE}
        action={
          <button className="btn primary" disabled={manifests.length === 0} onClick={() => setAdding(true)}>
            Add Secret Manager
          </button>
        }
      />
      <div className="content">
        <VaultTabs />
        <p className="muted" style={{ marginTop: 12 }}>
          Connect a secrets manager (HashiCorp Vault, AWS Secrets Manager) so Thumper
          can plant canary secrets in it and watch its audit log for reads. Plugins are
          auto-loaded from <span className="path">/plugins/vault</span>.
        </p>

        {connections.length === 0 ? (
          <div className="card">
            <div className="empty">
              No secret managers connected yet. Click <strong>Add Secret Manager</strong> to
              connect one.
            </div>
          </div>
        ) : (
          <div className="card">
            {connections.map((c) => {
              const m = manifestOf(c.plugin);
              const res = results[c.id];
              return (
                <div className="integration-row" key={c.id}>
                  <div>
                    <div className="row" style={{ gap: 8 }}>
                      <strong>{c.name}</strong>
                      {c.configured ? (
                        <span className="badge deployed"><span className="dot" /> configured</span>
                      ) : (
                        <span className="badge pending"><span className="dot" /> not tested</span>
                      )}
                      {c.last_poll_at && (
                        <span className="muted">· last poll <TimeAgo iso={c.last_poll_at} /></span>
                      )}
                    </div>
                    <div className="muted" style={{ marginTop: 4 }}>
                      {m?.display_name ?? c.plugin}
                    </div>
                    <div className="path" style={{ marginTop: 6 }}>
                      {Object.entries(c.config).map(([k, v]) => `${k}=${v}`).join("  ") || "—"}
                    </div>
                    {res && (
                      <div className={res.ok ? "muted" : "danger-text"} style={{ marginTop: 6 }}>
                        {res.ok ? "✓ Connected" : `✗ ${res.error}`}
                      </div>
                    )}
                  </div>
                  <div className="row" style={{ gap: 8 }}>
                    <button className="btn" disabled={testing[c.id]} onClick={() => test(c.id)}>
                      {testing[c.id] ? "Testing…" : "Test"}
                    </button>
                    <button className="btn" onClick={() => setEditing(c)}>Edit</button>
                    <button className="btn danger" onClick={() => remove(c)}>Remove</button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {adding && (
        <ConnectionModal
          manifests={manifests}
          onClose={() => setAdding(false)}
          onSaved={async () => {
            setAdding(false);
            await load();
          }}
        />
      )}
      {editing && (
        <ConnectionModal
          manifests={manifests}
          current={editing}
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

function ConnectionModal({
  manifests,
  current,
  onClose,
  onSaved,
}: {
  manifests: PluginManifest[];
  current?: VaultConnection;
  onClose: () => void;
  onSaved: () => void;
}) {
  // Editing keeps the plugin fixed; adding lets you pick one.
  const [plugin, setPlugin] = useState(current?.plugin ?? manifests[0]?.name ?? "");
  const [name, setName] = useState(current?.name ?? "");
  const manifest = manifests.find((m) => m.name === plugin);

  // Pre-fill non-secret fields from the saved config; secrets stay blank (masked
  // server-side) and a blank secret is left untouched on save (merge_config).
  const [values, setValues] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const init: Record<string, string> = {};
    for (const f of manifest?.config_schema ?? []) {
      const v = current?.config?.[f.key];
      if (f.type !== "secret" && v != null) init[f.key] = String(v);
    }
    setValues(init);
  }, [plugin, manifest, current]);

  const isSet = (f: PluginManifest["config_schema"][number]) =>
    Boolean(values[f.key]?.trim()) || Boolean(current?.config?.[f.key]);
  const missingRequired =
    !name.trim() || (manifest?.config_schema ?? []).some((f) => f.required && !isSet(f));

  async function save() {
    setSaving(true);
    setError(null);
    try {
      if (current) {
        await api.updateVaultConnection(current.id, { name: name.trim(), config: values });
      } else {
        await api.createVaultConnection({ name: name.trim(), plugin, config: values });
      }
      onSaved();
    } catch (e) {
      setError((e as Error).message);
      setSaving(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" style={{ width: 480 }} onClick={(e) => e.stopPropagation()}>
        <div className="card-head">
          <h2>{current ? "Edit" : "Add"} secret manager</h2>
          <span className="type-tag">vault</span>
        </div>

        <div className="field">
          <label>
            <span>Name</span>
            <span className="field-tag required">Required</span>
          </label>
          <input
            type="text"
            placeholder="e.g. Production Vault"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>

        {!current && (
          <div className="field">
            <label>
              <span>Plugin</span>
              <span className="field-tag required">Required</span>
            </label>
            <select value={plugin} onChange={(e) => setPlugin(e.target.value)}>
              {manifests.map((m) => (
                <option key={m.name} value={m.name}>{m.display_name}</option>
              ))}
            </select>
          </div>
        )}

        {(manifest?.config_schema ?? []).map((f) => {
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
              {f.type === "secret" && values[f.key] && (
                <div className="row field-actions">
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => setRevealed((r) => ({ ...r, [f.key]: !r[f.key] }))}
                  >
                    {revealed[f.key] ? "Hide" : "Show"}
                  </button>
                </div>
              )}
              {f.help && <div className="help">{f.help}</div>}
            </div>
          );
        })}

        {error && <div className="danger-text" style={{ marginTop: 6 }}>{error}</div>}

        <div className="row" style={{ marginTop: 6 }}>
          <button className="btn primary" disabled={saving || missingRequired} onClick={save}>
            {saving ? "Saving…" : "Save"}
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
        <p className="help" style={{ marginTop: 10 }}>
          After saving, click <strong>Test</strong> to verify the connection before planting
          canary secrets.
        </p>
      </div>
    </div>
  );
}
