import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import type {
  HoneytokenConnection,
  HoneytokenConnectionTestResult,
  PluginManifest,
} from "../api";
import { api } from "../api";
import { TimeAgo, Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";
import ProviderLogo from "../components/ProviderLogo.tsx";

const PAGE_TITLE = "Third Party SaaS";

// Shared tabs between the two honeytoken pages. Kept identical in Honeytokens.tsx.
export function SaasTabs() {
  const cls = ({ isActive }: { isActive: boolean }) => (isActive ? "active" : "");
  return (
    <nav className="nav-tabs">
      <NavLink to="/third-party" end className={cls}>Connections</NavLink>
      <NavLink to="/third-party/tokens" className={cls}>Honeytokens</NavLink>
    </nav>
  );
}

export default function HoneytokenConnections() {
  const [connections, setConnections] = useState<HoneytokenConnection[]>([]);
  const [manifests, setManifests] = useState<PluginManifest[]>([]);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<HoneytokenConnection | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, HoneytokenConnectionTestResult>>({});

  const load = () =>
    Promise.all([api.listHoneytokenConnections(), api.listManifests()]).then(([c, m]) => {
      setConnections(c);
      setManifests(m.filter((x) => x.kind === "honeytoken"));
    });
  useEffect(() => {
    load();
  }, []);

  async function test(id: string) {
    setTesting((t) => ({ ...t, [id]: true }));
    try {
      const res = await api.testHoneytokenConnection(id);
      setResults((r) => ({ ...r, [id]: res }));
    } catch (e) {
      setResults((r) => ({ ...r, [id]: { ok: false, error: (e as Error).message } }));
    } finally {
      setTesting((t) => ({ ...t, [id]: false }));
      await load();
    }
  }

  async function remove(c: HoneytokenConnection) {
    if (!window.confirm(
      `Remove "${c.name}"? Thumper best-effort revokes its live honeytokens on the ` +
      `platform, then deletes them from Thumper.`
    )) return;
    await api.deleteHoneytokenConnection(c.id);
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
            Add Platform
          </button>
        }
      />
      <div className="content">
        <SaasTabs />
        <p className="muted" style={{ marginTop: 12 }}>
          Connect a SaaS platform (Datadog, Salesforce, AWS) so Thumper can create
          fake credentials in it and watch its audit log for use. Plugins are
          auto-loaded from <span className="path">/plugins/honeytoken</span>.
        </p>

        {connections.length === 0 ? (
          <div className="card">
            <div className="empty">
              No platforms connected yet. Click <strong>Add Platform</strong> to connect one.
            </div>
          </div>
        ) : (
          <div className="card">
            {connections.map((c) => {
              const m = manifestOf(c.plugin);
              const res = results[c.id];
              return (
                <div className="integration-row" key={c.id}>
                  <div className="row" style={{ gap: 12, alignItems: "flex-start" }}>
                    <ProviderLogo plugin={c.plugin} label={m?.display_name ?? c.plugin} />
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
                    <div className="muted" style={{ marginTop: 4 }}>{m?.display_name ?? c.plugin}</div>
                    <div className="path" style={{ marginTop: 6 }}>
                      {Object.entries(c.config).map(([k, v]) => `${k}=${v}`).join("  ") || "—"}
                    </div>
                    {res && (
                      <div className={res.ok ? "muted" : "danger-text"} style={{ marginTop: 6 }}>
                        {res.ok ? "✓ Connected" : `✗ ${res.error}`}
                      </div>
                    )}
                    </div>
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
          onSaved={async () => { setAdding(false); await load(); }}
        />
      )}
      {editing && (
        <ConnectionModal
          manifests={manifests}
          current={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => { setEditing(null); await load(); }}
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
  current?: HoneytokenConnection;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [plugin, setPlugin] = useState(current?.plugin ?? manifests[0]?.name ?? "");
  const [name, setName] = useState(current?.name ?? "");
  const manifest = manifests.find((m) => m.name === plugin);

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
        await api.updateHoneytokenConnection(current.id, { name: name.trim(), config: values });
      } else {
        await api.createHoneytokenConnection({ name: name.trim(), plugin, config: values });
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
          <div className="row" style={{ gap: 10 }}>
            {plugin && <ProviderLogo plugin={plugin} label={manifest?.display_name} size={24} />}
            <h2>{current ? "Edit" : "Add"} platform</h2>
          </div>
          <span className="type-tag">honeytoken</span>
        </div>

        <div className="field">
          <label><span>Name</span><span className="field-tag required">Required</span></label>
          <input type="text" placeholder="e.g. Production Datadog"
                 value={name} onChange={(e) => setName(e.target.value)} />
        </div>

        {!current && (
          <div className="field">
            <label><span>Platform</span><span className="field-tag required">Required</span></label>
            <select value={plugin} onChange={(e) => setPlugin(e.target.value)}>
              {manifests.map((m) => <option key={m.name} value={m.name}>{m.display_name}</option>)}
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
                  <button type="button" className="btn small"
                          onClick={() => setRevealed((r) => ({ ...r, [f.key]: !r[f.key] }))}>
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
          After saving, click <strong>Test</strong> to verify the connection before
          creating honeytokens.
        </p>
      </div>
    </div>
  );
}
