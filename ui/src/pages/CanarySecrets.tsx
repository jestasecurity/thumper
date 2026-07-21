import { useEffect, useState } from "react";
import type {
  CanaryAccessLog,
  CanarySecret,
  CanaryTemplate,
  VaultConnection,
} from "../api";
import { api } from "../api";
import { TimeAgo, Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";
import { VaultTabs } from "./VaultConnections.tsx";

const PAGE_TITLE = "Canary Secrets";

// canary state -> the reused integration badge class. A read makes state
// "triggered", which is an ALERT, so it borrows the red "failed" styling.
const BADGE: Record<CanarySecret["state"], string> = {
  pending: "pending",
  planted: "deployed",
  failed: "failed",
  triggered: "triggered",
};

export default function CanarySecrets() {
  const [secrets, setSecrets] = useState<CanarySecret[]>([]);
  const [connections, setConnections] = useState<VaultConnection[]>([]);
  const [planting, setPlanting] = useState(false);
  const [logsFor, setLogsFor] = useState<CanarySecret | null>(null);

  const load = () =>
    Promise.all([api.listCanarySecrets(), api.listVaultConnections()]).then(([s, c]) => {
      setSecrets(s);
      setConnections(c);
    });
  useEffect(() => {
    load();
  }, []);

  async function remove(s: CanarySecret) {
    if (!window.confirm(
      `Delete "${s.path}"? Thumper removes it from the secrets manager too.`
    )) return;
    await api.deleteCanarySecret(s.id);
    await load();
  }

  // Only configured connections can hold a planted canary.
  const usable = connections.filter((c) => c.configured);

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <Topbar
        title={PAGE_TITLE}
        action={
          <button
            className="btn primary"
            disabled={usable.length === 0}
            title={usable.length === 0 ? "Connect and test a secret manager first" : ""}
            onClick={() => setPlanting(true)}
          >
            Plant Canary
          </button>
        }
      />
      <div className="content">
        <VaultTabs />
        <p className="muted" style={{ marginTop: 12 }}>
          Fake credentials planted in your secrets managers. Thumper polls each manager's
          audit log and raises an alert the moment one is read.
        </p>

        {secrets.length === 0 ? (
          <div className="card">
            <div className="empty">
              No canary secrets planted yet.
              {usable.length === 0
                ? " Connect and test a secret manager first."
                : " Click Plant Canary to plant one."}
            </div>
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Template</th>
                  <th>Secret manager</th>
                  <th>Path</th>
                  <th>State</th>
                  <th>Last read</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {secrets.map((s) => (
                  <tr key={s.id}>
                    <td>{s.template_name}</td>
                    <td>{s.vault_connection_name}</td>
                    <td className="path">{s.path}</td>
                    <td><span className={`badge ${BADGE[s.state]}`}><span className="dot" />{s.state}</span></td>
                    <td className="muted">
                      {s.last_accessed_at ? <TimeAgo iso={s.last_accessed_at} /> : "—"}
                    </td>
                    <td>
                      <div className="row" style={{ gap: 8, justifyContent: "flex-end" }}>
                        <button className="btn small" onClick={() => setLogsFor(s)}>Reads</button>
                        <button className="btn small danger" onClick={() => remove(s)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {planting && (
        <PlantModal
          connections={usable}
          onClose={() => setPlanting(false)}
          onPlanted={async () => {
            setPlanting(false);
            await load();
          }}
        />
      )}
      {logsFor && <AccessLogModal secret={logsFor} onClose={() => setLogsFor(null)} />}
    </>
  );
}

function PlantModal({
  connections,
  onClose,
  onPlanted,
}: {
  connections: VaultConnection[];
  onClose: () => void;
  onPlanted: () => void;
}) {
  const [templates, setTemplates] = useState<CanaryTemplate[]>([]);
  const [connId, setConnId] = useState(connections[0]?.id ?? "");
  const [template, setTemplate] = useState("");
  const [path, setPath] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listCanaryTemplates().then((t) => {
      setTemplates(t);
      if (t[0]) setTemplate(t[0].slug);
    });
  }, []);

  const chosen = templates.find((t) => t.slug === template);
  const missing = !connId || !template || !path.trim();

  async function plant() {
    setSaving(true);
    setError(null);
    try {
      await api.createCanarySecret({ vault_connection_id: connId, template, path: path.trim() });
      onPlanted();
    } catch (e) {
      setError((e as Error).message);
      setSaving(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" style={{ width: 480 }} onClick={(e) => e.stopPropagation()}>
        <div className="card-head">
          <h2>Plant canary secret</h2>
          <span className="type-tag">vault</span>
        </div>

        <div className="field">
          <label><span>Secret manager</span></label>
          <select value={connId} onChange={(e) => setConnId(e.target.value)}>
            {connections.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>

        <div className="field">
          <label><span>Template</span></label>
          <select value={template} onChange={(e) => setTemplate(e.target.value)}>
            {templates.map((t) => (
              <option key={t.slug} value={t.slug}>{t.name} · {t.category}</option>
            ))}
          </select>
        </div>

        <div className="field">
          <label><span>Path</span><span className="field-tag required">Required</span></label>
          <input
            type="text"
            placeholder="where to store it in the manager, e.g. production/stripe/key"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
          {chosen && chosen.suggested_paths.length > 0 && (
            <div className="row field-actions" style={{ flexWrap: "wrap" }}>
              {chosen.suggested_paths.map((p) => (
                <button type="button" key={p} className="btn small" onClick={() => setPath(p)}>
                  {p}
                </button>
              ))}
            </div>
          )}
          <div className="help">
            A realistic-looking fake value is generated for you and written at this path.
          </div>
        </div>

        {error && <div className="danger-text" style={{ marginTop: 6 }}>{error}</div>}

        <div className="row" style={{ marginTop: 6 }}>
          <button className="btn primary" disabled={saving || missing} onClick={plant}>
            {saving ? "Planting…" : "Plant"}
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

function AccessLogModal({ secret, onClose }: { secret: CanarySecret; onClose: () => void }) {
  const [logs, setLogs] = useState<CanaryAccessLog[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listCanaryAccessLogs(secret.id).then(setLogs).catch((e) => setError((e as Error).message));
  }, [secret.id]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" style={{ width: 560 }} onClick={(e) => e.stopPropagation()}>
        <div className="card-head">
          <h2>Reads of {secret.template_name}</h2>
          <span className="type-tag">{secret.path}</span>
        </div>
        {error ? (
          <div className="danger-text">{error}</div>
        ) : logs === null ? (
          <div className="empty">Loading…</div>
        ) : logs.length === 0 ? (
          <div className="empty">No reads recorded yet. A read here fires an alert.</div>
        ) : (
          <table>
            <thead>
              <tr><th>When</th><th>Accessor</th><th>Source IP</th></tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id}>
                  <td className="muted"><TimeAgo iso={l.timestamp} /></td>
                  <td>{l.accessor ?? "—"}</td>
                  <td className="path">{l.source_ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="row" style={{ marginTop: 6 }}>
          <button className="btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
