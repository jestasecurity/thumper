import { useEffect, useState } from "react";
import type {
  Honeytoken,
  HoneytokenConnection,
  HoneytokenUsageLog,
} from "../api";
import { api } from "../api";
import { TimeAgo, Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";
import { SaasTabs } from "./HoneytokenConnections.tsx";

const PAGE_TITLE = "Honeytokens";

// honeytoken state -> the reused integration badge class. A use makes state
// "triggered", which is an ALERT, so it borrows the red styling.
const BADGE: Record<Honeytoken["state"], string> = {
  pending: "pending",
  active: "deployed",
  failed: "failed",
  triggered: "triggered",
};

export default function Honeytokens() {
  const [tokens, setTokens] = useState<Honeytoken[]>([]);
  const [connections, setConnections] = useState<HoneytokenConnection[]>([]);
  const [creating, setCreating] = useState(false);
  const [usageFor, setUsageFor] = useState<Honeytoken | null>(null);

  const load = () =>
    Promise.all([api.listHoneytokens(), api.listHoneytokenConnections()]).then(([t, c]) => {
      setTokens(t);
      setConnections(c);
    });
  useEffect(() => {
    load();
  }, []);

  async function remove(t: Honeytoken) {
    if (!window.confirm(
      `Delete "${t.name}"? Thumper revokes it on the platform too.`
    )) return;
    await api.deleteHoneytoken(t.id);
    await load();
  }

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
            title={usable.length === 0 ? "Connect and test a platform first" : ""}
            onClick={() => setCreating(true)}
          >
            Create Honeytoken
          </button>
        }
      />
      <div className="content">
        <SaasTabs />
        <p className="muted" style={{ marginTop: 12 }}>
          Fake credentials created inside your SaaS platforms. Thumper polls each
          platform's audit log and raises an alert the moment one is used.
        </p>

        {tokens.length === 0 ? (
          <div className="card">
            <div className="empty">
              No honeytokens yet.
              {usable.length === 0
                ? " Connect and test a platform first."
                : " Click Create Honeytoken to create one."}
            </div>
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Platform</th>
                  <th>Type</th>
                  <th>State</th>
                  <th>Last used</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td>{t.connection_name}</td>
                    <td className="path">{t.token_type}</td>
                    <td><span className={`badge ${BADGE[t.state]}`}><span className="dot" />{t.state}</span></td>
                    <td className="muted">
                      {t.last_used_at ? <TimeAgo iso={t.last_used_at} /> : "—"}
                    </td>
                    <td>
                      <div className="row" style={{ gap: 8, justifyContent: "flex-end" }}>
                        <button className="btn small" onClick={() => setUsageFor(t)}>Usage</button>
                        <button className="btn small danger" onClick={() => remove(t)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {creating && (
        <CreateModal
          connections={usable}
          onClose={() => setCreating(false)}
          onCreated={async () => { setCreating(false); await load(); }}
        />
      )}
      {usageFor && <UsageModal token={usageFor} onClose={() => setUsageFor(null)} />}
    </>
  );
}

function CreateModal({
  connections,
  onClose,
  onCreated,
}: {
  connections: HoneytokenConnection[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [connId, setConnId] = useState(connections[0]?.id ?? "");
  const [name, setName] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const missing = !connId || !name.trim();

  async function create() {
    setSaving(true);
    setError(null);
    try {
      await api.createHoneytoken({ connection_id: connId, name: name.trim() });
      onCreated();
    } catch (e) {
      setError((e as Error).message);
      setSaving(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" style={{ width: 480 }} onClick={(e) => e.stopPropagation()}>
        <div className="card-head">
          <h2>Create honeytoken</h2>
          <span className="type-tag">honeytoken</span>
        </div>

        <div className="field">
          <label><span>Platform</span></label>
          <select value={connId} onChange={(e) => setConnId(e.target.value)}>
            {connections.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>

        <div className="field">
          <label><span>Name</span><span className="field-tag required">Required</span></label>
          <input
            type="text"
            placeholder="a recognizable label, e.g. finance-api-key"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <div className="help">
            The real fake credential is created on the platform; its use is what fires.
          </div>
        </div>

        {error && <div className="danger-text" style={{ marginTop: 6 }}>{error}</div>}

        <div className="row" style={{ marginTop: 6 }}>
          <button className="btn primary" disabled={saving || missing} onClick={create}>
            {saving ? "Creating…" : "Create"}
          </button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

function UsageModal({ token, onClose }: { token: Honeytoken; onClose: () => void }) {
  const [logs, setLogs] = useState<HoneytokenUsageLog[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listHoneytokenUsage(token.id).then(setLogs).catch((e) => setError((e as Error).message));
  }, [token.id]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" style={{ width: 560 }} onClick={(e) => e.stopPropagation()}>
        <div className="card-head">
          <h2>Usage of {token.name}</h2>
          <span className="type-tag">{token.connection_name}</span>
        </div>
        {error ? (
          <div className="danger-text">{error}</div>
        ) : logs === null ? (
          <div className="empty">Loading…</div>
        ) : logs.length === 0 ? (
          <div className="empty">No use recorded yet. A use here fires an alert.</div>
        ) : (
          <table>
            <thead>
              <tr><th>When</th><th>Actor</th><th>Action</th><th>Source IP</th></tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id}>
                  <td className="muted"><TimeAgo iso={l.timestamp} /></td>
                  <td>{l.actor ?? "—"}</td>
                  <td>{l.action ?? "—"}</td>
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
