import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, ApiError } from "../api";
import type { TripwireDetail as TD } from "../api";
import { CopyField, DeployBadge, Modal, TypeTag, Topbar, timeAgo } from "../components/ui.tsx";
import { Pencil, Trash2 } from "lucide-react";

export default function TripwireDetail() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const [tw, setTw] = useState<TD | null>(null);
  const [distributing, setDistributing] = useState(false);
  const [distResult, setDistResult] = useState<string | null>(null);
  const [renaming, setRenaming] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [confirmName, setConfirmName] = useState("");
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const load = () =>
    api.getTripwire(id).then(setTw).catch((e) => {
      if (e instanceof ApiError && e.status === 404) setNotFound(true);
      else setLoadErr(e instanceof Error ? e.message : "failed to load tripwire");
    });
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  async function saveRename() {
    const name = draft.trim();
    if (!name) return;
    setBusy(true); setActionErr(null);
    try {
      await api.renameTripwire(id, name);
      setRenaming(false);
      load();
    } catch (e) {
      setActionErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    setBusy(true); setActionErr(null);
    try {
      await api.deleteTripwire(id);
      nav("/tripwires");
    } catch (e) {
      setActionErr((e as Error).message);
      setBusy(false);
    }
  }

  async function distribute() {
    setDistributing(true);
    setDistResult(null);
    try {
      const r = await api.distributeTripwire(id);
      setDistResult(r.results.map((x) => `${x.plugin}: ${x.message}`).join("\n"));
    } catch (e) {
      setDistResult((e as Error).message);
    } finally {
      setDistributing(false);
      load();
    }
  }

  if (notFound) return (
    <>
      <Topbar title="Tripwire not found" />
      <div className="content">
        <div className="empty">
          This tripwire doesn't exist or was deleted.{" "}
          <Link to="/tripwires">← All tripwires</Link>
        </div>
      </div>
    </>
  );
  if (loadErr) return (
    <>
      <Topbar title="Couldn't load tripwire" />
      <div className="content">
        <div className="empty">
          {loadErr}{" "}
          <button className="btn" onClick={() => { setLoadErr(null); load(); }}>Retry</button>
          {" "}<Link to="/tripwires">← All tripwires</Link>
        </div>
      </div>
    </>
  );
  if (!tw) return <div className="content">Loading…</div>;

  return (
    <>
      <Topbar
        title={tw.name}
        action={
          <span className="row" style={{ gap: 8 }}>
            <button className="btn" onClick={() => { setDraft(tw.name); setActionErr(null); setRenaming(true); }}>
              <Pencil size={14} /> Rename
            </button>
            <button className="btn danger" onClick={() => { setConfirmName(""); setActionErr(null); setConfirming(true); }}>
              <Trash2 size={14} /> Delete
            </button>
          </span>
        }
      />
      <div className="content">
        <div className="card">
          <div className="row" style={{ gap: 10, marginBottom: 12 }}>
            <TypeTag type={tw.token_type} />
            <span className="path">{tw.path}</span>
            <span className="muted">source: {tw.source}</span>
            <span className="muted">created {timeAgo(tw.created_at)}</span>
          </div>

          {tw.token && (
            <div style={{ marginBottom: 20 }}>
              <div className="step-label">Honeytoken</div>
              <pre className="code-block">{tw.token}</pre>
            </div>
          )}

          <div className="step-label">Deploy this tripwire</div>
          <p className="muted" style={{ marginTop: 0 }}>
            Run the command below on the machines you choose - paste it on a box, or push it
            via your MDM / SSH / Ansible. It's self-bootstrapping: it downloads the agent,
            self-enrolls, and starts watching. Each machine gets its <strong>own unique</strong>{" "}
            honeytoken instance + secret. <code>sudo</code> is required so the monitor can see
            file reads (macOS <code>fs_usage</code>). Your MDM decides which devices are in
            scope - Thumper doesn't manage groups.
          </p>
          <CopyField value={tw.install.command} />
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn primary" onClick={distribute} disabled={distributing}>
              {distributing ? "Distributing…" : "Distribute via integrations"}
            </button>
            <Link to="/integrations" className="btn">Configure integrations</Link>
          </div>
          {distResult && <pre className="distresult">{distResult}</pre>}
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Endpoints ({tw.deployments.length})</h2>
            <span className="muted">one unique instance per endpoint</span>
          </div>
          {tw.deployments.length === 0 ? (
            <div className="empty">
              Not on any endpoint yet. Run the install command above on a machine.
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Instance</th>
                  <th>Planted</th>
                  <th>Last triggered</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {tw.deployments.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <Link to={`/endpoints/${d.endpoint_id}`}>{d.endpoint_hostname}</Link>
                    </td>
                    <td className="path">{d.id}</td>
                    <td className="muted">{timeAgo(d.created_at)}</td>
                    <td className="muted">
                      {d.last_triggered ? timeAgo(d.last_triggered) : "-"}
                    </td>
                    <td><DeployBadge state={d.state} triggered={d.triggered_count} endpointStatus={d.endpoint_status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {renaming && (
        <Modal onClose={() => { setRenaming(false); setActionErr(null); }}>
          <div className="card-head">
            <h2>Rename tripwire</h2>
          </div>
          <div className="field">
            <label>Name</label>
            <input
              type="text"
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") saveRename(); if (e.key === "Escape") { setRenaming(false); setActionErr(null); } }}
            />
          </div>
          {actionErr && <p className="danger-text">{actionErr}</p>}
          <div className="row" style={{ gap: 8 }}>
            <button className="btn primary" onClick={saveRename} disabled={!draft.trim() || busy}>Save</button>
            <button className="btn" onClick={() => { setRenaming(false); setActionErr(null); }}>Cancel</button>
          </div>
        </Modal>
      )}

      {confirming && (
        <Modal onClose={() => { setConfirming(false); setActionErr(null); }}>
          <div className="card-head">
            <h2>Delete tripwire</h2>
          </div>
          <p className="modal-intro">
            This removes <strong>{tw.name}</strong> from all endpoints - the planted bait
            will be unplanted on the next agent sync. Alert history is preserved.
          </p>
          <div className="field">
            <label><span>Type <strong>{tw.name}</strong> to confirm</span></label>
            <input
              type="text"
              autoFocus
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && confirmName === tw.name) confirmDelete(); }}
            />
          </div>
          {actionErr && <p className="danger-text">{actionErr}</p>}
          <div className="row" style={{ gap: 8 }}>
            <button className="btn danger" onClick={confirmDelete} disabled={confirmName !== tw.name || busy}>Delete</button>
            <button className="btn" onClick={() => { setConfirming(false); setActionErr(null); }}>Cancel</button>
          </div>
        </Modal>
      )}
    </>
  );
}
