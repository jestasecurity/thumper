import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Trash2 } from "lucide-react";
import { api } from "../api";
import type { EndpointDetail as ED, Tripwire } from "../api";
import { DeployBadge, EndpointBadge, Topbar, timeAgo } from "../components/ui.tsx";

function Modal({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

export default function EndpointDetail() {
  const { id = "" } = useParams();
  const [ep, setEp] = useState<ED | null>(null);
  const [tripwires, setTripwires] = useState<Tripwire[]>([]);
  const [showPicker, setShowPicker] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState<{ tripwireId: string; name: string } | null>(null);
  const [confirm, setConfirm] = useState<"decommission" | "force" | null>(null);
  const pickerRef = useRef<HTMLDivElement>(null);
  const nav = useNavigate();

  const reload = useCallback(() => {
    api.getEndpoint(id).then(setEp);
  }, [id]);

  useEffect(() => {
    reload();
    api.listTripwires().then(setTripwires);
  }, [id, reload]);

  useEffect(() => {
    if (!showPicker) return;
    function close(e: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) setShowPicker(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [showPicker]);

  if (!ep) return <div className="content">Loading…</div>;

  const onEndpoint = new Set(ep.deployments.map((d) => d.tripwire_id));
  const available = tripwires.filter((t) => !onEndpoint.has(t.id));
  const nameOf = (tid: string) => tripwires.find((t) => t.id === tid)?.name ?? tid;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "request failed");
    } finally {
      setBusy(false);
    }
  }

  const decommissioning = ep.status === "decommissioning";

  return (
    <>
      <Topbar
        title={ep.hostname}
        action={
          decommissioning ? (
            <span className="row" style={{ gap: 10, alignItems: "center" }}>
              <span className="muted">decommissioning…</span>
              <button className="btn danger" disabled={busy} onClick={() => setConfirm("force")}>
                Force remove
              </button>
            </span>
          ) : (
            <button className="btn danger" disabled={busy} onClick={() => setConfirm("decommission")}>
              Decommission
            </button>
          )
        }
      />
      <div className="content">
        <div className="card">
          <div className="row" style={{ gap: 10 }}>
            <EndpointBadge status={ep.status} />
            <span className="muted">{ep.platform ?? "unknown platform"}</span>
            <span className="muted">enrolled {timeAgo(ep.enrolled_at)}</span>
            <span className="muted">last seen {ep.last_seen ? timeAgo(ep.last_seen) : "-"}</span>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Tripwires ({ep.deployments.length})</h2>
            <div style={{ position: "relative" }} ref={pickerRef}>
              <button
                className="btn primary"
                disabled={busy}
                onClick={() => setShowPicker(!showPicker)}
              >
                + Add Tripwire
              </button>
              {showPicker && (
                <div className="picker-popover">
                  {available.length > 0 && (
                    <>
                      <div className="picker-heading">Existing tripwires</div>
                      {available.map((t) => (
                        <button
                          key={t.id}
                          className="picker-item"
                          onClick={() => {
                            setShowPicker(false);
                            act(() => api.assignTripwire(id, t.id));
                          }}
                        >
                          {t.name}
                        </button>
                      ))}
                      <div className="picker-divider" />
                    </>
                  )}
                  <Link to="/tripwires/new" className="picker-item" style={{ color: "var(--accent)" }}>
                    + Create new tripwire
                  </Link>
                </div>
              )}
            </div>
          </div>

          {error && <div className="empty">{error}</div>}

          {ep.deployments.length === 0 ? (
            <div className="empty">No tripwires on this endpoint.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Tripwire</th>
                  <th>Instance</th>
                  <th>Planted</th>
                  <th>Last triggered</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {ep.deployments.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <Link to={`/tripwires/${d.tripwire_id}`}>{nameOf(d.tripwire_id)}</Link>
                    </td>
                    <td className="path">{d.id}</td>
                    <td className="muted">{timeAgo(d.created_at)}</td>
                    <td className="muted">{d.last_triggered ? timeAgo(d.last_triggered) : "-"}</td>
                    <td><DeployBadge state={d.state} triggered={d.triggered_count} /></td>
                    <td>
                      <button
                        className="btn-icon danger"
                        title="Remove"
                        disabled={busy}
                        onClick={() => setRemoving({ tripwireId: d.tripwire_id, name: nameOf(d.tripwire_id) })}
                      >
                        <Trash2 size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {confirm === "decommission" && (
        <Modal onClose={() => setConfirm(null)}>
          <div className="card-head"><h2>Decommission endpoint</h2></div>
          <p className="modal-intro">
            Tell <strong>{ep.hostname}</strong> to self-destruct? On its next check-in the agent
            unplants all its bait, removes itself, and disappears from the dashboard. This can't be undone.
          </p>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn danger" onClick={() => {
              setConfirm(null);
              act(() => api.decommissionEndpoint(id));
            }}>Decommission</button>
            <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
          </div>
        </Modal>
      )}

      {confirm === "force" && (
        <Modal onClose={() => setConfirm(null)}>
          <div className="card-head"><h2>Force remove endpoint</h2></div>
          <p className="modal-intro">
            Remove <strong>{ep.hostname}</strong> from the dashboard now, without waiting for the
            agent to confirm. Use this only for a dead/offline machine - any bait already planted
            there will stay until cleaned up manually.
          </p>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn danger" onClick={() => {
              setConfirm(null);
              act(async () => { await api.removeEndpoint(id); nav("/endpoints"); });
            }}>Force remove</button>
            <button className="btn" onClick={() => setConfirm(null)}>Cancel</button>
          </div>
        </Modal>
      )}

      {removing && (
        <Modal onClose={() => setRemoving(null)}>
          <div className="card-head"><h2>Remove tripwire</h2></div>
          <p className="modal-intro">
            Remove <strong>{removing.name}</strong> from <strong>{ep.hostname}</strong>?
            The planted bait will be unplanted on the next agent sync.
          </p>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn danger" onClick={() => {
              const tid = removing.tripwireId;
              setRemoving(null);
              act(() => api.unassignTripwire(id, tid));
            }}>Remove</button>
            <button className="btn" onClick={() => setRemoving(null)}>Cancel</button>
          </div>
        </Modal>
      )}
    </>
  );
}
