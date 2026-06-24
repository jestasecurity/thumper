import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Pencil, Trash2 } from "lucide-react";
import { api } from "../api";
import type { InstallCommand, Tripwire } from "../api";
import { CopyField, Modal, TripwireBadge, TypeTag, Topbar, timeAgo } from "../components/ui.tsx";

export default function Tripwires() {
  const [tripwires, setTripwires] = useState<Tripwire[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [install, setInstall] = useState<InstallCommand | null>(null);
  const [error, setError] = useState<string | null>(null);
  const nav = useNavigate();
  const [renaming, setRenaming] = useState<Tripwire | null>(null);
  const [draft, setDraft] = useState("");
  const [deleting, setDeleting] = useState<Tripwire | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const load = () => api.listTripwires().then(setTripwires);
  useEffect(() => { load(); }, []);

  async function saveRename() {
    if (!renaming) return;
    const name = draft.trim();
    if (!name) return;
    setBusy(true); setActionErr(null);
    try {
      await api.renameTripwire(renaming.id, name);
      setRenaming(null);
      load();
    } catch (e) {
      setActionErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    if (!deleting) return;
    setBusy(true); setActionErr(null);
    try {
      await api.deleteTripwire(deleting.id);
      setDeleting(null);
      load();
    } catch (e) {
      setActionErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
    setInstall(null);
    setError(null);
  }

  function clear() {
    setSelected(new Set());
    setInstall(null);
    setError(null);
  }

  async function build() {
    setError(null);
    try {
      setInstall(await api.buildInstall([...selected]));
    } catch (e) {
      setInstall(null);
      setError(e instanceof Error ? e.message : "failed to build install command");
    }
  }

  return (
    <>
      <Topbar
        title="Tripwires"
        action={
          <Link to="/tripwires/new" className="btn primary">
            + New tripwire
          </Link>
        }
      />
      <div className="content">
        <div className="card">
          {selected.size > 0 && (
            <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
              <span className="muted">{selected.size} selected</span>
              <span className="row" style={{ gap: 8 }}>
                <button className="btn primary" onClick={build}>
                  Build install command
                </button>
                <button className="btn" onClick={clear}>
                  Clear
                </button>
              </span>
            </div>
          )}

          {error && <div className="empty">{error}</div>}

          {install && (
            <div style={{ marginBottom: 16 }}>
              <div className="step-label">
                Install command for {install.tripwire_ids.length} tripwire
                {install.tripwire_ids.length === 1 ? "" : "s"}
              </div>
              <p className="muted" style={{ marginTop: 0 }}>
                Run it on the machines you choose - paste it on a box, or push it via your MDM /
                SSH. One agent self-enrolls and plants + watches all selected tripwires.{" "}
                <code>sudo</code> is required (macOS <code>fs_usage</code>).
              </p>
              <CopyField value={install.command} />
            </div>
          )}

          {tripwires.length === 0 ? (
            <div className="empty">No tripwires yet. Create one to start baiting the worm.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th style={{ width: 28 }}></th>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Path</th>
                  <th>Source</th>
                  <th>Created</th>
                  <th>Endpoints</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {tripwires.map((t) => (
                  <tr key={t.id} className="clickable-row" onClick={() => nav(`/tripwires/${t.id}`)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`select ${t.name}`}
                        checked={selected.has(t.id)}
                        onChange={() => toggle(t.id)}
                      />
                    </td>
                    <td>{t.name}</td>
                    <td><TypeTag type={t.token_type} /></td>
                    <td className="path">{t.path}</td>
                    <td className="muted">{t.source}</td>
                    <td className="muted">{timeAgo(t.created_at)}</td>
                    <td>{t.deployed_count}</td>
                    <td><TripwireBadge deployed={t.deployed_count} triggered={t.triggered_count} /></td>
                    <td className="row-actions" onClick={(e) => e.stopPropagation()}>
                      <button className="btn-icon" title="Rename" aria-label="Rename tripwire" onClick={() => { setDraft(t.name); setActionErr(null); setRenaming(t); }}>
                        <Pencil size={14} />
                      </button>
                      <button className="btn-icon danger" title="Delete" aria-label="Delete tripwire" onClick={() => { setConfirmName(""); setActionErr(null); setDeleting(t); }}>
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

      {renaming && (
        <Modal onClose={() => { setRenaming(null); setActionErr(null); }}>
          <div className="card-head"><h2>Rename tripwire</h2></div>
          <div className="field">
            <label>Name</label>
            <input
              type="text"
              autoFocus
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") saveRename(); if (e.key === "Escape") { setRenaming(null); setActionErr(null); } }}
            />
          </div>
          {actionErr && <p className="danger-text">{actionErr}</p>}
          <div className="row" style={{ gap: 8 }}>
            <button className="btn primary" onClick={saveRename} disabled={!draft.trim() || busy}>Save</button>
            <button className="btn" onClick={() => { setRenaming(null); setActionErr(null); }}>Cancel</button>
          </div>
        </Modal>
      )}

      {deleting && (
        <Modal onClose={() => { setDeleting(null); setActionErr(null); }}>
          <div className="card-head"><h2>Delete tripwire</h2></div>
          <p className="modal-intro">
            This removes <strong>{deleting.name}</strong> from all endpoints - the planted bait
            will be unplanted on the next agent sync. Alert history is preserved.
          </p>
          <div className="field">
            <label><span>Type <strong>{deleting.name}</strong> to confirm</span></label>
            <input
              type="text"
              autoFocus
              value={confirmName}
              onChange={(e) => setConfirmName(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && confirmName === deleting.name) confirmDelete(); }}
            />
          </div>
          {actionErr && <p className="danger-text">{actionErr}</p>}
          <div className="row" style={{ gap: 8 }}>
            <button className="btn danger" onClick={confirmDelete} disabled={confirmName !== deleting.name || busy}>Delete</button>
            <button className="btn" onClick={() => { setDeleting(null); setActionErr(null); }}>Cancel</button>
          </div>
        </Modal>
      )}
    </>
  );
}
