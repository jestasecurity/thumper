import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import type { Alert, DashboardStats, Tripwire } from "../api";
import { api } from "../api";
import { AlertBadge, timeAgo, Topbar, TripwireBadge, TypeTag } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";

type AlertFilter = "open" | "all" | "resolved";

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [tripwires, setTripwires] = useState<Tripwire[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [refreshInterval, setRefreshInterval] = useState(60);
  const [countdown, setCountdown] = useState(60);
  const [spinning, setSpinning] = useState(false);
  const [flash, setFlash] = useState(false);
  const [filter, setFilter] = useState<AlertFilter>("open");
  const nav = useNavigate();
  const countdownRef = useRef<ReturnType<typeof setInterval>>();
  const PAGE_TITLE = "Dashboard";

  const reload = useCallback(() => {
    setSpinning(true);
    Promise.all([
      api.getStats().then(setStats),
      api.listTripwires().then(setTripwires),
      api.listAlerts().then(setAlerts),
    ]).then(() => {
      setFlash(true);
      setTimeout(() => setFlash(false), 400);
    }).finally(() => {
      setTimeout(() => setSpinning(false), 600);
    });
  }, []);

  useEffect(() => {
    api.getSettings().then((s) => {
      const interval = s.dashboard.refresh_seconds;
      setRefreshInterval(interval);
      setCountdown(interval);
    });
    reload();
  }, [reload]);

  const tickRef = useRef(refreshInterval);

  useEffect(() => {
    if (refreshInterval <= 0) return;
    tickRef.current = refreshInterval;
    setCountdown(refreshInterval);
    countdownRef.current = setInterval(() => {
      tickRef.current -= 1;
      if (tickRef.current <= 0) {
        reload();
        tickRef.current = refreshInterval;
      }
      setCountdown(tickRef.current);
    }, 1000);
    return () => clearInterval(countdownRef.current);
  }, [refreshInterval, reload]);

  function manualRefresh() {
    reload();
    tickRef.current = refreshInterval;
    setCountdown(refreshInterval);
  }

  const openAlerts = alerts.filter((a) => a.status === "open");
  const shownAlerts = (filter === "all" ? alerts : alerts.filter((a) => a.status === filter));

  function resolveOne(id: string) {
    api.resolveAlert(id).then(reload);
  }

  function resolveAllOpen() {
    api.resolveAllAlerts().then(reload);
  }

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <Topbar
        title={PAGE_TITLE}
        action={
          <span className="row" style={{ gap: 10, alignItems: "center" }}>
            {refreshInterval > 0 && (
              <span className="countdown-badge">{countdown}s</span>
            )}
            <button className="btn-icon" title="Refresh" onClick={manualRefresh}>
              <RefreshCw size={15} className={spinning ? "spin" : ""} />
            </button>
            <Link to="/tripwires/new" className="btn primary">
              + New tripwire
            </Link>
          </span>
        }
      />
      <div className={`content${flash ? " reload-flash" : ""}`}>
        {openAlerts.length > 0 && (
          <div className="banner">
            ⚠ <strong>{new Set(openAlerts.map((a) => a.endpoint_id)).size} endpoint(s) may be
            compromised.</strong> A planted honeytoken was read - this almost always means a
            process is harvesting credentials.
          </div>
        )}

        <div className="stat-grid">
          <div className="stat">
            <div className="stat-val">{stats?.tripwires ?? "-"}</div>
            <div className="stat-label">Tripwires</div>
          </div>
          <div className="stat">
            <div className="stat-val">{stats?.endpoints ?? "-"}</div>
            <div className="stat-label">Endpoints enrolled</div>
          </div>
          <div className="stat alert">
            <div className="stat-val">{stats?.alerts_24h ?? "-"}</div>
            <div className="stat-label">Open alerts (24h)</div>
          </div>
          <div className="stat alert">
            <div className="stat-val">{stats?.active_triggers ?? "-"}</div>
            <div className="stat-label">Active triggers</div>
          </div>
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Recent alerts</h2>
            <span className="row" style={{ gap: 8, alignItems: "center" }}>
              <span className="seg">
                {(["open", "all", "resolved"] as AlertFilter[]).map((f) => (
                  <button
                    key={f}
                    className={`seg-btn${filter === f ? " active" : ""}`}
                    onClick={() => setFilter(f)}
                  >
                    {f}
                  </button>
                ))}
              </span>
              {openAlerts.length > 0 && (
                <button className="btn small" onClick={resolveAllOpen}>
                  Resolve all
                </button>
              )}
            </span>
          </div>
          {shownAlerts.length === 0 ? (
            <div className="empty">
              {filter === "open"
                ? "No open alerts. All quiet on the endpoints. 🌵"
                : "Nothing here."}
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Status</th>
                  <th>Endpoint</th>
                  <th>User</th>
                  <th>Process</th>
                  <th>Tripwire</th>
                  <th>Accessed path</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {shownAlerts.slice(0, 8).map((a) => (
                  <tr key={a.id}>
                    <td className="muted">{timeAgo(a.timestamp)}</td>
                    <td><AlertBadge status={a.status} /></td>
                    <td>
                      <Link to={`/endpoints/${a.endpoint_id}`}>{a.endpoint_hostname}</Link>
                    </td>
                    <td>{a.os_user ?? "-"}</td>
                    <td className="path">
                      {a.process ?? "unknown"}
                      {a.pid ? ` (${a.pid})` : ""}
                    </td>
                    <td>
                      <Link to={`/tripwires/${a.tripwire_id}`}>{a.tripwire_name}</Link>{" "}
                      <TypeTag type={a.token_type} />
                    </td>
                    <td className="path">{a.accessed_path ?? "-"}</td>
                    <td style={{ textAlign: "right" }}>
                      {a.status === "open" && (
                        <button className="btn small" onClick={() => resolveOne(a.id)}>
                          Resolve
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Tripwires</h2>
            <Link to="/tripwires" className="muted">
              view all →
            </Link>
          </div>
          {tripwires.length === 0 ? (
            <div className="empty">No tripwires yet. Create one to start baiting the worm.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Path</th>
                  <th>Endpoints</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {tripwires.slice(0, 5).map((t) => (
                  <tr key={t.id} className="clickable-row" onClick={() => nav(`/tripwires/${t.id}`)}>
                    <td>{t.name}</td>
                    <td><TypeTag type={t.token_type} /></td>
                    <td className="path">{t.path}</td>
                    <td>{t.deployed_count}</td>
                    <td><TripwireBadge deployed={t.deployed_count} triggered={t.triggered_count} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
