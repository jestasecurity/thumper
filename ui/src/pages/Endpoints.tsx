import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Endpoint } from "../api";
import { api } from "../api";
import { EndpointBadge, PlatformBadge, TimeAgo, Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";

export default function Endpoints() {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const nav = useNavigate();
  const PAGE_TITLE = "Endpoints";

  useEffect(() => {
    api.listEndpoints().then(setEndpoints);
  }, []);

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <Topbar title="Endpoints" />
      <div className="content">
        <div className="card">
          <p className="muted" style={{ marginTop: 0 }}>
            Machines that have enrolled by running a tripwire's install command. Each holds its
            own unique honeytoken instances and reports reads via the on-box monitor.
          </p>
          {endpoints.length === 0 ? (
            <div className="empty">
              No endpoints enrolled yet. Open a tripwire and distribute its install command.
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Platform</th>
                  <th>Enrolled</th>
                  <th>Last seen</th>
                  <th>Tripwires</th>
                  <th>Triggers</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((e) => (
                  <tr key={e.id} className="clickable-row" onClick={() => nav(`/endpoints/${e.id}`)}>
                    <td>{e.hostname}</td>
                    <td><PlatformBadge platform={e.platform} /></td>
                    <td className="muted"><TimeAgo iso={e.enrolled_at} /></td>
                    <td className="muted">{e.last_seen ? <TimeAgo iso={e.last_seen} /> : "-"}</td>
                    <td>{e.deployment_count}</td>
                    <td className={e.triggered_count > 0 ? "danger-text" : ""}>
                      {e.triggered_count}
                    </td>
                    <td><EndpointBadge status={e.status} /></td>
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
