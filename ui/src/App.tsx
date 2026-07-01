import { useEffect, useRef, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import {
  Crosshair,
  LayoutDashboard,
  MonitorDot,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Settings as SettingsIcon,
} from "lucide-react";
import Dashboard from "./pages/Dashboard.tsx";
import Tripwires from "./pages/Tripwires.tsx";
import TripwireDetail from "./pages/TripwireDetail.tsx";
import CreateTripwire from "./pages/CreateTripwire.tsx";
import Endpoints from "./pages/Endpoints.tsx";
import EndpointDetail from "./pages/EndpointDetail.tsx";
import Integrations from "./pages/Integrations.tsx";
import Settings from "./pages/Settings.tsx";
import NotFound from "./pages/NotFound.tsx";
import AdminGate from "./AdminGate.tsx";

// How long to show the animated logo after a sidebar toggle, in ms. Tracks the
// length of the one-thump GIF (ui/public/thumper_gif.gif, ~2.46s) plus a small
// buffer; bump this if the GIF is re-cut to a different duration.
const THUMP_ANIMATION_MS = 2600;

function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? "active" : "");

  // Play the thumper animation each time the sidebar collapses/expands. At rest
  // we show the sharp still; on toggle we remount the <img> (key bump) so the
  // cached GIF restarts from frame 0, then revert to the still when it finishes.
  const [playing, setPlaying] = useState(false);
  const [playKey, setPlayKey] = useState(0);
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    setPlayKey((k) => k + 1);
    setPlaying(true);
    const timer = setTimeout(() => setPlaying(false), THUMP_ANIMATION_MS);
    return () => clearTimeout(timer);
  }, [collapsed]);

  return (
    // Clicking empty sidebar chrome toggles collapse; the nav links below stop
    // propagation so navigating to a page never also toggles the bar.
    <aside className="sidebar" onClick={onToggle}>
      <button
        className="nav-toggle"
        onClick={(e) => {
          e.stopPropagation();
          onToggle();
        }}
        aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        title={collapsed ? "Expand" : "Collapse"}
      >
        {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
      </button>

      <div className="brand">
        <div className="brand-logo" aria-label="Thumper" title="Thumper">
          <img
            key={playKey}
            src={playing ? "/thumper_gif.gif" : "/thumper_gif.png"}
            alt="Thumper"
          />
        </div>
        <div className="brand-text">
          <div className="brand-name">Thumper</div>
          <div className="brand-sub">Shai-Hulud tripwires</div>
        </div>
      </div>

      {/* stopPropagation: clicking a link navigates, it must NOT toggle the bar */}
      <nav className="nav" onClick={(e) => e.stopPropagation()}>
        <NavLink to="/" end className={linkClass} title="Dashboard">
          <span className="nav-icon"><LayoutDashboard size={18} /></span>{" "}
          <span className="nav-label">Dashboard</span>
        </NavLink>
        <NavLink to="/tripwires" className={linkClass} title="Tripwires">
          <span className="nav-icon"><Crosshair size={18} /></span>{" "}
          <span className="nav-label">Tripwires</span>
        </NavLink>
        <NavLink to="/endpoints" className={linkClass} title="Endpoints">
          <span className="nav-icon"><MonitorDot size={18} /></span>{" "}
          <span className="nav-label">Endpoints</span>
        </NavLink>
        <NavLink to="/integrations" className={linkClass} title="Integrations">
          <span className="nav-icon"><Plug size={18} /></span>{" "}
          <span className="nav-label">Integrations</span>
        </NavLink>
        <NavLink to="/settings" className={linkClass} title="Settings">
          <span className="nav-icon"><SettingsIcon size={18} /></span>{" "}
          <span className="nav-label">Settings</span>
        </NavLink>
      </nav>

      <div className="sidebar-foot">
        <span className="made-by">made by</span>
        <img src="/jesta-white.png" alt="Jesta" className="jesta-logo" />
      </div>
    </aside>
  );
}

export default function App() {
  const [collapsed, setCollapsed] = useState(false);
  return (
    <AdminGate>
    <div className={`app ${collapsed ? "collapsed" : ""}`}>
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} />
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/tripwires" element={<Tripwires />} />
          <Route path="/tripwires/new" element={<CreateTripwire />} />
          <Route path="/tripwires/:id" element={<TripwireDetail />} />
          <Route path="/endpoints" element={<Endpoints />} />
          <Route path="/endpoints/:id" element={<EndpointDetail />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
    </AdminGate>
  );
}
