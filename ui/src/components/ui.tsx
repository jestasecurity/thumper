import { useState } from "react";
import type { ReactNode } from "react";
import type { AlertStatus, DeploymentState, EndpointStatus } from "../api";

export function Topbar({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="topbar">
      <h1>{title}</h1>
      {action}
    </div>
  );
}

export function TypeTag({ type }: { type: string }) {
  return <span className="type-tag">{type}</span>;
}

/** Alert lifecycle status: open (still active) or resolved (acknowledged). */
export function AlertBadge({ status }: { status: AlertStatus }) {
  return (
    <span className={`badge ${status === "open" ? "triggered" : "resolved"}`}>
      <span className="dot" /> {status}
    </span>
  );
}

/** Tripwire (definition) rollup status, derived from its instances. */
export function TripwireBadge({ deployed, triggered }: { deployed: number; triggered: number }) {
  if (triggered > 0) {
    return (
      <span className="badge triggered">
        <span className="dot" /> {triggered} triggered
      </span>
    );
  }
  if (deployed > 0) {
    return (
      <span className="badge deployed">
        <span className="dot" /> on {deployed} endpoint{deployed === 1 ? "" : "s"}
      </span>
    );
  }
  return (
    <span className="badge pending">
      <span className="dot" /> not deployed
    </span>
  );
}

/** Per-endpoint instance status. */
export function DeployBadge({ state, triggered, endpointStatus }:
  { state: DeploymentState; triggered?: number; endpointStatus?: EndpointStatus }) {
  if (triggered && triggered > 0) {
    return (
      <span className="badge triggered">
        <span className="dot" /> {triggered} triggered
      </span>
    );
  }
  // Planted bait on an offline endpoint isn't really "covered" - the agent may no
  // longer be watching. Mute it (amber) instead of healthy green (#27).
  if (state === "planted" && endpointStatus && endpointStatus !== "online") {
    return (
      <span className="badge pending" title="endpoint offline - bait may not be watched">
        <span className="dot" /> planted · offline
      </span>
    );
  }
  const cls = state === "planted" ? "deployed" : state === "failed" ? "failed" : "pending";
  return (
    <span className={`badge ${cls}`}>
      <span className="dot" /> {state}
    </span>
  );
}

export function EndpointBadge({ status }: { status: EndpointStatus }) {
  const cls = status === "online" ? "deployed"
    : status === "stale" ? "pending"
    : "failed";   // inactive + decommissioning both use the red/danger style
  return (
    <span className={`badge ${cls}`}>
      <span className="dot" /> {status}
    </span>
  );
}

/** Monospace block with a copy button - used for the install command. */
export function CopyField({ value }: { value: string }) {
  const [label, setLabel] = useState("Copy");
  return (
    <div className="copyfield">
      <code>{value}</code>
      <button
        className="btn"
        onClick={() => {
          if (navigator.clipboard) {
            navigator.clipboard.writeText(value);
            setLabel("✓ Copied");
          } else {
            setLabel("Copy failed, try manually");
          }
          setTimeout(() => setLabel("Copy"), 1200);
        }}
      >
        {label}
      </button>
    </div>
  );
}

export function Modal({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="card modal-card" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
