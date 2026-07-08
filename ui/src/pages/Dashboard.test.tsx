import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import Dashboard from "./Dashboard.tsx";
import type { Alert, AppSettings, DashboardStats, Tripwire } from "../api";
import { api } from "../api";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      getSettings: vi.fn(),
      getStats: vi.fn(),
      listTripwires: vi.fn(),
      listAlerts: vi.fn(),
      resolveAlert: vi.fn(),
      resolveAllAlerts: vi.fn(),
    },
  };
});

const settings: AppSettings = {
  database: { backend: "sqlite", location: "thumper.db" },
  thresholds: { stale_minutes: 15, inactive_hours: 24 },
  dashboard: { refresh_seconds: 15 },
};

const stats: DashboardStats = {
  tripwires: 1,
  endpoints: 1,
  alerts_24h: 1,
  active_triggers: 1,
};

const tripwires: Tripwire[] = [{
  id: "tw-1",
  name: "AWS bait",
  token_type: "aws",
  path: "/Users/alice/.aws/credentials",
  source: "template",
  token: null,
  created_at: "2026-07-01T00:00:00Z",
  active: true,
  deployed_count: 1,
  triggered_count: 1,
}];

const alerts: Alert[] = [
  {
    id: "alert-open",
    deployment_id: "dep-1",
    tripwire_id: "tw-1",
    tripwire_name: "AWS bait",
    endpoint_id: "ep-1",
    endpoint_hostname: "macbook-prod",
    token_type: "aws",
    accessed_path: "/Users/alice/.aws/credentials",
    process: "cat",
    pid: 123,
    os_user: "alice",
    event_type: "read",
    timestamp: "2026-07-01T00:00:00Z",
    triggered_by: null,
    status: "open",
    resolved_at: null,
  },
  {
    id: "alert-resolved",
    deployment_id: "dep-2",
    tripwire_id: "tw-1",
    tripwire_name: "AWS bait",
    endpoint_id: "ep-2",
    endpoint_hostname: "linux-ci",
    token_type: "aws",
    accessed_path: "/home/runner/.aws/credentials",
    process: "python",
    pid: 456,
    os_user: "runner",
    event_type: "read",
    timestamp: "2026-07-01T00:01:00Z",
    triggered_by: null,
    status: "resolved",
    resolved_at: "2026-07-01T00:02:00Z",
  },
];

function renderDashboard() {
  return render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>
  );
}

describe("<Dashboard> page", () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    const storage = {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
      clear: () => values.clear(),
      key: (index: number) => Array.from(values.keys())[index] ?? null,
      get length() {
        return values.size;
      },
    } as Storage;

    Object.defineProperty(globalThis, "localStorage", {
      value: storage,
      configurable: true,
    });

    vi.mocked(api.getSettings).mockResolvedValue(settings);
    vi.mocked(api.getStats).mockResolvedValue(stats);
    vi.mocked(api.listTripwires).mockResolvedValue(tripwires);
    vi.mocked(api.listAlerts).mockResolvedValue(alerts);
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("filters recent alerts with the segmented control", async () => {
    renderDashboard();

    expect(await screen.findByText("macbook-prod")).toBeInTheDocument();
    expect(screen.queryByText("linux-ci")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "all" }));

    expect(screen.getByText("macbook-prod")).toBeInTheDocument();
    expect(screen.getByText("linux-ci")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "resolved" }));

    expect(screen.queryByText("macbook-prod")).not.toBeInTheDocument();
    expect(screen.getByText("linux-ci")).toBeInTheDocument();
    expect(within(screen.getAllByRole("table")[0]).getByText("resolved")).toBeInTheDocument();
  });

  it("uses the configured refresh interval for countdown and reload", async () => {
    vi.useFakeTimers();
    renderDashboard();

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(screen.getAllByText("15s")[0]).toBeInTheDocument();
    expect(api.listAlerts).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(15_000);
    });

    expect(api.listAlerts).toHaveBeenCalledTimes(2);
    expect(screen.getAllByText("15s")[0]).toBeInTheDocument();
    expect(localStorage.getItem("thumper.dashboard.refreshInterval")).toBe("15");
  });
});
