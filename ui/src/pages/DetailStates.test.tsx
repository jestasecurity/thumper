import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import "@testing-library/jest-dom/vitest";
import EndpointDetail from "./EndpointDetail.tsx";
import TripwireDetail from "./TripwireDetail.tsx";
import type { EndpointDetail as EndpointDetailData, Tripwire, TripwireDetail as TripwireDetailData } from "../api";
import { api, ApiError } from "../api";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      getTripwire: vi.fn(),
      renameTripwire: vi.fn(),
      deleteTripwire: vi.fn(),
      distributeTripwire: vi.fn(),
      getEndpoint: vi.fn(),
      listTripwires: vi.fn(),
      assignTripwire: vi.fn(),
      unassignTripwire: vi.fn(),
      decommissionEndpoint: vi.fn(),
      removeEndpoint: vi.fn(),
    },
  };
});

const tripwireDetail: TripwireDetailData = {
  id: "tw-1",
  name: "AWS bait",
  token_type: "aws",
  path: "/Users/alice/.aws/credentials",
  source: "template",
  token: "AKIAEXAMPLE",
  created_at: "2026-07-01T00:00:00Z",
  active: true,
  deployed_count: 0,
  triggered_count: 0,
  deployments: [],
  install: {
    tripwire_id: "tw-1",
    server_url: "https://thumper.example",
    enroll_token: "enroll-token",
    command: "curl https://thumper.example/install.sh | sh",
  },
};

const endpointDetail: EndpointDetailData = {
  id: "ep-1",
  hostname: "macbook-prod",
  platform: "darwin",
  enrolled_at: "2026-07-01T00:00:00Z",
  last_seen: "2026-07-01T00:05:00Z",
  status: "online",
  deployment_count: 0,
  triggered_count: 0,
  deployments: [],
};

const availableTripwire: Tripwire = {
  id: "tw-1",
  name: "AWS bait",
  token_type: "aws",
  path: "/Users/alice/.aws/credentials",
  source: "template",
  token: null,
  created_at: "2026-07-01T00:00:00Z",
  active: true,
  deployed_count: 0,
  triggered_count: 0,
};

function renderTripwireDetail() {
  return render(
    <MemoryRouter initialEntries={["/tripwires/tw-1"]}>
      <Routes>
        <Route path="/tripwires/:id" element={<TripwireDetail />} />
      </Routes>
    </MemoryRouter>
  );
}

function renderEndpointDetail() {
  return render(
    <MemoryRouter initialEntries={["/endpoints/ep-1"]}>
      <Routes>
        <Route path="/endpoints/:id" element={<EndpointDetail />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("detail page empty/error states", () => {
  beforeEach(() => {
    vi.mocked(api.listTripwires).mockResolvedValue([availableTripwire]);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows a tripwire not-found state for 404s", async () => {
    vi.mocked(api.getTripwire).mockRejectedValue(new ApiError(404, "404: Not found"));

    renderTripwireDetail();

    expect(await screen.findByRole("heading", { name: "Tripwire not found" })).toBeInTheDocument();
    expect(screen.getByText(/doesn't exist or was deleted/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /All tripwires/i })).toHaveAttribute("href", "/tripwires");
  });

  it("lets tripwire load errors retry into the normal detail view", async () => {
    vi.mocked(api.getTripwire)
      .mockRejectedValueOnce(new Error("network down"))
      .mockResolvedValueOnce(tripwireDetail);

    renderTripwireDetail();

    expect(await screen.findByRole("heading", { name: "Couldn't load tripwire" })).toBeInTheDocument();
    expect(screen.getByText(/network down/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("heading", { name: "AWS bait" })).toBeInTheDocument();
    expect(screen.getByText("Honeytoken")).toBeInTheDocument();
  });

  it("shows an endpoint not-found state for 404s", async () => {
    vi.mocked(api.getEndpoint).mockRejectedValue(new ApiError(404, "404: Not found"));

    renderEndpointDetail();

    expect(await screen.findByRole("heading", { name: "Endpoint not found" })).toBeInTheDocument();
    expect(screen.getByText(/doesn't exist or was removed/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /All endpoints/i })).toHaveAttribute("href", "/endpoints");
  });

  it("lets endpoint load errors retry into the normal detail view", async () => {
    vi.mocked(api.getEndpoint)
      .mockRejectedValueOnce(new Error("backend unavailable"))
      .mockResolvedValueOnce(endpointDetail);

    renderEndpointDetail();

    expect(await screen.findByRole("heading", { name: "Couldn't load endpoint" })).toBeInTheDocument();
    expect(screen.getByText(/backend unavailable/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    expect(await screen.findByRole("heading", { name: "macbook-prod" })).toBeInTheDocument();
    expect(screen.getByText("macOS")).toBeInTheDocument();
  });
});
