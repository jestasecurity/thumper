import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpApi } from "./http.ts";
import { clearAdminToken, getAdminToken, setAdminToken } from "./auth.ts";

describe("httpApi auth handling", () => {
  const fetchMock = vi.fn();
  const reloadMock = vi.fn();

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
    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
    });
    Object.defineProperty(window, "location", {
      value: { ...window.location, reload: reloadMock },
      configurable: true,
    });
  });

  afterEach(() => {
    clearAdminToken();
    fetchMock.mockReset();
    reloadMock.mockReset();
  });

  it("sends the stored admin token as a bearer header", async () => {
    setAdminToken("admin-secret");
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        tripwires: 1,
        endpoints: 2,
        alerts_24h: 3,
        active_triggers: 4,
      }),
    });

    await expect(httpApi.getStats()).resolves.toEqual({
      tripwires: 1,
      endpoints: 2,
      alerts_24h: 3,
      active_triggers: 4,
    });

    expect(fetchMock).toHaveBeenCalledWith("/api/stats", {
      headers: {
        "content-type": "application/json",
        authorization: "Bearer admin-secret",
      },
    });
  });

  it("clears the admin token and reloads on 401 responses", async () => {
    setAdminToken("expired-token");
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      json: async () => ({ detail: "invalid or missing admin token" }),
    });

    await expect(httpApi.getStats()).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      message: "401: invalid or missing admin token",
    });

    expect(getAdminToken()).toBe("");
    expect(reloadMock).toHaveBeenCalledTimes(1);
  });
});
