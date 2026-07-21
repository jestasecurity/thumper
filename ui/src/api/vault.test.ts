import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpApi } from "./http.ts";
import { clearAdminToken, setAdminToken } from "./auth.ts";

describe("vault API client", () => {
  const fetchMock = vi.fn();

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
    Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });
    Object.defineProperty(globalThis, "fetch", { value: fetchMock, configurable: true });
    setAdminToken("admin-secret");
  });

  afterEach(() => {
    clearAdminToken();
    fetchMock.mockReset();
  });

  function ok(body: unknown) {
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => body });
  }

  it("creates a connection with a JSON body", async () => {
    ok({ id: "vc_1", name: "Prod", plugin: "hashicorp", configured: false, config: {}, created_at: "t" });
    await httpApi.createVaultConnection({ name: "Prod", plugin: "hashicorp", config: { url: "http://v" } });
    expect(fetchMock).toHaveBeenCalledWith("/api/vault/connections", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ name: "Prod", plugin: "hashicorp", config: { url: "http://v" } }),
    }));
  });

  it("tests a connection via POST to its /test path", async () => {
    ok({ ok: true, error: null });
    await expect(httpApi.testVaultConnection("vc_9")).resolves.toEqual({ ok: true, error: null });
    expect(fetchMock).toHaveBeenCalledWith("/api/vault/connections/vc_9/test",
      expect.objectContaining({ method: "POST" }));
  });

  it("plants a canary secret with the template and path", async () => {
    ok({ id: "cs_1", template: "stripe", state: "planted" });
    await httpApi.createCanarySecret({ vault_connection_id: "vc_1", template: "stripe", path: "prod/stripe" });
    expect(fetchMock).toHaveBeenCalledWith("/api/vault/secrets", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ vault_connection_id: "vc_1", template: "stripe", path: "prod/stripe" }),
    }));
  });

  it("fetches access logs for a secret", async () => {
    ok([{ id: "cal_1", event_id: "e1", accessor: "mallory", source_ip: "10.0.0.1", timestamp: "t" }]);
    const logs = await httpApi.listCanaryAccessLogs("cs_1");
    expect(logs[0].accessor).toBe("mallory");
    expect(fetchMock).toHaveBeenCalledWith("/api/vault/secrets/cs_1/access-logs",
      expect.objectContaining({ headers: expect.objectContaining({ authorization: "Bearer admin-secret" }) }));
  });

  it("deletes a connection via DELETE", async () => {
    ok({ status: "ok" });
    await httpApi.deleteVaultConnection("vc_1");
    expect(fetchMock).toHaveBeenCalledWith("/api/vault/connections/vc_1",
      expect.objectContaining({ method: "DELETE" }));
  });
});
