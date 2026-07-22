import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { httpApi } from "./http.ts";
import { clearAdminToken, setAdminToken } from "./auth.ts";

describe("honeytoken API client", () => {
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
    ok({ id: "htc_1", name: "DD", plugin: "datadog", configured: false, config: {}, created_at: "t" });
    await httpApi.createHoneytokenConnection({
      name: "DD", plugin: "datadog", config: { api_key: "k" } });
    expect(fetchMock).toHaveBeenCalledWith("/api/honeytokens/connections", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ name: "DD", plugin: "datadog", config: { api_key: "k" } }),
    }));
  });

  it("tests a connection via POST to its /test path", async () => {
    ok({ ok: true, error: null });
    await expect(httpApi.testHoneytokenConnection("htc_9")).resolves.toEqual({ ok: true, error: null });
    expect(fetchMock).toHaveBeenCalledWith("/api/honeytokens/connections/htc_9/test",
      expect.objectContaining({ method: "POST" }));
  });

  it("creates a honeytoken with connection + name", async () => {
    ok({ id: "ht_1", name: "canary", token_type: "api_key", state: "active" });
    await httpApi.createHoneytoken({ connection_id: "htc_1", name: "canary" });
    expect(fetchMock).toHaveBeenCalledWith("/api/honeytokens/tokens", expect.objectContaining({
      method: "POST",
      body: JSON.stringify({ connection_id: "htc_1", name: "canary" }),
    }));
  });

  it("fetches usage logs for a token", async () => {
    ok([{ id: "hul_1", event_id: "e1", actor: "mallory", source_ip: "10.0.0.1", action: "query", timestamp: "t" }]);
    const logs = await httpApi.listHoneytokenUsage("ht_1");
    expect(logs[0].actor).toBe("mallory");
    expect(fetchMock).toHaveBeenCalledWith("/api/honeytokens/tokens/ht_1/usage",
      expect.objectContaining({ headers: expect.objectContaining({ authorization: "Bearer admin-secret" }) }));
  });

  it("deletes a token via DELETE", async () => {
    ok({ status: "ok" });
    await httpApi.deleteHoneytoken("ht_1");
    expect(fetchMock).toHaveBeenCalledWith("/api/honeytokens/tokens/ht_1",
      expect.objectContaining({ method: "DELETE" }));
  });
});
