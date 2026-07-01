// Admin token for the management API (#20). Stored in localStorage and sent as
// `Authorization: Bearer <token>` on every /api request (see http.ts). The
// AdminGate prompts for it; a 401 clears it and re-prompts.
const KEY = "thumper.adminToken";

export const getAdminToken = (): string => localStorage.getItem(KEY) ?? "";
export const setAdminToken = (t: string): void => localStorage.setItem(KEY, t.trim());
export const clearAdminToken = (): void => localStorage.removeItem(KEY);
