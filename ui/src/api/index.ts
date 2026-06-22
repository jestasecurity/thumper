// Single import point for the API, wired to the real FastAPI backend.
// The Vite dev proxy forwards /api → http://localhost:8000.
//
// Token generation + the token-type catalog come from the SERVER
// (api.getTokenTypes / api.previewToken) - the browser never generates
// honeytokens, because creating one is security-relevant (per-instance HMAC).
export { httpApi as api, ApiError } from "./http";
export * from "./types";
