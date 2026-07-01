import { useState, type ReactNode } from "react";
import { getAdminToken, setAdminToken } from "./api/auth";

// Token-entry gate for the management console (#20). The server gates every
// /api management route on THUMPER_ADMIN_TOKEN; the SPA stores the operator's
// token and sends it as a bearer header (see api/http.ts). No token → this
// screen; a wrong token gets a 401 which clears it and lands back here.
export default function AdminGate({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState(() => getAdminToken() !== "");
  const [value, setValue] = useState("");

  if (authed) return <>{children}</>;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const t = value.trim();
    if (!t) return;
    setAdminToken(t);
    setAuthed(true);
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: "2rem" }}>
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: ".75rem", width: "min(360px, 100%)" }}>
        <h1 style={{ margin: 0 }}>Thumper</h1>
        <p style={{ margin: 0, opacity: 0.7 }}>Enter the admin token to access the console.</p>
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Admin token"
          aria-label="Admin token"
          autoFocus
          style={{ padding: ".6rem .75rem", fontSize: "1rem" }}
        />
        <button type="submit" disabled={!value.trim()} style={{ padding: ".6rem .75rem" }}>
          Continue
        </button>
      </form>
    </div>
  );
}
