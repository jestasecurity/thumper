import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { CredentialSource, TokenType, TokenTypeInfo } from "../api";
import { api } from "../api";
import { Topbar } from "../components/ui.tsx";
import PageTitle from "../components/PageTitle.tsx";

const SOURCES: { key: CredentialSource; label: string; desc: string; soon?: boolean }[] = [
  { key: "template", label: "Generated template", desc: "A realistic fake we generate. Alerts on read." },
  { key: "custom", label: "Bring your own", desc: "Paste a real-but-revoked credential.", soon: true },
  { key: "managed", label: "Managed canary", desc: "Monitored real credential - detects use off the box.", soon: true },
];

export default function CreateTripwire() {
  const nav = useNavigate();
  const [types, setTypes] = useState<TokenTypeInfo[]>([]);
  const [type, setType] = useState<TokenType>("aws");
  const [source] = useState<CredentialSource>("template"); // only template active in v1
  const [name, setName] = useState("");
  const [path, setPath] = useState("");
  const [content, setContent] = useState("");
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const PAGE_TITLE = "Create tripwire";

  const info = useMemo(() => types.find((t) => t.type === type), [types, type]);
  const isRecommended = !!info && info.suggested_paths.includes(path.trim());

  useEffect(() => {
    api
      .getTokenTypes()
      .then((catalog) => {
        setTypes(catalog);
        const first = catalog[0];
        if (first) {
          setType(first.type);
          setPath(first.default_path);
          api.previewToken(first.type).then((p) => setContent(p.content)).catch(() => {});
        }
      })
      .catch((e) =>
        setLoadError(
          `Couldn't load the credential catalog from the backend (${(e as Error).message}). ` +
            `Is the server running on :8000?`,
        ),
      );
  }, []);

  async function pickType(t: TokenType) {
    setType(t);
    const i = types.find((x) => x.type === t);
    if (i) setPath(i.default_path);
    setContent((await api.previewToken(t)).content);
  }

  async function regenerate() {
    setContent((await api.previewToken(type)).content);
  }

  async function submit() {
    if (!name.trim() || !path.trim()) return;
    setSaving(true);
    try {
      const tw = await api.createTripwire({
        name: name.trim(), token_type: type, path: path.trim(), source, token: content,
      });
      nav(`/tripwires/${tw.id}`); // land on the install page
    } catch (e) {
      setSaving(false);
      alert(`Could not create tripwire: ${(e as Error).message}`);
    }
  }

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <Topbar title={PAGE_TITLE} />
      <div className="content">
        {loadError && <div className="banner">⚠ {loadError}</div>}
        <div className="card">
          <div className="step-label">Step 1 · Credential source</div>
          <div className="provider-grid">
            {SOURCES.map((s) => (
              <div
                key={s.key}
                className={`provider ${source === s.key ? "selected" : ""} ${s.soon ? "disabled" : ""}`}
                title={s.soon ? "Coming soon" : ""}
              >
                <div className="provider-name">
                  {s.label} {s.soon && <span className="soon">soon</span>}
                </div>
                <div className="provider-desc">{s.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="step-label">Step 2 · Pick a credential to fake</div>
          <div className="provider-grid">
            {types.map((t) => (
              <div
                key={t.type}
                className={`provider ${type === t.type ? "selected" : ""}`}
                onClick={() => pickType(t.type)}
              >
                <div className="provider-name">{t.display_name}</div>
                <div className="provider-desc">{t.description}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="step-label">Step 3 · Name &amp; placement</div>
          <div className="field">
            <label>Name <span className="req">*</span></label>
            <input
              type="text"
              value={name}
              placeholder="e.g. AWS prod creds - engineering laptops"
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="field">
            <label>Target path on endpoint <span className="req">*</span></label>
            <input
              type="text"
              value={path}
              placeholder="~/.aws/credentials, ./config/.env, /etc/ssh/ssh_host_rsa_key, …"
              onChange={(e) => setPath(e.target.value)}
            />
            <div className="help">
              {isRecommended ? (
                <span className="rec-yes">★ Recommended location - attackers commonly inspect this path.</span>
              ) : (
                <span>Free text - any absolute, relative, or <code>~</code> path works.</span>
              )}
            </div>
            {info && info.suggested_paths.length > 0 && (
              <>
                <div className="muted" style={{ fontSize: 11, margin: "10px 0 6px" }}>
                  ★ Recommended for {info.display_name.toLowerCase()} (where Shai-Hulud scans):
                </div>
                <div className="suggestions">
                  {info.suggested_paths.map((p) => (
                    <button
                      type="button"
                      key={p}
                      className={`chip ${path === p ? "active" : ""}`}
                      onClick={() => setPath(p)}
                    >
                      ★ {p}
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        <div className="card">
          <div className="step-label">Step 4 · Honeytoken content</div>
          <div className="spread" style={{ marginBottom: 10 }}>
            <span className="muted">
              This is the credential that will be planted on endpoints.
            </span>
            <button className="btn" onClick={regenerate}>↻ Regenerate</button>
          </div>
          <textarea value={content} readOnly />
        </div>

        <div className="row">
          <button className="btn primary" disabled={saving || !name.trim() || !path.trim()} onClick={submit}>
            {saving ? "Creating…" : "Create tripwire"}
          </button>
          <button className="btn" onClick={() => nav("/tripwires")}>Cancel</button>
        </div>
      </div>
    </>
  );
}
