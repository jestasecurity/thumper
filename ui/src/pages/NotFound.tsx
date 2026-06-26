import { Link } from "react-router-dom";
import PageTitle from "../components/PageTitle.tsx";
import { APP_NAME } from "../config/app.ts";

// Catch-all for unknown client routes. Real pages refresh fine (the server
// serves index.html and React renders them); only genuinely unknown paths fall
// through to here. The looping GIF is the same asset the sidebar uses.
export default function NotFound() {
  const PAGE_TITLE = "404 - Not Found";

  return (
    <>
      <PageTitle title={PAGE_TITLE} />
      <div
        style={{
          minHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "1.5rem",
          textAlign: "center",
        }}
      >
        <img src="/thumper_gif.gif" alt="Thumper" style={{width: 180, height: "auto"}} />
        <h1 style={{margin: 0, fontSize: "2.25rem", letterSpacing: ".12em"}}>
          {PAGE_TITLE}
        </h1>
        <Link to="/" style={{color: "#7c9cff", textDecoration: "none"}}>
          ← back to {APP_NAME}
        </Link>
      </div>
    </>
  );
}
