"""Thumper monolith entrypoint: `uvicorn thumper.main:app`.

Serves the JSON API under /api and, when a built UI exists at ui/dist (Docker /
monolith mode), the React app at /.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import router
from .config import UI_DIST, insecure_default_tokens
from .db import init_db
from .services.secrets_crypto import encryption_enabled

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("thumper")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    flagged = insecure_default_tokens()
    if flagged:
        log.warning(
            "SECURITY: %s still set to the built-in dev default(s) - anyone can "
            "guess them. Set them to random secrets (env vars) before production.",
            ", ".join(flagged),
        )
    if not encryption_enabled():
        log.warning(
            "SECURITY: integration secrets are stored UNENCRYPTED at rest - set "
            "THUMPER_SECRET_KEY to encrypt them (#24).")
    yield


app = FastAPI(title="Thumper", version="0.1.0", lifespan=lifespan)

# In dev the UI runs on :5173 and proxies /api → :8000, so it's same-origin to
# the browser; CORS is permissive here to keep direct API calls / tools simple.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.exception_handler(StarletteHTTPException)
async def spa_fallback_handler(request: Request, exc: StarletteHTTPException):
    """SPA fallback: serve index.html for unknown UI paths so client-side routes
    (e.g. refreshing /tripwires) load and React handles routing - including its
    own catch-all 404. API/health 404s stay JSON.
    """
    path = request.url.path
    index = UI_DIST / "index.html"
    if (
        exc.status_code == 404
        and not (path.startswith("/api") or path == "/healthz")
        and index.is_file()
    ):
        return HTMLResponse(index.read_text())
    # Preserve any headers the original error carried (e.g. Allow on a 405,
    # WWW-Authenticate on a 401) - this handler overrides the default one, which
    # would otherwise have set them.
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                        headers=getattr(exc, "headers", None))


# Serve the built SPA last so it only catches paths the API didn't.
if UI_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(UI_DIST), html=True), name="ui")
