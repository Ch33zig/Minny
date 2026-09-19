"""FastAPI application wiring (owned by track B).

Every track's routes live in its own module so nobody has to edit a shared
file. The imports below name all four router modules before they exist; a
module that is not written yet logs a warning and the rest of the app still
serves. Create your router file with the agreed name and you are wired up.

Route ownership is fixed in docs/handoff/00-CONTRACTS.md section 12.
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("minny.api")

ROUTER_MODULES = (
    "minny.api.routes_case",  # A: case file, evidence lookup
    "minny.api.routes_detect",  # B: baselines, incidents, replay, SSE
    "minny.api.routes_redteam",  # C: variant generation, metrics, blue agent
    "minny.api.routes_integrations",  # D: Slack, Gmail evidence
)

WEB_DIR = Path("dist")

app = FastAPI(title="Minny", version="0.1.0")


def _register_routers() -> list[str]:
    """Import each track's router independently.

    One track being mid-build must never take down the API for the other
    three, so an import failure is a warning and a missing capability, not a
    crash.
    """
    registered = []
    for module_name in ROUTER_MODULES:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            logger.warning("router %s not present yet, skipping", module_name)
            continue
        except Exception:  # noqa: BLE001 - a broken router must not be fatal
            logger.exception("router %s failed to import", module_name)
            continue

        router = getattr(module, "router", None)
        if router is None:
            logger.warning("router %s has no `router` attribute", module_name)
            continue

        app.include_router(router, prefix="/api")
        registered.append(module_name)
    return registered


REGISTERED = _register_routers()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "routers": REGISTERED}


@app.exception_handler(404)
async def api_404(request, exc):  # noqa: ANN001, ARG001
    """A missing /api route returns JSON, never the single-page app shell."""
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "not_found",
                    "message": f"No route for {request.url.path}",
                }
            },
        )
    return JSONResponse(status_code=404, content={"error": {"code": "not_found"}})


# Static assets mount last so it can never shadow an API route.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
