"""Mini-SOAR — FastAPI app: webhook receiver + Thai web UI + admin API."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import core

BASE = Path(__file__).resolve().parent.parent
app = FastAPI(title="Mini-SOAR", version="0.1.0")
templates = Jinja2Templates(directory=str(BASE / "app" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "app" / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    core.init_db()


class AlertIn(BaseModel):
    """Any SIEM's alert JSON — fields are optional; we normalize."""
    pass


# --------------------------------------------------------------------------
# SIEM-agnostic webhook — THE entry point for any SIEM
# --------------------------------------------------------------------------

@app.post("/webhook")
async def webhook(request: Request) -> JSONResponse:
    secret = core.CONFIG.get("webhook_secret", "")
    if secret:
        got = request.headers.get("X-Mini-SOAR-Secret", "")
        if got != secret:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        alert = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "invalid JSON"}, status_code=400)
    if not isinstance(alert, dict):
        return JSONResponse({"error": "expected JSON object"}, status_code=400)
    result = core.process_alert(alert)
    return JSONResponse(result)


# --------------------------------------------------------------------------
# Thai web UI — for the non-technical admin (forms, toggles, buttons)
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    with core.db_conn() as conn:
        alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"
        ).fetchall()
        actions = conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT 20"
        ).fetchall()
        pending = conn.execute(
            "SELECT count(*) AS n FROM approvals WHERE status='pending'"
        ).fetchone()["n"]
        active_blocks = conn.execute(
            "SELECT count(*) AS n FROM blocks WHERE status IN ('active','simulated')"
        ).fetchone()["n"]
        total_alerts = conn.execute("SELECT count(*) AS n FROM alerts").fetchone()["n"]
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "alerts": alerts,
            "actions": actions,
            "pending": pending,
            "active_blocks": active_blocks,
            "total_alerts": total_alerts,
        },
    )


@app.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request) -> HTMLResponse:
    books = core.load_playbooks()
    rows = []
    for b in books:
        rows.append({
            "name": b.get("name"),
            "description": b.get("description", ""),
            "gate": b.get("gate", "auto"),
            "enabled": core._state_enabled(b.get("name", ""), b.get("enabled", True)),
        })
    return templates.TemplateResponse("playbooks.html", {"request": request, "books": rows})


@app.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request) -> HTMLResponse:
    with core.db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM approvals WHERE status='pending' ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return templates.TemplateResponse("approvals.html", {"request": request, "rows": rows})


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request) -> HTMLResponse:
    with core.db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return templates.TemplateResponse("audit.html", {"request": request, "rows": rows})


# --------------------------------------------------------------------------
# Admin API — the UI's buttons talk to these
# --------------------------------------------------------------------------

@app.post("/api/playbooks/{name}/toggle")
async def toggle_playbook(name: str, request: Request) -> JSONResponse:
    body = await request.json()
    core._set_state(name, bool(body.get("enabled", True)))
    return JSONResponse({"name": name, "enabled": body.get("enabled", True)})


@app.post("/api/approvals/{approval_id}/approve")
async def approve_action(approval_id: int) -> JSONResponse:
    return JSONResponse(core.approve(approval_id, True))


@app.post("/api/approvals/{approval_id}/deny")
async def deny_action(approval_id: int) -> JSONResponse:
    return JSONResponse(core.approve(approval_id, False))


@app.get("/api/alerts")
async def api_alerts(limit: int = 20) -> JSONResponse:
    with core.db_conn() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/actions")
async def api_actions(limit: int = 50) -> JSONResponse:
    with core.db_conn() as conn:
        rows = conn.execute("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return JSONResponse([dict(r) for r in rows])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
