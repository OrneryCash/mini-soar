"""Mini-SOAR — FastAPI app: webhook receiver + Thai web UI + admin API."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

import core

BASE = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(_: FastAPI):
    core.init_db()
    yield


app = FastAPI(title="Mini-SOAR", version="0.1.0", lifespan=lifespan)
templates = Jinja2Templates(directory=str(BASE / "app" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE / "app" / "static")), name="static")


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
            "SELECT count(*) AS n FROM blocks WHERE status IN ('active','simulated') "
            "AND expires_at > ?",
            (core.now_iso(),),
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
            "enabled": b.get("enabled", True),
            "custom": bool(b.get("_custom")),
            "edited": core.has_history(b.get("name", "")),
        })
    # Deep-link demo: /playbooks?test=<name> renders the edit modal server-side
    # (form prefilled + dry-run preview) — deterministic, no JS timing needed
    initial_preview = None
    initial_playbook = None
    test_name = request.query_params.get("test", "")
    if test_name:
        book = core.get_playbook(test_name)
        if book:
            initial_preview = core.preview_playbook(book, core.SAMPLE_ALERT)
            initial_preview["name"] = test_name
            initial_playbook = core.playbook_form_payload(book)
    return templates.TemplateResponse(
        "playbooks.html",
        {"request": request, "books": rows,
         "initial_preview": initial_preview, "initial_playbook": initial_playbook},
    )


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
    rows = [dict(r) | {"human_detail": core.human_action_detail(r)} for r in rows]
    return templates.TemplateResponse("audit.html", {"request": request, "rows": rows})


# --------------------------------------------------------------------------
# Admin API — the UI's buttons talk to these
# --------------------------------------------------------------------------

@app.post("/api/playbooks/{name}/toggle")
async def toggle_playbook(name: str, request: Request) -> JSONResponse:
    body = await request.json()
    core._set_state(name, bool(body.get("enabled", True)))
    return JSONResponse({"name": name, "enabled": body.get("enabled", True)})


# --------------------------------------------------------------------------
# Playbook customization API — the Thai edit form talks to these
# --------------------------------------------------------------------------

@app.get("/api/playbooks")
async def api_playbooks_list() -> JSONResponse:
    books = core.load_playbooks()
    return JSONResponse([
        {k: b.get(k) for k in ("name", "description", "gate", "enabled", "_custom")}
        for b in books
    ])


@app.get("/api/playbooks/{name}")
async def api_playbook_get(name: str) -> JSONResponse:
    book = core.get_playbook(name)
    if not book:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(core.playbook_form_payload(book))


@app.put("/api/playbooks/{name}")
async def api_playbook_put(name: str, request: Request) -> JSONResponse:
    body = await request.json()
    result = core.save_playbook_form(name, body)
    if not result["ok"]:
        return JSONResponse({"error": result["errors"]}, status_code=400)
    return JSONResponse(core.playbook_form_payload(result["playbook"]))


@app.post("/api/playbooks")
async def api_playbook_create(request: Request) -> JSONResponse:
    body = await request.json()
    name = str(body.get("name", "") or "").strip()
    result = core.save_playbook_form(name, body)
    if not result["ok"]:
        return JSONResponse({"error": result["errors"]}, status_code=400)
    return JSONResponse(core.playbook_form_payload(result["playbook"]))


@app.post("/api/playbooks/{name}/test")
async def api_playbook_test(name: str, request: Request) -> JSONResponse:
    body = await request.json() or {}
    alert = body.get("sample_alert") or core.SAMPLE_ALERT
    if not isinstance(alert, dict):
        return JSONResponse({"error": ["alert ตัวอย่างไม่ถูกต้อง — ต้องเป็น JSON object"]},
                            status_code=400)
    if body.get("draft"):
        # Preview an UNSAVED form draft — validate, build, dry-run (no side effects)
        locks = (core.get_playbook(name) or {}).get("locks") or {}
        errs, clean = core.validate_playbook_form(body["draft"], locks)
        if errs:
            return JSONResponse({"error": errs}, status_code=400)
        return JSONResponse(core.preview_playbook(core.book_from_form(name, clean), alert))
    book = core.get_playbook(name)
    if not book:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(core.preview_playbook(book, alert))


@app.post("/api/playbooks/{name}/revert")
async def api_playbook_revert(name: str) -> JSONResponse:
    result = core.revert_playbook(name)
    if not result["ok"]:
        return JSONResponse({"error": result["error"]}, status_code=400)
    return JSONResponse(core.playbook_form_payload(result["playbook"]))


@app.delete("/api/playbooks/{name}")
async def api_playbook_delete(name: str) -> JSONResponse:
    result = core.delete_playbook(name)
    if not result["ok"]:
        return JSONResponse({"error": result["error"]}, status_code=400)
    return JSONResponse({"ok": True})


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


@app.get("/api/approvals")
async def api_approvals(limit: int = 50, status: str = "") -> JSONResponse:
    core.check_expired_approvals()  # keep the queue truthful to the time-box
    with core.db_conn() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status=? ORDER BY id DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM approvals ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return JSONResponse([dict(r) for r in rows])


@app.get("/api/stats")
async def api_stats() -> JSONResponse:
    """Live counters for the UI's auto-refresh (badge + cards)."""
    core.check_expired_approvals()
    with core.db_conn() as conn:
        return {
            "pending": conn.execute(
                "SELECT count(*) AS n FROM approvals WHERE status='pending'"
            ).fetchone()["n"],
            "active_blocks": conn.execute(
                "SELECT count(*) AS n FROM blocks WHERE status IN ('active','simulated') "
                "AND expires_at > ?",
                (core.now_iso(),),
            ).fetchone()["n"],
            "total_alerts": conn.execute(
                "SELECT count(*) AS n FROM alerts"
            ).fetchone()["n"],
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
