"""Mini-SOAR — core service.

Webhook receiver (SIEM-agnostic) -> rules engine (YAML playbooks) -> actions.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parent.parent


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config() -> dict:
    with open(BASE / "config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


CONFIG = load_config()


# --------------------------------------------------------------------------
# Audit store (SQLite) — PDPA defensible log
# --------------------------------------------------------------------------

def db_conn() -> sqlite3.Connection:
    db_path = BASE / CONFIG.get("data_dir", "data") / "minisoar.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                source TEXT,
                title TEXT,
                severity INTEGER DEFAULT 0,
                raw TEXT NOT NULL,
                matched_playbooks TEXT
            );
            CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                alert_id INTEGER,
                playbook TEXT,
                action TEXT,
                detail TEXT,
                status TEXT DEFAULT 'executed'
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                alert_id INTEGER,
                playbook TEXT,
                action TEXT,
                params TEXT,
                summary TEXT,
                status TEXT DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                duration INTEGER,
                expires_at TEXT,
                backend TEXT,
                status TEXT DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS playbook_state (
                name TEXT PRIMARY KEY,
                enabled INTEGER DEFAULT 1
            );
            """
        )


def audit_insert(table: str, **cols) -> int:
    with db_conn() as conn:
        keys = ", ".join(cols.keys())
        marks = ", ".join("?" for _ in cols)
        cur = conn.execute(
            f"INSERT INTO {table} ({keys}) VALUES ({marks})", list(cols.values())
        )
        return cur.lastrowid


# --------------------------------------------------------------------------
# Field extraction — accept any SIEM's JSON shape
# --------------------------------------------------------------------------

def _get_path(obj, path: str):
    """Resolve dotted path like data.srcip or rule.id against a dict."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def extract_fields(alert: dict) -> dict:
    """Flatten common SIEM field names into a canonical namespace.

    Handles real schemas:
    - Wazuh:    rule.description/level/groups, agent.name, data.srcip, predecoded
    - Elastic:  ECS — source.ip, destination.ip, host.name, user.name, rule.name,
                event.category/severity, file.hash.sha256, url.full
    - Splunk:   CIM-ish — src_ip/src_port, dest_ip, signature, host, sourcetype
    - Sentinel: name, severity string, entities[] (ip/host/account)
    """
    out = {}
    aliases = {
        "src_ip": ["data.srcip", "data.src_ip", "src_ip", "srcip",
                   "source.ip", "source_ip", "data.source_ip", "data.src",
                   "predecoded.srcip", "event.src_ip"],
        "dst_ip": ["data.dstip", "data.dst_ip", "dst_ip", "dstip",
                   "destination.ip", "destination_ip", "dest_ip",
                   "data.dst", "predecoded.dstip", "event.dest_ip"],
        "user": ["data.user", "user.name", "username", "data.username",
                 "user", "predecoded.user", "data.srcuser", "event.user"],
        "host": ["agent.name", "host.name", "hostname", "data.host",
                 "host", "agent.hostname", "data.hostname",
                 "predecoded.hostname", "event.hostname"],
        "hash": ["data.hash", "file.hash.sha256", "file.hash.md5",
                 "data.md5", "data.sha256", "hash", "sha256", "md5"],
        "url": ["data.url", "url.full", "url.domain", "url",
                 "data.full_url", "data.reference"],
        "rule_id": ["rule.id", "rule_id", "event.code"],
        "rule_group": ["rule.groups", "rule.group", "event.category",
                        "rule.category", "rule_group"],
    }
    for canon, paths in aliases.items():
        for p in paths:
            v = _get_path(alert, p)
            if v is not None and v != "":
                if isinstance(v, list):
                    v = ",".join(str(x) for x in v)
                out[canon] = str(v)
                break
    # Title: generic, then Wazuh rule.description, ECS rule.name, Splunk
    # signature, Sentinel name, then message as last resort
    out["title"] = str(
        alert.get("title")
        or _get_path(alert, "rule.description")
        or _get_path(alert, "rule.name")
        or _get_path(alert, "event.signature")
        or _get_path(alert, "signature")
        or alert.get("name")
        or alert.get("message")
        or ""
    )
    # Severity: numeric (generic -> Wazuh rule.level -> ECS event.severity),
    # or a named string (High/Critical -> high number)
    sev = alert.get("severity") or alert.get("level") \
        or _get_path(alert, "rule.level") or _get_path(alert, "event.severity")
    out["severity"] = _to_severity(sev)
    # Source system: agent/host name, event.module, sourcetype, or string
    src = _get_path(alert, "agent.name") or _get_path(alert, "host.name") \
        or _get_path(alert, "event.module") or alert.get("sourcetype") \
        or alert.get("provider")
    if isinstance(src, dict):
        src = src.get("name", "unknown")
    out["source"] = str(src or "unknown")
    out["timestamp"] = str(alert.get("timestamp") or alert.get("@timestamp")
                            or alert.get("_time") or now_iso())
    _extract_sentinel_entities(alert, out)
    return out


def _to_severity(sev):
    if sev is None:
        return 0
    try:
        return int(sev)
    except (TypeError, ValueError):
        pass
    mapping = {"critical": 15, "high": 12, "medium": 8, "low": 4,
               "informational": 1, "info": 1}
    return mapping.get(str(sev).strip().lower(), 0)


def _extract_sentinel_entities(alert: dict, out: dict) -> None:
    """Microsoft Sentinel alerts carry entities[] instead of flat fields."""
    for ent in alert.get("entities") or []:
        if not isinstance(ent, dict):
            continue
        etype = str(ent.get("type", "")).lower()
        if etype == "ip" and "src_ip" not in out and ent.get("address"):
            out["src_ip"] = str(ent["address"])
        elif etype == "host" and "host" not in out and ent.get("hostName"):
            out["host"] = str(ent["hostName"])
        elif etype == "account" and "user" not in out and ent.get("name"):
            out["user"] = str(ent["name"])


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def _line_notify(message: str) -> dict:
    token = CONFIG.get("line_token", "")
    if not token:
        return {"status": "simulated", "detail": "LINE token not set — notification simulated"}
    url = CONFIG["line_notify_url"]
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode({"message": message}).encode(),
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"status": "sent", "detail": f"HTTP {resp.status}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "detail": str(exc)}


def _safe_format(template: str, fields: dict) -> str:
    """Format {field} placeholders; missing fields become '' (no KeyError)."""
    def _repl(m):
        return str(fields.get(m.group(1), ""))
    import re as _re
    return _re.sub(r"\{([a-zA-Z0-9_]+)\}", _repl, template)


def action_notify(fields: dict, template: str, alert_id: int, playbook: str) -> dict:
    msg = _safe_format(template, fields) if template else f"Alert: {fields.get('title')}"
    result = _line_notify(msg)
    audit_insert(
        "actions", ts=now_iso(), alert_id=alert_id, playbook=playbook,
        action="notify", detail=json.dumps({"message": msg, **result}, ensure_ascii=False),
    )
    return result


def action_block_ip(fields: dict, ip_field: str, duration: int, alert_id: int,
                    playbook: str) -> dict:
    ip = fields.get(ip_field or "src_ip", "")
    if not ip:
        return {"status": "skipped", "detail": "no source IP in alert"}
    backend = CONFIG.get("firewall_backend", "simulated")
    dur = duration or CONFIG.get("block_default_duration", 600)
    expires = datetime.now(timezone.utc).timestamp() + dur
    expires_iso = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(timespec="seconds")

    if backend == "iptables":
        # Linux real block; best-effort, logged
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            import subprocess
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)
            status = "blocked"
            detail = f"iptables: {ip} blocked for {dur}s"
            threading.Timer(dur, _iptables_unblock, args=(ip,)).start()
        except Exception as exc:  # noqa: BLE001
            status = "error"
            detail = str(exc)
    else:
        status = "simulated"
        detail = f"SIMULATED block of {ip} for {dur}s (backend: {backend})"

    audit_insert(
        "blocks", ts=now_iso(), ip=ip, duration=dur,
        expires_at=expires_iso, backend=backend, status=status,
    )
    audit_insert(
        "actions", ts=now_iso(), alert_id=alert_id, playbook=playbook,
        action="block_ip", detail=json.dumps({"ip": ip, "duration": dur, **{"result": detail}}, ensure_ascii=False),
    )
    return {"status": status, "detail": detail, "ip": ip}


def _iptables_unblock(ip: str) -> None:
    import subprocess
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                   check=False, capture_output=True, timeout=10)


def action_isolate_host(fields: dict, host_field: str, alert_id: int, playbook: str) -> dict:
    """Disruptive action — by policy always human-gated upstream.
    Simulated: marks host isolated in the blocks table for the demo."""
    host = fields.get(host_field or "host", "")
    detail = f"HOST ISOLATED (simulated): {host}" if host else "no host in alert"
    audit_insert(
        "actions", ts=now_iso(), alert_id=alert_id, playbook=playbook,
        action="isolate_host", detail=detail,
    )
    return {"status": "isolated_simulated", "detail": detail, "host": host}


def action_evidence(fields: dict, alert: dict, alert_id: int, playbook: str) -> dict:
    ev_dir = BASE / CONFIG.get("evidence_dir", "evidence")
    ev_dir.mkdir(parents=True, exist_ok=True)
    path = ev_dir / f"alert-{alert_id}-{int(time.time())}.json"
    path.write_text(json.dumps(alert, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_insert(
        "actions", ts=now_iso(), alert_id=alert_id, playbook=playbook,
        action="preserve_evidence", detail=str(path),
    )
    return {"status": "saved", "detail": str(path)}


# --------------------------------------------------------------------------
# Rules engine — declarative YAML playbooks, hot-reload
# --------------------------------------------------------------------------

def load_playbooks() -> list[dict]:
    pdir = BASE / CONFIG.get("playbooks_dir", "playbooks")
    books = []
    if not pdir.exists():
        return books
    for path in sorted(pdir.glob("*.yaml")):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data:
            data["_file"] = path.name
            books.append(data)
    return books


def _state_enabled(name: str, default: bool = True) -> bool:
    with db_conn() as conn:
        row = conn.execute(
            "SELECT enabled FROM playbook_state WHERE name = ?", (name,)
        ).fetchone()
    return bool(row["enabled"]) if row else default


def _set_state(name: str, enabled: bool) -> None:
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO playbook_state (name, enabled) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled",
            (name, enabled),
        )


def match_playbook(book: dict, fields: dict) -> bool:
    when = book.get("when", {})
    pattern = when.get("pattern", "")
    if not pattern:
        return True
    # Match against a searchable text: title + rule ids + all canonical fields
    hay = " ".join(
        str(v) for v in [fields.get("title"), fields.get("rule_id"),
                         fields.get("rule_group"), fields.get("src_ip"),
                         fields.get("dst_ip"), fields.get("user"),
                         fields.get("url"), fields.get("hash")]
        if v
    )
    try:
        return re.search(pattern, hay, re.IGNORECASE) is not None
    except re.error:
        return False


def _resolve_approval_summary(action: str, params: dict, fields: dict) -> str:
    """Turn raw params into a human-readable Thai summary with REAL values.

    e.g. block_ip {ip_field: src_ip} -> 'บล็อก IP 203.0.113.66 เป็นเวลา 600 วินาที'
    """
    if action == "block_ip":
        ip = fields.get(params.get("ip_field", "src_ip"), "")
        dur = int(params.get("duration", 0)) or int(CONFIG.get("block_default_duration", 600))
        if ip:
            return f"บล็อก IP {ip} เป็นเวลา {dur} วินาที"
        return f"บล็อก IP (ไม่พบค่าใน alert) เป็นเวลา {dur} วินาที"
    if action == "isolate_host":
        host = fields.get(params.get("host_field", "host"), "")
        if host:
            return f"แยกโฮสต์ {host} ออกจากเครือข่าย"
        return "แยกโฮสต์ (ไม่พบค่าใน alert) ออกจากเครือข่าย"
    return json.dumps(params, ensure_ascii=False)


def _queue_approval(action: str, params: dict, fields: dict, alert_id: int,
                    playbook: str) -> int:
    """Create a human-gate approval row with a resolved Thai summary."""
    summary = _resolve_approval_summary(action, params, fields)
    return audit_insert(
        "approvals", ts=now_iso(), alert_id=alert_id, playbook=playbook,
        action=action, params=json.dumps(params, ensure_ascii=False),
        summary=summary,
    )


def run_playbook(book: dict, alert: dict, fields: dict, alert_id: int) -> list[dict]:
    """Execute steps; human-gated steps queue blocking actions for approval.

    Gate resolution: a step-level `gate` overrides the playbook-level `gate`,
    so a playbook can auto-block reversible actions (IP) while gating
    disruptive ones (host isolation). Time-boxed: unanswered approvals
    auto-execute or escalate per config (approval_timeout_*).
    """
    results = []
    playbook_gate = book.get("gate", "auto")
    name = book.get("name", "unnamed")

    for step in book.get("steps", []):
        action = step.get("action", "")
        params = step.get("params", {})
        gate = step.get("gate", playbook_gate)  # per-action override
        if action == "notify":
            results.append(action_notify(fields, params.get("template", ""), alert_id, name))
        elif action == "preserve_evidence":
            results.append(action_evidence(fields, alert, alert_id, name))
        elif action == "block_ip":
            if gate == "human":
                # Queue for human approval (the one-man SOC clicks "อนุมัติ")
                aid = _queue_approval("block_ip", params, fields, alert_id, name)
                action_notify(fields, f"🔔 ขออนุมัติบล็อก IP {fields.get('src_ip')} — รอการยืนยัน", alert_id, name)
                results.append({"status": "pending_approval", "approval_id": aid,
                                "detail": f"block_ip queued for approval ({name})"})
            else:
                results.append(action_block_ip(fields, params.get("ip_field", "src_ip"),
                                               int(params.get("duration", 0)),
                                               alert_id, name))
        elif action == "isolate_host":
            if gate == "human":
                aid = _queue_approval("isolate_host", params, fields, alert_id, name)
                action_notify(fields, f"🛑 ขออนุมัติแยกโฮสต์ {fields.get('host')} — มีผลต่อระบบ", alert_id, name)
                results.append({"status": "pending_approval", "approval_id": aid,
                                "detail": f"isolate_host queued for approval ({name})"})
            else:
                results.append(action_isolate_host(fields, params.get("host_field", "host"),
                                                   alert_id, name))
        elif action == "audit":
            results.append({"status": "logged", "detail": "audit row written"})
    return results


def check_expired_approvals() -> list[dict]:
    """Time-box human gates: unanswered approvals auto-execute or escalate."""
    timeout = int(CONFIG.get("approval_timeout_seconds", 0) or 0)
    if timeout <= 0:
        return []
    mode = CONFIG.get("approval_timeout_action", "escalate")
    cutoff = time.time() - timeout
    acted = []

    # Snapshot pending approvals WITHOUT holding the connection open,
    # because actions open their own connections (SQLite lock avoidance).
    with db_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM approvals WHERE status='pending'"
        ).fetchall()]

    for row in rows:
        try:
            created = datetime.fromisoformat(row["ts"]).timestamp()
        except ValueError:
            continue
        if created >= cutoff:
            continue
        params = json.loads(row["params"])
        alert_row = None
        with db_conn() as conn:
            alert_row = conn.execute(
                "SELECT raw FROM alerts WHERE id=?", (row["alert_id"],)
            ).fetchone()
        fields = extract_fields(json.loads(alert_row["raw"])) if alert_row else {}
        if mode == "auto_execute":
            if row["action"] == "block_ip":
                res = action_block_ip(fields, params.get("ip_field", "src_ip"),
                                      int(params.get("duration", 0)),
                                      row["alert_id"], row["playbook"])
            elif row["action"] == "isolate_host":
                res = action_isolate_host(fields, params.get("host_field", "host"),
                                          row["alert_id"], row["playbook"])
            else:
                res = {"status": "unknown_action"}
            with db_conn() as conn:
                conn.execute("UPDATE approvals SET status='auto_executed' WHERE id=?", (row["id"],))
            action_notify(fields,
                          f"⏰ หมดเวลาอนุมัติ — ดำเนินการอัตโนมัติ: {fields.get('src_ip') or fields.get('host')}",
                          row["alert_id"], row["playbook"])
            acted.append({"approval_id": row["id"], "status": "auto_executed", "block": res})
        else:
            with db_conn() as conn:
                conn.execute("UPDATE approvals SET status='escalated' WHERE id=?", (row["id"],))
            action_notify({},
                          f"🚨 ยังไม่ได้รับการอนุมัติ (ใบที่ {row['id']}) — กรุณาตัดสินใจโดยด่วน",
                          row["alert_id"], row["playbook"])
            acted.append({"approval_id": row["id"], "status": "escalated"})
    return acted


def process_alert(alert: dict) -> dict:
    """Entry point for any SIEM webhook POST."""
    check_expired_approvals()  # time-box any stale human gates first
    fields = extract_fields(alert)
    alert_id = audit_insert(
        "alerts", ts=now_iso(), source=fields["source"], title=fields["title"],
        severity=fields["severity"], raw=json.dumps(alert, ensure_ascii=False),
        matched_playbooks="",
    )
    matched = []
    for book in load_playbooks():
        if not _state_enabled(book.get("name", ""), book.get("enabled", True)):
            continue
        if match_playbook(book, fields):
            matched.append(book.get("name"))
            run_playbook(book, alert, fields, alert_id)
    if matched:
        with db_conn() as conn:
            conn.execute(
                "UPDATE alerts SET matched_playbooks = ? WHERE id = ?",
                (",".join(matched), alert_id),
            )
    return {"accepted": True, "alert_id": alert_id, "matched_playbooks": matched}


def approve(approval_id: int, decision: bool) -> dict:
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not row:
            return {"error": "approval not found"}
        if row["status"] != "pending":
            return {"error": f"already {row['status']}"}
        # If the time-box already expired, force the timeout policy instead
        timeout = int(CONFIG.get("approval_timeout_seconds", 0) or 0)
        if timeout > 0:
            try:
                created = datetime.fromisoformat(row["ts"]).timestamp()
                if time.time() - created > timeout:
                    return {"error": "approval expired — timeout policy applies",
                            "run": "reload page to trigger timeout processing"}
            except ValueError:
                pass
        conn.execute("UPDATE approvals SET status = ? WHERE id = ?",
                     ("approved" if decision else "denied", approval_id))
    if decision:
        params = json.loads(row["params"])
        alert_row = conn.execute("SELECT raw FROM alerts WHERE id = ?", (row["alert_id"],)).fetchone()
        fields = extract_fields(json.loads(alert_row["raw"])) if alert_row else {}
        if row["action"] == "block_ip":
            result = action_block_ip(fields, params.get("ip_field", "src_ip"),
                                     int(params.get("duration", 0)),
                                     row["alert_id"], row["playbook"])
        elif row["action"] == "isolate_host":
            result = action_isolate_host(fields, params.get("host_field", "host"),
                                         row["alert_id"], row["playbook"])
        else:
            result = {"status": "unknown_action"}
        return {"status": "approved", "block": result}
    return {"status": "denied"}
