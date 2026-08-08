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
            CREATE TABLE IF NOT EXISTS playbook_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                data TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            """
        )
        # Migrate older DBs: add the siem column if missing
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "siem" not in cols:
            conn.execute("ALTER TABLE alerts ADD COLUMN siem TEXT")
        _migrate_legacy_state(conn)


def _migrate_legacy_state(conn: sqlite3.Connection) -> None:
    """One-time migration (2026-08-08): YAML files became the single source of
    truth. Materialize any legacy SQLite overrides/state into playbooks/*.yaml,
    then drop the legacy tables."""
    def table_exists(t: str) -> bool:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (t,)
        ).fetchone() is not None

    if table_exists("playbook_overrides"):
        rows = conn.execute("SELECT name, data FROM playbook_overrides").fetchall()
        for row in rows:
            try:
                ov = json.loads(row["data"])
            except ValueError:
                continue
            existing = _read_book(row["name"])
            when = {}
            if ov.get("keywords"):
                pat = _build_keywords_pattern(ov["keywords"])
                if pat:
                    when["pattern"] = pat
                    when["keywords"] = ov["keywords"]
            if ov.get("min_severity"):
                when["min_severity"] = int(ov["min_severity"])
            if ov.get("not_ip"):
                when["not_ip"] = [str(x) for x in ov["not_ip"]]
            if existing is not None:
                book = dict(existing)
                for key in ("enabled", "gate", "description"):
                    if key in ov:
                        book[key] = ov[key]
                book["when"] = when if when else book.get("when") or {}
                if "actions" in ov:
                    book["steps"] = _build_steps(ov["actions"],
                                                  ov.get("notify_template", ""),
                                                  ov.get("block_duration", 0))
            else:
                book = {
                    "name": row["name"],
                    "description": ov.get("description", ""),
                    "enabled": bool(ov.get("enabled", True)),
                    "gate": ov.get("gate", "auto"),
                    "when": when,
                    "source": "custom",
                    "steps": _build_steps(ov.get("actions", ["notify", "audit"]),
                                           ov.get("notify_template", ""),
                                           ov.get("block_duration", 0)),
                }
            _write_book(row["name"], book)
        conn.execute("DROP TABLE playbook_overrides")

    if table_exists("playbook_state"):
        rows = conn.execute("SELECT name, enabled FROM playbook_state").fetchall()
        for row in rows:
            book = _read_book(row["name"])
            if book is not None:
                book["enabled"] = bool(row["enabled"])
                _write_book(row["name"], book)
        conn.execute("DROP TABLE playbook_state")

    # Old undo-log rows were JSON (pre-refactor) — the new log stores raw YAML
    # text. Clear stale entries; fresh history starts after this migration.
    conn.execute("DELETE FROM playbook_history")


def human_action_detail(row: sqlite3.Row) -> str:
    """Render an actions row's stored detail as a short, readable Thai line.

    The raw detail is a JSON blob (or plain text) meant for forensics; the
    audit UI shows this human-friendly form instead of escaped JSON.
    """
    raw = row["detail"] or ""
    action = row["action"]
    try:
        d = json.loads(raw)
    except (TypeError, ValueError):
        return str(raw)[:160]
    if not isinstance(d, dict):
        return str(d)[:160]
    if action == "notify":
        msg = d.get("message", "")
        st = d.get("status", "")
        return f"{msg}  [{st}]" if st else str(msg)
    if action == "block_ip":
        ip = d.get("ip", "")
        dur = d.get("duration", "")
        res = str(d.get("result", d.get("detail", "")))
        suffix = "จำลอง" if "SIMULATED" in res else ("บล็อกจริง (iptables)" if "iptables" in res else res)
        return f"บล็อก IP {ip} ({dur}s) [{suffix}]"
    if action == "preserve_evidence":
        short = raw.rsplit("/", 1)[-1]
        return f"เก็บหลักฐาน: {short}"
    if action == "isolate_host":
        return f"แยกโฮสต์: {raw[:160]}"
    return str(raw)[:160]


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

def _detect_siem(alert: dict) -> str:
    """Best-effort guess of the sending SIEM from the alert's schema.

    Order matters — check the most distinctive shape first:
    Sentinel has entities[]/provider, Splunk uses _time + event.signature,
    Wazuh integrator JSON has rule.description + agent.name,
    Elastic ECS has @timestamp + source.ip.
    """
    if alert.get("provider") == "Microsoft Sentinel" or \
            isinstance(alert.get("entities"), list):
        return "sentinel"
    if "_time" in alert and isinstance(alert.get("event"), dict) \
            and "signature" in alert["event"]:
        return "splunk"
    if isinstance(alert.get("rule"), dict) and alert["rule"].get("description") \
            and isinstance(alert.get("agent"), dict):
        return "wazuh"
    if "@timestamp" in alert and isinstance(alert.get("source"), dict) \
            and "ip" in alert["source"]:
        return "elastic"
    return "generic"


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
    out["siem"] = _detect_siem(alert)
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
    """Send via LINE Messaging API (LINE Notify was EOL 2025-03-31).

    Requires a LINE Official Account with Messaging API enabled:
      channel access token (line_channel_token) + recipient user ID
      (line_target_user_id). Empty config = simulated (logged + shown in UI).
    """
    token = CONFIG.get("line_channel_token", "")
    target = CONFIG.get("line_target_user_id", "")
    if not token:
        return {"status": "simulated", "detail": "LINE token not set — notification simulated"}
    if not target:
        return {"status": "simulated", "detail": "LINE target user ID not set — notification simulated"}
    url = "https://api.line.me/v2/bot/message/push"
    body = json.dumps({
        "to": target,
        "messages": [{"type": "text", "text": message}],
    }).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
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
    """Parse every playbooks/*.yaml file — YAML files are the single source of
    truth. Hot-reloaded on every alert (no caching, no merge layer)."""
    pdir = BASE / CONFIG.get("playbooks_dir", "playbooks")
    books = []
    if not pdir.exists():
        return books
    for path in sorted(pdir.glob("*.yaml")):
        if path.name.endswith(".tmp"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        data["_file"] = path.name
        data["_custom"] = data.get("source") == "custom"
        books.append(data)
    return books


def _set_state(name: str, enabled: bool) -> None:
    """Toggle ON/OFF by writing enabled: into the playbook's YAML file.
    The file is the source of truth, so the toggle persists there too."""
    book = _read_book(name)
    if book is None:
        return
    book["enabled"] = bool(enabled)
    _write_book(name, book)


# --------------------------------------------------------------------------
# Customer playbook customization — provider YAML + SQLite override layer
# --------------------------------------------------------------------------
# Customers edit playbooks through the Thai form UI (no YAML). Their changes
# are stored as overrides and merged over the provider YAML at load time, so
# provider updates (new patterns, security fixes) never clobber customer
# choices. Customers can also CREATE playbooks from the same building blocks.

CUSTOM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-_]{0,63}$")
ALLOWED_ACTIONS = ["notify", "preserve_evidence", "block_ip", "isolate_host", "audit"]
ALLOWED_DURATIONS = [600, 1800, 3600, 86400]  # 10/30/60 นาที, 24 ชม.
TEMPLATE_PLACEHOLDERS = {"title", "src_ip", "dst_ip", "host", "user", "url",
                         "hash", "severity", "source"}

SAMPLE_ALERT = {
    "title": "ตัวอย่าง: SSH brute force",
    "severity": 10,
    "src_ip": "203.0.113.66",
    "host": "HIS-SERVER-01",
    "user": "root",
    "source": "wazuh",
    "rule_id": "5551",
}


def _playbook_path(name: str) -> Path:
    return BASE / CONFIG.get("playbooks_dir", "playbooks") / f"{name}.yaml"


def _read_text(name: str) -> str | None:
    """Raw YAML text (for the undo log / exact restore)."""
    path = _playbook_path(name)
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8")


def _read_book(name: str) -> dict | None:
    """Parse a playbook YAML file into a usable playbook dict."""
    path = _playbook_path(name)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    data["_file"] = path.name
    data["_custom"] = data.get("source") == "custom"
    return data


def _write_book(name: str, book: dict) -> None:
    """Serialize a playbook dict to its YAML file (atomic write)."""
    path = _playbook_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    out = {k: v for k, v in book.items() if not k.startswith("_")}
    header = (
        "# Mini-SOAR playbook — แก้ไขผ่านฟอร์มภาษาไทย (Thai UI)\n"
        "# แก้ไขแต่ละครั้งจะบันทึกเป็น YAML ไฟล์โดยตรง — single source of truth\n"
    )
    text = header + yaml.safe_dump(
        out, allow_unicode=True, sort_keys=False, width=100, default_flow_style=False
    )
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _history_push(name: str, yaml_text: str) -> None:
    """Undo log: keep the last 10 previous versions (raw YAML text)."""
    with db_conn() as conn:
        conn.execute(
            "INSERT INTO playbook_history (name, data, ts) VALUES (?, ?, ?)",
            (name, yaml_text, now_iso()),
        )
        conn.execute(
            "DELETE FROM playbook_history WHERE name=? AND id NOT IN "
            "(SELECT id FROM playbook_history WHERE name=? ORDER BY id DESC LIMIT 10)",
            (name, name),
        )


def _history_pop(name: str) -> str | None:
    """Restore + remove the most recent previous version."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id, data FROM playbook_history WHERE name=? "
            "ORDER BY id DESC LIMIT 1",
            (name,),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM playbook_history WHERE id=?", (row["id"],))
    return row["data"]


def has_history(name: str) -> bool:
    with db_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM playbook_history WHERE name=? LIMIT 1", (name,)
        ).fetchone()
    return row is not None


def _build_keywords_pattern(keywords) -> str:
    """Customer keyword chips → regex alternation (safe-escaped, no regex craft)."""
    kws = [str(k).strip() for k in (keywords or []) if str(k).strip()]
    if not kws:
        return ""
    return "(" + "|".join(re.escape(k) for k in kws) + ")"


def _build_steps(actions: list, notify_template: str, block_duration: int) -> list:
    """Build steps from the customer's action checkboxes.

    The step order FOLLOWS the actions list order — the form's up/down arrows
    set it, and YAML stores it. Order matters once there are more primitives
    (e.g. capture evidence before blocking, disable account before isolation).

    Safety envelope: isolate_host is ALWAYS human-gated here, regardless of
    playbook gate or customer choice — a host isolation must never be silent.
    """
    steps = []
    for action in actions:
        if action == "notify":
            steps.append({"action": "notify",
                          "params": {"template": (notify_template or "").strip()}})
        elif action == "preserve_evidence":
            steps.append({"action": "preserve_evidence", "params": {}})
        elif action == "block_ip":
            dur = int(block_duration or 0) or int(CONFIG.get("block_default_duration", 600))
            steps.append({"action": "block_ip",
                          "params": {"ip_field": "src_ip", "duration": dur}})
        elif action == "isolate_host":
            steps.append({"action": "isolate_host",
                          "params": {"host_field": "host"}, "gate": "human"})
        elif action == "audit":
            steps.append({"action": "audit", "params": {}})
    return steps


def book_from_form(name: str, clean: dict) -> dict:
    """Build a playbook dict from a validated form (used for test dry-runs
    of unsaved drafts — no DB writes, no side effects)."""
    when = {}
    pat = _build_keywords_pattern(clean.get("keywords"))
    if pat:
        when["pattern"] = pat
    if clean.get("min_severity"):
        when["min_severity"] = int(clean["min_severity"])
    if clean.get("not_ip"):
        when["not_ip"] = [str(x) for x in clean["not_ip"]]
    return {
        "name": name,
        "description": clean.get("description", ""),
        "enabled": bool(clean.get("enabled", True)),
        "gate": clean.get("gate", "auto"),
        "when": when,
        "steps": _build_steps(clean.get("actions", []),
                               clean.get("notify_template", ""),
                               clean.get("block_duration", 0)),
    }


def get_playbook(name: str) -> dict | None:
    """Parse the playbook's YAML file — the single source of truth."""
    return _read_book(name)


def playbook_form_payload(book: dict) -> dict:
    """The exact shape the Thai edit form needs (prefill values)."""
    steps = book.get("steps") or []
    when = book.get("when") or {}
    actions = [s.get("action") for s in steps
               if s.get("action") in ALLOWED_ACTIONS]
    tpl = next((s.get("params", {}).get("template", "")
                for s in steps if s.get("action") == "notify"), "")
    dur = next((int(s.get("params", {}).get("duration", 0))
                for s in steps if s.get("action") == "block_ip"), 0)
    dur = dur or int(CONFIG.get("block_default_duration", 600))
    return {
        "name": book.get("name"),
        "description": book.get("description", ""),
        "enabled": bool(book.get("enabled", True)),
        "gate": book.get("gate", "auto"),
        "keywords": when.get("keywords") or [],
        "min_severity": when.get("min_severity", 0),
        "not_ip": when.get("not_ip") or [],
        "block_duration": dur,
        "notify_template": tpl,
        "actions": actions,
        "locks": book.get("locks") or {},
        "custom": bool(book.get("_custom")),
    }


def validate_playbook_form(data: dict, locks: dict) -> tuple[list, dict]:
    """Validate the Thai form. Returns (Thai error list, cleaned dict)."""
    errs: list = []
    out: dict = {}

    desc = str(data.get("description", "") or "").strip()
    if len(desc) > 200:
        errs.append("คำอธิบายยาวเกินไป (สูงสุด 200 ตัวอักษร)")
    out["description"] = desc

    out["enabled"] = bool(data.get("enabled", True))

    gate = str(data.get("gate", "auto"))
    if gate not in ("auto", "human"):
        errs.append("โหมดการทำงานไม่ถูกต้อง")
    out["gate"] = gate

    kws = [str(k).strip() for k in (data.get("keywords") or []) if str(k).strip()]
    for k in kws:
        if len(k) > 64:
            errs.append(f"คำค้นหายาวเกินไป (สูงสุด 64 ตัวอักษร): {k}")
    out["keywords"] = kws

    try:
        min_sev = int(data.get("min_severity", 0) or 0)
        if not (0 <= min_sev <= 15):
            raise ValueError
    except (TypeError, ValueError):
        errs.append("ความรุนแรงขั้นต่ำต้องเป็นตัวเลข 0–15")
        min_sev = 0
    out["min_severity"] = min_sev

    import ipaddress
    ips = [str(x).strip() for x in (data.get("not_ip") or []) if str(x).strip()]
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            errs.append(f"IP ข้อยกเว้นไม่ถูกต้อง: {ip}")
    out["not_ip"] = ips

    try:
        dur = int(data.get("block_duration", 0) or 0)
        if dur and dur not in ALLOWED_DURATIONS:
            raise ValueError
    except (TypeError, ValueError):
        errs.append("ระยะเวลาบล็อกต้องเป็นหนึ่งในตัวเลือกที่กำหนด")
        dur = 600
    out["block_duration"] = dur or 600

    tpl = str(data.get("notify_template", "") or "")
    if len(tpl) > 200:
        errs.append("ข้อความแจ้งเตือนยาวเกินไป (สูงสุด 200 ตัวอักษร)")
    for ph in re.findall(r"\{([a-zA-Z0-9_]+)\}", tpl):
        if ph not in TEMPLATE_PLACEHOLDERS:
            errs.append(f"ตัวแปร {{{ph}}} ไม่ได้รับอนุญาต — ใช้ได้เฉพาะ: "
                        "title, src_ip, dst_ip, host, user, url, hash, severity, source")
    out["notify_template"] = tpl

    acts = [str(a) for a in (data.get("actions") or []) if str(a) in ALLOWED_ACTIONS]
    acts = list(dict.fromkeys(acts))  # dedupe, keep order
    if not acts:
        errs.append("กรุณาเพิ่มขั้นตอนอย่างน้อย 1 ขั้นตอน")
    out["actions"] = acts

    if locks.get("isolate_host") == "human" and "isolate_host" in acts:
        pass  # allowed — _build_steps keeps it human-gated regardless
    return errs, out


def save_playbook_form(name: str, data: dict) -> dict:
    """Validate + write a playbook straight to its YAML file (create or edit).

    YAML files are the single source of truth — the form serializes the same
    structure the engine parses. The previous file content goes to the undo
    log so ย้อนกลับ (เวอร์ชันก่อนหน้า) can restore it exactly.
    """
    name = str(name or "").strip()
    existing = _read_book(name)
    is_create = existing is None
    if not is_create and not CUSTOM_NAME_RE.match(name):
        return {"ok": False, "errors": ["ชื่อเพลย์บุ๊กต้องเป็นภาษาอังกฤษตัวพิมพ์เล็ก (a-z, 0-9, -, _)"]}
    if is_create and _playbook_path(name).exists():
        return {"ok": False, "errors": ["มีเพลย์บุ๊กชื่อนี้อยู่แล้ว — กรุณาใช้ชื่ออื่น"]}
    locks = (existing or {}).get("locks") or {}
    errs, clean = validate_playbook_form(data, locks)
    if errs:
        return {"ok": False, "errors": errs}

    when = {}
    if clean["keywords"]:
        when["pattern"] = _build_keywords_pattern(clean["keywords"])
        when["keywords"] = clean["keywords"]  # round-trips back into the form
    if clean["min_severity"]:
        when["min_severity"] = clean["min_severity"]
    if clean["not_ip"]:
        when["not_ip"] = clean["not_ip"]

    book = {
        "name": name,
        "description": clean["description"],
        "enabled": clean["enabled"],
        "gate": clean["gate"],
        "when": when,
        "steps": _build_steps(clean["actions"], clean["notify_template"],
                               clean["block_duration"]),
    }
    if is_create:
        book["source"] = "custom"  # customer-created playbook marker
    if existing and existing.get("locks"):
        book["locks"] = existing["locks"]  # safety envelope survives edits

    prev = _read_text(name)
    if prev:
        _history_push(name, prev)
    _write_book(name, book)
    return {"ok": True, "playbook": _read_book(name)}


def revert_playbook(name: str) -> dict:
    """Restore the most recent previous version (exact YAML text)."""
    prev = _history_pop(name)
    if prev is None:
        return {"ok": False, "error": "ยังไม่มีเวอร์ชันก่อนหน้าให้ย้อนกลับ"}
    path = _playbook_path(name)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(prev, encoding="utf-8")
    os.replace(tmp, path)
    book = _read_book(name)
    if book is None:
        return {"ok": False, "error": "ไม่พบเพลย์บุ๊ก"}
    return {"ok": True, "playbook": book}


def delete_playbook(name: str) -> dict:
    """Delete a customer-created playbook file (provider books → revert only)."""
    book = _read_book(name)
    if book is None:
        return {"ok": False, "error": "ไม่พบเพลย์บุ๊ก"}
    if not book.get("_custom"):
        return {"ok": False, "error": "เพลย์บุ๊กมาตรฐานลบไม่ได้ — ใช้ 'ย้อนกลับ' แทน"}
    prev = _read_text(name)
    if prev:
        _history_push(name, prev)
    _playbook_path(name).unlink(missing_ok=True)
    return {"ok": True}


def preview_playbook(book: dict, alert: dict) -> dict:
    """Dry-run: what WOULD happen with this alert (no side effects, no audit)."""
    fields = extract_fields(alert)
    matched = match_playbook(book, fields)
    steps_out = []
    if matched:
        for step in book.get("steps", []):
            action = step.get("action", "")
            params = step.get("params", {})
            gate = step.get("gate", book.get("gate", "auto"))
            if action == "notify":
                msg = _safe_format(params.get("template", ""), fields)
                steps_out.append({"action": "notify", "gate": gate, "detail": msg})
            elif action == "block_ip":
                ip = fields.get(params.get("ip_field", "src_ip"), "")
                dur = int(params.get("duration", 0)) or int(CONFIG.get("block_default_duration", 600))
                steps_out.append({"action": "block_ip", "gate": gate,
                                  "detail": f"บล็อก IP {ip or '(ไม่พบ)'} ({dur}s)"})
            elif action == "isolate_host":
                host = fields.get(params.get("host_field", "host"), "")
                steps_out.append({"action": "isolate_host", "gate": gate,
                                  "detail": f"แยกโฮสต์ {host or '(ไม่พบ)'}"})
            elif action == "preserve_evidence":
                steps_out.append({"action": "preserve_evidence", "gate": gate,
                                  "detail": "เก็บหลักฐาน (alert JSON)"})
            elif action == "audit":
                steps_out.append({"action": "audit", "gate": gate,
                                  "detail": "บันทึกประวัติ"})
    return {
        "matched": matched,
        "fields": {k: fields.get(k) for k in
                    ("title", "severity", "src_ip", "host", "user", "url", "hash", "source")},
        "steps": steps_out,
    }


def match_playbook(book: dict, fields: dict) -> bool:
    when = book.get("when", {})
    # Severity floor: alerts below the customer's minimum never match
    min_sev = when.get("min_severity")
    if min_sev is not None and int(fields.get("severity", 0) or 0) < int(min_sev):
        return False
    # IP whitelist: the customer's own workstations/clinics are never blocked
    not_ip = when.get("not_ip") or []
    if not_ip and fields.get("src_ip") in not_ip:
        return False
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
            return f"บล็อก IP {ip} นาน {dur} วินาที"
        return f"บล็อก IP (ไม่พบค่าใน alert) นาน {dur} วินาที"
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
                action_notify(fields, f"🔔 ขออนุมัติบล็อก IP {fields.get('src_ip')} — กรุณายืนยัน", alert_id, name)
                results.append({"status": "pending_approval", "approval_id": aid,
                                "detail": f"block_ip queued for approval ({name})"})
            else:
                results.append(action_block_ip(fields, params.get("ip_field", "src_ip"),
                                               int(params.get("duration", 0)),
                                               alert_id, name))
        elif action == "isolate_host":
            if gate == "human":
                aid = _queue_approval("isolate_host", params, fields, alert_id, name)
                action_notify(fields, f"🛑 ขออนุมัติแยกโฮสต์ {fields.get('host')} — มีผลกระทบต่อระบบ", alert_id, name)
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
                          f"⏰ ครบเวลารออนุมัติ — ระบบดำเนินการอัตโนมัติ: {fields.get('src_ip') or fields.get('host')}",
                          row["alert_id"], row["playbook"])
            acted.append({"approval_id": row["id"], "status": "auto_executed", "block": res})
        else:
            with db_conn() as conn:
                conn.execute("UPDATE approvals SET status='escalated' WHERE id=?", (row["id"],))
            action_notify({},
                          f"🚨 คำขออนุมัติใบที่ {row['id']} ยังไม่ได้รับการตัดสินใจ — กรุณารีบตัดสินใจ",
                          row["alert_id"], row["playbook"])
            acted.append({"approval_id": row["id"], "status": "escalated"})
    return acted


def process_alert(alert: dict) -> dict:
    """Entry point for any SIEM webhook POST."""
    check_expired_approvals()  # time-box any stale human gates first
    fields = extract_fields(alert)
    alert_id = audit_insert(
        "alerts", ts=now_iso(), source=fields["source"], title=fields["title"],
        severity=fields["severity"], siem=fields.get("siem", "generic"),
        raw=json.dumps(alert, ensure_ascii=False), matched_playbooks="",
    )
    matched = []
    for book in load_playbooks():
        if not book.get("enabled", True):
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
