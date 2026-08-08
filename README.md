# Mini-SOAR — PoC

A lightweight, SIEM-agnostic automated security response service for Thai small
hospitals/clinics/SMEs (one-man SOC reality). Course 261491 PoC.

**No Shuffle. No TheHive. No orchestrator. No SIEM of our own.**
Any SIEM POSTs alerts to one webhook; YAML playbooks decide what happens;
LINE notifies; blocks are stateful and (where configured) human-approved.

## Architecture

```
ANY SIEM (Wazuh, Elastic, Splunk, QRadar, ...)
   │  POST alert JSON
   ▼
POST /webhook ──► rules engine (playbooks/*.yaml, hot-reload)
                     │
                     ├─ LINE notify (Thai)          [line_channel_token optional]
                     ├─ block IP (stateful, expiry) [simulated | iptables]
                     ├─ preserve evidence (JSON)    [evidence/]
                     └─ audit log (SQLite)          [data/minisoar.db]
                     │
                     ▼
        Thai web UI: dashboard / playbooks (ON-OFF) / approvals / audit
```

## Run it

```bash
cd mini-soar
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app/main.py            # or: uvicorn app.main:app --port 8080
```

Then in another terminal:

```bash
# Simulate FOUR different SIEMs firing all 9 threat scenarios
python demo/send_alerts.py                 # 4 SIEMs x 9 threats = 36 alerts
python demo/send_alerts.py --siem elastic  # one SIEM, all threats
python demo/send_alerts.py brute           # one threat, all SIEMs

# Open the Thai admin UI
open http://localhost:8080/
```

Demo payloads use **real SIEM alert schemas** (not invented shapes):

| SIEM | Format used | Key fields exercised |
|---|---|---|
| Wazuh | Integrator JSON | `rule.description/level`, `agent.name`, `data.srcip` |
| Elastic | ECS | `source.ip`, `destination.ip`, `host.name`, `rule.name` |
| Splunk | CIM-ish | `src_ip`/`dest_ip`, `signature`, `sourcetype`, `event.*` |
| Microsoft Sentinel | Alert JSON | `name`, `severity` string, `entities[]` (ip/host/account) |

The normalizer (`extract_fields` in `app/core.py`) maps each schema onto one
canonical namespace — that's what makes Mini-SOAR SIEM-agnostic.

## Demo flow (3 minutes)

```bash
./demo/reset_db.sh        # fresh DB (alert IDs start at 1) + restart server
python3 demo/send_alerts.py --pace 1.5   # --pace = seconds between alerts (live narration)
```

1. `python3 demo/send_alerts.py brute` → webhook receives it, T3 playbook
   matches → LINE alert (simulated) + IP blocked (stateful, 600s) → audit rows.
2. `python3 demo/send_alerts.py ransomware` → T1 is **human-gated** → alert goes
   to the approvals queue instead of auto-blocking.
3. Open `http://localhost:8080/approvals` → click **อนุมัติ** → block executes.
4. Open `/playbooks` → flip a playbook OFF → resend its alert → nothing happens
   (the non-technical admin controls everything with switches).
5. `/audit` shows the full PDPA-ready log of every alert + action.

> ⏰ The approval time-box (60s default) is enforced by the UI's live polling —
> an unanswered approval auto-executes or escalates while you watch. Approve
> within the window during the live demo, or tell that story deliberately.

Full narrated walkthrough (what to say, what to click): **`demo/demo-script.md`**.

## Playbook format (provider layer — customers never touch this)

```yaml
name: t3-bruteforce
description: บรู๊ตฟอร์ซ SSH/RDP — บล็อก IP ต้นตออัตโนมัติ
enabled: true
gate: auto            # default for the playbook
when:
  pattern: 'brute|failed login|5551|5712'   # regex over alert text
steps:
  - action: notify
    params: {template: "⚠️ บรู๊ตฟอร์ซ: {title} จาก IP {src_ip}"}
  - action: block_ip
    params: {ip_field: src_ip, duration: 600}
    gate: auto        # per-action override: reversible → no approval wait
  - action: audit
```

### Gate design rule (important)

- **Reversible actions (block IP, stateful with expiry) → `gate: auto`** — waiting
  for approval on ransomware would be TOO LATE.
- **Disruptive actions (isolate host, clinical shutdown) → `gate: human`** —
  queued in the approvals page; the one-man SOC clicks อนุมัติ/ปฏิเสธ.
- A step-level `gate` overrides the playbook-level `gate`.

### Approval timeout (never wait forever)

`config.yaml`: `approval_timeout_seconds` + `approval_timeout_action`.
If an approval is unanswered past the timeout:
- `auto_execute` → the queued action runs anyway + LINE alert
  (⏰ หมดเวลาอนุมัติ — ดำเนินการอัตโนมัติ)
- `escalate` → a loud LINE alert asks for a decision

Timeout check runs on every incoming alert + page load, so a one-man SOC
sleeping through a ransomware alert still gets a bounded, safe response.

## Customization boundary

- **Customer admin (non-technical):** Thai web UI — toggles, switches, approve
  buttons, **and a full Thai playbook edit/create form** (keyword chips, IP
  whitelist, block duration, LINE template, action checkboxes, dry-run test,
  revert). No YAML, no code.
- **Provider (us):** author/edit playbooks, tune patterns, per-customer rules.
  **YAML files are the single source of truth** — the form writes playbooks
  straight to `playbooks/*.yaml` (same structure the engine parses). SQLite
  keeps only runtime data + an undo log for ย้อนกลับ (เวอร์ชันก่อนหน้า) (last 10
  versions).
- **Safety envelope:** host isolation is ALWAYS human-gated (locked), whatever
  the customer picks.
- **Tradeoff:** a provider update that replaces a YAML file overwrites customer
  edits to it — the undo log preserves the previous version, and updates ship
  as new files or diffs.

## Deep links

- `#edit-<name>` — open the edit modal for a playbook (e.g. `/playbooks#edit-t3-bruteforce`)
- `?test=<name>` — open the edit modal with the dry-run preview already rendered
  (e.g. `/playbooks?test=t3-bruteforce`)

## Configuration (config.yaml)

| Key | Meaning |
|---|---|
| `line_channel_token` | LINE Messaging API channel access token (LINE Notify EOL 2025-03-31) — empty = simulated notifications |
| `line_target_user_id` | LINE user ID of the recipient (LINE Official Account's Messaging API) |
| `firewall_backend` | `simulated` (safe demo) or `iptables` (Linux real block) |
| `block_default_duration` | stateful block expiry seconds |
| `approval_timeout_seconds` | human-gate time-box (0 = wait forever) |
| `approval_timeout_action` | `auto_execute` or `escalate` after timeout |
| `webhook_secret` | optional shared secret check on /webhook |

## Threat coverage (T1–T9)

ransomware · phishing/LINE · malware/RAT · exfiltration · BEC · account
takeover · web shell/C2 · vuln (alert-only) · agent killed. Breadth = priority;
automation depth = safety-first (clinical = alert-only always).
