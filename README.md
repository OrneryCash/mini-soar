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
                     ├─ LINE notify (Thai)          [line_token optional]
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

1. `python demo/send_alerts.py brute` → webhook receives it, T3 playbook
   matches → LINE alert (simulated) + IP blocked (stateful, 600s) → audit rows.
2. `python demo/send_alerts.py ransomware` → T1 is **human-gated** → alert goes
   to the approvals queue instead of auto-blocking.
3. Open `http://localhost:8080/approvals` → click **อนุมัติ** → block executes.
4. Open `/playbooks` → flip a playbook OFF → resend its alert → nothing happens
   (the non-technical admin controls everything with switches).
5. `/audit` shows the full PDPA-ready log of every alert + action.

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
  buttons. No YAML, no code.
- **Provider (us):** author/edit playbooks, tune patterns, per-customer rules.

## Configuration (config.yaml)

| Key | Meaning |
|---|---|
| `line_token` | LINE Notify token — empty = simulated notifications |
| `firewall_backend` | `simulated` (safe demo) or `iptables` (Linux real block) |
| `block_default_duration` | stateful block expiry seconds |
| `approval_timeout_seconds` | human-gate time-box (0 = wait forever) |
| `approval_timeout_action` | `auto_execute` or `escalate` after timeout |
| `webhook_secret` | optional shared secret check on /webhook |

## Threat coverage (T1–T9)

ransomware · phishing/LINE · malware/RAT · exfiltration · BEC · account
takeover · web shell/C2 · vuln (alert-only) · agent killed. Breadth = priority;
automation depth = safety-first (clinical = alert-only always).
