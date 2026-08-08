# Mini-SOAR — Live Demo Script (3–4 min)

Purpose: show the committee the full loop — **SIEM fires → Mini-SOAR responds →
one-man SOC approves → audit trail**. The Thai UI is the product; narrate in Thai.

## Setup (before the committee arrives)

```bash
cd mini-soar
./demo/reset_db.sh          # fresh DB, IDs start at 1, server restarted
```

## Act 1 — SIEM-agnostic webhook (terminal, ~40s)

> "Any SIEM can send to us. Same webhook, same playbooks — four different formats."

```bash
python3 demo/send_alerts.py brute --pace 1.5
# shows Wazuh, Elastic, Splunk, Sentinel each firing the SAME brute-force scenario
```

Point at the output: **4 SIEMs × same threat → same response**. Then open the
dashboard so they see it live.

## Act 2 — Auto response (dashboard, ~40s)

Open **http://localhost:8080/** (dashboard auto-refreshes every 3s).

> "The brute-force playbook is set to อัตโนมัติ (auto). Watch the alerts appear —
> each one shows which SIEM sent it. The IP 203.0.113.66 gets blocked statefully
> for 600 seconds, and every step lands in the audit log."

Narrate what they see: SIEM badges, severity colors (บรู๊ตฟอร์ซ = สูง/แดง), pill tags
(t3-bruteforce). Click **ประวัติการทำงาน** — show notify + block_ip rows.

## Act 3 — Human gate (approvals, ~60s) ⭐ the money shot

> "Now the dangerous one: ransomware. This playbook is **ต้องอนุมัติ** (gated) —
> we don't block a hospital network without a human confirming."

```bash
python3 demo/send_alerts.py ransomware --pace 1.5
```

Wait ~3s. The nav badge **รออนุมัติ** turns red with a count. Click it.

> "A real approval request — with a Thai summary of exactly what will happen:
> บล็อก IP … และแยกโฮสต์ HIS-SERVER-01. This is the one-man SOC's decision point."

Click **✅ อนุมัติ** → row disappears live → switch to dashboard → show the new block.
Mention: if nobody answers within 60s, the timeout policy auto-executes (never wait
forever on a ransomware night). Optionally: send `python3 demo/send_alerts.py takeover`
and deny one to show ปฏิเสธ.

## Act 4 — Non-technical admin (playbooks, ~40s)

Open **/playbooks**.

> "The customer admin never sees YAML. Nine threat playbooks — one switch each."

Flip **t2-phishing OFF**, resend its alert, show nothing happens, flip it back ON.
That's the customization boundary: **customer gets switches, we get the YAML.**

## Act 5 — PDPA audit (30s)

Open **/audit**, type `block` in the filter box.

> "Every alert, every decision, every action — timestamped and searchable.
> That's the PDPA 72-hour notification trail, without a compliance team."

## Close

> "No 8-component Docker stack, no weeks of setup — one lightweight service,
> 1–2 hours a week to operate, Thai UI, LINE alerts. Built for the one-man SOC."
