#!/usr/bin/env python3
"""Mini-SOAR demo — send REAL-FORMAT alerts from FOUR different SIEMs.

Proves SIEM-agnosticism: the same webhook + playbooks handle:
  - Wazuh     (rule.description / agent.name / data.srcip)
  - Elastic   (ECS: source.ip / destination.ip / host.name / rule.name)
  - Splunk    (CIM-ish: src_ip / dest_ip / signature / sourcetype)
  - Sentinel  (name / severity string / entities[] array)

Usage:
    python3 demo/send_alerts.py                # all 4 SIEMs x 9 threats
    python3 demo/send_alerts.py brute          # one threat, all SIEMs
    python3 demo/send_alerts.py --siem elastic # one SIEM, all threats
    python3 demo/send_alerts.py brute --siem wazuh
"""

import argparse
import json
import sys
import time
import urllib.request

TS = "2026-08-03T12:00:00.000Z"

# --------------------------------------------------------------------------
# Threat scenario data (shared facts per threat, formatted per SIEM below)
# --------------------------------------------------------------------------

THREATS = {
    "brute": dict(
        title="SSH brute force",
        rule_id="5551", sev_num=10, sev_str="high",
        src_ip="203.0.113.66", dst_ip="10.0.0.5", user="root",
        host="HIS-SERVER-01", msg="Failed password for root from 203.0.113.66 port 54321 ssh2",
    ),
    "ransomware": dict(
        title="Mass file change - possible ransomware",
        rule_id="99901", sev_num=15, sev_str="critical",
        src_ip="10.0.0.5", host="HIS-SERVER-01",
        msg="[syscheck] 847 files changed in C:/ProgramData in 60s - encryption pattern",
    ),
    "phishing": dict(
        title="Suspicious URL - credential harvest pattern",
        rule_id="E221", sev_num=7, sev_str="medium",
        src_ip="198.51.100.23", user="nurse01", host="MAIL-GW-01",
        url="https://fake-line-login.example.com/verify",
        msg="Email scan: link matched credential-harvesting ruleset",
    ),
    "malware": dict(
        title="Malware detected - infostealer",
        rule_id="85201", sev_num=12, sev_str="high",
        src_ip="45.155.205.100", host="WORKSTATION-23",
        hash="44d88612fea8a8f36de82e1278abb02f",
        msg="[virustotal] agent.exe has 58/68 detection ratio (infostealer)",
    ),
    "exfil": dict(
        title="Large outbound data transfer detected",
        rule_id="FW445", sev_num=13, sev_str="high",
        src_ip="10.0.0.9", dst_ip="45.155.205.101", host="FIREWALL-01",
        msg="Session transferred 4.2GB in 3 min to external host",
    ),
    "bec": dict(
        title="DMARC fail - possible invoice fraud",
        rule_id="BEC112", sev_num=8, sev_str="medium",
        src_ip="198.51.100.7", user="finance01", host="MAIL-GW-01",
        msg="Email from spoofed supplier domain, invoice change request",
    ),
    "takeover": dict(
        title="Impossible travel - unusual login",
        rule_id="AAD77", sev_num=9, sev_str="medium",
        src_ip="203.0.113.200", user="doctor.somchai", host="IDP-01",
        msg="Login for doctor.somchai from Bangkok 08:01 then Lagos 08:03",
    ),
    "webshell": dict(
        title="Web shell uploaded to web server",
        rule_id="31160", sev_num=14, sev_str="high",
        src_ip="185.220.101.34", dst_ip="10.0.2.31", host="WEB-01",
        msg="PHP file cmd.php uploaded to /var/www/html/",
    ),
    "agent": dict(
        title="Agent disconnected - possible kill",
        rule_id="1204", sev_num=11, sev_str="high",
        host="HIS-SERVER-01",
        msg="Wazuh agent 001 connection lost - last seen 12:04:00",
    ),
}


# --------------------------------------------------------------------------
# Per-SIEM formatters (real field schemas)
# --------------------------------------------------------------------------

def wazuh(t: dict) -> dict:
    return {
        "timestamp": TS,
        "rule": {"level": t["sev_num"], "description": t["title"], "id": t["rule_id"],
                 "groups": ["authentication", "attack"]},
        "agent": {"id": "001", "name": t["host"], "ip": t.get("dst_ip", "10.0.0.5")},
        "manager": {"name": "wazuh-manager"},
        "id": "1785800000.000001",
        "full_log": t["msg"],
        "predecoded": {"program_name": "sshd", "hostname": t["host"]},
        "data": {"srcip": t.get("src_ip", ""), "dstip": t.get("dst_ip", ""),
                 "user": t.get("user", ""), "url": t.get("url", ""),
                 "hash": t.get("hash", "")},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "input": {"type": "log"},
    }


def elastic(t: dict) -> dict:
    return {
        "@timestamp": TS,
        "event": {"kind": "alert", "category": ["authentication"],
                  "module": "system", "severity": t["sev_num"]},
        "rule": {"name": t["title"], "id": t["rule_id"], "severity": t["sev_str"]},
        "host": {"name": t["host"]},
        "source": {"ip": t.get("src_ip", ""), "port": 54321},
        "destination": {"ip": t.get("dst_ip", ""), "port": 22},
        "user": {"name": t.get("user", "")},
        "message": t["msg"],
        "file": {"hash": {"sha256": t.get("hash", "")}},
        "url": {"full": t.get("url", "")},
    }


def splunk(t: dict) -> dict:
    return {
        "index": "main",
        "sourcetype": "linux:auth",
        "source": "/var/log/auth.log",
        "host": t["host"],
        "_time": TS,
        "event": {
            "signature": t["title"],
            "src_ip": t.get("src_ip", ""), "src_port": 54321,
            "dest_ip": t.get("dst_ip", ""), "dest_port": 22,
            "user": t.get("user", ""),
            "file_hash": t.get("hash", ""),
            "url": t.get("url", ""),
            "severity": t["sev_num"],
        },
    }


def sentinel(t: dict) -> dict:
    entities = []
    if t.get("src_ip"):
        entities.append({"type": "ip", "address": t["src_ip"]})
    if t.get("host"):
        entities.append({"type": "host", "hostName": t["host"]})
    if t.get("user"):
        entities.append({"type": "account", "name": t["user"]})
    return {
        "id": f"sentinel-{t['rule_id']}",
        "name": t["title"],
        "severity": t["sev_str"].capitalize(),
        "description": t["msg"],
        "tactics": ["CredentialAccess"],
        "alertType": "Custom",
        "provider": "Microsoft Sentinel",
        "entities": entities,
    }


SIEMS = {"wazuh": wazuh, "elastic": elastic, "splunk": splunk, "sentinel": sentinel}


def send(url: str, siem: str, name: str, payload: dict) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            print(f"  [{siem:8s}] {name:10s} -> HTTP {resp.status} {body}")
    except Exception as exc:  # noqa: BLE001
        print(f"  [{siem:8s}] {name:10s} -> ERROR {exc}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario", nargs="?", default="all",
                    help="threat name or 'all' (default: all)")
    ap.add_argument("--siem", default=None,
                    help="one of: " + ", ".join(SIEMS) + " (default: all)")
    ap.add_argument("--url", default="http://localhost:8080/webhook")
    ap.add_argument("--pace", type=float, default=0.15,
                    help="seconds to wait between alerts (default 0.15; use ~3 for a narrated live demo)")
    args = ap.parse_args()

    siem_list = [args.siem] if args.siem in SIEMS else list(SIEMS)
    if args.scenario == "all":
        threat_list = list(THREATS)
    elif args.scenario in THREATS:
        threat_list = [args.scenario]
    else:
        print(f"Unknown scenario '{args.scenario}'. Choose: all, "
              f"{', '.join(THREATS)} or a SIEM filter via --siem")
        sys.exit(1)

    total = len(siem_list) * len(threat_list)
    print(f"Sending {total} alerts ({len(siem_list)} SIEMs x {len(threat_list)} threats)...\n")
    for siem in siem_list:
        fmt = SIEMS[siem]
        for name in threat_list:
            send(args.url, siem, name, fmt(THREATS[name]))
            time.sleep(args.pace)


if __name__ == "__main__":
    main()
