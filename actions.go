package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// humanActionDetail mirrors core.human_action_detail().
func humanActionDetail(r Action) string {
	raw := r.Detail
	var d map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		if len(raw) > 160 {
			return raw[:160]
		}
		return raw
	}
	switch r.Action {
	case "notify":
		msg := str(d["message"])
		st := str(d["status"])
		if st != "" {
			return msg + "  [" + st + "]"
		}
		return msg
	case "block_ip":
		ip := str(d["ip"])
		dur := str(d["duration"])
		res := str(d["result"])
		if res == "" {
			res = str(d["detail"])
		}
		suffix := res
		switch {
		case strings.Contains(res, "SIMULATED"):
			suffix = "จำลอง"
		case strings.Contains(res, "QUEUED"):
			suffix = "สั่งจริง (queued)"
		}
		return fmt.Sprintf("บล็อก IP %s (%ss) [%s]", ip, dur, suffix)
	case "preserve_evidence":
		parts := strings.Split(raw, "/")
		return "เก็บหลักฐาน: " + parts[len(parts)-1]
	case "isolate_host":
		if len(raw) > 160 {
			return "แยกโฮสต์: " + raw[:160]
		}
		return "แยกโฮสต์: " + raw
	}
	if len(raw) > 160 {
		return raw[:160]
	}
	return raw
}

// ------------------------------------------------------------------ extraction
//
// Notification delivery lives in line.go (status vocabulary, retry, truncation,
// quota, renderer) and line_agg.go (aggregation + send-time policy). The old
// lineNotify() was removed: it never checked the HTTP status, so a 401 was
// recorded as "sent".

func safeFormat(tpl string, fields map[string]interface{}) string {
	return safeFormatRe.ReplaceAllStringFunc(tpl, func(m string) string {
		k := m[1 : len(m)-1]
		if v, ok := fields[k]; ok {
			return str(v)
		}
		return ""
	})
}

// actionNotify queues one notification for this incident. The playbook's
// wording becomes the event line, expanded through the disclosure gate so a
// template written with {user}/{hash}/{url} cannot leak personal data at
// disclosure=minimal (design §7).
func actionNotify(fields map[string]interface{}, template string, actions []string, alertID int64, playbook string) map[string]interface{} {
	f := map[string]interface{}{}
	for k, v := range fields {
		f[k] = v
	}
	// Keep the ORIGINAL alert title for aggregation: the template below rewrites
	// the display title, while the approval path sees the raw fields. Keying the
	// notification on the display title split one incident into two messages.
	f["_group_title"] = str(fields["title"])
	if template != "" {
		if t := strings.TrimSpace(gatedFormat(template, fields, disclosureLevel())); t != "" {
			f["title"] = t
		}
	}
	if strings.TrimSpace(str(f["title"])) == "" {
		f["title"] = "พบเหตุการณ์ผิดปกติ"
	}
	if len(actions) == 0 {
		actions = []string{"notify"}
	}
	return lineNotifyFor(f, actions, alertID, playbook, alertID)
}

func actionBlockIP(fields map[string]interface{}, ipField string, duration int, alertID int64, playbook string) map[string]interface{} {
	if ipField == "" {
		ipField = "src_ip"
	}
	ip := str(fields[ipField])
	if ip == "" {
		return map[string]interface{}{"status": "skipped", "detail": "no source IP in alert"}
	}
	backend := CONFIG.Firewall
	dur := duration
	if dur == 0 {
		dur = CONFIG.BlockDefault
	}
	expiresISO := time.Now().UTC().Add(time.Duration(dur) * time.Second).Format("2006-01-02T15:04:05+00:00")

	status, detail := "", ""
	switch {
	case !actionIsReal("block_ip"):
		// Simulated (the default): record exactly what would have run, change nothing.
		status = "simulated"
		detail = fmt.Sprintf("SIMULATED block of %s for %ds — set block_ip to real in Settings to enforce it", ip, dur)
	case !wazuh.configured():
		status = "error"
		detail = "block_ip is set to real but the Wazuh API is not configured"
	default:
		agentID, err := wazuh.agentIDFor(str(fields["host"]))
		if err != nil {
			status, detail = "error", err.Error()
			break
		}
		// firewall-drop reads -srcip, and the standard script also reads
		// alert.data.srcip — send both, per the Wazuh API contract.
		if err := wazuh.runActiveResponse(agentID, "!firewall-drop",
			[]string{"-srcip", ip}, map[string]interface{}{"srcip": ip}); err != nil {
			status, detail = "error", err.Error()
			break
		}
		// 200 means QUEUED on the manager, not executed on the agent. Never "done".
		status = "queued"
		detail = fmt.Sprintf("QUEUED firewall-drop %s for %ds on agent %s — verify with iptables on the endpoint",
			ip, dur, agentID)
	}
	_, _ = auditInsert("blocks", map[string]interface{}{
		"ts": nowISO(), "ip": ip, "duration": dur, "expires_at": expiresISO,
		"backend": backend, "status": status,
	})
	dj, _ := json.Marshal(map[string]interface{}{"ip": ip, "duration": dur, "result": detail})
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook, "action": "block_ip", "detail": string(dj),
	})
	return map[string]interface{}{"status": status, "detail": detail, "ip": ip}
}

func actionIsolateHost(fields map[string]interface{}, hostField string, alertID int64, playbook string) map[string]interface{} {
	if hostField == "" {
		hostField = "host"
	}
	host := str(fields[hostField])
	status, detail := "", ""

	switch {
	case host == "":
		status, detail = "skipped", "no host in the alert to isolate"
	case !actionIsReal("isolate_host"):
		status = "isolated_simulated"
		detail = "SIMULATED isolation of " + host + " — set isolate_host to real in Settings to enforce it"
	case !wazuh.configured():
		status, detail = "error", "isolate_host is set to real but the Wazuh API is not configured"
	default:
		agentID, err := wazuh.agentIDFor(host)
		if err != nil {
			status, detail = "error", err.Error()
			break
		}
		if err := wazuh.runActiveResponse(agentID, "!isolate-host", nil,
			map[string]interface{}{"host": host}); err != nil {
			status, detail = "error", err.Error()
			break
		}
		// Queued, not done. The allowlist and the TTL live in isolate-host.sh on the
		// endpoint, so the SOAR cannot narrow or widen them.
		status = "queued"
		detail = fmt.Sprintf("QUEUED isolate-host on %s (agent %s) — allowlist and TTL are enforced on the endpoint",
			host, agentID)
	}

	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook, "action": "isolate_host",
		"detail": detail + "  [mode: " + actionMode("isolate_host") + "]",
	})
	return map[string]interface{}{"status": status, "detail": detail, "host": host}
}

func actionEvidence(fields map[string]interface{}, alert map[string]interface{}, alertID int64, playbook string) map[string]interface{} {
	dir := filepath.Join(BASE, CONFIG.EvidenceDir)
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fmt.Sprintf("alert-%d-%d.json", alertID, time.Now().Unix()))
	b, _ := json.MarshalIndent(alert, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook, "action": "preserve_evidence", "detail": path,
	})
	return map[string]interface{}{"status": "saved", "detail": path}
}

// ------------------------------------------------------------------ playbooks
