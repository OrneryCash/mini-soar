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
		if strings.Contains(res, "SIMULATED") {
			suffix = "จำลอง"
		} else if strings.Contains(res, "iptables") {
			suffix = "บล็อกจริง (iptables)"
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
	if backend == "iptables" {
		// Real block is Linux-only; kept as best-effort and logged like Python.
		status = "error"
		detail = "iptables backend not executed by the Go port"
	} else {
		status = "simulated"
		detail = fmt.Sprintf("SIMULATED block of %s for %ds (backend: %s)", ip, dur, backend)
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
	detail := "no host in alert"
	if host != "" {
		detail = "HOST ISOLATED (simulated): " + host
	}
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook, "action": "isolate_host", "detail": detail,
	})
	return map[string]interface{}{"status": "isolated_simulated", "detail": detail, "host": host}
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
