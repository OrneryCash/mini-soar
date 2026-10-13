package main

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func lineNotify(message string) map[string]interface{} {
	if CONFIG.LineToken == "" {
		return map[string]interface{}{"status": "simulated", "detail": "LINE token not set — notification simulated"}
	}
	if CONFIG.LineTarget == "" {
		return map[string]interface{}{"status": "simulated", "detail": "LINE target user ID not set — notification simulated"}
	}
	body, _ := json.Marshal(map[string]interface{}{
		"to":       CONFIG.LineTarget,
		"messages": []map[string]string{{"type": "text", "text": message}},
	})
	req, _ := http.NewRequest("POST", "https://api.line.me/v2/bot/message/push", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+CONFIG.LineToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return map[string]interface{}{"status": "error", "detail": err.Error()}
	}
	defer resp.Body.Close()
	return map[string]interface{}{"status": "sent", "detail": fmt.Sprintf("HTTP %d", resp.StatusCode)}
}

func safeFormat(tpl string, fields map[string]interface{}) string {
	return safeFormatRe.ReplaceAllStringFunc(tpl, func(m string) string {
		k := m[1 : len(m)-1]
		if v, ok := fields[k]; ok {
			return str(v)
		}
		return ""
	})
}

func actionNotify(fields map[string]interface{}, template string, alertID int64, playbook string) map[string]interface{} {
	msg := template
	if msg != "" {
		msg = safeFormat(template, fields)
	} else {
		msg = "Alert: " + str(fields["title"])
	}
	result := lineNotify(msg)
	detail := map[string]interface{}{"message": msg}
	for k, v := range result {
		detail[k] = v
	}
	dj, _ := json.Marshal(detail)
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook, "action": "notify", "detail": string(dj),
	})
	return result
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
