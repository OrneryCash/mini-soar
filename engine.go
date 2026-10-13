package main

import (
	"encoding/json"
	"strings"
)

func runPlaybook(book *Playbook, alert map[string]interface{}, fields map[string]interface{}, alertID int64) []map[string]interface{} {
	results := []map[string]interface{}{}
	gateDefault := book.Gate
	if gateDefault == "" {
		gateDefault = "auto"
	}
	name := book.Name
	if name == "" {
		name = "unnamed"
	}
	for _, step := range book.Steps {
		gate := gateDefault
		if step.Gate != "" {
			gate = step.Gate
		}
		switch step.Action {
		case "notify":
			results = append(results, actionNotify(fields, strParam(step.Params, "template", ""), alertID, name))
		case "preserve_evidence":
			results = append(results, actionEvidence(fields, alert, alertID, name))
		case "block_ip":
			if gate == "human" {
				aid := queueApproval("block_ip", step.Params, fields, alertID, name)
				actionNotify(fields, "🔔 ขออนุมัติบล็อก IP "+str(fields["src_ip"])+" — กรุณายืนยัน", alertID, name)
				results = append(results, map[string]interface{}{"status": "pending_approval", "approval_id": aid,
					"detail": "block_ip queued for approval (" + name + ")"})
			} else {
				results = append(results, actionBlockIP(fields, strParam(step.Params, "ip_field", "src_ip"),
					numParam(step.Params, "duration", 0), alertID, name))
			}
		case "isolate_host":
			if gate == "human" {
				aid := queueApproval("isolate_host", step.Params, fields, alertID, name)
				actionNotify(fields, "🛑 ขออนุมัติแยกโฮสต์ "+str(fields["host"])+" — มีผลกระทบต่อระบบ", alertID, name)
				results = append(results, map[string]interface{}{"status": "pending_approval", "approval_id": aid,
					"detail": "isolate_host queued for approval (" + name + ")"})
			} else {
				results = append(results, actionIsolateHost(fields, strParam(step.Params, "host_field", "host"), alertID, name))
			}
		case "audit":
			results = append(results, map[string]interface{}{"status": "logged", "detail": "audit row written"})
		}
	}
	return results
}

func processAlert(alert map[string]interface{}) map[string]interface{} {
	checkExpiredApprovals()
	fields := extractFields(alert)
	raw, _ := json.Marshal(alert)
	alertID, _ := auditInsert("alerts", map[string]interface{}{
		"ts": nowISO(), "source": str(fields["source"]), "title": str(fields["title"]),
		"severity": numParam(fields, "severity", 0), "siem": str(fields["siem"]),
		"raw": string(raw), "matched_playbooks": "",
	})
	matched := []string{}
	for _, book := range loadPlaybooks() {
		if !book.Enabled {
			continue
		}
		if matchPlaybook(book, fields) {
			matched = append(matched, book.Name)
			runPlaybook(book, alert, fields, alertID)
		}
	}
	if len(matched) > 0 {
		_, _ = db.Exec("UPDATE alerts SET matched_playbooks = ? WHERE id = ?", strings.Join(matched, ","), alertID)
	}
	return map[string]interface{}{"accepted": true, "alert_id": alertID, "matched_playbooks": matched}
}
