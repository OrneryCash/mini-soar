package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func resolveApprovalSummary(action string, params map[string]interface{}, fields map[string]interface{}) string {
	if action == "block_ip" {
		ip := str(fields[strParam(params, "ip_field", "src_ip")])
		dur := numParam(params, "duration", 0)
		if dur == 0 {
			dur = CONFIG.BlockDefault
		}
		if ip != "" {
			return fmt.Sprintf("บล็อก IP %s นาน %d วินาที", ip, dur)
		}
		return fmt.Sprintf("บล็อก IP (ไม่พบค่าใน alert) นาน %d วินาที", dur)
	}
	if action == "isolate_host" {
		host := str(fields[strParam(params, "host_field", "host")])
		if host != "" {
			return "แยกโฮสต์ " + host + " ออกจากเครือข่าย"
		}
		return "แยกโฮสต์ (ไม่พบค่าใน alert) ออกจากเครือข่าย"
	}
	b, _ := json.Marshal(params)
	return string(b)
}

func queueApproval(action string, params map[string]interface{}, fields map[string]interface{}, alertID int64, playbook string) int64 {
	summary := resolveApprovalSummary(action, params, fields)
	if summary != "" {
		var existing int64
		var cnt int64
		if err := db.QueryRow("SELECT id, ifnull(count,1) FROM approvals WHERE status='pending' AND playbook=? AND action=? AND summary=? ORDER BY id LIMIT 1", playbook, action, summary).Scan(&existing, &cnt); err == nil && existing > 0 {
			// aggregation: one open request per (playbook, action, target)
			_, _ = db.Exec("UPDATE approvals SET count=?, ts=? WHERE id=?", cnt+1, nowISO(), existing)
			return existing
		}
	}
	pj, _ := json.Marshal(params)
	id, _ := auditInsert("approvals", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook,
		"action": action, "params": string(pj), "summary": summary,
	})
	return id
}

func checkExpiredApprovals() []map[string]interface{} {
	timeout := CONFIG.ApprovalTO
	if timeout <= 0 {
		return nil
	}
	mode := CONFIG.ApprovalMode
	cutoff := time.Now().Add(-time.Duration(timeout) * time.Second)
	acted := []map[string]interface{}{}

	rows, err := db.Query("SELECT id, ts, alert_id, playbook, action, params, summary, status FROM approvals WHERE status='pending'")
	if err != nil {
		return nil
	}
	pending := []apprRow{}
	for rows.Next() {
		var r apprRow
		var sum sql.NullString
		if err := rows.Scan(&r.ID, &r.Ts, &r.AlertID, &r.Playbook, &r.Action, &r.Params, &sum, &r.Status); err != nil {
			continue
		}
		r.Summary = sum.String
		pending = append(pending, r)
	}
	rows.Close()

	for _, row := range pending {
		created, err := parseISO(row.Ts)
		if err != nil || !created.Before(cutoff) {
			continue
		}
		var params map[string]interface{}
		_ = json.Unmarshal([]byte(row.Params), &params)
		var raw string
		_ = db.QueryRow("SELECT raw FROM alerts WHERE id=?", row.AlertID).Scan(&raw)
		fields := map[string]interface{}{}
		if raw != "" {
			var alert map[string]interface{}
			if json.Unmarshal([]byte(raw), &alert) == nil {
				fields = extractFields(alert)
			}
		}
		if mode == "hold" {
			// hold: containment waits for a human, indefinitely
			continue
		}
		if mode == "auto_execute" {
			var res map[string]interface{}
			switch row.Action {
			case "block_ip":
				res = actionBlockIP(fields, strParam(params, "ip_field", "src_ip"), numParam(params, "duration", 0), row.AlertID, row.Playbook)
			case "isolate_host":
				res = actionIsolateHost(fields, strParam(params, "host_field", "host"), row.AlertID, row.Playbook)
			default:
				res = map[string]interface{}{"status": "unknown_action"}
			}
			_, _ = db.Exec("UPDATE approvals SET status='auto_executed' WHERE id=?", row.ID)
			who := str(fields["src_ip"])
			if who == "" {
				who = str(fields["host"])
			}
			actionNotify(fields, "⏰ ครบเวลารออนุมัติ — ระบบดำเนินการอัตโนมัติ: "+who, row.AlertID, row.Playbook)
			acted = append(acted, map[string]interface{}{"approval_id": row.ID, "status": "auto_executed", "block": res})
		} else {
			_, _ = db.Exec("UPDATE approvals SET status='escalated' WHERE id=?", row.ID)
			actionNotify(map[string]interface{}{}, fmt.Sprintf("🚨 คำขออนุมัติใบที่ %d ยังไม่ได้รับการตัดสินใจ — กรุณารีบตัดสินใจ", row.ID), row.AlertID, row.Playbook)
			acted = append(acted, map[string]interface{}{"approval_id": row.ID, "status": "escalated"})
		}
	}
	return acted
}

func approve(approvalID int64, decision bool) map[string]interface{} {
	var row apprRow
	var sum sql.NullString
	err := db.QueryRow("SELECT id, ts, alert_id, playbook, action, params, summary, status FROM approvals WHERE id=?", approvalID).
		Scan(&row.ID, &row.Ts, &row.AlertID, &row.Playbook, &row.Action, &row.Params, &sum, &row.Status)
	if err != nil {
		return map[string]interface{}{"error": "approval not found"}
	}
	row.Summary = sum.String
	if row.Status != "pending" {
		return map[string]interface{}{"error": "already " + row.Status}
	}
	if CONFIG.ApprovalTO > 0 && CONFIG.ApprovalMode != "hold" {
		if created, err := parseISO(row.Ts); err == nil {
			if time.Since(created) > time.Duration(CONFIG.ApprovalTO)*time.Second {
				return map[string]interface{}{"error": "approval expired — timeout policy applies",
					"run": "reload page to trigger timeout processing"}
			}
		}
	}
	status := "denied"
	if decision {
		status = "approved"
	}
	_, _ = db.Exec("UPDATE approvals SET status = ? WHERE id = ?", status, approvalID)
	if !decision {
		return map[string]interface{}{"status": "denied"}
	}
	var params map[string]interface{}
	_ = json.Unmarshal([]byte(row.Params), &params)
	var raw string
	_ = db.QueryRow("SELECT raw FROM alerts WHERE id=?", row.AlertID).Scan(&raw)
	fields := map[string]interface{}{}
	if raw != "" {
		var alert map[string]interface{}
		if json.Unmarshal([]byte(raw), &alert) == nil {
			fields = extractFields(alert)
		}
	}
	var result map[string]interface{}
	switch row.Action {
	case "block_ip":
		result = actionBlockIP(fields, strParam(params, "ip_field", "src_ip"), numParam(params, "duration", 0), row.AlertID, row.Playbook)
	case "isolate_host":
		result = actionIsolateHost(fields, strParam(params, "host_field", "host"), row.AlertID, row.Playbook)
	default:
		result = map[string]interface{}{"status": "unknown_action"}
	}
	return map[string]interface{}{"status": "approved", "block": result}
}
