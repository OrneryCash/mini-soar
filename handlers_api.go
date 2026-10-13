package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if CONFIG.WebhookSecret != "" {
		if r.Header.Get("X-Mini-SOAR-Secret") != CONFIG.WebhookSecret {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
	}
	var alert map[string]interface{}
	b, _ := readAll(r)
	if err := json.Unmarshal(b, &alert); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	writeJSON(w, 200, processAlert(alert))
}

func handleAPIList(w http.ResponseWriter, r *http.Request) {
	out := []map[string]interface{}{}
	for _, b := range loadPlaybooks() {
		out = append(out, map[string]interface{}{
			"name": b.Name, "description": b.Description, "gate": b.Gate,
			"enabled": b.Enabled, "_custom": b.custom,
		})
	}
	writeJSON(w, 200, out)
}

func handleAPIGet(w http.ResponseWriter, r *http.Request) {
	book := readBook(r.PathValue("name"))
	if book == nil {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, 200, playbookFormPayload(book))
}

func handleAPIPut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body := readJSON(r)
	result := savePlaybookForm(name, body)
	if ok, _ := result["ok"].(bool); !ok {
		writeJSON(w, 400, map[string]interface{}{"error": result["errors"]})
		return
	}
	writeJSON(w, 200, playbookFormPayload(result["playbook"].(*Playbook)))
}

func handleAPICreate(w http.ResponseWriter, r *http.Request) {
	body := readJSON(r)
	name := strings.TrimSpace(dictStr(body, "name"))
	result := savePlaybookForm(name, body)
	if ok, _ := result["ok"].(bool); !ok {
		writeJSON(w, 400, map[string]interface{}{"error": result["errors"]})
		return
	}
	writeJSON(w, 200, playbookFormPayload(result["playbook"].(*Playbook)))
}

func handleAPITest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body := readJSON(r)
	var alert map[string]interface{}
	if sa, ok := body["sample_alert"].(map[string]interface{}); ok {
		alert = sa
	} else {
		alert = sampleAlert
	}
	if draft, ok := body["draft"].(map[string]interface{}); ok {
		var locks *Locks
		if ex := readBook(name); ex != nil {
			locks = ex.Locks
		}
		errs, clean := validatePlaybookForm(draft, locks)
		if len(errs) > 0 {
			writeJSON(w, 400, map[string]interface{}{"error": errs})
			return
		}
		writeJSON(w, 200, previewPlaybook(bookFromForm(name, clean), alert))
		return
	}
	book := readBook(name)
	if book == nil {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, 200, previewPlaybook(book, alert))
}

func handleAPIRevert(w http.ResponseWriter, r *http.Request) {
	result := revertPlaybook(r.PathValue("name"))
	if ok, _ := result["ok"].(bool); !ok {
		writeJSON(w, 400, map[string]interface{}{"error": result["error"]})
		return
	}
	writeJSON(w, 200, playbookFormPayload(result["playbook"].(*Playbook)))
}

func handleAPIDelete(w http.ResponseWriter, r *http.Request) {
	result := deletePlaybook(r.PathValue("name"))
	if ok, _ := result["ok"].(bool); !ok {
		writeJSON(w, 400, map[string]interface{}{"error": result["error"]})
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func handleApprove(w http.ResponseWriter, r *http.Request) {
	id := mustInt(r.PathValue("id"))
	writeJSON(w, 200, approve(id, true))
}

func handleDeny(w http.ResponseWriter, r *http.Request) {
	id := mustInt(r.PathValue("id"))
	writeJSON(w, 200, approve(id, false))
}

func handleAPIAlerts(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 20)
	rows, _ := db.Query("SELECT id, ts, source, title, severity, siem, matched_playbooks FROM alerts ORDER BY id DESC LIMIT ?", limit)
	out := []map[string]interface{}{}
	if rows != nil {
		defer rows.Close()
		for _, a := range scanAlerts(rows) {
			siem := a.SIEM
			if siem == "" {
				siem = "generic"
			}
			out = append(out, map[string]interface{}{"id": a.ID, "ts": a.Ts, "source": a.Source,
				"title": a.Title, "severity": a.Severity, "siem": siem, "matched_playbooks": a.MatchedPlaybooks})
		}
	}
	writeJSON(w, 200, out)
}

func handleAPIActions(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	rows, _ := db.Query("SELECT id, ts, alert_id, playbook, action, detail, status FROM actions ORDER BY id DESC LIMIT ?", limit)
	out := []map[string]interface{}{}
	if rows != nil {
		defer rows.Close()
		for _, a := range scanActions(rows) {
			out = append(out, map[string]interface{}{"id": a.ID, "ts": a.Ts, "alert_id": a.AlertID,
				"playbook": a.Playbook, "action": a.Action, "detail": a.Detail, "status": a.Status})
		}
	}
	writeJSON(w, 200, out)
}

func handleAPIApprovals(w http.ResponseWriter, r *http.Request) {
	checkExpiredApprovals()
	limit := queryInt(r, "limit", 50)
	status := r.URL.Query().Get("status")
	var rows *sql.Rows
	if status != "" {
		rows, _ = db.Query("SELECT id, ts, alert_id, playbook, action, params, summary, status, ifnull(count,1) FROM approvals WHERE status=? ORDER BY id DESC LIMIT ?", status, limit)
	} else {
		rows, _ = db.Query("SELECT id, ts, alert_id, playbook, action, params, summary, status, ifnull(count,1) FROM approvals ORDER BY id DESC LIMIT ?", limit)
	}
	out := []map[string]interface{}{}
	if rows != nil {
		defer rows.Close()
		for _, a := range scanApprovals(rows) {
			out = append(out, map[string]interface{}{"id": a.ID, "ts": a.Ts, "alert_id": a.AlertID,
				"playbook": a.Playbook, "action": a.Action, "params": a.Params,
				"summary": a.Summary, "status": a.Status, "count": a.Count})
		}
	}
	writeJSON(w, 200, out)
}

func handleAPIStats(w http.ResponseWriter, r *http.Request) {
	checkExpiredApprovals()
	var pending, activeBlocks, total int
	_ = db.QueryRow("SELECT count(*) FROM approvals WHERE status='pending'").Scan(&pending)
	_ = db.QueryRow("SELECT count(*) FROM blocks WHERE status IN ('active','simulated') AND expires_at > ?", nowISO()).Scan(&activeBlocks)
	_ = db.QueryRow("SELECT count(*) FROM alerts").Scan(&total)
	writeJSON(w, 200, map[string]int{"pending": pending, "active_blocks": activeBlocks, "total_alerts": total})
}

// ---------------------------------------------------------------- helpers
