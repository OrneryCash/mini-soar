package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	d := DashboardData{}
	_ = db.QueryRow("SELECT count(*) FROM alerts").Scan(&d.TotalAlerts)
	_ = db.QueryRow("SELECT count(*) FROM approvals WHERE status='pending'").Scan(&d.Pending)
	_ = db.QueryRow("SELECT count(*) FROM blocks WHERE status IN ('active','simulated') AND expires_at > ?", nowISO()).Scan(&d.ActiveBlocks)
	rows, _ := db.Query("SELECT id, ts, source, title, severity, siem, matched_playbooks FROM alerts ORDER BY id DESC LIMIT 20")
	if rows != nil {
		defer rows.Close()
		for _, a := range scanAlerts(rows) {
			cls, lbl := sevParts(a.Severity)
			pills := []string{}
			for _, m := range strings.Split(a.MatchedPlaybooks, ",") {
				if m != "" {
					pills = append(pills, m)
				}
			}
			siem := a.SIEM
			if siem == "" {
				siem = "generic"
			}
			d.Alerts = append(d.Alerts, AlertView{ID: a.ID, Ts: a.Ts, SIEM: siem, Source: a.Source,
				Title: a.Title, SevClass: cls, SevLabel: lbl, Pills: pills})
		}
	}
	render(w, "dashboard", d)
}

func handlePlaybooksPage(w http.ResponseWriter, r *http.Request) {
	d := PlaybooksData{}
	for _, b := range loadPlaybooks() {
		gclass := b.Gate
		if gclass == "" {
			gclass = "auto"
		}
		gv := "ต้องอนุมัติ"
		if gclass != "human" {
			gv = "อัตโนมัติ"
		}
		sl, sc := "เปิด", "on"
		if !b.Enabled {
			sl, sc = "ปิด", "off"
		}
		d.Books = append(d.Books, BookView{
			Name: b.Name, Description: b.Description, Enabled: b.Enabled,
			IsCustom: b.custom, Edited: hasHistory(b.Name),
			GateClass: gclass, GateLabel: gv, StatusLabel: sl, StatusClass: sc,
		})
	}
	if testName := r.URL.Query().Get("test"); testName != "" {
		if book := readBook(testName); book != nil {
			form := playbookFormPayload(book)
			d.HasInitial = true
			d.InitName = str(form["name"])
			d.InitDesc = str(form["description"])
			d.InitTemplate = str(form["notify_template"])
			d.InitEnabled = dictBool(form, "enabled", true)
			d.InitCustom = dictBool(form, "custom", false)
			d.InitGate = dictStrDefault(form, "gate", "auto")
			d.InitKeywords = dictList(form, "keywords")
			d.InitActions = dictList(form, "actions")
			d.InitNotIPText = strings.Join(dictList(form, "not_ip"), "\n")
			if aj, err := json.Marshal(d.InitActions); err == nil {
				d.InitActionsJS = template.JS(aj)
			}
			locks := form["locks"]
			if locks == nil {
				locks = map[string]interface{}{}
			}
			if lj, err := json.Marshal(locks); err == nil {
				d.InitLocksJS = template.JS(lj)
			}
			pv := previewPlaybook(book, sampleAlert)
			pv["name"] = testName
			d.InitialPreview = pv
		}
	}
	minSev := 0
	if d.HasInitial {
		if book := readBook(testName2(r)); book != nil {
			f := playbookFormPayload(book)
			minSev = numParam(f, "min_severity", 0)
		}
	}
	for i := 0; i < 16; i++ {
		lbl := strconv.Itoa(i)
		if i == 0 {
			lbl = "ไม่จำกัด (0)"
		}
		d.MinSevOptions = append(d.MinSevOptions, SelectOpt{Value: i, Label: lbl, Selected: i == minSev})
	}
	dur := CONFIG.BlockDefault
	if d.HasInitial {
		if book := readBook(testName2(r)); book != nil {
			if dd := numParam(playbookFormPayload(book), "block_duration", 0); dd != 0 {
				dur = dd
			}
		}
	}
	for _, o := range []SelectOpt{{600, "10 นาที", false}, {1800, "30 นาที", false}, {3600, "60 นาที", false}, {86400, "24 ชั่วโมง", false}} {
		o.Selected = o.Value == dur
		d.DurOptions = append(d.DurOptions, o)
	}
	render(w, "playbooks", d)
}

func testName2(r *http.Request) string { return r.URL.Query().Get("test") }

func handleApprovalsPage(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, ts, alert_id, playbook, action, params, summary, status, ifnull(count,1) FROM approvals WHERE status='pending' ORDER BY id DESC LIMIT 50")
	d := ApprovalsData{Rows: []Approval{}}
	if rows != nil {
		defer rows.Close()
		d.Rows = scanApprovals(rows)
	}
	render(w, "approvals", d)
}

func handleAuditPage(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, ts, alert_id, playbook, action, detail, status FROM actions ORDER BY id DESC LIMIT 100")
	d := AuditData{Rows: []Action{}}
	if rows != nil {
		defer rows.Close()
		d.Rows = scanActions(rows)
	}
	render(w, "audit", d)
}

func handleToggle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body := readJSON(r)
	enabled := dictBool(body, "enabled", true)
	setState(name, enabled)
	writeJSON(w, 200, map[string]interface{}{"name": name, "enabled": enabled})
}
