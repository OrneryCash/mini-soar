// main.go — mini-SOAR HTTP layer (Go port of app/main.py):
// webhook receiver + Thai web UI + admin API.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- view models

type AlertView struct {
	ID                        int64
	Ts, SIEM, Source, Title   string
	SevClass, SevLabel        string
	Pills                     []string
}

type BookView struct {
	Name, Description                      string
	Enabled, IsCustom, Edited              bool
	GateClass, GateLabel, StatusLabel      string
	StatusClass                            string
}

type DashboardData struct {
	TotalAlerts, Pending, ActiveBlocks int
	Alerts                             []AlertView
}

type SelectOpt struct {
	Value    int
	Label    string
	Selected bool
}

type PlaybooksData struct {
	Books []BookView

	HasInitial     bool
	InitName       string
	InitDesc       string
	InitTemplate   string
	InitNotIPText  string
	InitEnabled    bool
	InitCustom     bool
	InitGate       string
	InitKeywords   []string
	InitActions    []string
	InitActionsJS  template.JS
	InitLocksJS    template.JS
	MinSevOptions  []SelectOpt
	DurOptions     []SelectOpt
	InitialPreview map[string]interface{}
}

type ApprovalsData struct{ Rows []Approval }
type AuditData struct{ Rows []Action }

var pages map[string]*template.Template

func sevParts(n int64) (string, string) {
	switch {
	case n >= 13:
		return "crit", "วิกฤต"
	case n >= 10:
		return "high", "สูง"
	case n >= 6:
		return "med", "กลาง"
	default:
		return "low", "ต่ำ"
	}
}

func loadPages() {
	funcs := template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
	}
	pages = map[string]*template.Template{}
	for _, p := range []string{"dashboard", "playbooks", "approvals", "audit"} {
		t, err := template.New("base.html").Funcs(funcs).ParseFiles(
			filepath.Join(BASE, "templates", "base.html"),
			filepath.Join(BASE, "templates", p+".html"))
		if err != nil {
			log.Fatalf("template %s: %v", p, err)
		}
		pages[p] = t
	}
}

func render(w http.ResponseWriter, page string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages[page].ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("render %s: %v", page, err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	w.Write(b)
}

func readJSON(r *http.Request) map[string]interface{} {
	var m map[string]interface{}
	b, _ := readAll(r)
	_ = json.Unmarshal(b, &m)
	if m == nil {
		m = map[string]interface{}{}
	}
	return m
}

func readAll(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := r.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

// ---------------------------------------------------------------- handlers

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

func mustInt(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// ---------------------------------------------------------------- main

func main() {
	exe, _ := os.Executable()
	BASE = filepath.Dir(exe)
	// Allow running from the source dir too.
	if _, err := os.Stat(filepath.Join(BASE, "config.yaml")); err != nil {
		if wd, err := os.Getwd(); err == nil {
			BASE = wd
		}
	}
	CONFIG = loadConfig()
	if err := initDB(); err != nil {
		log.Fatalf("db: %v", err)
	}
	loadPages()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook", handleWebhook)
	mux.HandleFunc("GET /{$}", handleDashboard)
	mux.HandleFunc("GET /playbooks", handlePlaybooksPage)
	mux.HandleFunc("GET /approvals", handleApprovalsPage)
	mux.HandleFunc("GET /audit", handleAuditPage)
	mux.HandleFunc("POST /api/playbooks/{name}/toggle", handleToggle)
	mux.HandleFunc("GET /api/playbooks", handleAPIList)
	mux.HandleFunc("GET /api/playbooks/{name}", handleAPIGet)
	mux.HandleFunc("PUT /api/playbooks/{name}", handleAPIPut)
	mux.HandleFunc("POST /api/playbooks", handleAPICreate)
	mux.HandleFunc("POST /api/playbooks/{name}/test", handleAPITest)
	mux.HandleFunc("POST /api/playbooks/{name}/revert", handleAPIRevert)
	mux.HandleFunc("DELETE /api/playbooks/{name}", handleAPIDelete)
	mux.HandleFunc("POST /api/approvals/{id}/approve", handleApprove)
	mux.HandleFunc("POST /api/approvals/{id}/deny", handleDeny)
	mux.HandleFunc("GET /api/alerts", handleAPIAlerts)
	mux.HandleFunc("GET /api/actions", handleAPIActions)
	mux.HandleFunc("GET /api/approvals", handleAPIApprovals)
	mux.HandleFunc("GET /api/stats", handleAPIStats)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(BASE, "static")))))

	port := CONFIG.Server.Port
	if port == 0 {
		port = 8080
	}
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("mini-SOAR (Go) listening on %s  (base=%s)", addr, BASE)
	log.Fatal(http.ListenAndServe(addr, mux))
}
