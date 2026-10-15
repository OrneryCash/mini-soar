package main

import (
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

var pages map[string]*template.Template

func loadPages() {
	funcs := template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
	}
	pages = map[string]*template.Template{}
	for _, p := range []string{"dashboard", "playbooks", "approvals", "audit", "line", "settings"} {
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
	mux.HandleFunc("GET /line", handleLinePage)
	mux.HandleFunc("GET /settings", handleSettingsPage)
	mux.HandleFunc("POST /api/settings/{action}", handleAPISetMode)
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
	mux.HandleFunc("POST /api/line/test", handleLineTest)
	mux.HandleFunc("POST /api/line/send", handleLineSendTest)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(BASE, "static")))))

	port := CONFIG.Server.Port
	if port == 0 {
		port = 8080
	}
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Printf("mini-SOAR (Go) listening on %s  (base=%s)", addr, BASE)
	log.Fatal(http.ListenAndServe(addr, mux))
}
