// core.go — mini-SOAR engine (Go port of app/core.py).
//
// Webhook receiver (SIEM-agnostic) -> rules engine (YAML playbooks) -> actions.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

// ------------------------------------------------------------------ config

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	PlaybooksDir  string `yaml:"playbooks_dir"`
	DataDir       string `yaml:"data_dir"`
	EvidenceDir   string `yaml:"evidence_dir"`
	LineToken     string `yaml:"line_channel_token"`
	LineTarget    string `yaml:"line_target_user_id"`
	Firewall      string `yaml:"firewall_backend"`
	BlockDefault  int    `yaml:"block_default_duration"`
	ApprovalTO    int    `yaml:"approval_timeout_seconds"`
	ApprovalMode  string `yaml:"approval_timeout_action"`
	WebhookSecret string `yaml:"webhook_secret"`
	DBPath        string `yaml:"db_path"`
}

var BASE string

func loadConfig() Config {
	var c Config
	b, err := os.ReadFile(filepath.Join(BASE, "config.yaml"))
	if err == nil {
		_ = yaml.Unmarshal(b, &c)
	}
	if c.PlaybooksDir == "" {
		c.PlaybooksDir = "playbooks"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.EvidenceDir == "" {
		c.EvidenceDir = "evidence"
	}
	if c.Firewall == "" {
		c.Firewall = "simulated"
	}
	if c.BlockDefault == 0 {
		c.BlockDefault = 600
	}
	if c.ApprovalMode == "" {
		c.ApprovalMode = "escalate"
	}
	return c
}

var CONFIG Config

func nowISO() string { return time.Now().UTC().Format("2006-01-02T15:04:05+00:00") }

func parseISO(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02T15:04:05+00:00", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// ------------------------------------------------------------------ database

var db *sql.DB

func dbPath() string {
	if CONFIG.DBPath != "" {
		return CONFIG.DBPath
	}
	return filepath.Join(BASE, CONFIG.DataDir, "minisoar.db")
}

func initDB() error {
	p := dbPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	var err error
	db, err = sql.Open("sqlite3", "file:"+p+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(8)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, source TEXT, title TEXT, severity INTEGER DEFAULT 0, raw TEXT NOT NULL, matched_playbooks TEXT);
CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER, playbook TEXT, action TEXT, detail TEXT, status TEXT DEFAULT 'executed');
CREATE TABLE IF NOT EXISTS approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER, playbook TEXT, action TEXT, params TEXT, summary TEXT, status TEXT DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL, duration INTEGER, expires_at TEXT, backend TEXT, status TEXT DEFAULT 'active');
CREATE TABLE IF NOT EXISTS playbook_history (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data TEXT NOT NULL, ts TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	var n int
	_ = db.QueryRow("SELECT count(*) FROM pragma_table_info('alerts') WHERE name='siem'").Scan(&n)
	if n == 0 {
		_, _ = db.Exec("ALTER TABLE alerts ADD COLUMN siem TEXT")
	}
	return nil
}

func auditInsert(table string, cols map[string]interface{}) (int64, error) {
	keys := make([]string, 0, len(cols))
	for k := range cols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	marks := make([]string, len(keys))
	vals := make([]interface{}, len(keys))
	for i, k := range keys {
		marks[i] = "?"
		vals[i] = cols[k]
	}
	res, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(keys, ", "), strings.Join(marks, ", ")), vals...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ------------------------------------------------------------------ rows

type Alert struct {
	ID, Severity           int64
	Ts, Source, Title      string
	SIEM, MatchedPlaybooks string
}

type Action struct {
	ID, AlertID     int64
	Ts, Playbook    string
	Action, Detail  string
	Status          string
	HumanDetail     string
}

type Approval struct {
	ID, AlertID                     int64
	Ts, Playbook, Action, Params    string
	Summary, Status                 string
}

type Block struct {
	ID, Duration            int64
	Ts, IP, ExpiresAt       string
	Backend, Status         string
}

func scanAlerts(rows *sql.Rows) []Alert {
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var siem, mp sql.NullString
		if err := rows.Scan(&a.ID, &a.Ts, &a.Source, &a.Title, &a.Severity, &siem, &mp); err != nil {
			continue
		}
		a.SIEM, a.MatchedPlaybooks = siem.String, mp.String
		out = append(out, a)
	}
	return out
}

func scanActions(rows *sql.Rows) []Action {
	out := []Action{}
	for rows.Next() {
		var a Action
		if err := rows.Scan(&a.ID, &a.Ts, &a.AlertID, &a.Playbook, &a.Action, &a.Detail, &a.Status); err != nil {
			continue
		}
		a.HumanDetail = humanActionDetail(a)
		out = append(out, a)
	}
	return out
}

func scanApprovals(rows *sql.Rows) []Approval {
	out := []Approval{}
	for rows.Next() {
		var a Approval
		var sum sql.NullString
		if err := rows.Scan(&a.ID, &a.Ts, &a.AlertID, &a.Playbook, &a.Action, &a.Params, &sum, &a.Status); err != nil {
			continue
		}
		a.Summary = sum.String
		out = append(out, a)
	}
	return out
}

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

func detectSIEM(a map[string]interface{}) string {
	if str(a["provider"]) == "Microsoft Sentinel" {
		return "sentinel"
	}
	if _, ok := a["entities"].([]interface{}); ok {
		return "sentinel"
	}
	if _, ok := a["_time"]; ok {
		if ev, ok := a["event"].(map[string]interface{}); ok {
			if _, ok := ev["signature"]; ok {
				return "splunk"
			}
		}
	}
	if r, ok := a["rule"].(map[string]interface{}); ok && str(r["description"]) != "" {
		if _, ok := a["agent"].(map[string]interface{}); ok {
			return "wazuh"
		}
	}
	if _, ok := a["@timestamp"]; ok {
		if s, ok := a["source"].(map[string]interface{}); ok {
			if _, ok := s["ip"]; ok {
				return "elastic"
			}
		}
	}
	return "generic"
}

func getPath(obj interface{}, path string) interface{} {
	cur := obj
	for _, part := range strings.Split(path, ".") {
		switch t := cur.(type) {
		case map[string]interface{}:
			v, ok := t[part]
			if !ok {
				return nil
			}
			cur = v
		case []interface{}:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			cur = t[i]
		default:
			return nil
		}
	}
	return cur
}

// str renders any JSON value as Python's str() would for our purposes.
func str(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, str(x))
		}
		return strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

var aliases = map[string][]string{
	"src_ip":     {"data.srcip", "data.src_ip", "src_ip", "srcip", "source.ip", "source_ip", "data.source_ip", "data.src", "predecoded.srcip", "event.src_ip"},
	"dst_ip":     {"data.dstip", "data.dst_ip", "dst_ip", "dstip", "destination.ip", "destination_ip", "dest_ip", "data.dst", "predecoded.dstip", "event.dest_ip"},
	"user":       {"data.user", "user.name", "username", "data.username", "user", "predecoded.user", "data.srcuser", "event.user"},
	"host":       {"agent.name", "host.name", "hostname", "data.host", "host", "agent.hostname", "data.hostname", "predecoded.hostname", "event.hostname"},
	"hash":       {"data.hash", "file.hash.sha256", "file.hash.md5", "data.md5", "data.sha256", "hash", "sha256", "md5"},
	"url":        {"data.url", "url.full", "url.domain", "url", "data.full_url", "data.reference"},
	"rule_id":    {"rule.id", "rule_id", "event.code"},
	"rule_group": {"rule.groups", "rule.group", "event.category", "rule.category", "rule_group"},
}

func extractFields(a map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	pick := func(canon string) string {
		for _, p := range aliases[canon] {
			v := getPath(a, p)
			if v != nil && str(v) != "" {
				return str(v)
			}
		}
		return ""
	}
	for canon := range aliases {
		if v := pick(canon); v != "" {
			out[canon] = v
		}
	}
	title := ""
	for _, k := range []string{"title"} {
		if v := str(a[k]); v != "" {
			title = v
		}
	}
	if title == "" {
		for _, p := range []string{"rule.description", "rule.name", "event.signature", "signature", "name", "message"} {
			if v := str(getPath(a, p)); v != "" {
				title = v
				break
			}
		}
	}
	out["title"] = title

	sev := a["severity"]
	if sev == nil {
		sev = a["level"]
	}
	if sev == nil {
		sev = getPath(a, "rule.level")
	}
	if sev == nil {
		sev = getPath(a, "event.severity")
	}
	out["severity"] = toSeverity(sev)

	src := str(getPath(a, "agent.name"))
	if src == "" {
		src = str(getPath(a, "host.name"))
	}
	if src == "" {
		src = str(getPath(a, "event.module"))
	}
	if src == "" {
		src = str(a["sourcetype"])
	}
	if src == "" {
		src = str(a["provider"])
	}
	if src == "" {
		src = "unknown"
	}
	out["source"] = src

	ts := ""
	for _, k := range []string{"timestamp", "@timestamp", "_time"} {
		if v := str(a[k]); v != "" {
			ts = v
			break
		}
	}
	if ts == "" {
		ts = nowISO()
	}
	out["timestamp"] = ts
	extractSentinelEntities(a, out)
	out["siem"] = detectSIEM(a)
	return out
}

var sevNames = map[string]int{"critical": 15, "high": 12, "medium": 8, "low": 4, "informational": 1, "info": 1}

func toSeverity(sev interface{}) int {
	if sev == nil {
		return 0
	}
	switch t := sev.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
		return sevNames[strings.ToLower(strings.TrimSpace(t))]
	}
	return 0
}

func extractSentinelEntities(a map[string]interface{}, out map[string]interface{}) {
	ents, _ := a["entities"].([]interface{})
	for _, e := range ents {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		etype := strings.ToLower(str(m["type"]))
		switch etype {
		case "ip":
			if _, has := out["src_ip"]; !has && str(m["address"]) != "" {
				out["src_ip"] = str(m["address"])
			}
		case "host":
			if _, has := out["host"]; !has && str(m["hostName"]) != "" {
				out["host"] = str(m["hostName"])
			}
		case "account":
			if _, has := out["user"]; !has && str(m["name"]) != "" {
				out["user"] = str(m["name"])
			}
		}
	}
}

// ------------------------------------------------------------------ actions

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

var safeFormatRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

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

type When struct {
	Pattern     string   `yaml:"pattern,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty"`
	MinSeverity int      `yaml:"min_severity,omitempty"`
	NotIP       []string `yaml:"not_ip,omitempty"`
}

type Step struct {
	Action string                 `yaml:"action"`
	Params map[string]interface{} `yaml:"params,omitempty"`
	Gate   string                 `yaml:"gate,omitempty"`
}

type Locks struct {
	IsolateHost string `yaml:"isolate_host,omitempty"`
}

type Playbook struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled"`
	Gate        string `yaml:"gate,omitempty"`
	Locks       *Locks `yaml:"locks,omitempty"`
	When        When   `yaml:"when,omitempty"`
	Source      string `yaml:"source,omitempty"`
	Steps       []Step `yaml:"steps"`

	re     *regexp.Regexp
	custom bool
}

var (
	pbMu  sync.Mutex
	pbSig string
	pbSet []*Playbook
)

func playbooksDir() string { return filepath.Join(BASE, CONFIG.PlaybooksDir) }

func playbookPath(name string) string { return filepath.Join(playbooksDir(), name+".yaml") }

func dirSignature(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".tmp") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", n, st.ModTime().UnixNano(), st.Size())
		}
	}
	return b.String()
}

func compile(p *Playbook) {
	if p.When.Pattern != "" {
		if re, err := regexp.Compile("(?i)" + p.When.Pattern); err == nil {
			p.re = re
		}
	}
}

func loadPlaybooks() []*Playbook {
	dir := playbooksDir()
	sig := dirSignature(dir)
	pbMu.Lock()
	defer pbMu.Unlock()
	if pbSet != nil && sig == pbSig {
		return pbSet
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".tmp") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	books := make([]*Playbook, 0, len(names))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		var p Playbook
		if err := yaml.Unmarshal(b, &p); err != nil {
			continue
		}
		p.custom = p.Source == "custom"
		compile(&p)
		books = append(books, &p)
	}
	pbSet, pbSig = books, sig
	return pbSet
}

func readBook(name string) *Playbook {
	p := playbookPath(name)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var book Playbook
	if err := yaml.Unmarshal(b, &book); err != nil {
		return nil
	}
	book.custom = book.Source == "custom"
	compile(&book)
	return &book
}

func readText(name string) (string, bool) {
	b, err := os.ReadFile(playbookPath(name))
	if err != nil {
		return "", false
	}
	return string(b), true
}

const yamlHeader = "# Mini-SOAR playbook — แก้ไขผ่านฟอร์มภาษาไทย (Thai UI)\n" +
	"# แก้ไขแต่ละครั้งจะบันทึกเป็น YAML ไฟล์โดยตรง — single source of truth\n"

func writeBook(name string, book *Playbook) error {
	path := playbookPath(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := yaml.Marshal(book)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(yamlHeader+string(out)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func historyPush(name, yamlText string) {
	res, err := db.Exec("INSERT INTO playbook_history (name, data, ts) VALUES (?, ?, ?)", name, yamlText, nowISO())
	if err != nil {
		return
	}
	_ = res
	_, _ = db.Exec(`DELETE FROM playbook_history WHERE name=? AND id NOT IN (SELECT id FROM playbook_history WHERE name=? ORDER BY id DESC LIMIT 10)`, name, name)
}

func historyPop(name string) (string, bool) {
	var id int64
	var data string
	err := db.QueryRow("SELECT id, data FROM playbook_history WHERE name=? ORDER BY id DESC LIMIT 1", name).Scan(&id, &data)
	if err != nil {
		return "", false
	}
	_, _ = db.Exec("DELETE FROM playbook_history WHERE id=?", id)
	return data, true
}

func hasHistory(name string) bool {
	var n int
	_ = db.QueryRow("SELECT count(*) FROM playbook_history WHERE name=?", name).Scan(&n)
	return n > 0
}

func setState(name string, enabled bool) {
	book := readBook(name)
	if book == nil {
		return
	}
	book.Enabled = enabled
	_ = writeBook(name, book)
}

// ------------------------------------------------------------------ form

var customNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-_]{0,63}$`)

var allowedActions = []string{"notify", "preserve_evidence", "block_ip", "isolate_host", "audit"}
var allowedDurations = []int{600, 1800, 3600, 86400}
var templatePlaceholders = map[string]bool{"title": true, "src_ip": true, "dst_ip": true, "host": true, "user": true, "url": true, "hash": true, "severity": true, "source": true}

var sampleAlert = map[string]interface{}{
	"title": "ตัวอย่าง: SSH brute force", "severity": 10, "src_ip": "203.0.113.66",
	"host": "HIS-SERVER-01", "user": "root", "source": "wazuh", "rule_id": "5551",
}

func inList(s string, list []string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func buildKeywordsPattern(keywords []string) string {
	kws := []string{}
	for _, k := range keywords {
		if s := strings.TrimSpace(k); s != "" {
			kws = append(kws, regexp.QuoteMeta(s))
		}
	}
	if len(kws) == 0 {
		return ""
	}
	return "(" + strings.Join(kws, "|") + ")"
}

func numParam(p map[string]interface{}, key string, def int) int {
	if p == nil {
		return def
	}
	switch t := p[key].(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n
		}
	}
	return def
}

func strParam(p map[string]interface{}, key, def string) string {
	if p == nil {
		return def
	}
	if v, ok := p[key]; ok {
		return str(v)
	}
	return def
}

func buildSteps(actions []string, notifyTemplate string, blockDuration int) []Step {
	steps := []Step{}
	for _, a := range actions {
		switch a {
		case "notify":
			steps = append(steps, Step{Action: "notify", Params: map[string]interface{}{"template": strings.TrimSpace(notifyTemplate)}})
		case "preserve_evidence":
			steps = append(steps, Step{Action: "preserve_evidence", Params: map[string]interface{}{}})
		case "block_ip":
			dur := blockDuration
			if dur == 0 {
				dur = CONFIG.BlockDefault
			}
			steps = append(steps, Step{Action: "block_ip", Params: map[string]interface{}{"ip_field": "src_ip", "duration": dur}})
		case "isolate_host":
			steps = append(steps, Step{Action: "isolate_host", Params: map[string]interface{}{"host_field": "host"}, Gate: "human"})
		case "audit":
			steps = append(steps, Step{Action: "audit", Params: map[string]interface{}{}})
		}
	}
	return steps
}

func dictStr(d map[string]interface{}, k string) string {
	if d == nil {
		return ""
	}
	return str(d[k])
}

func dictList(d map[string]interface{}, k string) []string {
	if d == nil {
		return nil
	}
	raw, ok := d[k].([]interface{})
	if !ok {
		if ss, ok := d[k].([]string); ok {
			return ss
		}
		return nil
	}
	out := []string{}
	for _, x := range raw {
		out = append(out, str(x))
	}
	return out
}

func bookFromForm(name string, clean map[string]interface{}) *Playbook {
	w := When{}
	if pat := buildKeywordsPattern(dictList(clean, "keywords")); pat != "" {
		w.Pattern = pat
		w.Keywords = dictList(clean, "keywords")
	}
	if ms := numParam(clean, "min_severity", 0); ms != 0 {
		w.MinSeverity = ms
	}
	if ip := dictList(clean, "not_ip"); len(ip) > 0 {
		w.NotIP = ip
	}
	return &Playbook{
		Name:        name,
		Description: dictStr(clean, "description"),
		Enabled:     dictBool(clean, "enabled", true),
		Gate:        dictStrDefault(clean, "gate", "auto"),
		When:        w,
		Steps:       buildSteps(dictList(clean, "actions"), dictStr(clean, "notify_template"), numParam(clean, "block_duration", 0)),
	}
}

func dictBool(d map[string]interface{}, k string, def bool) bool {
	if d == nil {
		return def
	}
	if v, ok := d[k]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return t == "true" || t == "1"
		}
	}
	return def
}

func dictStrDefault(d map[string]interface{}, k, def string) string {
	if v := dictStr(d, k); v != "" {
		return v
	}
	return def
}

// validatePlaybookForm mirrors core.validate_playbook_form().
func validatePlaybookForm(data map[string]interface{}, locks *Locks) ([]string, map[string]interface{}) {
	errs := []string{}
	out := map[string]interface{}{}

	desc := strings.TrimSpace(dictStr(data, "description"))
	if len([]rune(desc)) > 200 {
		errs = append(errs, "คำอธิบายยาวเกินไป (สูงสุด 200 ตัวอักษร)")
	}
	out["description"] = desc
	out["enabled"] = dictBool(data, "enabled", true)

	gate := dictStrDefault(data, "gate", "auto")
	if gate != "auto" && gate != "human" {
		errs = append(errs, "โหมดการทำงานไม่ถูกต้อง")
	}
	out["gate"] = gate

	kws := []string{}
	for _, k := range dictList(data, "keywords") {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if len([]rune(k)) > 64 {
			errs = append(errs, "คำค้นหายาวเกินไป (สูงสุด 64 ตัวอักษร): "+k)
		}
		kws = append(kws, k)
	}
	out["keywords"] = kws

	minSev := numParam(data, "min_severity", 0)
	if minSev < 0 || minSev > 15 {
		errs = append(errs, "ความรุนแรงขั้นต่ำต้องเป็นตัวเลข 0–15")
		minSev = 0
	}
	out["min_severity"] = minSev

	ips := []string{}
	for _, x := range dictList(data, "not_ip") {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if net.ParseIP(x) == nil {
			errs = append(errs, "IP ข้อยกเว้นไม่ถูกต้อง: "+x)
		}
		ips = append(ips, x)
	}
	out["not_ip"] = ips

	dur := numParam(data, "block_duration", 0)
	if dur != 0 {
		ok := false
		for _, d := range allowedDurations {
			if d == dur {
				ok = true
			}
		}
		if !ok {
			errs = append(errs, "ระยะเวลาบล็อกต้องเป็นหนึ่งในตัวเลือกที่กำหนด")
			dur = 600
		}
	}
	out["block_duration"] = dur
	if dur == 0 {
		out["block_duration"] = 600
	}

	tpl := dictStr(data, "notify_template")
	if len([]rune(tpl)) > 200 {
		errs = append(errs, "ข้อความแจ้งเตือนยาวเกินไป (สูงสุด 200 ตัวอักษร)")
	}
	for _, m := range safeFormatRe.FindAllStringSubmatch(tpl, -1) {
		if !templatePlaceholders[m[1]] {
			errs = append(errs, "ตัวแปร {"+m[1]+"} ไม่ได้รับอนุญาต — ใช้ได้เฉพาะ: title, src_ip, dst_ip, host, user, url, hash, severity, source")
		}
	}
	out["notify_template"] = tpl

	acts := []string{}
	seen := map[string]bool{}
	for _, a := range dictList(data, "actions") {
		if inList(a, allowedActions) && !seen[a] {
			seen[a] = true
			acts = append(acts, a)
		}
	}
	if len(acts) == 0 {
		errs = append(errs, "กรุณาเพิ่มขั้นตอนอย่างน้อย 1 ขั้นตอน")
	}
	out["actions"] = acts
	return errs, out
}

func savePlaybookForm(name string, data map[string]interface{}) map[string]interface{} {
	name = strings.TrimSpace(name)
	existing := readBook(name)
	isCreate := existing == nil
	if !isCreate && !customNameRe.MatchString(name) {
		return map[string]interface{}{"ok": false, "errors": []string{"ชื่อเพลย์บุ๊กต้องเป็นภาษาอังกฤษตัวพิมพ์เล็ก (a-z, 0-9, -, _)"}}
	}
	if isCreate {
		if _, err := os.Stat(playbookPath(name)); err == nil {
			return map[string]interface{}{"ok": false, "errors": []string{"มีเพลย์บุ๊กชื่อนี้อยู่แล้ว — กรุณาใช้ชื่ออื่น"}}
		}
	}
	var locks *Locks
	if existing != nil {
		locks = existing.Locks
	}
	errs, clean := validatePlaybookForm(data, locks)
	if len(errs) > 0 {
		return map[string]interface{}{"ok": false, "errors": errs}
	}

	w := When{}
	if kws := dictList(clean, "keywords"); len(kws) > 0 {
		w.Pattern = buildKeywordsPattern(kws)
		w.Keywords = kws
	}
	if ms := numParam(clean, "min_severity", 0); ms != 0 {
		w.MinSeverity = ms
	}
	if ip := dictList(clean, "not_ip"); len(ip) > 0 {
		w.NotIP = ip
	}
	book := &Playbook{
		Name:        name,
		Description: dictStr(clean, "description"),
		Enabled:     dictBool(clean, "enabled", true),
		Gate:        dictStrDefault(clean, "gate", "auto"),
		When:        w,
		Steps:       buildSteps(dictList(clean, "actions"), dictStr(clean, "notify_template"), numParam(clean, "block_duration", 0)),
	}
	if isCreate {
		book.Source = "custom"
	}
	if existing != nil && existing.Locks != nil {
		book.Locks = existing.Locks
	}
	if prev, ok := readText(name); ok && prev != "" {
		historyPush(name, prev)
	}
	if err := writeBook(name, book); err != nil {
		return map[string]interface{}{"ok": false, "errors": []string{err.Error()}}
	}
	return map[string]interface{}{"ok": true, "playbook": readBook(name)}
}

func revertPlaybook(name string) map[string]interface{} {
	prev, ok := historyPop(name)
	if !ok {
		return map[string]interface{}{"ok": false, "error": "ยังไม่มีเวอร์ชันก่อนหน้าให้ย้อนกลับ"}
	}
	path := playbookPath(name)
	tmp := path + ".tmp"
	_ = os.WriteFile(tmp, []byte(prev), 0o644)
	_ = os.Rename(tmp, path)
	book := readBook(name)
	if book == nil {
		return map[string]interface{}{"ok": false, "error": "ไม่พบเพลย์บุ๊ก"}
	}
	return map[string]interface{}{"ok": true, "playbook": book}
}

func deletePlaybook(name string) map[string]interface{} {
	book := readBook(name)
	if book == nil {
		return map[string]interface{}{"ok": false, "error": "ไม่พบเพลย์บุ๊ก"}
	}
	if !book.custom {
		return map[string]interface{}{"ok": false, "error": "เพลย์บุ๊กมาตรฐานลบไม่ได้ — ใช้ 'ย้อนกลับ' แทน"}
	}
	if prev, ok := readText(name); ok && prev != "" {
		historyPush(name, prev)
	}
	_ = os.Remove(playbookPath(name))
	return map[string]interface{}{"ok": true}
}

func playbookFormPayload(book *Playbook) map[string]interface{} {
	actions := []string{}
	seen := map[string]bool{}
	tpl := ""
	dur := 0
	for _, s := range book.Steps {
		if inList(s.Action, allowedActions) && !seen[s.Action] {
			seen[s.Action] = true
			actions = append(actions, s.Action)
		}
		if s.Action == "notify" && tpl == "" {
			tpl = strParam(s.Params, "template", "")
		}
		if s.Action == "block_ip" && dur == 0 {
			dur = numParam(s.Params, "duration", 0)
		}
	}
	if dur == 0 {
		dur = CONFIG.BlockDefault
	}
	keywords := book.When.Keywords
	if keywords == nil {
		keywords = []string{}
	}
	notip := book.When.NotIP
	if notip == nil {
		notip = []string{}
	}
	var locks interface{} = map[string]interface{}{}
	if book.Locks != nil {
		locks = book.Locks
	}
	return map[string]interface{}{
		"name": book.Name, "description": book.Description, "enabled": book.Enabled,
		"gate": book.Gate, "keywords": keywords, "min_severity": book.When.MinSeverity,
		"not_ip": notip, "block_duration": dur, "notify_template": tpl,
		"actions": actions, "locks": locks, "custom": book.custom,
	}
}

func previewPlaybook(book *Playbook, alert map[string]interface{}) map[string]interface{} {
	fields := extractFields(alert)
	matched := matchPlaybook(book, fields)
	stepsOut := []map[string]interface{}{}
	if matched {
		gateDefault := book.Gate
		if gateDefault == "" {
			gateDefault = "auto"
		}
		for _, step := range book.Steps {
			gate := gateDefault
			if step.Gate != "" {
				gate = step.Gate
			}
			var detail string
			icon := "📝"
			switch step.Action {
			case "notify":
				icon = "🔔"
				detail = safeFormat(strParam(step.Params, "template", ""), fields)
			case "block_ip":
				icon = "🚫"
				if step.Params == nil {
					step.Params = map[string]interface{}{}
				}
				ip := str(fields[strParam(step.Params, "ip_field", "src_ip")])
				if ip == "" {
					ip = "(ไม่พบ)"
				}
				dur := numParam(step.Params, "duration", 0)
				if dur == 0 {
					dur = CONFIG.BlockDefault
				}
				detail = fmt.Sprintf("บล็อก IP %s (%ds)", ip, dur)
			case "isolate_host":
				icon = "🛑"
				host := str(fields[strParam(step.Params, "host_field", "host")])
				if host == "" {
					host = "(ไม่พบ)"
				}
				detail = "แยกโฮสต์ " + host
			case "preserve_evidence":
				icon = "📁"
				detail = "เก็บหลักฐาน (alert JSON)"
			case "audit":
				icon = "📝"
				detail = "บันทึกประวัติ"
			}
			stepsOut = append(stepsOut, map[string]interface{}{"action": step.Action, "gate": gate, "detail": detail, "icon": icon})
		}
	}
	return map[string]interface{}{
		"matched": matched,
		"fields": map[string]interface{}{
			"title": str(fields["title"]), "severity": fields["severity"],
			"src_ip": str(fields["src_ip"]), "host": str(fields["host"]),
			"user": str(fields["user"]), "url": str(fields["url"]),
			"hash": str(fields["hash"]), "source": str(fields["source"]),
		},
		"steps": stepsOut,
	}
}

// ------------------------------------------------------------------ matching

func matchPlaybook(book *Playbook, fields map[string]interface{}) bool {
	if numParam(fields, "severity", 0) < book.When.MinSeverity {
		return false
	}
	if len(book.When.NotIP) > 0 {
		src := str(fields["src_ip"])
		for _, ip := range book.When.NotIP {
			if ip == src {
				return false
			}
		}
	}
	if book.When.Pattern == "" {
		return true
	}
	if book.re == nil {
		return false
	}
	hay := strings.Join(nonEmpty(
		str(fields["title"]), str(fields["rule_id"]), str(fields["rule_group"]),
		str(fields["src_ip"]), str(fields["dst_ip"]), str(fields["user"]),
		str(fields["url"]), str(fields["hash"])), " ")
	return book.re.MatchString(hay)
}

func nonEmpty(vals ...string) []string {
	out := []string{}
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ------------------------------------------------------------------ approvals

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
	pj, _ := json.Marshal(params)
	id, _ := auditInsert("approvals", map[string]interface{}{
		"ts": nowISO(), "alert_id": alertID, "playbook": playbook,
		"action": action, "params": string(pj), "summary": summary,
	})
	return id
}

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

type apprRow struct {
	ID, AlertID            int64
	Ts, Playbook, Action   string
	Params                 string
	Summary, Status        string
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
	if CONFIG.ApprovalTO > 0 {
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
