package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

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
CREATE TABLE IF NOT EXISTS approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert_id INTEGER, playbook TEXT, action TEXT, params TEXT, summary TEXT, status TEXT DEFAULT 'pending', count INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL, duration INTEGER, expires_at TEXT, backend TEXT, status TEXT DEFAULT 'active');
CREATE TABLE IF NOT EXISTS playbook_history (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data TEXT NOT NULL, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL, ts TEXT);`)
	if err != nil {
		return err
	}
	// migration: aggregation counter for DBs created before fix #3
	_, _ = db.Exec("ALTER TABLE approvals ADD COLUMN count INTEGER DEFAULT 1")
	var n int
	_ = db.QueryRow("SELECT count(*) FROM pragma_table_info('alerts') WHERE name='siem'").Scan(&n)
	if n == 0 {
		_, _ = db.Exec("ALTER TABLE alerts ADD COLUMN siem TEXT")
	}
	return nil
}

func auditInsert(table string, cols map[string]interface{}) (int64, error) {
	if db == nil {
		return 0, nil
	}
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
		if err := rows.Scan(&a.ID, &a.Ts, &a.AlertID, &a.Playbook, &a.Action, &a.Params, &sum, &a.Status, &a.Count); err != nil {
			continue
		}
		a.Summary = sum.String
		out = append(out, a)
	}
	return out
}
