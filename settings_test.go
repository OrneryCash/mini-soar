package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testDB points the package at a throwaway SQLite file and restores the old handle.
func testDB(t *testing.T) {
	t.Helper()
	oldPath, oldDB := CONFIG.DBPath, db
	CONFIG.DBPath = filepath.Join(t.TempDir(), "t.db")
	if err := initDB(); err != nil {
		t.Fatalf("initDB: %v", err)
	}
	t.Cleanup(func() {
		if db != nil {
			db.Close()
		}
		db, CONFIG.DBPath = oldDB, oldPath
	})
}

// An action nobody has armed must be simulated. This is the safety default: an
// un-configured responder must never touch a real network.
func TestActionModeDefaultsToSimulate(t *testing.T) {
	testDB(t)
	for _, a := range []string{"block_ip", "isolate_host", "preserve_evidence"} {
		if got := actionMode(a); got != modeSimulate {
			t.Errorf("actionMode(%q) = %q, want %q", a, got, modeSimulate)
		}
		if actionIsReal(a) {
			t.Errorf("actionIsReal(%q) = true on a fresh install", a)
		}
	}
}

func TestSetActionModeRoundTrip(t *testing.T) {
	testDB(t)
	if !setActionMode("isolate_host", modeReal) {
		t.Fatal("setActionMode returned false for a known action")
	}
	if !actionIsReal("isolate_host") {
		t.Fatal("isolate_host is not real after being set")
	}
	if actionIsReal("block_ip") {
		t.Error("setting isolate_host to real also armed block_ip")
	}
	if !setActionMode("isolate_host", modeSimulate) {
		t.Fatal("could not return isolate_host to simulate")
	}
	if actionIsReal("isolate_host") {
		t.Error("isolate_host is still real after being set back")
	}
}

// A typo must degrade to simulate, never arm a disruptive action.
func TestSetActionModeRejectsTypos(t *testing.T) {
	testDB(t)
	for _, bad := range []string{"REAL", "yes", "true", "1", "ของจริง", ""} {
		setActionMode("block_ip", bad)
		if actionIsReal("block_ip") {
			t.Fatalf("mode %q armed block_ip; only the exact string %q may", bad, modeReal)
		}
	}
}

func TestSetActionModeRejectsUnknownAction(t *testing.T) {
	testDB(t)
	if setActionMode("rm_rf", modeReal) {
		t.Error("setActionMode accepted an action that is not in actionSpecs")
	}
	if v := settingGet("mode.rm_rf", ""); v != "" {
		t.Errorf("an unknown action wrote a setting: %q", v)
	}
}

func TestRealActionsList(t *testing.T) {
	testDB(t)
	setActionMode("isolate_host", modeReal)
	setActionMode("block_ip", modeReal)
	got := strings.Join(realActions(), ",")
	if got != "isolate_host,block_ip" {
		t.Errorf("realActions() = %q, want %q", got, "isolate_host,block_ip")
	}
}

// In simulate mode the block must not even try to reach the network, and the detail
// has to say so plainly rather than implying something happened.
func TestBlockIPSimulatesByDefault(t *testing.T) {
	testDB(t)
	CONFIG.Wazuh = WazuhConfig{} // no API configured
	fields := map[string]interface{}{"host": "end-host2", "src_ip": "203.0.113.123"}
	res := actionBlockIP(fields, "src_ip", 600, 1, "t3-bruteforce")
	if got := str(res["status"]); got != "simulated" {
		t.Fatalf("status = %q, want simulated", got)
	}
	if d := str(res["detail"]); !strings.Contains(d, "SIMULATED") {
		t.Errorf("detail should say SIMULATED, got %q", d)
	}
}

// Armed but unreachable is an ERROR, not a success. Reporting "done" when the API is
// missing is exactly the class of lie this project has been fixing.
func TestBlockIPRealWithoutAPIIsError(t *testing.T) {
	testDB(t)
	CONFIG.Wazuh = WazuhConfig{}
	setActionMode("block_ip", modeReal)
	fields := map[string]interface{}{"host": "end-host2", "src_ip": "203.0.113.123"}
	res := actionBlockIP(fields, "src_ip", 600, 1, "t3-bruteforce")
	if got := str(res["status"]); got != "error" {
		t.Fatalf("status = %q, want error when the API is unconfigured", got)
	}
	if d := str(res["detail"]); !strings.Contains(d, "not configured") {
		t.Errorf("detail should name the cause, got %q", d)
	}
}

func TestBlockIPWithoutSourceIPSkipped(t *testing.T) {
	testDB(t)
	res := actionBlockIP(map[string]interface{}{"host": "end-host2"}, "src_ip", 600, 1, "t1-ransomware")
	if got := str(res["status"]); got != "skipped" {
		t.Fatalf("status = %q, want skipped when the alert has no source IP", got)
	}
}

func TestIsolateHostSimulatesByDefault(t *testing.T) {
	testDB(t)
	res := actionIsolateHost(map[string]interface{}{"host": "end-host2"}, "host", 1, "t1-ransomware")
	if got := str(res["status"]); got != "isolated_simulated" {
		t.Fatalf("status = %q, want isolated_simulated", got)
	}
	if d := str(res["detail"]); !strings.Contains(d, "SIMULATED") {
		t.Errorf("detail should say SIMULATED, got %q", d)
	}
}

func TestIsolateHostWithoutHostSkipped(t *testing.T) {
	testDB(t)
	res := actionIsolateHost(map[string]interface{}{}, "host", 1, "t1-ransomware")
	if got := str(res["status"]); got != "skipped" {
		t.Fatalf("status = %q, want skipped", got)
	}
}

// Every mode change is audited — an incident review must be able to see when the
// responder was armed.
func TestSetModeHandlerAuditsTheChange(t *testing.T) {
	testDB(t)
	req := httptest.NewRequest("POST", "/api/settings/isolate_host", strings.NewReader("mode=real"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("action", "isolate_host")
	rr := httptest.NewRecorder()
	handleAPISetMode(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	if !actionIsReal("isolate_host") {
		t.Fatal("handler returned ok but the mode did not change")
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM actions WHERE action = 'set_mode'").Scan(&n); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if n != 1 {
		t.Errorf("set_mode rows = %d, want 1", n)
	}
}

func TestSetModeHandlerRejectsUnknownAction(t *testing.T) {
	testDB(t)
	req := httptest.NewRequest("POST", "/api/settings/rm_rf", strings.NewReader("mode=real"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("action", "rm_rf")
	rr := httptest.NewRecorder()
	handleAPISetMode(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status %d, want 400 for an unknown action", rr.Code)
	}
}

// A broken settings template is fatal at startup, so render it for real.
func TestSettingsPageRenders(t *testing.T) {
	testDB(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	oldBase := BASE
	BASE = wd
	t.Cleanup(func() { BASE = oldBase })
	loadPages()
	rr := httptest.NewRecorder()
	handleSettingsPage(rr, httptest.NewRequest("GET", "/settings", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"isolate_host", "block_ip", "โหมดจำลองทั้งหมด", "Wazuh API"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
}

// The 4-messages bug: a burst that keeps arriving must stay ONE message. With a fixed
// timer armed at group creation, a sustained burst flushes repeatedly and the operator
// gets one message per batch instead of one per incident.
func TestSlidingWindowKeepsOneMessage(t *testing.T) {
	a := &lineAggregator{items: map[string]*aggItem{}, window: 120 * time.Millisecond}
	flushed := 0
	a.flush = func(it *aggItem) LineResult {
		flushed++
		return LineResult{Status: stSkipped, Detail: "test"}
	}
	mk := func() *aggItem {
		return &aggItem{key: "k", fields: map[string]interface{}{"title": "t"}, incident: 1, playbook: "p"}
	}
	a.add(mk())
	// Fold every 40ms for 240ms — twice the window. Batches arrive faster than the
	// window, so nothing should have flushed yet.
	for i := 0; i < 6; i++ {
		time.Sleep(40 * time.Millisecond)
		a.add(mk())
	}
	if flushed != 0 {
		t.Fatalf("the burst was split into %d messages; a sliding window holds it as one", flushed)
	}
	a.FlushAll()
	if flushed != 1 {
		t.Fatalf("after the burst ended: %d messages, want 1", flushed)
	}
}
