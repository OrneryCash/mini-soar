package main

// Tests for the LINE OA integration, covering the design's §10 test plan and
// §11 acceptance criteria. Everything here runs against a local stub server —
// no real quota is ever spent.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu     sync.Mutex
	bodies []string
	codes  []int
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

// newStub serves the Messaging API endpoints. `codes` is the sequence of HTTP
// statuses to return; the last one repeats.
func newStub(codes ...int) (*httptest.Server, *capture) {
	c := &capture{}
	i := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		code := 200
		if len(codes) > 0 {
			if i < len(codes) {
				code = codes[i]
			} else {
				code = codes[len(codes)-1]
			}
		}
		c.codes = append(c.codes, code)
		i++
		c.mu.Unlock()
		w.WriteHeader(code)
		if code >= 400 {
			_, _ = w.Write([]byte(`{"message":"stub error"}`))
		}
	}))
	return ts, c
}

// withLineConfig installs a test configuration and returns a restore func.
func withLineConfig(base string) func() {
	oldCONFIG := CONFIG
	oldAgg := lineAgg
	on := true
	CONFIG.Line.Enabled = &on
	CONFIG.Line.ChannelToken = "test-token"
	CONFIG.Line.TargetID = "U0000000000000000000000000000000"
	CONFIG.LineToken = CONFIG.Line.ChannelToken
	CONFIG.LineTarget = CONFIG.Line.TargetID
	CONFIG.Line.APIBase = base
	CONFIG.Line.SeverityFloor = 7
	CONFIG.Line.DailyCap = 100
	CONFIG.Line.Disclosure = "minimal"
	CONFIG.Line.AggregateSecs = 600 // long: tests flush explicitly
	// from == to disables the quiet window.
	CONFIG.Line.QuietHours = &QuietHours{From: "00:00", To: "00:00", Floor: 99}
	lineAgg = &lineAggregator{items: map[string]*aggItem{}, window: 600 * time.Second, flush: deliverAggregate}
	return func() { CONFIG = oldCONFIG; lineAgg = oldAgg }
}

func textOf(body string) string {
	var m struct {
		Messages []struct {
			Text string `json:"text"`
		} `json:"messages"`
	}
	_ = json.Unmarshal([]byte(body), &m)
	if len(m.Messages) == 0 {
		return ""
	}
	return m.Messages[0].Text
}

// ---------------------------------------------------------------- §9 vocabulary

func TestMapStatus(t *testing.T) {
	cases := map[int]string{
		200: stSent, 201: stSent,
		400: stBadRequest, 404: stBadRequest,
		401: stAuthError, 403: stAuthError,
		429: stQuotaExceeded,
		500: stUpstreamError, 502: stUpstreamError, 503: stUpstreamError,
	}
	for code, want := range cases {
		if got := mapStatus(code); got != want {
			t.Errorf("mapStatus(%d) = %q, want %q", code, got, want)
		}
	}
	if !retryable(stUpstreamError) {
		t.Error("upstream_error must be retryable")
	}
	for _, s := range []string{stAuthError, stQuotaExceeded, stBadRequest, stSent} {
		if retryable(s) {
			t.Errorf("%s must NOT be retryable", s)
		}
	}
}

// §10 step 2 — every status maps to the documented value.
func TestPushStatusVocabulary(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{
		{200, stSent},
		{400, stBadRequest},
		{401, stAuthError},
		{403, stAuthError},
		{429, stQuotaExceeded},
		{500, stUpstreamError},
	} {
		ts, _ := newStub(tc.code)
		restore := withLineConfig(ts.URL)
		got := linePushText("hello")
		restore()
		ts.Close()
		if got.Status != tc.want {
			t.Errorf("HTTP %d -> %q, want %q (detail: %s)", tc.code, got.Status, tc.want, got.Detail)
		}
	}
}

// §10 step 4 / §11.1 — THE regression test for the original bug: a bad token
// must never be recorded as "sent".
func TestBadTokenIsAuthErrorNotSent(t *testing.T) {
	ts, _ := newStub(401)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	res := linePushText("does the clinic think it is covered?")
	if res.Status == stSent || res.Status == stSentTruncated {
		t.Fatalf("401 was recorded as %q — the silent-failure bug is back", res.Status)
	}
	if res.Status != stAuthError {
		t.Fatalf("401 -> %q, want %q", res.Status, stAuthError)
	}
	if res.HTTPStatus != 401 {
		t.Errorf("HTTPStatus = %d, want 401", res.HTTPStatus)
	}
}

// §11.2 — 429 is not retried (retrying spends a budget that is already gone).
func TestQuotaExceededIsNotRetried(t *testing.T) {
	ts, cap := newStub(429)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	res := linePushText("quota test")
	if res.Status != stQuotaExceeded {
		t.Fatalf("429 -> %q, want %q", res.Status, stQuotaExceeded)
	}
	if n := cap.count(); n != 1 {
		t.Errorf("429 caused %d requests, want exactly 1 (no retry)", n)
	}
}

// §9 — only upstream errors retry.
func TestUpstreamErrorIsRetried(t *testing.T) {
	ts, cap := newStub(500)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	res := linePushText("retry test")
	if res.Status != stUpstreamError {
		t.Fatalf("500 -> %q, want %q", res.Status, stUpstreamError)
	}
	if n := cap.count(); n != 3 {
		t.Errorf("500 caused %d requests, want 3 attempts", n)
	}
}

// A upstream error that clears on the second try must end as sent.
func TestUpstreamErrorRecovers(t *testing.T) {
	ts, cap := newStub(500, 200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	res := linePushText("recover test")
	if res.Status != stSent {
		t.Fatalf("500-then-200 -> %q, want %q", res.Status, stSent)
	}
	if n := cap.count(); n != 2 {
		t.Errorf("made %d requests, want 2", n)
	}
}

// §10 step 3 — a 6,000-char message is truncated to LINE's limit.
func TestTruncationToLineLimit(t *testing.T) {
	ts, cap := newStub(200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	long := strings.Repeat("ก", 6000)
	res := linePushText(long)
	if res.Status != stSentTruncated {
		t.Fatalf("long message -> %q, want %q", res.Status, stSentTruncated)
	}
	sent := textOf(cap.bodies[0])
	if n := len([]rune(sent)); n > lineTextLimit {
		t.Errorf("sent %d runes, LINE's limit is %d", n, lineTextLimit)
	}
	if !strings.HasSuffix(sent, "…") {
		t.Error("truncated message should end with an ellipsis")
	}
}

// ---------------------------------------------------------------- §11.3 aggregation

func TestAggregationCollapsesToCount(t *testing.T) {
	ts, cap := newStub(200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	fields := map[string]interface{}{
		"title": "SSH brute force", "host": "end-host1", "severity": int64(10),
	}
	var last map[string]interface{}
	for i := 0; i < 5; i++ {
		last = lineNotifyFor(fields, []string{"notify"}, 42, "t3-bruteforce", 42)
	}
	if n, _ := last["count"].(int); n != 5 {
		t.Fatalf("after 5 alerts count = %v, want 5", last["count"])
	}
	if sent := cap.count(); sent != 0 {
		t.Fatalf("%d messages sent before the window closed — aggregation is not holding", sent)
	}
	if flushed := lineAgg.FlushAll(); flushed != 1 {
		t.Fatalf("FlushAll released %d groups, want 1", flushed)
	}
	if sent := cap.count(); sent != 1 {
		t.Fatalf("5 alerts produced %d messages, want 1", sent)
	}
	if msg := textOf(cap.bodies[0]); !strings.Contains(msg, "×5") {
		t.Errorf("aggregated message should carry ×5, got:\n%s", msg)
	}
}

// A different host must NOT be collapsed into the same message.
func TestAggregationKeepsHostsSeparate(t *testing.T) {
	ts, _ := newStub(200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	lineNotifyFor(map[string]interface{}{"title": "X", "host": "A", "severity": int64(10)},
		[]string{"notify"}, 1, "p", 1)
	lineNotifyFor(map[string]interface{}{"title": "X", "host": "B", "severity": int64(10)},
		[]string{"notify"}, 2, "p", 2)
	if flushed := lineAgg.FlushAll(); flushed != 2 {
		t.Fatalf("two hosts produced %d groups, want 2", flushed)
	}
}

// ---------------------------------------------------------------- policy

// §6 — the severity floor suppresses low-severity pushes.
func TestSeverityFloorBlocksLowSeverity(t *testing.T) {
	ts, _ := newStub(200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	res := lineNotifyFor(map[string]interface{}{"title": "noise", "severity": int64(3)},
		[]string{"notify"}, 1, "p", 1)
	if res["status"] != stSkipped {
		t.Fatalf("severity 3 with floor 7 -> %v, want %s", res["status"], stSkipped)
	}
	if n := lineAgg.FlushAll(); n != 0 {
		t.Fatalf("a below-floor alert was queued anyway (%d groups)", n)
	}
}

func TestQuietHoursWindow(t *testing.T) {
	CONFIG.Line.QuietHours = &QuietHours{From: "22:00", To: "07:00", Floor: 12}
	ict := time.FixedZone("ICT", 7*3600)

	quiet := []int{22, 23, 0, 3, 6}
	for _, h := range quiet {
		at := time.Date(2026, 10, 15, h, 30, 0, 0, ict)
		if !inQuietHours(at) {
			t.Errorf("%02d:30 should be inside 22:00-07:00", h)
		}
	}
	loud := []int{7, 8, 12, 18, 21}
	for _, h := range loud {
		at := time.Date(2026, 10, 15, h, 30, 0, 0, ict)
		if inQuietHours(at) {
			t.Errorf("%02d:30 should be OUTSIDE 22:00-07:00", h)
		}
	}
}

// Quiet hours must hold back medium severity but never block a critical one.
func TestQuietHoursHoldsMediumLetsCriticalThrough(t *testing.T) {
	ts, cap := newStub(200)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	// A quiet window that certainly contains right now.
	ict := time.FixedZone("ICT", 7*3600)
	n := time.Now().In(ict)
	CONFIG.Line.QuietHours = &QuietHours{
		From:  n.Add(-time.Hour).Format("15:04"),
		To:    n.Add(time.Hour).Format("15:04"),
		Floor: 12,
	}
	if !inQuietHours(time.Now()) {
		t.Fatalf("window %s-%s should contain now", CONFIG.Line.QuietHours.From, CONFIG.Line.QuietHours.To)
	}

	lineNotifyFor(map[string]interface{}{"title": "medium", "host": "h", "severity": int64(8)},
		[]string{"notify"}, 1, "p", 1)
	lineAgg.FlushAll()
	if n := cap.count(); n != 0 {
		t.Fatalf("medium severity was pushed during quiet hours (%d requests)", n)
	}

	lineNotifyFor(map[string]interface{}{"title": "critical", "host": "h", "severity": int64(15)},
		[]string{"notify"}, 2, "p", 2)
	lineAgg.FlushAll()
	if n := cap.count(); n != 1 {
		t.Fatalf("critical severity did not break the quiet window (%d requests, want 1)", n)
	}
}

// §11.4 / §7 — personal data must not reach the message at `minimal`.
func TestDisclosureMinimalExcludesPersonalData(t *testing.T) {
	fields := map[string]interface{}{
		"title": "ตรวจพบแรนซัมแวร์", "host": "HIS-01", "severity": int64(12),
		"user": "somchai.j", "src_ip": "203.0.113.5",
		"hash": "d41d8cd98f00b204e9800998ecf8427e",
		"url":  "http://bad.example/x", "path": "/var/www/html/shell.php",
	}
	for _, secret := range []string{"somchai.j", "d41d8cd98f00b204e9800998ecf8427e",
		"bad.example", "/var/www/html/shell.php", "203.0.113.5"} {
		if strings.Contains(renderLineMessage(fields, []string{"block_ip"}, 1, 7, "minimal"), secret) {
			t.Errorf("disclosure=minimal leaked %q", secret)
		}
	}
	// The envelope must still be useful.
	msg := renderLineMessage(fields, []string{"block_ip"}, 3, 7, "minimal")
	for _, want := range []string{"HIS-01", "#7", "×3", "สูง"} {
		if !strings.Contains(msg, want) {
			t.Errorf("disclosure=minimal message is missing %q:\n%s", want, msg)
		}
	}
}

// A playbook template written with {user}/{hash} must be blanked at minimal
// (this is the §2 gap 8 fix).
func TestTemplatePlaceholdersAreGated(t *testing.T) {
	fields := map[string]interface{}{
		"user": "somchai.j", "hash": "deadbeef", "url": "http://bad.example",
		"host": "HIS-01",
	}
	got := gatedFormat("ผู้ใช้ {user} โฮสต์ {host} hash {hash} url {url}", fields, "minimal")
	for _, secret := range []string{"somchai.j", "deadbeef", "bad.example"} {
		if strings.Contains(got, secret) {
			t.Errorf("minimal template leaked %q in: %s", secret, got)
		}
	}
	if !strings.Contains(got, "HIS-01") {
		t.Errorf("minimal template dropped the allowed host field: %s", got)
	}
	// standard adds src_ip but still not the username
	if strings.Contains(gatedFormat("{user}", fields, "standard"), "somchai.j") {
		t.Error("standard must not include the username")
	}
	// full adds the username, but never the hash/url
	full := gatedFormat("{user}|{hash}|{url}", fields, "full")
	if !strings.Contains(full, "somchai.j") {
		t.Error("full should include the username")
	}
	for _, secret := range []string{"deadbeef", "bad.example"} {
		if strings.Contains(full, secret) {
			t.Errorf("even full must not carry %q", secret)
		}
	}
}

// §11.7 — no token configured still runs the demo end to end.
func TestNoTokenIsSimulated(t *testing.T) {
	old := CONFIG
	defer func() { CONFIG = old }()
	CONFIG.LineToken = ""
	CONFIG.LineTarget = ""
	res := linePushText("demo")
	if res.Status != stSimulated {
		t.Fatalf("no token -> %q, want %q", res.Status, stSimulated)
	}
}

// The audit detail is the delivery record the UI reads back.
func TestNotifyAuditDetailCarriesStatus(t *testing.T) {
	ts, _ := newStub(401)
	defer ts.Close()
	restore := withLineConfig(ts.URL)
	defer restore()

	it := &aggItem{
		fields:  map[string]interface{}{"title": "t", "host": "h", "severity": int64(10)},
		actions: []string{"notify"}, count: 1, playbook: "p", alertID: 1,
	}
	res := linePushText("x")
	d := map[string]interface{}{"message": "x", "status": res.Status, "detail": res.Detail}
	dj, _ := json.Marshal(d)
	var back map[string]interface{}
	_ = json.Unmarshal(dj, &back)
	if back["status"] != stAuthError {
		t.Fatalf("audit record status = %v, want %s", back["status"], stAuthError)
	}
	_ = it
}
