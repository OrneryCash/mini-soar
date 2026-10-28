package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ------------------------------------------------------------------ status vocabulary
//
// Design §9. The old code recorded every outcome as "sent" — a 401 and a 429
// both looked like success, so a clinic whose token had expired believed it was
// covered. These are the only values the audit trail should ever contain for a
// notification.
const (
	stSent          = "sent"
	stSentTruncated = "sent_truncated"
	stSimulated     = "simulated"
	stBadRequest    = "bad_request"
	stAuthError     = "auth_error"
	stQuotaExceeded = "quota_exceeded"
	stUpstreamError = "upstream_error"
	stSkipped       = "skipped"
	stCapped        = "capped"
	stAggregated    = "aggregated"
)

const lineTextLimit = 5000 // LINE: text <= 5,000 chars

// mapStatus maps an HTTP status to the vocabulary. Everything here is
// deterministic: only upstream errors may be retried.
func mapStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return stSent
	case code == 401 || code == 403:
		return stAuthError
	case code == 429:
		return stQuotaExceeded
	case code >= 400 && code < 500:
		return stBadRequest
	default:
		return stUpstreamError
	}
}

func retryable(status string) bool { return status == stUpstreamError }

func newRetryKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("mini-soar-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

// ------------------------------------------------------------------ HTTP

var lineHTTPClient = &http.Client{Timeout: 10 * time.Second}

// lineCall performs one request against the Messaging API.
func lineCall(method, path string, body []byte, retryKey string) (int, []byte, error) {
	url := strings.TrimRight(CONFIG.Line.APIBase, "/") + path
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+CONFIG.LineToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if retryKey != "" {
		// Idempotency: LINE deduplicates a repeated key, so a retry can never
		// double-post the same alert.
		req.Header.Set("X-Line-Retry-Key", retryKey)
	}
	resp, err := lineHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, b, nil
}

// ------------------------------------------------------------------ send

type LineResult struct {
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Attempts   int    `json:"attempts,omitempty"`
}

func buildPushPayload(target, text string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"to":       target,
		"messages": []map[string]string{{"type": "text", "text": text}},
	})
	return b
}

// linePushText sends one text message, retrying ONLY upstream errors.
// auth_error / quota_exceeded / bad_request are never retried: retrying a quota
// error spends more of a budget that is already exhausted, and a bad token can
// never succeed.
func linePushText(text string) LineResult {
	if CONFIG.LineToken == "" {
		return LineResult{Status: stSimulated, Detail: "LINE channel token not set — simulated"}
	}
	if CONFIG.LineTarget == "" {
		return LineResult{Status: stSimulated, Detail: "LINE target ID not set — simulated"}
	}

	truncated := false
	runes := []rune(text)
	if len(runes) > lineTextLimit {
		text = string(runes[:lineTextLimit-1]) + "…"
		truncated = true
	}

	payload := buildPushPayload(CONFIG.LineTarget, text)
	key := newRetryKey()
	var last LineResult
	for attempt := 1; attempt <= 3; attempt++ {
		code, body, err := lineCall("POST", "/v2/bot/message/push", payload, key)
		if err != nil {
			last = LineResult{Status: stUpstreamError, Detail: err.Error(), Attempts: attempt}
		} else {
			st := mapStatus(code)
			detail := fmt.Sprintf("HTTP %d", code)
			if st != stSent && len(body) > 0 {
				detail += ": " + strings.TrimSpace(string(body))
			}
			last = LineResult{Status: st, Detail: detail, HTTPStatus: code, Attempts: attempt}
		}
		if !retryable(last.Status) {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Duration(200*(1<<uint(attempt-1))) * time.Millisecond)
		}
	}
	if last.Status == stSent && truncated {
		last.Status = stSentTruncated
		last.Detail += " (truncated to fit LINE's 5,000-char limit)"
	}
	return last
}

// ------------------------------------------------------------------ quota

// lineQuota returns the monthly allowance and amount consumed.
func lineQuota() (limit, used int, detail string, ok bool) {
	if CONFIG.LineToken == "" {
		return 0, 0, "no token", false
	}
	code, body, err := lineCall("GET", "/v2/bot/message/quota", nil, "")
	if err != nil {
		return 0, 0, err.Error(), false
	}
	if code != 200 {
		return 0, 0, fmt.Sprintf("quota HTTP %d: %s", code, strings.TrimSpace(string(body))), false
	}
	var q struct {
		Type  string `json:"type"`
		Value int    `json:"value"`
	}
	_ = json.Unmarshal(body, &q)
	if q.Type == "none" {
		return 0, 0, "unlimited", true
	}
	limit = q.Value

	code, body, err = lineCall("GET", "/v2/bot/message/quota/consumption", nil, "")
	if err != nil {
		return limit, 0, err.Error(), true
	}
	if code == 200 {
		var c struct {
			Total int `json:"totalUsage"`
		}
		_ = json.Unmarshal(body, &c)
		used = c.Total
	}
	return limit, used, "", true
}

// lineValidate checks the payload WITHOUT sending and WITHOUT spending quota.
// This is the dry-run the ทดสอบ button uses.
func lineValidate(text string) LineResult {
	if CONFIG.LineToken == "" {
		return LineResult{Status: stSimulated, Detail: "no token — nothing to validate"}
	}
	target := CONFIG.LineTarget
	if target == "" {
		target = "U0000000000000000000000000000000"
	}
	code, body, err := lineCall("POST", "/v2/bot/message/validate/push",
		buildPushPayload(target, text), newRetryKey())
	if err != nil {
		return LineResult{Status: stUpstreamError, Detail: err.Error()}
	}
	if code >= 200 && code < 300 {
		return LineResult{Status: "valid", Detail: "payload accepted (no quota spent)", HTTPStatus: code}
	}
	st := mapStatus(code)
	return LineResult{Status: "invalid", Detail: fmt.Sprintf("%s — %s", st, strings.TrimSpace(string(body))), HTTPStatus: code}
}

// ------------------------------------------------------------------ disclosure

// allowedForDisclosure implements design §7. `minimal` sends no personal data
// at all — that is stronger than "minimise": with nothing personal in the
// message there is no disclosure to lawfully justify under PDPA.
//
// Nothing ever ships url / hash / file path / raw log, not even at `full`.
func allowedForDisclosure(level, field string) bool {
	switch field {
	case "url", "hash", "path", "log", "full_log":
		return false
	}
	switch level {
	case "full":
		return true
	case "standard":
		return field != "user"
	default: // minimal
		switch field {
		case "title", "host", "severity", "source", "count", "incident", "action", "time", "rule_id":
			return true
		}
		return false
	}
}

// withheldMarker stands in for a field the disclosure level forbids. Blanking
// it outright leaves dangling labels in the message ("…จาก IP" with no value),
// which reads like a bug and hides the fact that a field was deliberately
// withheld. A marker is honest and language-independent.
const withheldMarker = "—"

// tidyText collapses the whitespace a substitution can leave behind, without
// touching line breaks.
func tidyText(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.Join(strings.Fields(l), " ")
	}
	return strings.Join(lines, "\n")
}

// gatedFormat expands a playbook template but replaces any placeholder the
// current disclosure level forbids, so a template written with {user}/{hash}
// cannot leak at `minimal`.
func gatedFormat(tpl string, fields map[string]interface{}, level string) string {
	out := safeFormatRe.ReplaceAllStringFunc(tpl, func(m string) string {
		k := m[1 : len(m)-1]
		if !allowedForDisclosure(level, k) {
			return withheldMarker
		}
		if v, ok := fields[k]; ok {
			if s := str(v); s != "" {
				return s
			}
		}
		return withheldMarker
	})
	return tidyText(out)
}

var thaiMonths = []string{"ม.ค.", "ก.พ.", "มี.ค.", "เม.ย.", "พ.ค.", "มิ.ย.",
	"ก.ค.", "ส.ค.", "ก.ย.", "ต.ค.", "พ.ย.", "ธ.ค."}

func thaiTime(t time.Time) string {
	t = t.In(time.FixedZone("ICT", 7*3600))
	return fmt.Sprintf("%02d %s %02d:%02d", t.Day(), thaiMonths[int(t.Month())-1], t.Hour(), t.Minute())
}

var sevEmoji = map[string]string{"crit": "🔴", "high": "🚨", "med": "⚠️", "low": "ℹ️"}

var actionThai = map[string]string{
	"notify": "แจ้งเตือน", "block_ip": "บล็อกไอพี", "isolate_host": "แยกโฮสต์",
	"preserve_evidence": "เก็บหลักฐาน", "audit": "บันทึก",
}

// renderLineMessage builds the fixed envelope (design §8). One renderer, so the
// disclosure gate cannot be bypassed by a per-playbook template.
func renderLineMessage(fields map[string]interface{}, actions []string, pending []string, count int, incident int64, level string) string {
	sev := int64(0)
	if v, ok := fields["severity"]; ok {
		switch n := v.(type) {
		case int64:
			sev = n
		case int:
			sev = int64(n)
		case float64:
			sev = int64(n)
		}
	}
	cls, lbl := sevParts(sev)
	var b strings.Builder
	fmt.Fprintf(&b, "%s [ระดับ: %s] %s\n", sevEmoji[cls], lbl, str(fields["title"]))
	if h := str(fields["host"]); h != "" {
		fmt.Fprintf(&b, "โฮสต์: %s\n", h)
	}
	fmt.Fprintf(&b, "เวลา: %s\n", thaiTime(time.Now()))
	if allowedForDisclosure(level, "src_ip") {
		if ip := str(fields["src_ip"]); ip != "" {
			fmt.Fprintf(&b, "ไอพีต้นทาง: %s\n", ip)
		}
	}
	if allowedForDisclosure(level, "user") {
		if u := str(fields["user"]); u != "" {
			fmt.Fprintf(&b, "ผู้ใช้: %s\n", u)
		}
	}
	if len(actions) > 0 {
		var parts []string
		for _, a := range actions {
			if t, ok := actionThai[a]; ok {
				parts = append(parts, t)
			} else {
				parts = append(parts, a)
			}
		}
		line := "การดำเนินการ: " + strings.Join(parts, " · ")
		if count > 1 {
			line += fmt.Sprintf(" (×%d)", count)
		}
		b.WriteString(line + "\n")
	}
	for _, p := range pending {
		if p = strings.TrimSpace(p); p != "" {
			b.WriteString("⏳ " + p + "\n")
		}
	}
	if incident > 0 {
		fmt.Fprintf(&b, "เหตุการณ์: #%d\n", incident)
	}
	b.WriteString("— Better Call SOAR")
	return b.String()
}

// ------------------------------------------------------------------ policy

func parseHHMM(s string) (int, int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
		return 0, 0, false
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// inQuietHours reports whether now is inside the configured window. Handles the
// wrap-around case (22:00 → 07:00).
func inQuietHours(now time.Time) bool {
	q := CONFIG.Line.QuietHours
	if q == nil || q.From == "" || q.To == "" {
		return false
	}
	fh, fm, ok1 := parseHHMM(q.From)
	th, tm, ok2 := parseHHMM(q.To)
	if !ok1 || !ok2 {
		return false
	}
	now = now.In(time.FixedZone("ICT", 7*3600))
	cur := now.Hour()*60 + now.Minute()
	from := fh*60 + fm
	to := th*60 + tm
	if from == to {
		return false
	}
	if from < to {
		return cur >= from && cur < to
	}
	return cur >= from || cur < to
}

// lineMessagesSentToday counts today's actually-sent notifications from the
// audit table — the same table that is the delivery record.
func lineMessagesSentToday() int {
	if db == nil {
		return 0
	}
	// ts is ISO-8601 in UTC ("2026-10-15T04:12:02+00:00"); slice the date part
	// rather than using datetime()/date() comparisons on the string.
	day := time.Now().UTC().Format("2006-01-02")
	var n int
	row := db.QueryRow(
		"SELECT count(*) FROM actions WHERE action='notify' AND substr(ts,1,10)=? "+
			"AND (detail LIKE '%\"status\":\"sent\"%' OR detail LIKE '%\"status\":\"sent_truncated\"%')", day)
	if err := row.Scan(&n); err != nil {
		return 0
	}
	return n
}
