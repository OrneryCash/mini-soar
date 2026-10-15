package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Notification aggregation.
//
// Measured volume was 122 playbook matches in a single day against a ~300/month
// budget counted PER RECIPIENT — uncontrolled, the month is gone by lunchtime.
// So one incident produces ONE message carrying ×N. A short debounce window is
// what makes a burst collapse.

type aggItem struct {
	key      string
	count    int
	first    time.Time
	fields   map[string]interface{}
	actions  []string
	incident int64
	playbook string
	alertID  int64

	// notified separates "a real alert opened this group" from "a pending
	// approval note opened it", so ×N stays the number of ALERTS and is not
	// inflated by the approval folded into the same message.
	notified bool

	// pending holds approval requests folded into this incident's single
	// message. Measured on the lab: an incident cost 2 messages because the
	// approval request was its own message. Folding it in halves the cost and
	// loses nothing — the incident is still announced exactly once.
	pending []string

	// timer arms the flush. It is RE-ARMED on every fold so the window measures
	// QUIET time rather than age. Measured on the lab: a ransomware burst made the
	// correlation rule re-fire every 30-60s against a fixed 30s window, so one
	// incident fragmented into four separate messages on the operator's phone.
	timer *time.Timer
}

type lineAggregator struct {
	mu     sync.Mutex
	items  map[string]*aggItem
	window time.Duration
	flush  func(it *aggItem) LineResult // injectable so tests need no timers
}

var lineAgg = &lineAggregator{
	items:  map[string]*aggItem{},
	window: 30 * time.Second,
	flush:  deliverAggregate,
}

func (a *lineAggregator) windowOrDefault() time.Duration {
	if CONFIG.Line.AggregateSecs > 0 {
		return time.Duration(CONFIG.Line.AggregateSecs) * time.Second
	}
	if a.window > 0 {
		return a.window
	}
	return 30 * time.Second
}

// maxHoldMult caps how long a sliding window may stay open. Without it a sustained
// attack that never pauses would never notify at all.
const maxHoldMult = 5

// armLocked (re)schedules the flush for `window` after the most recent fold, but never
// later than maxHoldMult x window after the group opened. Called with a.mu held.
func (a *lineAggregator) armLocked(it *aggItem) {
	if it.timer != nil {
		it.timer.Stop()
	}
	d := a.windowOrDefault()
	if left := maxHoldMult*d - time.Since(it.first); left < d {
		d = left
	}
	if d < time.Second {
		d = time.Second
	}
	key := it.key
	it.timer = time.AfterFunc(d, func() { a.release(key) })
}

// aggKeyFor groups everything belonging to one incident. A notification and its
// approval request MUST produce the same key, or they become two messages.
//
// The key deliberately uses the ORIGINAL alert title (_group_title), not the
// display title: the notify path rewrites `title` with the playbook's template
// while the approval path passes the raw fields. Keying on the display title
// split one incident into two messages — which is exactly what happened in the
// lab before this was fixed.
func aggKeyFor(playbook string, fields map[string]interface{}, actions []string) string {
	title := str(fields["_group_title"])
	if title == "" {
		title = str(fields["title"])
	}
	return fmt.Sprintf("%s|%s|%s|%v", playbook, title, str(fields["host"]), actions)
}

// add queues an alert, collapsing repeats into one message with a count.
// Returns the current count and whether this call started a new group.
func (a *lineAggregator) add(it *aggItem) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.items[it.key]; ok {
		if existing.notified {
			existing.count++
		} else {
			// A pending note opened this group before the notify step ran: the
			// notify step's (richer) fields and actions win for display, but the
			// count stays at 1 — one alert, not two.
			existing.notified = true
			existing.fields = it.fields
			existing.actions = it.actions
		}
		a.armLocked(existing)
		return existing.count, false
	}
	it.count = 1
	it.notified = true
	it.first = time.Now()
	a.items[it.key] = it
	a.armLocked(it)
	return 1, true
}

// addPending folds an approval request into the incident's message, creating the
// group if the playbook has not notified yet.
func (a *lineAggregator) addPending(it *aggItem, note string) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.items[it.key]; ok {
		// Dedupe. N alerts folding into one message produced the same approval
		// request N times — the operator saw each "⏳ ขออนุมัติ:" line twice.
		for _, p := range existing.pending {
			if p == note {
				a.armLocked(existing)
				return existing.count, false
			}
		}
		existing.pending = append(existing.pending, note)
		a.armLocked(existing)
		return existing.count, false
	}
	it.count = 1
	it.first = time.Now()
	it.pending = []string{note}
	a.items[it.key] = it
	a.armLocked(it)
	return 1, true
}

// release flushes one group (used by the timer, by FlushAll and by tests).
func (a *lineAggregator) release(key string) {
	a.mu.Lock()
	it, ok := a.items[key]
	if ok {
		delete(a.items, key)
	}
	fn := a.flush
	a.mu.Unlock()
	if !ok {
		return
	}
	if fn == nil {
		fn = deliverAggregate
	}
	res := fn(it)
	auditNotify(it, res, res.Status)
}

// FlushAll sends every queued group immediately (tests, shutdown).
func (a *lineAggregator) FlushAll() int {
	a.mu.Lock()
	keys := make([]string, 0, len(a.items))
	for k := range a.items {
		keys = append(keys, k)
	}
	a.mu.Unlock()
	for _, k := range keys {
		a.release(k)
	}
	return len(keys)
}

// deliverAggregate applies the send-time policy and performs the delivery.
func deliverAggregate(it *aggItem) LineResult {
	sev := severityOf(it.fields)
	// Quiet hours: hold back medium severity overnight, never critical.
	if inQuietHours(time.Now()) {
		q := CONFIG.Line.QuietHours
		floor := 12
		if q != nil && q.Floor > 0 {
			floor = q.Floor
		}
		if sev < int64(floor) {
			return LineResult{Status: stSkipped,
				Detail: fmt.Sprintf("quiet hours (severity %d < %d)", sev, floor)}
		}
	}
	// Daily cap, in MESSAGES not incidents (design §6). It protects the 300/month budget,
	// but it must NEVER silence a severe alert: measured on the lab, a ransomware
	// notification was recorded as `capped` because an earlier burst had already spent the
	// day's budget, so the operator was never told. The cap now applies only below
	// capExemptSeverity, and a suppressed send is still recorded as `capped` so the
	// omission stays visible rather than silent.
	if ok, why := capAllows(sev, CONFIG.Line.DailyCap, lineMessagesSentToday(), hasContainment(it.actions)); !ok {
		return LineResult{Status: stCapped, Detail: why}
	}
	msg := renderLineMessage(it.fields, it.actions, it.pending, it.count, it.incident, disclosureLevel())
	return linePushText(msg)
}

func disclosureLevel() string {
	l := CONFIG.Line.Disclosure
	if l == "" {
		return "minimal"
	}
	return l
}

func auditNotify(it *aggItem, res LineResult, status string) {
	msg := renderLineMessage(it.fields, it.actions, it.pending, it.count, it.incident, disclosureLevel())
	d := map[string]interface{}{
		"message": msg,
		"status":  status,
		"detail":  res.Detail,
	}
	if res.HTTPStatus != 0 {
		d["http_status"] = res.HTTPStatus
	}
	if res.Attempts != 0 {
		d["attempts"] = res.Attempts
	}
	if it.count > 1 {
		d["count"] = it.count
	}
	dj, _ := json.Marshal(d)
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": it.alertID, "playbook": it.playbook,
		"action": "notify", "detail": string(dj),
	})
}

// capExemptSeverity: at or above this severity the daily message cap does not apply.
const capExemptSeverity = 12

// hasContainment reports whether this incident's playbook will block or isolate something.
func hasContainment(actions []string) bool {
	for _, a := range actions {
		if a == "block_ip" || a == "isolate_host" {
			return true
		}
	}
	return false
}

// capAllows decides whether the daily cap permits a send. Extracted from deliverAggregate
// so the rule is unit-testable without a clock, a network call or a database.
//
// Two exemptions, both learned by measuring the lab:
//   - a CONTAINMENT incident is never capped. It is the alert a clinic cannot afford to
//     miss, and it is naturally rare — 476 file alerts from one ransomware attack folded
//     into 3 messages, so folding already keeps the volume sustainable.
//   - severity >= capExemptSeverity, for severe incidents with no containment step.
//
// Severity alone was the wrong test: the stock FIM signal that carries T1485 is level 7,
// so a ransomware verdict fell below a severity-12 floor and was silently held for the
// rest of the day.
func capAllows(sev int64, cap, sentToday int, containment bool) (bool, string) {
	if cap <= 0 || containment || sev >= capExemptSeverity {
		return true, ""
	}
	if sentToday >= cap {
		return false, fmt.Sprintf(
			"daily cap reached (%d/%d messages today); severity %d is below the cap-exempt floor %d and the incident carries no containment step",
			sentToday, cap, sev, capExemptSeverity)
	}
	return true, ""
}

func severityOf(fields map[string]interface{}) int64 {
	if v, ok := fields["severity"]; ok {
		switch n := v.(type) {
		case int64:
			return n
		case int:
			return int64(n)
		case float64:
			return int64(n)
		}
	}
	return 0
}

// notifyGate applies the cheap pre-send policy shared by both entry points.
func notifyGate(fields map[string]interface{}) (bool, string) {
	if CONFIG.Line.Enabled != nil && !*CONFIG.Line.Enabled {
		return false, "LINE notifications disabled in config"
	}
	sev := severityOf(fields)
	if floor := CONFIG.Line.SeverityFloor; floor > 0 && sev < int64(floor) {
		return false, fmt.Sprintf("below severity floor (%d < %d)", sev, floor)
	}
	return true, ""
}

// lineNotifyFor is the entry point actions.go uses for a notify step.
func lineNotifyFor(fields map[string]interface{}, actions []string, incident int64, playbook string, alertID int64) map[string]interface{} {
	if ok, why := notifyGate(fields); !ok {
		return map[string]interface{}{"status": stSkipped, "detail": why}
	}
	it := &aggItem{
		key: aggKeyFor(playbook, fields, actions), fields: fields, actions: actions,
		incident: incident, playbook: playbook, alertID: alertID,
	}
	n, created := lineAgg.add(it)
	if created {
		return map[string]interface{}{
			"status": stAggregated,
			"detail": fmt.Sprintf("queued — one message for this incident in %ds", CONFIG.Line.AggregateSecs),
			"count":  1,
		}
	}
	return map[string]interface{}{
		"status": stAggregated,
		"detail": fmt.Sprintf("collapsed into the open notification (×%d)", n),
		"count":  n,
	}
}

// notifyApproval folds an approval request into the incident's single message
// instead of spending a second one on it.
func notifyApproval(fields map[string]interface{}, note string, actions []string, incident int64, playbook string, alertID int64) map[string]interface{} {
	if ok, why := notifyGate(fields); !ok {
		return map[string]interface{}{"status": stSkipped, "detail": why}
	}
	it := &aggItem{
		key: aggKeyFor(playbook, fields, actions), fields: fields, actions: actions,
		incident: incident, playbook: playbook, alertID: alertID,
	}
	n, created := lineAgg.addPending(it, note)
	if created {
		return map[string]interface{}{"status": stAggregated,
			"detail": "queued with the incident notification", "count": 1}
	}
	return map[string]interface{}{"status": stAggregated,
		"detail": fmt.Sprintf("folded into the incident notification (×%d)", n), "count": n}
}
