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
// So one incident produces ONE message carrying ×N, reusing the same idea as the
// approval dedup. A short debounce window is what makes a burst collapse.

type aggItem struct {
	key      string
	count    int
	first    time.Time
	fields   map[string]interface{}
	actions  []string
	incident int64
	playbook string
	alertID  int64
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

// add queues an alert, collapsing repeats into one message with a count.
// Returns the current count and whether this call started a new group.
func (a *lineAggregator) add(it *aggItem) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if existing, ok := a.items[it.key]; ok {
		existing.count++
		return existing.count, false
	}
	it.count = 1
	it.first = time.Now()
	a.items[it.key] = it
	w := a.windowOrDefault()
	time.AfterFunc(w, func() { a.release(it.key) })
	return 1, true
}

// release flushes one group (used by the timer and by tests).
func (a *lineAggregator) release(key string) {
	a.mu.Lock()
	it, ok := a.items[key]
	if ok {
		delete(a.items, key)
	}
	a.mu.Unlock()
	if !ok {
		return
	}
	res := deliverAggregate(it)
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
	sev := int64(0)
	if v, ok := it.fields["severity"]; ok {
		switch n := v.(type) {
		case int64:
			sev = n
		case int:
			sev = int64(n)
		case float64:
			sev = int64(n)
		}
	}
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
	// Daily cap is in MESSAGES, not incidents (design §6).
	if cap := CONFIG.Line.DailyCap; cap > 0 {
		if sent := lineMessagesSentToday(); sent >= cap {
			return LineResult{Status: stCapped,
				Detail: fmt.Sprintf("daily cap reached (%d/%d messages today)", sent, cap)}
		}
	}
	level := disclosureLevel()
	msg := renderLineMessage(it.fields, it.actions, it.count, it.incident, level)
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
	msg := renderLineMessage(it.fields, it.actions, it.count, it.incident, disclosureLevel())
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

// lineNotifyFor is the entry point actions.go uses. It applies the severity
// floor, then queues the alert for aggregation.
func lineNotifyFor(fields map[string]interface{}, actions []string, incident int64, playbook string, alertID int64) map[string]interface{} {
	if CONFIG.Line.Enabled != nil && !*CONFIG.Line.Enabled {
		return map[string]interface{}{"status": stSkipped, "detail": "LINE notifications disabled in config"}
	}
	sev := severityOf(fields)
	if floor := CONFIG.Line.SeverityFloor; floor > 0 && sev < int64(floor) {
		return map[string]interface{}{
			"status": stSkipped,
			"detail": fmt.Sprintf("below severity floor (%d < %d)", sev, floor),
		}
	}
	// One message per host+event, not per raw alert.
	key := fmt.Sprintf("%s|%s|%s|%v", playbook, str(fields["title"]), str(fields["host"]), actions)
	it := &aggItem{
		key: key, fields: fields, actions: actions,
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
