package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------------------------------------------------------------- helpers

func maskID(id string) string {
	if len(id) <= 6 {
		return strings.Repeat("•", len(id))
	}
	return id[:4] + strings.Repeat("•", 6) + id[len(id)-2:]
}

func targetKind(id string) string {
	if id == "" {
		return "—"
	}
	switch id[0] {
	case 'U':
		return "ผู้ใช้ (userId)"
	case 'C':
		return "กลุ่ม (groupId)"
	case 'R':
		return "ห้อง (roomId)"
	}
	return "ไม่ทราบรูปแบบ"
}

type notifyRecord struct {
	Status, Detail, Ts string
}

func lastNotify() notifyRecord {
	var detail, ts string
	row := db.QueryRow("SELECT detail, ts FROM actions WHERE action='notify' ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&detail, &ts); err != nil {
		return notifyRecord{}
	}
	var d map[string]interface{}
	_ = json.Unmarshal([]byte(detail), &d)
	return notifyRecord{Status: str(d["status"]), Detail: str(d["detail"]), Ts: ts}
}

// The onboarding check is recorded in the same audit table as deliveries, so
// the trail answers "when was the channel last proven to work?" as well as
// "what was last sent?".
type testRecord struct {
	Status, Detail, Ts string
}

func lastLineTest() testRecord {
	var detail, ts string
	row := db.QueryRow("SELECT detail, ts FROM actions WHERE action='line_test' ORDER BY id DESC LIMIT 1")
	if err := row.Scan(&detail, &ts); err != nil {
		return testRecord{}
	}
	var d map[string]interface{}
	_ = json.Unmarshal([]byte(detail), &d)
	return testRecord{Status: str(d["status"]), Detail: str(d["detail"]), Ts: ts}
}

func auditLineTest(status, detail string) {
	dj, _ := json.Marshal(map[string]interface{}{"status": status, "detail": detail})
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "playbook": "line-onboarding", "action": "line_test", "detail": string(dj),
	})
}

// failureBanner makes a delivery failure impossible to miss in the UI. The
// whole point of the status vocabulary is that a clinic never again believes it
// is covered while nothing is being delivered.
func failureBanner(r notifyRecord) string {
	switch r.Status {
	case stAuthError:
		return "การแจ้งเตือนล้มเหลว: โทเคนไม่ถูกต้องหรือถูกเพิกถอน — ตรวจสอบ channel access token แล้วกดทดสอบ"
	case stQuotaExceeded:
		return "การแจ้งเตือนล้มเหลว: โควตาข้อความ LINE เดือนนี้เต็ม — ข้อความจะไม่ถูกส่งจนกว่าจะรีเซ็ตหรืออัปเกรดแพ็กเกจ"
	case stCapped:
		return fmt.Sprintf("เพดานการแจ้งเตือนต่อวันเต็ม (%d ข้อความ) — ระบบระงับการส่งเพิ่มเติมในวันนี้", CONFIG.Line.DailyCap)
	case stUpstreamError:
		return "การแจ้งเตือนล้มเหลว: LINE ตอบกลับผิดพลาด (ตรวจสอบการเชื่อมต่ออินเทอร์เน็ตของเครื่องนี้)"
	case stBadRequest:
		return "การแจ้งเตือนล้มเหลว: LINE ปฏิเสธรูปแบบข้อความ (bad request)"
	}
	return ""
}

// observedState replaces the old "connected means both fields are non-empty"
// test, which reported เชื่อมต่อแล้ว for a token LINE had already rejected with
// 401. What we can honestly claim is only what we have observed.
func observedState(d *LineData) {
	switch {
	case !d.Configured:
		d.ChannelState, d.ChannelLabel = "unconfigured", "จำลอง (ยังไม่ได้ตั้งค่า)"
	case d.LastTestStatus == "ok":
		d.ChannelState, d.ChannelLabel = "ok", "เชื่อมต่อแล้ว"
	case d.LastTestStatus != "":
		d.ChannelState, d.ChannelLabel = "failed", "เชื่อมต่อไม่ได้"
	default:
		d.ChannelState, d.ChannelLabel = "untested", "ตั้งค่าแล้ว — ยังไม่ได้ทดสอบ"
	}
}

// banner returns the most recent failure worth shouting about. A failed
// verification outranks a stale delivery failure because it means nothing is
// leaving the system at all.
func channelBanner(d LineData) string {
	if d.LastTestStatus == "failed" && d.LastTestTs >= d.LastTs {
		msg := "ทดสอบการเชื่อมต่อล้มเหลว"
		if d.LastTestDetail != "" {
			msg += ": " + d.LastTestDetail
		}
		return msg + " — ยังไม่มีการส่งข้อความใดออกจากระบบ"
	}
	return failureBanner(notifyRecord{Status: d.LastStatus, Detail: d.LastDetail})
}

func gatherLineData() LineData {
	d := LineData{}
	d.Enabled = CONFIG.Line.Enabled == nil || *CONFIG.Line.Enabled
	d.Disclosure = disclosureLevel()
	d.SeverityFloor = CONFIG.Line.SeverityFloor
	d.DailyCap = CONFIG.Line.DailyCap
	d.SentToday = lineMessagesSentToday()
	if q := CONFIG.Line.QuietHours; q != nil {
		d.QuietFrom, d.QuietTo, d.QuietFloor = q.From, q.To, q.Floor
	}
	d.InQuiet = inQuietHours(time.Now())
	d.Configured = CONFIG.LineToken != "" && CONFIG.LineTarget != ""
	d.Simulated = !d.Configured
	if CONFIG.LineTarget != "" {
		d.TargetMasked = maskID(CONFIG.LineTarget)
		d.TargetKind = targetKind(CONFIG.LineTarget)
	} else {
		d.TargetKind = "—"
	}

	rec := lastNotify()
	d.LastStatus, d.LastDetail, d.LastTs = rec.Status, rec.Detail, rec.Ts
	tst := lastLineTest()
	d.LastTestStatus, d.LastTestDetail, d.LastTestTs = tst.Status, tst.Detail, tst.Ts

	observedState(&d)
	d.FailureBanner = channelBanner(d)
	d.DisclosureRows = []DisclosureRow{
		{"ระดับความรุนแรง เวลา เลขเหตุการณ์", "✅", "✅", "✅"},
		{"ชื่อโฮสต์", "✅", "✅", "✅"},
		{"การดำเนินการ + จำนวนครั้ง", "✅", "✅", "✅"},
		{"ไอพีต้นทาง (src_ip)", "❌", "✅", "✅"},
		{"ชื่อผู้ใช้ (username)", "❌", "❌", "✅"},
		{"hash / URL / path / log ดิบ", "❌", "❌", "❌"},
	}
	return d
}

// ---------------------------------------------------------------- handlers

func handleLinePage(w http.ResponseWriter, r *http.Request) {
	render(w, "line", gatherLineData())
}

// handleLineTest runs the real onboarding checks: quota → consumption →
// validate/push. validate spends NO quota, so this is safe to press repeatedly.
// The outcome is audited so the page can report what was actually observed.
func handleLineTest(w http.ResponseWriter, r *http.Request) {
	out := map[string]interface{}{}
	if CONFIG.LineToken == "" {
		auditLineTest("failed", "ยังไม่ได้ตั้งค่า channel access token")
		writeJSON(w, 200, map[string]interface{}{
			"token": "MISSING", "payload": "skipped",
			"note": "ยังไม่ได้ตั้งค่า channel access token — ระบบจะบันทึกเป็น simulated",
		})
		return
	}
	limit, used, note, ok := lineQuota()
	if ok {
		out["token"] = "OK"
		out["quota_limit"] = limit
		out["quota_used"] = used
		if limit > 0 {
			out["remaining"] = fmt.Sprintf("%d/%d", limit-used, limit)
		} else {
			out["remaining"] = "ไม่จำกัด"
		}
	} else {
		out["token"] = "FAILED"
		out["quota_error"] = note
	}

	payload := renderLineMessage(
		map[string]interface{}{"title": "ทดสอบการเชื่อมต่อ mini-SOAR", "host": "mini-soar", "severity": int64(10)},
		[]string{"notify"}, nil, 1, 0, disclosureLevel())
	out["sample_message"] = payload
	vr := lineValidate(payload)
	out["payload"] = vr.Status
	out["payload_detail"] = vr.Detail

	status, detail := "ok", "token "+str(out["token"])+" · payload "+str(out["payload"])
	if str(out["token"]) != "OK" || str(out["payload"]) != "valid" {
		status = "failed"
		switch {
		case str(out["quota_error"]) != "":
			detail = str(out["quota_error"])
		case str(out["payload_detail"]) != "":
			detail = str(out["payload_detail"])
		default:
			detail = "ทดสอบไม่ผ่าน (token " + str(out["token"]) + " · payload " + str(out["payload"]) + ")"
		}
	} else if rem := str(out["remaining"]); rem != "" {
		detail += " · โควตาคงเหลือ " + rem
	}
	auditLineTest(status, detail)
	writeJSON(w, 200, out)
}

// handleLineSendTest performs ONE real send to the configured target. This is
// the only path that spends quota, so it is a separate explicit action.
func handleLineSendTest(w http.ResponseWriter, r *http.Request) {
	// Report WHICH setting is missing — the old combined message sent an admin
	// looking for a target that was in fact already configured.
	switch {
	case CONFIG.LineToken == "":
		writeJSON(w, 200, map[string]interface{}{
			"status": stSimulated, "detail": "ยังไม่ได้ตั้งค่า channel access token — ไม่มีการส่งจริง",
		})
		return
	case CONFIG.LineTarget == "":
		writeJSON(w, 200, map[string]interface{}{
			"status": stSimulated, "detail": "ยังไม่ได้ตั้งค่า target ID — ไม่มีการส่งจริง",
		})
		return
	}
	msg := renderLineMessage(
		map[string]interface{}{"title": "ทดสอบการแจ้งเตือน mini-SOAR", "host": "mini-soar", "severity": int64(10)},
		[]string{"notify"}, nil, 1, 0, disclosureLevel())
	res := linePushText(msg)
	it := &aggItem{fields: map[string]interface{}{"title": "ทดสอบการแจ้งเตือน mini-SOAR", "host": "mini-soar", "severity": int64(10)},
		actions: []string{"notify"}, count: 1, playbook: "manual-test"}
	auditNotify(it, res, res.Status)
	writeJSON(w, 200, map[string]interface{}{
		"status": res.Status, "detail": res.Detail, "http_status": res.HTTPStatus,
		"attempts": res.Attempts, "message": msg,
	})
}
