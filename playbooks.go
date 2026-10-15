package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

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
	case int64: // JSON-derived fields and tests carry this; without it a severity of 0 is
		return int(t) // returned and EVERY alert clears a min_severity floor - fail-open.
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
