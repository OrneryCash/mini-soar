package main

import "sync"

// Action modes.
//
// Every responder action that can touch the real world has a MODE:
//
//	simulate — the default. It records exactly what it *would* do and changes nothing.
//	real     — it actually performs the action.
//
// simulate is the default on purpose. A responder that can really block and really
// isolate is one careless playbook away from cutting a hospital off the network, so
// real execution is an explicit per-action opt-in made in the UI — and the mode that
// ran is written into the audit row, so an incident review can always tell what
// actually happened instead of inferring it from a log line.
//
// The mode is stored in the DB, not in config.yaml: config.yaml is root-owned and
// part of the deployed git checkout, so flipping a switch in the UI must not require
// a redeploy or root access. It also survives a restart.
const (
	modeSimulate = "simulate"
	modeReal     = "real"
)

// ActionSpec describes one controllable action for the settings page.
type ActionSpec struct {
	Name    string // the playbook verb: block_ip, isolate_host, ...
	Label   string // Thai label
	Backend string // which subsystem performs the real action
	Detail  string // what real execution does, in one line
	High    bool   // true = disruptive, gets the red warning treatment
}

var actionSpecs = []ActionSpec{
	{
		Name: "isolate_host", Label: "แยกโฮสต์", High: true,
		Backend: "Wazuh Active Response (isolate-host.sh)",
		Detail:  "ตัดการเชื่อมต่อทั้งหมดของโฮสต์ ยกเว้น Wazuh manager และเครื่องควบคุม — สคริปต์มี allowlist และ TTL ยกเลิกเองอัตโนมัติ",
	},
	{
		Name: "block_ip", Label: "บล็อกไอพี", High: true,
		Backend: "Wazuh Active Response (firewall-drop)",
		Detail:  "สั่งให้ endpoint ใส่ iptables DROP ที่ IP ต้นทาง ผ่าน Wazuh API — บล็อกที่ปลายทาง ไม่ใช่ที่ตัว SOAR",
	},
	{
		Name: "preserve_evidence", Label: "เก็บหลักฐาน", High: false,
		Backend: "local filesystem",
		Detail:  "เขียน alert JSON ฉบับเต็มลงโฟลเดอร์ evidence",
	},
	{
		Name: "notify", Label: "แจ้งเตือน LINE", High: false,
		Backend: "LINE Messaging API",
		Detail:  "ส่งข้อความจริงผ่าน LINE OA (มีอยู่แล้ว)",
	},
}

var settingsMu sync.Mutex

func settingGet(key, def string) string {
	if db == nil {
		return def
	}
	var v string
	if err := db.QueryRow("SELECT v FROM settings WHERE k = ?", key).Scan(&v); err != nil || v == "" {
		return def
	}
	return v
}

func settingPut(key, val string) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(
		"INSERT INTO settings (k, v, ts) VALUES (?, ?, ?) "+
			"ON CONFLICT(k) DO UPDATE SET v = excluded.v, ts = excluded.ts",
		key, val, nowISO())
	return err
}

// actionMode returns "simulate" unless a real opt-in was recorded for this action.
func actionMode(action string) string {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	if settingGet("mode."+action, modeSimulate) == modeReal {
		return modeReal
	}
	return modeSimulate
}

func actionIsReal(action string) bool { return actionMode(action) == modeReal }

// specFor returns the spec for a controllable action.
func specFor(action string) (ActionSpec, bool) {
	for _, s := range actionSpecs {
		if s.Name == action {
			return s, true
		}
	}
	return ActionSpec{}, false
}

// setActionMode records a mode. Any value that is not exactly "real" degrades to
// "simulate" — a typo in a setting must never arm a disruptive action.
func setActionMode(action, mode string) bool {
	if _, ok := specFor(action); !ok {
		return false
	}
	m := modeSimulate
	if mode == modeReal {
		m = modeReal
	}
	settingsMu.Lock()
	defer settingsMu.Unlock()
	return settingPut("mode."+action, m) == nil
}

// ActionState is one row of the settings page.
type ActionState struct {
	ActionSpec
	Mode string
	Real bool
}

func actionStates() []ActionState {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	out := make([]ActionState, 0, len(actionSpecs))
	for _, s := range actionSpecs {
		m := modeSimulate
		if settingGet("mode."+s.Name, modeSimulate) == modeReal {
			m = modeReal
		}
		out = append(out, ActionState{ActionSpec: s, Mode: m, Real: m == modeReal})
	}
	return out
}

// realActions lists the actions currently armed for real execution — shown as a
// banner on every page so nobody forgets which mode the responder is in.
func realActions() []string {
	var out []string
	for _, s := range actionStates() {
		if s.Real {
			out = append(out, s.Name)
		}
	}
	return out
}

// modeLabel is what the audit UI and the LINE message print.
func modeLabel(action string) string {
	if actionIsReal(action) {
		return "ของจริง"
	}
	return "จำลอง"
}
