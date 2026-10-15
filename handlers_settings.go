package main

import (
	"net/http"
	"strings"
)

// SettingsView is what /settings renders.
type SettingsView struct {
	Actions   []ActionState
	RealCount int
	RealList  string
	WazuhOK   bool
	WazuhMsg  string
	ModeSim   string
	ModeReal  string
}

func handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	st := actionStates()
	var names []string
	for _, s := range st {
		if s.Real {
			names = append(names, s.Name)
		}
	}
	ok, msg := wazuhHealth()
	render(w, "settings", SettingsView{
		Actions:   st,
		RealCount: len(names),
		RealList:  strings.Join(names, ", "),
		WazuhOK:   ok,
		WazuhMsg:  msg,
		ModeSim:   modeSimulate,
		ModeReal:  modeReal,
	})
}

// handleAPISetMode flips one action between simulate and real.
//
// Arming a disruptive action is a security-relevant change, so it is written to the
// audit table like any other action — an incident review can see when the responder was
// armed, by whom the setting was changed, and from which state.
func handleAPISetMode(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if _, known := specFor(action); !known {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "unknown action: " + action})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]interface{}{"ok": false, "error": "bad form"})
		return
	}
	before := actionMode(action)
	if !setActionMode(action, r.FormValue("mode")) {
		writeJSON(w, 500, map[string]interface{}{"ok": false, "error": "could not save the setting"})
		return
	}
	after := actionMode(action)
	_, _ = auditInsert("actions", map[string]interface{}{
		"ts": nowISO(), "alert_id": 0, "playbook": "settings", "action": "set_mode",
		"detail": action + ": " + before + " -> " + after,
	})
	writeJSON(w, 200, map[string]interface{}{"ok": true, "action": action, "mode": after})
}
