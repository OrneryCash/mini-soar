package main

import "testing"

// A parent technique must match its sub-technique, so a playbook can name T1070 without
// knowing whether the SIEM chose T1070.004.
func TestMitreMatchesParentAndSubTechnique(t *testing.T) {
	// This is exactly what stock Wazuh puts on a file-deletion alert.
	alert := "T1070.004,T1485"
	cases := []struct {
		want []string
		ok   bool
	}{
		{[]string{"T1485"}, true},
		{[]string{"T1486", "T1485"}, true},
		{[]string{"T1070"}, true},     // parent matches the child
		{[]string{"T1070.004"}, true}, // exact
		{[]string{"t1485"}, true},     // SIEMs disagree on casing
		{[]string{"T1486"}, false},    // absent
		{[]string{"T148"}, false},     // must not prefix-match across techniques
		{[]string{""}, false},
	}
	for _, c := range cases {
		if got := mitreMatches(c.want, alert); got != c.ok {
			t.Errorf("mitreMatches(%v, %q) = %v, want %v", c.want, alert, got, c.ok)
		}
	}
}

// Stock rule 554 ("File added to the system") carries NO technique tag, so a
// technique-selected playbook must not match it.
func TestMitreAbsentNeverMatches(t *testing.T) {
	if mitreMatches([]string{"T1485"}, "") {
		t.Fatal("an alert with no technique matched a technique-selected playbook")
	}
}

func TestPlaybookMatchesOnMitreAlone(t *testing.T) {
	book := &Playbook{Name: "t1", Enabled: true, When: When{Mitre: []string{"T1485"}, MinSeverity: 7}}

	// A stock file-deletion alert: level 7, tagged T1485.
	if !matchPlaybook(book, map[string]interface{}{"severity": int64(7), "mitre": "T1070.004,T1485"}) {
		t.Error("a level-7 T1485 alert did not match the T1485 playbook")
	}
	// A stock file-add alert: level 5, no technique. Neither the level nor the tag fits.
	if matchPlaybook(book, map[string]interface{}{"severity": int64(5), "title": "File added to the system."}) {
		t.Error("an untagged file-add matched a technique-selected playbook")
	}
	// Same technique but below the scenario's severity floor.
	if matchPlaybook(book, map[string]interface{}{"severity": int64(3), "mitre": "T1485"}) {
		t.Error("a below-floor alert matched a playbook with min_severity 7")
	}
}
