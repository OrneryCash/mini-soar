package main

import "testing"

// The cap must never silence an incident that will contain a host.
//
// Measured on the lab: a ransomware notification carrying the stock FIM signal (rule 553,
// severity 7, T1485) came out as `capped` because an earlier burst had already spent the
// day's budget, so the operator was never told. Severity alone was the wrong test — the
// vanilla signal is level 7, below any sensible "severe" floor.
func TestCapNeverSilencesContainment(t *testing.T) {
	// The exact lab case: severity 7, cap exhausted, but the playbook isolates the host.
	if ok, why := capAllows(7, 10, 10, true); !ok {
		t.Fatalf("a containment incident was capped: %s", why)
	}
	// Severe incident with no containment step: also exempt.
	if ok, why := capAllows(12, 10, 57, false); !ok {
		t.Fatalf("a severity-12 alert was capped: %s", why)
	}
	// Below both exemptions the cap still holds, and says why.
	ok, why := capAllows(7, 10, 10, false)
	if ok {
		t.Error("a low-severity incident with no containment bypassed an exhausted cap")
	}
	if why == "" {
		t.Error("a capped result must explain itself")
	}
	// With budget left, everything sends.
	if ok, _ := capAllows(7, 10, 3, false); !ok {
		t.Error("an incident was capped while budget remained")
	}
	// cap <= 0 disables the cap entirely (the site decides its own risk).
	if ok, _ := capAllows(4, 0, 9999, false); !ok {
		t.Error("cap 0 should disable the cap")
	}
}

func TestHasContainment(t *testing.T) {
	cases := []struct {
		actions []string
		want    bool
	}{
		{[]string{"notify", "preserve_evidence", "isolate_host", "audit"}, true},
		{[]string{"notify", "block_ip"}, true},
		{[]string{"notify", "preserve_evidence", "audit"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := hasContainment(c.actions); got != c.want {
			t.Errorf("hasContainment(%v) = %v, want %v", c.actions, got, c.want)
		}
	}
}
