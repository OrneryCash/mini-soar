package main

import "testing"

// The daily cap must never silence a severe alert. Measured on the lab: a ransomware
// notification came out as `capped` because an earlier burst had already spent the day's
// budget, so the operator was never told — the guard protecting the budget became the
// thing hiding the incident.
func TestCapNeverSilencesSevereAlerts(t *testing.T) {
	// A ransomware-grade alert (severity 12) with the cap exhausted must still send.
	if ok, why := capAllows(12, 10, 10); !ok {
		t.Fatalf("a severity-12 alert was capped: %s", why)
	}
	if ok, why := capAllows(15, 10, 57); !ok {
		t.Fatalf("a critical alert was capped: %s", why)
	}
	// Below the exempt floor the cap still holds, and says why.
	ok, why := capAllows(8, 10, 10)
	if ok {
		t.Error("a medium alert bypassed an exhausted cap")
	}
	if why == "" {
		t.Error("a capped result must explain itself")
	}
	// With budget left, everything sends.
	if ok, _ := capAllows(8, 10, 3); !ok {
		t.Error("a medium alert was capped while budget remained")
	}
	// cap <= 0 disables the cap entirely (the site decides its own risk).
	if ok, _ := capAllows(4, 0, 9999); !ok {
		t.Error("cap 0 should disable the cap")
	}
}
