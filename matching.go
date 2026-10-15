package main

import (
	"strings"
)

func matchPlaybook(book *Playbook, fields map[string]interface{}) bool {
	if numParam(fields, "severity", 0) < book.When.MinSeverity {
		return false
	}
	// Scenario selection by the SIEM's own technique classification. This is what keeps
	// a playbook free of per-SIEM detection content: the playbook names techniques, and
	// the per-SIEM JSON paths live in the field aliases.
	if len(book.When.Mitre) > 0 && !mitreMatches(book.When.Mitre, str(fields["mitre"])) {
		return false
	}
	if len(book.When.NotIP) > 0 {
		src := str(fields["src_ip"])
		for _, ip := range book.When.NotIP {
			if ip == src {
				return false
			}
		}
	}
	if book.When.Pattern == "" {
		return true
	}
	if book.re == nil {
		return false
	}
	hay := strings.Join(nonEmpty(
		str(fields["title"]), str(fields["rule_id"]), str(fields["rule_group"]),
		str(fields["src_ip"]), str(fields["dst_ip"]), str(fields["user"]),
		str(fields["url"]), str(fields["hash"])), " ")
	return book.re.MatchString(hay)
}

func nonEmpty(vals ...string) []string {
	out := []string{}
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// mitreMatches reports whether the alert carries any of the wanted techniques.
//
// A wanted base technique matches its sub-techniques, so a playbook can name T1070
// without knowing whether the SIEM chose T1070.004. Matching is case-insensitive
// because SIEMs disagree about casing.
func mitreMatches(want []string, got string) bool {
	if got == "" {
		return false
	}
	have := strings.Split(got, ",")
	for _, w := range want {
		w = strings.ToUpper(strings.TrimSpace(w))
		if w == "" {
			continue
		}
		for _, h := range have {
			h = strings.ToUpper(strings.TrimSpace(h))
			if h == w || strings.HasPrefix(h, w+".") {
				return true
			}
		}
	}
	return false
}

// ------------------------------------------------------------------ approvals
