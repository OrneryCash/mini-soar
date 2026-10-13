package main

import (
	"strings"
)

func matchPlaybook(book *Playbook, fields map[string]interface{}) bool {
	if numParam(fields, "severity", 0) < book.When.MinSeverity {
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

// ------------------------------------------------------------------ approvals
