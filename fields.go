package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

func detectSIEM(a map[string]interface{}) string {
	if str(a["provider"]) == "Microsoft Sentinel" {
		return "sentinel"
	}
	if _, ok := a["entities"].([]interface{}); ok {
		return "sentinel"
	}
	if _, ok := a["_time"]; ok {
		if ev, ok := a["event"].(map[string]interface{}); ok {
			if _, ok := ev["signature"]; ok {
				return "splunk"
			}
		}
	}
	if r, ok := a["rule"].(map[string]interface{}); ok && str(r["description"]) != "" {
		if _, ok := a["agent"].(map[string]interface{}); ok {
			return "wazuh"
		}
	}
	if _, ok := a["@timestamp"]; ok {
		if s, ok := a["source"].(map[string]interface{}); ok {
			if _, ok := s["ip"]; ok {
				return "elastic"
			}
		}
	}
	return "generic"
}

func getPath(obj interface{}, path string) interface{} {
	cur := obj
	for _, part := range strings.Split(path, ".") {
		switch t := cur.(type) {
		case map[string]interface{}:
			v, ok := t[part]
			if !ok {
				return nil
			}
			cur = v
		case []interface{}:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			cur = t[i]
		default:
			return nil
		}
	}
	return cur
}

// str renders any JSON value as Python's str() would for our purposes.
func str(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, str(x))
		}
		return strings.Join(parts, ",")
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

var aliases = map[string][]string{
	"src_ip":     {"data.srcip", "data.src_ip", "src_ip", "srcip", "source.ip", "source_ip", "data.source_ip", "data.src", "predecoded.srcip", "event.src_ip"},
	"dst_ip":     {"data.dstip", "data.dst_ip", "dst_ip", "dstip", "destination.ip", "destination_ip", "dest_ip", "data.dst", "predecoded.dstip", "event.dest_ip"},
	"user":       {"data.user", "user.name", "username", "data.username", "user", "predecoded.user", "data.srcuser", "event.user"},
	"host":       {"agent.name", "host.name", "hostname", "data.host", "host", "agent.hostname", "data.hostname", "predecoded.hostname", "event.hostname"},
	"hash":       {"data.hash", "file.hash.sha256", "file.hash.md5", "data.md5", "data.sha256", "hash", "sha256", "md5"},
	"url":        {"data.url", "url.full", "url.domain", "url", "data.full_url", "data.reference"},
	"rule_id":    {"rule.id", "rule_id", "event.code"},
	"rule_group": {"rule.groups", "rule.group", "event.category", "rule.category", "rule_group"},
	// The technique. Per-SIEM JSON paths live here, in one place — which is what lets a
	// playbook name a technique and stay portable across SIEMs.
	"mitre": {"rule.mitre.id", "mitre.id", "mitre.technique.id", "threat.technique.id",
		"event.mitre.id", "data.mitre.id", "mitre_technique_id", "labels.mitre_id"},
}

func extractFields(a map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	pick := func(canon string) string {
		for _, p := range aliases[canon] {
			v := getPath(a, p)
			if v != nil && str(v) != "" {
				return str(v)
			}
		}
		return ""
	}
	for canon := range aliases {
		if v := pick(canon); v != "" {
			out[canon] = v
		}
	}
	title := ""
	for _, k := range []string{"title"} {
		if v := str(a[k]); v != "" {
			title = v
		}
	}
	if title == "" {
		for _, p := range []string{"rule.description", "rule.name", "event.signature", "signature", "name", "message"} {
			if v := str(getPath(a, p)); v != "" {
				title = v
				break
			}
		}
	}
	out["title"] = title

	sev := a["severity"]
	if sev == nil {
		sev = a["level"]
	}
	if sev == nil {
		sev = getPath(a, "rule.level")
	}
	if sev == nil {
		sev = getPath(a, "event.severity")
	}
	out["severity"] = toSeverity(sev)

	src := str(getPath(a, "agent.name"))
	if src == "" {
		src = str(getPath(a, "host.name"))
	}
	if src == "" {
		src = str(getPath(a, "event.module"))
	}
	if src == "" {
		src = str(a["sourcetype"])
	}
	if src == "" {
		src = str(a["provider"])
	}
	if src == "" {
		src = "unknown"
	}
	out["source"] = src

	ts := ""
	for _, k := range []string{"timestamp", "@timestamp", "_time"} {
		if v := str(a[k]); v != "" {
			ts = v
			break
		}
	}
	if ts == "" {
		ts = nowISO()
	}
	out["timestamp"] = ts
	extractSentinelEntities(a, out)
	out["siem"] = detectSIEM(a)
	return out
}

func toSeverity(sev interface{}) int {
	if sev == nil {
		return 0
	}
	switch t := sev.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
		return sevNames[strings.ToLower(strings.TrimSpace(t))]
	}
	return 0
}

func extractSentinelEntities(a map[string]interface{}, out map[string]interface{}) {
	ents, _ := a["entities"].([]interface{})
	for _, e := range ents {
		m, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		etype := strings.ToLower(str(m["type"]))
		switch etype {
		case "ip":
			if _, has := out["src_ip"]; !has && str(m["address"]) != "" {
				out["src_ip"] = str(m["address"])
			}
		case "host":
			if _, has := out["host"]; !has && str(m["hostName"]) != "" {
				out["host"] = str(m["hostName"])
			}
		case "account":
			if _, has := out["user"]; !has && str(m["name"]) != "" {
				out["user"] = str(m["name"])
			}
		}
	}
}

// ------------------------------------------------------------------ actions
