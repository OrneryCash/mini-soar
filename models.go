package main

import (
	"regexp"
)

type Alert struct {
	ID, Severity           int64
	Ts, Source, Title      string
	SIEM, MatchedPlaybooks string
}

type Action struct {
	ID, AlertID    int64
	Ts, Playbook   string
	Action, Detail string
	Status         string
	HumanDetail    string
}

type Approval struct {
	ID, AlertID                  int64
	Ts, Playbook, Action, Params string
	Summary, Status              string
	Count                        int64
}

type Block struct {
	ID, Duration      int64
	Ts, IP, ExpiresAt string
	Backend, Status   string
}

type When struct {
	Pattern     string   `yaml:"pattern,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty"`
	MinSeverity int      `yaml:"min_severity,omitempty"`
	NotIP       []string `yaml:"not_ip,omitempty"`

	// Mitre selects the scenario by the SIEM's OWN technique classification, so the
	// playbook carries no per-SIEM detection content. Stock Wazuh tags file deletion
	// T1485 and a checksum change T1565.001 from its shipped ruleset; any other SIEM
	// that tags the same technique matches the same playbook. The per-SIEM part —
	// which JSON path carries the technique — lives in the field aliases, not here.
	Mitre []string `yaml:"mitre,omitempty"`
}

type Step struct {
	Action string                 `yaml:"action"`
	Params map[string]interface{} `yaml:"params,omitempty"`
	Gate   string                 `yaml:"gate,omitempty"`
}

type Locks struct {
	IsolateHost string `yaml:"isolate_host,omitempty"`
}

type Playbook struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled"`
	Gate        string `yaml:"gate,omitempty"`
	Locks       *Locks `yaml:"locks,omitempty"`
	When        When   `yaml:"when,omitempty"`
	Source      string `yaml:"source,omitempty"`
	Steps       []Step `yaml:"steps"`

	re     *regexp.Regexp
	custom bool
}

type apprRow struct {
	ID, AlertID          int64
	Ts, Playbook, Action string
	Params               string
	Summary, Status      string
}
