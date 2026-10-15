package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
)

// QuietHours pauses non-critical pushes overnight.
type QuietHours struct {
	From  string `yaml:"from"`
	To    string `yaml:"to"`
	Floor int    `yaml:"floor"`
}

// LineConfig is the non-secret LINE policy. The credential and target live in
// config.local.yaml (gitignored) or the environment — never in config.yaml,
// which is tracked in a public repo.
type LineConfig struct {
	Enabled       *bool       `yaml:"enabled"`
	Disclosure    string      `yaml:"disclosure"` // minimal | standard | full
	SeverityFloor int         `yaml:"severity_floor"`
	DailyCap      int         `yaml:"daily_cap"` // messages/day, not incidents
	QuietHours    *QuietHours `yaml:"quiet_hours"`
	AggregateSecs int         `yaml:"aggregate_seconds"`
	ChannelToken  string      `yaml:"channel_access_token"`
	TargetID      string      `yaml:"target_id"`
	APIBase       string      `yaml:"api_base"` // test hook; empty = real LINE
}

// WazuhConfig is the manager's REST API, used to run REAL Active Response.
//
// The SOAR never touches an endpoint directly: it asks the manager's API to queue an
// Active Response command and the AGENT runs it locally. That is why no host
// credentials live in mini-SOAR, why the manager's own logs record every real
// action, and why the endpoint's guardrails (allowlist, TTL) cannot be overridden
// from the SOAR. Credentials belong in config.local.yaml (gitignored) or the env.
type WazuhConfig struct {
	APIURL  string `yaml:"api_url"` // e.g. https://10.10.221.18:55000
	APIUser string `yaml:"api_user"`
	APIPass string `yaml:"api_password"`
}

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	PlaybooksDir  string      `yaml:"playbooks_dir"`
	DataDir       string      `yaml:"data_dir"`
	EvidenceDir   string      `yaml:"evidence_dir"`
	Line          LineConfig  `yaml:"line"`
	Wazuh         WazuhConfig `yaml:"wazuh"`
	Firewall      string      `yaml:"firewall_backend"`
	BlockDefault  int         `yaml:"block_default_duration"`
	ApprovalTO    int         `yaml:"approval_timeout_seconds"`
	ApprovalMode  string      `yaml:"approval_timeout_action"`
	WebhookSecret string      `yaml:"webhook_secret"`
	DBPath        string      `yaml:"db_path"`

	// Legacy flat keys (pre-`line:` schema). Still honoured so an existing
	// deployment does not lose its target on upgrade.
	LineTokenLegacy  string `yaml:"line_channel_token"`
	LineTargetLegacy string `yaml:"line_target_user_id"`

	// Resolved delivery values — what the rest of the app reads.
	LineToken  string `yaml:"-"`
	LineTarget string `yaml:"-"`
}

var BASE string

// mergeLineOverlay copies only the fields the overlay actually set, so a
// one-line config.local.yaml does not blank the tracked policy.
func mergeLineOverlay(dst, o *Config) {
	if o.Line.Enabled != nil {
		dst.Line.Enabled = o.Line.Enabled
	}
	if o.Line.Disclosure != "" {
		dst.Line.Disclosure = o.Line.Disclosure
	}
	if o.Line.SeverityFloor != 0 {
		dst.Line.SeverityFloor = o.Line.SeverityFloor
	}
	if o.Line.DailyCap != 0 {
		dst.Line.DailyCap = o.Line.DailyCap
	}
	if o.Line.AggregateSecs != 0 {
		dst.Line.AggregateSecs = o.Line.AggregateSecs
	}
	if o.Line.QuietHours != nil {
		dst.Line.QuietHours = o.Line.QuietHours
	}
	if o.Line.ChannelToken != "" {
		dst.Line.ChannelToken = o.Line.ChannelToken
	}
	if o.Line.TargetID != "" {
		dst.Line.TargetID = o.Line.TargetID
	}
	if o.Line.APIBase != "" {
		dst.Line.APIBase = o.Line.APIBase
	}
	if o.Firewall != "" {
		dst.Firewall = o.Firewall
	}
	if o.Wazuh.APIURL != "" {
		dst.Wazuh.APIURL = o.Wazuh.APIURL
	}
	if o.Wazuh.APIUser != "" {
		dst.Wazuh.APIUser = o.Wazuh.APIUser
	}
	if o.Wazuh.APIPass != "" {
		dst.Wazuh.APIPass = o.Wazuh.APIPass
	}
}

func loadConfig() Config {
	var c Config
	if b, err := os.ReadFile(filepath.Join(BASE, "config.yaml")); err == nil {
		_ = yaml.Unmarshal(b, &c)
	}
	// Per-site overlay: gitignored, holds the credential + target.
	if b, err := os.ReadFile(filepath.Join(BASE, "config.local.yaml")); err == nil {
		var o Config
		if yaml.Unmarshal(b, &o) == nil {
			mergeLineOverlay(&c, &o)
		}
	}
	// Environment wins over both — useful for containers and CI.
	if v := os.Getenv("LINE_CHANNEL_TOKEN"); v != "" {
		c.Line.ChannelToken = v
	}
	if v := os.Getenv("LINE_TARGET_ID"); v != "" {
		c.Line.TargetID = v
	}
	if v := os.Getenv("LINE_API_BASE"); v != "" {
		c.Line.APIBase = v
	}
	if v := os.Getenv("WAZUH_API_URL"); v != "" {
		c.Wazuh.APIURL = v
	}
	if v := os.Getenv("WAZUH_API_USER"); v != "" {
		c.Wazuh.APIUser = v
	}
	if v := os.Getenv("WAZUH_API_PASSWORD"); v != "" {
		c.Wazuh.APIPass = v
	}

	// Defaults
	if c.PlaybooksDir == "" {
		c.PlaybooksDir = "playbooks"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.EvidenceDir == "" {
		c.EvidenceDir = "evidence"
	}
	if c.Firewall == "" {
		c.Firewall = "simulated"
	}
	if c.BlockDefault == 0 {
		c.BlockDefault = 600
	}
	if c.ApprovalMode == "" {
		c.ApprovalMode = "hold"
	}
	if c.Line.Enabled == nil {
		t := true
		c.Line.Enabled = &t
	}
	if c.Line.Disclosure == "" {
		c.Line.Disclosure = "minimal"
	}
	if c.Line.SeverityFloor == 0 {
		c.Line.SeverityFloor = 7
	}
	if c.Line.DailyCap == 0 {
		c.Line.DailyCap = 10
	}
	if c.Line.AggregateSecs == 0 {
		c.Line.AggregateSecs = 30
	}
	if c.Line.QuietHours == nil {
		c.Line.QuietHours = &QuietHours{From: "22:00", To: "07:00", Floor: 12}
	}
	if c.Line.APIBase == "" {
		c.Line.APIBase = "https://api.line.me"
	}

	// Legacy flat keys are the last fallback.
	if c.Line.ChannelToken == "" {
		c.Line.ChannelToken = c.LineTokenLegacy
	}
	if c.Line.TargetID == "" {
		c.Line.TargetID = c.LineTargetLegacy
	}
	c.LineToken = c.Line.ChannelToken
	c.LineTarget = c.Line.TargetID
	return c
}

var CONFIG Config

var sevNames = map[string]int{"critical": 15, "high": 12, "medium": 8, "low": 4, "informational": 1, "info": 1}

var safeFormatRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

const yamlHeader = "# Mini-SOAR playbook — แก้ไขผ่านฟอร์มภาษาไทย (Thai UI)\n" +
	"# แก้ไขแต่ละครั้งจะบันทึกเป็น YAML ไฟล์โดยตรง — single source of truth\n"

var customNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9\-_]{0,63}$`)

var allowedActions = []string{"notify", "preserve_evidence", "block_ip", "isolate_host", "audit"}

var allowedDurations = []int{600, 1800, 3600, 86400}

var templatePlaceholders = map[string]bool{"title": true, "src_ip": true, "dst_ip": true, "host": true, "user": true, "url": true, "hash": true, "severity": true, "source": true}

var sampleAlert = map[string]interface{}{
	"title": "ตัวอย่าง: SSH brute force", "severity": 10, "src_ip": "203.0.113.66",
	"host": "HIS-SERVER-01", "user": "root", "source": "wazuh", "rule_id": "5551",
}

func sevParts(n int64) (string, string) {
	switch {
	case n >= 13:
		return "crit", "วิกฤต"
	case n >= 10:
		return "high", "สูง"
	case n >= 6:
		return "med", "กลาง"
	default:
		return "low", "ต่ำ"
	}
}
