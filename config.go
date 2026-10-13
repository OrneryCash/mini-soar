package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
)

type Config struct {
	Server struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	PlaybooksDir  string `yaml:"playbooks_dir"`
	DataDir       string `yaml:"data_dir"`
	EvidenceDir   string `yaml:"evidence_dir"`
	LineToken     string `yaml:"line_channel_token"`
	LineTarget    string `yaml:"line_target_user_id"`
	Firewall      string `yaml:"firewall_backend"`
	BlockDefault  int    `yaml:"block_default_duration"`
	ApprovalTO    int    `yaml:"approval_timeout_seconds"`
	ApprovalMode  string `yaml:"approval_timeout_action"`
	WebhookSecret string `yaml:"webhook_secret"`
	DBPath        string `yaml:"db_path"`
}

var BASE string

func loadConfig() Config {
	var c Config
	b, err := os.ReadFile(filepath.Join(BASE, "config.yaml"))
	if err == nil {
		_ = yaml.Unmarshal(b, &c)
	}
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
