package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Wazuh API client — how mini-SOAR performs a REAL response.
//
// The SOAR never touches the endpoint. It asks the manager's API to queue an Active
// Response command; the manager relays it and the AGENT runs it locally. Two
// consequences shape this file:
//
//  1. No host credentials live in mini-SOAR, and the endpoint's own guardrails
//     (allowlist, TTL in isolate-host.sh) stay beyond the SOAR's reach.
//  2. The API answers 200 when the command is QUEUED, not when it ran — Wazuh does not
//     verify that the script exists or succeeded. So a 200 is NOT evidence of effect.
//     Every real action is therefore reported as "queued", never as "done", and the
//     effect is verified on the endpoint itself.

type wazuhClient struct {
	mu    sync.Mutex
	token string
	exp   time.Time
	ids   map[string]string // agent name -> id, resolved lazily
	http  *http.Client
}

var wazuh = &wazuhClient{
	ids: map[string]string{},
	http: &http.Client{
		Timeout: 15 * time.Second,
		// The manager serves a self-signed certificate. Pinning its CA would be better
		// in production; for the lab this is the honest trade-off, stated rather than
		// hidden. It is the only place we skip verification.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	},
}

func (w *wazuhClient) configured() bool {
	return CONFIG.Wazuh.APIURL != "" && CONFIG.Wazuh.APIUser != "" && CONFIG.Wazuh.APIPass != ""
}

func (w *wazuhClient) base() string { return strings.TrimRight(CONFIG.Wazuh.APIURL, "/") }

func clipStr(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// authenticate fetches and caches a JWT (Wazuh's last 15 minutes by default).
func (w *wazuhClient) authenticate() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.token != "" && time.Now().Before(w.exp) {
		return w.token, nil
	}
	req, err := http.NewRequest("POST", w.base()+"/security/user/authenticate", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(CONFIG.Wazuh.APIUser, CONFIG.Wazuh.APIPass)
	resp, err := w.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("wazuh api unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("wazuh auth failed: HTTP %d %s", resp.StatusCode, clipStr(string(body), 140))
	}
	var out struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Data.Token == "" {
		return "", fmt.Errorf("wazuh auth: no token in the response")
	}
	w.token = out.Data.Token
	w.exp = time.Now().Add(10 * time.Minute)
	return w.token, nil
}

// agentIDFor resolves the agent name that appears in the alert (e.g. "end-host2")
// to the agent ID the Active Response API needs (e.g. "003").
func (w *wazuhClient) agentIDFor(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("no host in the alert to target")
	}
	w.mu.Lock()
	if id, ok := w.ids[name]; ok {
		w.mu.Unlock()
		return id, nil
	}
	w.mu.Unlock()

	tok, err := w.authenticate()
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("GET", w.base()+"/agents?name="+name, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := w.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("agent lookup failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("agent lookup: HTTP %d %s", resp.StatusCode, clipStr(string(body), 140))
	}
	var out struct {
		Data struct {
			Affected []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"affected_items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Data.Affected) == 0 {
		return "", fmt.Errorf("agent %q is not registered with the manager", name)
	}
	id := out.Data.Affected[0].ID
	w.mu.Lock()
	w.ids[name] = id
	w.mu.Unlock()
	return id, nil
}

// runActiveResponse asks the manager to run an AR command on one agent.
// A command starting with "!" names a script on the agent (Wazuh convention).
//
// Returns nil when the command is QUEUED. That is deliberately not "success": the
// caller must record it as queued and verify the effect on the endpoint.
func (w *wazuhClient) runActiveResponse(agentID, command string, args []string, alertData map[string]interface{}) error {
	if !w.configured() {
		return fmt.Errorf("wazuh API not configured (wazuh.api_url / api_user / api_password)")
	}
	if agentID == "" {
		return fmt.Errorf("no agent id")
	}
	tok, err := w.authenticate()
	if err != nil {
		return err
	}
	if args == nil {
		args = []string{}
	}
	if alertData == nil {
		alertData = map[string]interface{}{}
	}
	payload := map[string]interface{}{
		"command":   command,
		"arguments": args,
		"alert":     map[string]interface{}{"data": alertData},
	}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/active-response?agents_list=%s", w.base(), agentID)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("active-response call failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("active-response: HTTP %d %s", resp.StatusCode, clipStr(string(body), 180))
	}
	return nil
}

// wazuhHealth is used by the settings page to show whether real mode can work at all.
func wazuhHealth() (bool, string) {
	if !wazuh.configured() {
		return false, "ยังไม่ได้ตั้งค่า Wazuh API (config.local.yaml)"
	}
	if _, err := wazuh.authenticate(); err != nil {
		return false, err.Error()
	}
	return true, "เชื่อมต่อ Wazuh API ได้"
}
