package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// stubWazuh serves the two endpoints the client uses.
func stubWazuh(t *testing.T, arBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/security/user/authenticate"):
			_, _ = w.Write([]byte(`{"data":{"token":"test-token"}}`))
		case strings.HasSuffix(r.URL.Path, "/active-response"):
			_, _ = w.Write([]byte(arBody))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withWazuh(t *testing.T, url string) {
	t.Helper()
	old := CONFIG.Wazuh
	CONFIG.Wazuh = WazuhConfig{APIURL: url, APIUser: "u", APIPass: "p"}
	wazuh.mu.Lock()
	wazuh.token, wazuh.exp, wazuh.ids = "", time.Time{}, map[string]string{}
	wazuh.mu.Unlock()
	t.Cleanup(func() {
		CONFIG.Wazuh = old
		wazuh.mu.Lock()
		wazuh.token, wazuh.exp = "", time.Time{}
		wazuh.mu.Unlock()
	})
}

// Wazuh answers 200 with failed_items when it cannot reach the agent — measured on the
// lab as {"code":1707,"message":"Cannot send request, agent is not active"}. That must be
// an error: reporting it as "queued" tells an operator a host is contained when nothing
// was sent at all.
func TestActiveResponseRejectsUndelivered(t *testing.T) {
	srv := stubWazuh(t, `{"data":{"affected_items":[],"total_affected_items":0,
	  "total_failed_items":1,"failed_items":[{"error":{"code":1707,
	  "message":"Cannot send request, agent is not active"}}]},
	  "message":"AR command was sent to all agents","error":0}`)
	withWazuh(t, srv.URL)

	err := wazuh.runActiveResponse("003", "!isolate-host", []string{"--isolate"}, nil)
	if err == nil {
		t.Fatal("a 200 carrying failed_items was accepted as delivered")
	}
	if !strings.Contains(err.Error(), "NOT delivered") {
		t.Errorf("the error should say it was not delivered, got: %v", err)
	}
	if !strings.Contains(err.Error(), "1707") {
		t.Errorf("the error should surface Wazuh's own code, got: %v", err)
	}
}

func TestActiveResponseAcceptsDelivered(t *testing.T) {
	srv := stubWazuh(t, `{"data":{"affected_items":["003"],"total_affected_items":1,
	  "total_failed_items":0,"failed_items":[]},
	  "message":"AR command was sent to all agents","error":0}`)
	withWazuh(t, srv.URL)

	if err := wazuh.runActiveResponse("003", "!isolate-host", nil, nil); err != nil {
		t.Fatalf("a genuinely dispatched command was rejected: %v", err)
	}
}

func TestActiveResponseUnconfigured(t *testing.T) {
	old := CONFIG.Wazuh
	CONFIG.Wazuh = WazuhConfig{}
	defer func() { CONFIG.Wazuh = old }()

	err := wazuh.runActiveResponse("003", "!isolate-host", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("want a 'not configured' error, got %v", err)
	}
}
