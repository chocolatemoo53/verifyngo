package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSanitizeReturnPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "/"},
		{"plain", "/foo", "/foo"},
		{"with-query", "/foo?a=b", "/foo?a=b"},
		{"protocol-relative", "//evil.example", "/"},
		{"backslash", `/fooevil.example`, "/fooevil.example"},
		{"backslash-in-path", `/foo\bar`, "/"},
		{"backslash-slash", `/\evil.example`, "/"},
		{"crlf", "/foo\r\nBar: x", "/"},
		{"absolute", "https://evil.example", "/"},
		{"scheme-relative-path", "http:/\\evil.example", "/"},
	}
	for _, c := range cases {
		if got := sanitizeReturnPath(c.in); got != c.want {
			t.Errorf("%s: sanitizeReturnPath(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestAnonymizeIP(t *testing.T) {
	v4 := anonymizeIP(net.ParseIP("203.0.113.123"))
	if v4.String() != "203.0.113.0" {
		t.Errorf("ipv4 anonymize = %s, want 203.0.113.0", v4)
	}
	v6 := anonymizeIP(net.ParseIP("2001:db8:1:2:3:4:5:6"))
	if v6.String() != "2001:db8:1::" {
		t.Errorf("ipv6 anonymize = %s, want 2001:db8:1::", v6)
	}
	if anonymizeIP(nil) != nil {
		t.Error("nil should stay nil")
	}
}

func TestStripQuery(t *testing.T) {
	if got := stripQuery("/search?q=password-reset-token"); got != "/search" {
		t.Errorf("stripQuery = %q", got)
	}
	if got := stripQuery("/plain"); got != "/plain" {
		t.Errorf("stripQuery plain = %q", got)
	}
}

func TestClientIPRightToLeft(t *testing.T) {
	cfg := &Config{}
	cfg.TrustRealIP = true
	cfg.TrustedProxies = []string{"10.0.0.1"}
	cfg.compiledTrustedProxies = compileWhitelist(cfg.TrustedProxies)

	newReq := func(remote, xff string) *http.Request {
		req := &http.Request{RemoteAddr: remote}
		if xff != "" {
			req.Header = http.Header{}
			req.Header.Set("X-Forwarded-For", xff)
		}
		return req
	}

	// Spoofed leftmost entry is ignored; the rightmost untrusted IP wins.
	if got, _ := clientIP(newReq("10.0.0.1:1000", "1.2.3.4, 203.0.113.9"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("spoofed chain: got %s, want 203.0.113.9", got)
	}
	// Single entry from a trusted proxy is the client.
	if got, _ := clientIP(newReq("10.0.0.1:1000", "203.0.113.9"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("single entry: got %s, want 203.0.113.9", got)
	}
	// Trusted chain is popped right-to-left.
	if got, _ := clientIP(newReq("10.0.0.1:1000", "203.0.113.9, 10.0.0.1"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("trusted chain: got %s, want 203.0.113.9", got)
	}
	// Connection from a non-trusted peer: XFF is ignored entirely.
	if got, _ := clientIP(newReq("192.0.2.50:1000", "1.2.3.4"), cfg); !got.Equal(net.ParseIP("192.0.2.50")) {
		t.Errorf("untrusted peer: got %s, want 192.0.2.50", got)
	}
	// Trusted proxy without XFF: IP resolved but marked unresolved (Tor hidden service).
	got, resolved := clientIP(newReq("10.0.0.1:1000", ""), cfg)
	if !got.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("proxy no-xff: got %s, want 10.0.0.1", got)
	}
	if resolved {
		t.Error("proxy without XFF should be unresolved")
	}
}

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRejectsWeakCookieSecret(t *testing.T) {
	path := writeTempConfig(t, `{"cookie_secret": "short"}`)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for short cookie_secret")
	}
}

func TestLoadConfigRejectsUnsetCookieSecret(t *testing.T) {
	path := writeTempConfig(t, `{"listen_addr": "127.0.0.1:0"}`)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for missing cookie_secret")
	}
}

func TestLoadConfigRequiresTrustedProxies(t *testing.T) {
	path := writeTempConfig(t, `{"cookie_secret": "`+string(make([]byte, 0))+`"}`)
	_ = path
	body := `{"cookie_secret": "abcdefghijklmnopqrstuvwxyz012345", "trust_real_ip": true}`
	path2 := writeTempConfig(t, body)
	if _, err := loadConfig(path2); err == nil {
		t.Fatal("expected error for trust_real_ip without trusted_proxies")
	}

	ok := `{"cookie_secret": "abcdefghijklmnopqrstuvwxyz012345", "trust_real_ip": true, "trusted_proxies": ["127.0.0.0/8"]}`
	path3 := writeTempConfig(t, ok)
	if _, err := loadConfig(path3); err != nil {
		t.Fatalf("expected valid config with trusted_proxies, got %v", err)
	}
}

func TestAnonymizeDefaultsTrue(t *testing.T) {
	cfg := &Config{}
	if !cfg.Anonymize() {
		t.Fatal("anonymize should default to true when key is absent")
	}
	off := false
	cfg.AnonymizeIPs = &off
	if cfg.Anonymize() {
		t.Fatal("anonymize should be disableable")
	}
}

func TestMemoryStorePrunesRecentPaths(t *testing.T) {
	s := newMemoryStore("", time.Minute)
	s.LogPath("1.2.3.4", "/a")
	s.LogPath("5.6.7.8", "/b")
	s.IncrBanCount("5.6.7.8")

	// Force-expire walkaway entries so both IPs look inactive.
	for ip, e := range s.walkaways {
		e.Expires = time.Now().Add(-time.Minute)
		s.walkaways[ip] = e
	}
	s.sweepOnce()

	if len(s.recentPath) != 0 {
		t.Errorf("recentPath not pruned: %v", s.recentPath)
	}
}

func TestMemoryStoreKeepsRecentPathsWhileBlocked(t *testing.T) {
	s := newMemoryStore("", time.Minute)
	s.LogPath("1.2.3.4", "/a")
	s.Block("1.2.3.4", time.Hour)
	for ip, e := range s.walkaways {
		e.Expires = time.Now().Add(-time.Minute)
		s.walkaways[ip] = e
	}
	s.sweepOnce()
	if len(s.recentPath) != 1 {
		t.Errorf("recentPath for blocked IP should be kept: %v", s.recentPath)
	}
}
