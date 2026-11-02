package main

import (
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
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
		{"protocol-relative-backslash", "/\\evil.example", "/"},
		{"double-backslash-slash", "/\\\\evil.example", "/"},
		{"mixed-scheme-relative", "/\\//evil.example", "/"},
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

	if got, _ := clientIP(newReq("10.0.0.1:1000", "1.2.3.4, 203.0.113.9"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("spoofed chain: got %s, want 203.0.113.9", got)
	}
	if got, _ := clientIP(newReq("10.0.0.1:1000", "203.0.113.9"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("single entry: got %s, want 203.0.113.9", got)
	}
	if got, _ := clientIP(newReq("10.0.0.1:1000", "203.0.113.9, 10.0.0.1"), cfg); !got.Equal(net.ParseIP("203.0.113.9")) {
		t.Errorf("trusted chain: got %s, want 203.0.113.9", got)
	}
	if got, _ := clientIP(newReq("192.0.2.50:1000", "1.2.3.4"), cfg); !got.Equal(net.ParseIP("192.0.2.50")) {
		t.Errorf("untrusted peer: got %s, want 192.0.2.50", got)
	}
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

func TestClientFingerprintTrust(t *testing.T) {
	cfg := &Config{TrustFingerprintHeaders: true}
	cfg.compiledTrustedProxies = compileWhitelist([]string{"10.0.0.1"})

	const tlsfp = "t13d1513h2_8daaf6152771_8b8af37844ec_30e06788707b"
	newReq := func(remote, name, value string) *http.Request {
		req := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		req.Header.Set(name, value)
		return req
	}

	if fp, ok := clientFingerprint(newReq("10.0.0.1:1000", "X-TLSFP", tlsfp), cfg); !ok || fp != "tlsfp:"+tlsfp {
		t.Errorf("trusted proxy: got %q %v", fp, ok)
	}
	if _, ok := clientFingerprint(newReq("192.0.2.50:1000", "X-TLSFP", tlsfp), cfg); ok {
		t.Error("header from untrusted peer must be ignored")
	}
	if _, ok := clientFingerprint(newReq("10.0.0.1:1000", "X-TLSFP", "anything|else"), cfg); ok {
		t.Error("malformed fingerprint must be ignored")
	}
	if fp, ok := clientFingerprint(newReq("10.0.0.1:1000", "X-JA4", "t13d1516h2_8daaf6152771_e5627efa2ab1"), cfg); !ok || fp != "ja4:t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("ja4 fallback: got %q %v", fp, ok)
	}

	cfg.TrustFingerprintHeaders = false
	if _, ok := clientFingerprint(newReq("10.0.0.1:1000", "X-TLSFP", tlsfp), cfg); ok {
		t.Error("headers must be ignored unless trust_fingerprint_headers is set")
	}
	cfg.TrustFingerprintHeaders = true

	req := newReq("10.0.0.1:1000", "X-TLSFP", tlsfp)
	a, _, _ := fingerprintKey(req, cfg, net.ParseIP("203.0.113.9"))
	b, _, _ := fingerprintKey(req, cfg, net.ParseIP("203.0.113.200"))
	c, _, _ := fingerprintKey(req, cfg, net.ParseIP("198.51.100.9"))
	if a != b || a == c {
		t.Errorf("fingerprint key must be scoped to the client subnet: %q %q %q", a, b, c)
	}
}

func TestCookieBoundToBrowser(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	expiry := time.Now().Add(time.Hour)
	chrome := "Mozilla/5.0 Chrome/141.0.0.0\nen-US,en;q=0.9"
	value := signCookie(secret, expiry, cookieScopeFull, "", chrome)

	if !verifyCookie(secret, value, cookieScopeFull, "", chrome) {
		t.Error("cookie must verify for the browser it was issued to")
	}
	if verifyCookie(secret, value, cookieScopeFull, "", "python-requests/2.32\nen-US,en;q=0.9") {
		t.Error("cookie must not verify for a different user agent")
	}
	if verifyCookie(secret, value, cookieScopeFull, "", "Mozilla/5.0 Chrome/141.0.0.0\nde-DE") {
		t.Error("cookie must not verify for a different language")
	}
	if verifyCookie(secret, value, cookieScopePassive, "", chrome) {
		t.Error("cookie must not verify for another scope")
	}
	if verifyCookie(secret, signCookie(secret, time.Now().Add(-time.Second), cookieScopeFull, "", chrome), cookieScopeFull, "", chrome) {
		t.Error("expired cookie must not verify")
	}
	parts := strings.Split(value, ".")
	if verifyCookie(secret, parts[0]+"."+parts[1]+"."+parts[3], cookieScopeFull, "", chrome) {
		t.Error("cookie in the old format must not verify")
	}
}

func TestCookieBoundToTLS(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	const binding = "Mozilla/5.0 Chrome/141.0.0.0\nen-US"
	expiry := time.Now().Add(time.Hour)
	bound := signCookie(secret, expiry, cookieScopeFull, "8daaf6152771", binding)

	if !verifyCookie(secret, bound, cookieScopeFull, "8daaf6152771", binding) {
		t.Error("cookie must verify with the same cipher hash")
	}
	if verifyCookie(secret, bound, cookieScopeFull, "aaaaaaaaaaaa", binding) {
		t.Error("cookie must not verify from a different TLS client")
	}
	if !verifyCookie(secret, bound, cookieScopeFull, "", binding) {
		t.Error("cookie must verify when the request carries no fingerprint")
	}
	unbound := signCookie(secret, expiry, cookieScopeFull, "", binding)
	if !verifyCookie(secret, unbound, cookieScopeFull, "8daaf6152771", binding) {
		t.Error("cookie issued without a fingerprint must verify on a request with one")
	}
	parts := strings.Split(bound, ".")
	if verifyCookie(secret, parts[0]+"."+parts[1]+".."+parts[3], cookieScopeFull, "aaaaaaaaaaaa", binding) {
		t.Error("removing the cipher hash from a cookie must break its signature")
	}
}

func TestBrowserMismatch(t *testing.T) {
	cfg := &Config{}
	const (
		chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
		firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0"
		safari  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15"
		criOS   = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/141.0.0.0 Mobile/15E148 Safari/604.1"
		hints   = `"Chromium";v="141", "Google Chrome";v="141", "Not?A_Brand";v="99"`
	)
	cases := []struct {
		ua, hints, proto, want string
	}{
		{chrome, hints, "https", ""},
		{chrome, "", "https", "no-hints"},
		{chrome, "", "http", ""},
		{firefox, "", "https", ""},
		{firefox, hints, "https", "fake"},
		{safari, "", "https", ""},
		{safari, hints, "https", "fake"},
		{criOS, "", "https", ""},
		{"curl/8.10.1", "", "https", ""},
	}
	for _, c := range cases {
		req := &http.Request{Header: http.Header{}}
		req.Header.Set("User-Agent", c.ua)
		req.Header.Set("X-Forwarded-Proto", c.proto)
		if c.hints != "" {
			req.Header.Set("Sec-CH-UA", c.hints)
		}
		if got := browserMismatch(req, cfg); got != c.want {
			t.Errorf("ua=%q hints=%v proto=%s: got %q, want %q", c.ua, c.hints != "", c.proto, got, c.want)
		}
	}
}

func TestPolicyRegexCompiledAtLoad(t *testing.T) {
	write := func(cond string) *Config {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		body := "rules:\n  - name: r\n    conditions:\n      - '" + cond + "'\n    action: deny\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return &Config{PolicyFile: path}
	}

	rules, err := compilePolicyFile(write(`path.matches("\\.php$") && headers["User-Agent"].matches("bot")`))
	if err != nil {
		t.Fatal(err)
	}
	match := func(path, ua string) bool {
		req := &http.Request{URL: &url.URL{Path: path}, Header: http.Header{"User-Agent": {ua}}}
		action, rule := evaluate(rules, "allow", req, net.ParseIP("192.0.2.1"))
		return action == "deny" && rule == "r"
	}
	if !match("/x.php", "somebot") || match("/xphp", "somebot") || match("/x.php", "Mozilla") {
		t.Error("compiled matches() does not behave like a regex match")
	}

	if _, err := compilePolicyFile(write(`path.matches("(unclosed")`)); err == nil {
		t.Error("invalid regex must fail at load")
	}
	if _, err := compilePolicyFile(write(`path.matches(userAgent)`)); err == nil {
		t.Error("unquoted pattern must fail at load")
	}
}

func testServer(t *testing.T, cfgJSON string) (*Config, Store, func(r *http.Request, loaded bool) *httptest.ResponseRecorder) {
	t.Helper()
	cfg, err := loadConfig(writeTempConfig(t, cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	cfg.sliderChallenges = newSliderChallengeStore(time.Minute, 100)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "1")
		io.Copy(w, r.Body)
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	store := newMemoryStore("", 0)
	cfg.store = store
	passive, _ := compileRegexList(cfg.Progressive.PassivePaths)
	return cfg, store, func(r *http.Request, loaded bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		w.Header().Set("X-Test-Decision", handleRequest(w, r, cfg, nil, loaded, passive, nil, nil, store, nil, proxy))
		return w
	}
}

const testConfig = `{"cookie_secret": "abcdefghijklmnopqrstuvwxyz012345", "upstream_url": "http://127.0.0.1:1", "provider": "slider", "default_action": "challenge",
	"progressive": {"enabled": true, "passive_paths": ["^/$"], "max_requests": 3, "request_window": "1m", "passive_ttl": "1h"}}`

func TestPassiveCookieLimitPerNetwork(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	passed := 0
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "203.0.113." + strconv.Itoa(10+i) + ":1000"
		if serve(req, true).Header().Get("X-Upstream") == "1" {
			passed++
		}
	}
	if passed != 3 {
		t.Errorf("cookie-less requests from one network passed %d times, want 3", passed)
	}
}

func TestRulesLoadingPassesTraffic(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	req := httptest.NewRequest("GET", "/private", nil)
	if serve(req, false).Header().Get("X-Upstream") != "1" {
		t.Error("requests must pass while rules are loading")
	}
	if serve(httptest.NewRequest("GET", "/private", nil), true).Header().Get("X-Upstream") == "1" {
		t.Error("requests must be challenged once rules are loaded")
	}
}

func TestFailedAttemptsBanLaterThanWalkaways(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	ip := net.ParseIP("203.0.113.7")
	limit := failedAttemptFactor * cfg.Walkaway.Threshold
	for i := 1; i < limit; i++ {
		w := httptest.NewRecorder()
		retryChallenge(w, httptest.NewRequest("POST", "/__verify", nil), cfg, store, ip, "/", penaltyFailed)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want the challenge again", i, w.Code)
		}
	}
	if store.IsBlocked(ip.String()) {
		t.Fatal("banned before the failed-attempt limit")
	}
	w := httptest.NewRecorder()
	retryChallenge(w, httptest.NewRequest("POST", "/__verify", nil), cfg, store, ip, "/", penaltyFailed)
	if w.Code != http.StatusForbidden || !store.IsBlocked(ip.String()) {
		t.Errorf("attempt %d must ban, got %d", limit, w.Code)
	}
}

func TestMetricsCountDecisions(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	issued := testutil.ToFloat64(metricChallenges.WithLabelValues("slider", "issued"))
	ruleHits := testutil.ToFloat64(metricRuleHits.WithLabelValues("default", "challenge"))

	req := httptest.NewRequest("GET", "/private", nil)
	req.RemoteAddr = "198.51.100.20:1000"
	if got := serve(req, true).Header().Get("X-Test-Decision"); got != "challenge" {
		t.Errorf("decision = %q, want challenge", got)
	}
	if got := testutil.ToFloat64(metricChallenges.WithLabelValues("slider", "issued")); got != issued+1 {
		t.Errorf("challenges issued = %v, want %v", got, issued+1)
	}
	if got := testutil.ToFloat64(metricRuleHits.WithLabelValues("default", "challenge")); got != ruleHits+1 {
		t.Errorf("default rule hits = %v, want %v", got, ruleHits+1)
	}
	if got := serve(httptest.NewRequest("GET", "/private", nil), false).Header().Get("X-Test-Decision"); got != "rules_loading" {
		t.Errorf("decision while loading = %q, want rules_loading", got)
	}
}

func TestTorKind(t *testing.T) {
	cfg := &Config{}
	exits := newIPTrie()
	exitNet, _ := parseCIDROrIP("185.220.101.5")
	exits.Insert(exitNet)
	cfg.torExits.Store(exits)

	cases := []struct {
		host, ip, want string
	}{
		{"example.org", "fc00:dead:beef:4dad::1:2", "onion"},
		{"abcdefghijklmnop.onion", "127.0.0.1", "onion"},
		{"ABCDEFGHIJKLMNOP.ONION:80", "172.18.0.5", "onion"},
		{"abcdefghijklmnop.onion", "203.0.113.9", ""},
		{"example.org", "185.220.101.5", "exit"},
		{"example.org", "203.0.113.9", ""},
	}
	for _, c := range cases {
		req := &http.Request{Host: c.host}
		if got := torKind(req, cfg, net.ParseIP(c.ip)); got != c.want {
			t.Errorf("host=%s ip=%s: got %q, want %q", c.host, c.ip, got, c.want)
		}
	}

	if clientNetwork(net.ParseIP("fc00:dead:beef:4dad::1")) == clientNetwork(net.ParseIP("fc00:dead:beef:4dad::2")) {
		t.Error("each onion circuit must be its own network")
	}
	if clientNetwork(net.ParseIP("2001:db8:1::1")) != clientNetwork(net.ParseIP("2001:db8:1::2")) {
		t.Error("regular IPv6 addresses in one /48 must share a network")
	}
}

func TestTorPrefersSlider(t *testing.T) {
	cfg := &Config{Provider: "turnstile"}
	cfg.Slider.Enabled = true
	onion := &http.Request{RemoteAddr: "127.0.0.1:1000", Host: "abcdefghijklmnop.onion", Header: http.Header{}}
	clear := &http.Request{RemoteAddr: "203.0.113.9:1000", Host: "example.org", Header: http.Header{}}
	if got := providerForRequest(cfg, onion); got != "slider" {
		t.Errorf("onion provider = %q, want slider", got)
	}
	if got := providerForRequest(cfg, clear); got != "turnstile" {
		t.Errorf("clearnet provider = %q, want turnstile", got)
	}
}

func TestTorExitNeverBanned(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	exits := newIPTrie()
	exitNet, _ := parseCIDROrIP("185.220.101.5")
	exits.Insert(exitNet)
	cfg.torExits.Store(exits)

	for i := 0; i < 3*cfg.Walkaway.Threshold; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "185.220.101.5:1000"
		if got := serve(req, true).Header().Get("X-Test-Decision"); got != "challenge" {
			t.Fatalf("request %d from an exit: decision %q, want challenge", i, got)
		}
	}
	if store.IsBlocked("185.220.101.5") {
		t.Error("a shared exit IP must never be banned")
	}
}

func TestOnionCircuitsBannedSeparately(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.TrustRealIP = true
	cfg.compiledTrustedProxies = compileWhitelist([]string{"10.0.0.1"})
	request := func(circuit string) {
		req := httptest.NewRequest("GET", "/private", nil)
		req.Host = "abcdefghijklmnop.onion"
		req.RemoteAddr = "10.0.0.1:1000"
		req.Header.Set("X-Forwarded-For", circuit)
		serve(req, true)
	}
	for i := 0; i < cfg.Walkaway.Threshold; i++ {
		request("fc00:dead:beef:4dad::aa")
	}
	request("fc00:dead:beef:4dad::bb")
	if !store.IsBlocked("fc00:dead:beef:4dad::aa") {
		t.Error("a circuit that keeps walking away must be banned")
	}
	if store.IsBlocked("fc00:dead:beef:4dad::bb") {
		t.Error("another circuit must not share that ban")
	}
}

func TestSlowUploadSurvivesReadTimeout(t *testing.T) {
	upload := func(h http.Handler) (int, error) {
		srv := httptest.NewUnstartedServer(h)
		srv.Config.ReadTimeout = 200 * time.Millisecond
		srv.Start()
		defer srv.Close()

		pr, pw := io.Pipe()
		go func() {
			for i := 0; i < 6; i++ {
				pw.Write([]byte("chunk"))
				time.Sleep(100 * time.Millisecond)
			}
			pw.Close()
		}()
		resp, err := http.Post(srv.URL, "application/octet-stream", pr)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != strings.Repeat("chunk", 6) {
			return resp.StatusCode, fmt.Errorf("upstream got %q", body)
		}
		return resp.StatusCode, nil
	}
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(w, r.Body)
	})

	if _, err := upload(echo); err == nil {
		t.Fatal("the slow upload should fail without clearing the deadline, so this test proves nothing")
	}
	if code, err := upload(withoutDeadlines(echo)); err != nil || code != http.StatusOK {
		t.Errorf("slow upload through withoutDeadlines: code=%d err=%v", code, err)
	}
}

func TestCapCheckmark(t *testing.T) {
	got := string(capCheckmark("#E0218A"))
	if !strings.HasPrefix(got, `url("data:image/svg+xml,`) || !strings.Contains(got, "%23E0218A") {
		t.Fatalf("checkmark missing accent: %s", got)
	}
	if strings.ContainsAny(strings.TrimSuffix(strings.TrimPrefix(got, `url("`), `")`), `"'() `) {
		t.Fatalf("checkmark not escaped for CSS: %s", got)
	}
	for _, bad := range []string{"", "red", "#fff", `#12345"`, "#zzzzzz"} {
		if c := capCheckmark(bad); c != "" {
			t.Fatalf("capCheckmark(%q) = %q, want empty", bad, c)
		}
	}
}

var hiddenInputRe = regexp.MustCompile(`<input type="hidden" (?:id="[^"]*" )?name="([^"]+)" value="([^"]*)">`)

func hiddenInputs(page string) url.Values {
	out := url.Values{}
	for _, m := range hiddenInputRe.FindAllStringSubmatch(page, -1) {
		out.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return out
}

func formPost(path string, form url.Values, site string) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 Firefox/143.0")
	if site != "" {
		req.Header.Set("Sec-Fetch-Site", site)
	}
	req.RemoteAddr = "198.51.100.30:1000"
	return req
}

func TestReplayCapturedOnEveryProvider(t *testing.T) {
	cfg, _, serve := testServer(t, testConfig)
	cfg.Cap.SiteKey, cfg.HCaptcha.SiteKey, cfg.Turnstile.SiteKey = "k", "k", "k"
	for _, provider := range []string{"slider", "cap", "hcaptcha", "turnstile"} {
		cfg.Provider = provider
		page := serve(formPost("/search", url.Values{"q": {`cats "&" <dogs>`}}, "same-origin"), true).Body.String()
		if n := strings.Count(page, `name="__replay_q"`); n != 2 {
			t.Errorf("%s: replay field rendered %d times, want the challenge and wait forms", provider, n)
		}
		if got := hiddenInputs(page).Get("__replay_q"); got != `cats "&" <dogs>` {
			t.Errorf("%s: replay value = %q", provider, got)
		}
		if strings.Contains(page, "<dogs>") {
			t.Errorf("%s: replay value was not escaped", provider)
		}
	}
	if !strings.Contains(challengeTpl, "f.appendChild(document.getElementById('verifyngo-replay'))") {
		t.Error("cap form must carry the replay fields")
	}
}

func TestReplayIgnoredWhenUnsafe(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	cases := map[string]*http.Request{
		"cross-site": formPost("/search", url.Values{"q": {"cats"}}, "cross-site"),
		"no origin":  formPost("/search", url.Values{"q": {"cats"}}, ""),
		"too large":  formPost("/search", url.Values{"q": {strings.Repeat("a", maxReplayBytes)}}, "same-origin"),
	}
	multipart := formPost("/upload", nil, "same-origin")
	multipart.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	cases["multipart"] = multipart
	for name, req := range cases {
		if page := serve(req, true).Body.String(); strings.Contains(page, "__replay_") {
			t.Errorf("%s: form fields must not be carried", name)
		}
	}
}

func TestFinishVerifyResubmits(t *testing.T) {
	form := url.Values{"__replay_q": {"cats"}, "__replay_category_general": {"1"}, "return_to": {"/search"}}
	req := formPost("/__verify", form, "same-origin")
	req.ParseForm()
	w := httptest.NewRecorder()
	finishVerify(w, req, "/search")
	page := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(page, `action="/search"`) || !strings.Contains(page, "<button type=\"submit\">Continue</button>") {
		t.Fatalf("expected a resubmit page, got %d:\n%s", w.Code, page)
	}
	if got := hiddenInputs(page); got.Get("q") != "cats" || got.Get("category_general") != "1" || len(got) != 2 {
		t.Errorf("resubmit fields = %v", got)
	}

	plain := formPost("/__verify", url.Values{"return_to": {"/search"}}, "same-origin")
	plain.ParseForm()
	w = httptest.NewRecorder()
	finishVerify(w, plain, "/search")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/search" {
		t.Errorf("without replay fields: got %d %q, want a redirect", w.Code, w.Header().Get("Location"))
	}

	cross := formPost("/__verify", form, "cross-site")
	cross.ParseForm()
	w = httptest.NewRecorder()
	finishVerify(w, cross, "/search")
	if w.Code != http.StatusFound {
		t.Errorf("cross-site verify must not resubmit, got %d", w.Code)
	}
}

func TestSearchPostSurvivesChallenge(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	page := serve(formPost("/search", url.Values{"q": {"cats"}}, "same-origin"), true).Body.String()
	fields := hiddenInputs(page[:strings.Index(page, "<summary>Having trouble?")])
	id := fields.Get("captcha_id")

	cfg.sliderChallenges.mu.Lock()
	ch, ok := cfg.sliderChallenges.challenges[id]
	ch.issued = time.Now().Add(-5 * time.Second)
	cfg.sliderChallenges.challenges[id] = ch
	cfg.sliderChallenges.mu.Unlock()
	if !ok {
		t.Fatalf("no slider challenge issued, page:\n%s", page)
	}

	fields.Set("answer", strconv.Itoa(ch.answer))
	w := httptest.NewRecorder()
	handleVerify(w, formPost("/__verify", fields, "same-origin"), cfg, store)
	resubmit := hiddenInputs(w.Body.String())
	if w.Code != http.StatusOK || resubmit.Get("q") != "cats" {
		t.Fatalf("verify: got %d with fields %v", w.Code, resubmit)
	}

	again := formPost("/search", resubmit, "same-origin")
	for _, c := range w.Result().Cookies() {
		again.AddCookie(c)
	}
	res := serve(again, true)
	if res.Header().Get("X-Test-Decision") != "verified" || res.Body.String() != "q=cats" {
		t.Errorf("resubmitted search: decision %q, upstream got %q", res.Header().Get("X-Test-Decision"), res.Body.String())
	}
}

func TestVerifyCookieRejectsTampering(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	binding := "Mozilla/5.0 Chrome/141.0.0.0\nen-US"
	value := signCookie(secret, time.Now().Add(time.Hour), cookieScopeFull, "", binding)
	dot := strings.IndexByte(value, '.')
	sig := value[strings.LastIndexByte(value, '.')+1:]
	cases := map[string]string{
		"later expiry":  strconv.FormatInt(time.Now().Add(48*time.Hour).Unix(), 10) + value[dot:],
		"bad hex":       value[:len(value)-1] + "z",
		"short sig":     value[:len(value)-2],
		"extra segment": value + ".00",
		"sig only":      sig,
	}
	for name, v := range cases {
		if verifyCookie(secret, v, cookieScopeFull, "", binding) {
			t.Errorf("%s: tampered cookie verified", name)
		}
	}
}

func TestCookiesAlwaysSecure(t *testing.T) {
	cfg := &Config{CookieName: "verifyngo", CookieSecret: "0123456789abcdef0123456789abcdef"}
	cfg.CookieTTL = Duration{time.Hour}
	cfg.Progressive.PassiveTTL = Duration{time.Hour}
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	w := httptest.NewRecorder()
	setVerifiedCookie(w, r, cfg)
	setPassiveCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	cookies := w.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("got %d cookies, want 3", len(cookies))
	}
	for _, c := range cookies {
		if !c.Secure || !c.HttpOnly {
			t.Errorf("cookie %s: Secure=%v HttpOnly=%v", c.Name, c.Secure, c.HttpOnly)
		}
	}
}

func TestCleanPathForMatch(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/admin", "/admin"},
		{"/admin;jsessionid=123", "/admin"},
		{"/admin/users;foo=bar/edit", "/admin/users/edit"},
		{"/style.css?v=123", "/style.css"},
		{"/style.css;matrix?v=123", "/style.css"},
		{"", "/"},
	}
	for _, c := range cases {
		if got := cleanPathForMatch(c.in); got != c.want {
			t.Errorf("cleanPathForMatch(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSensitiveFieldsNotReplayed(t *testing.T) {
	vals := url.Values{
		"username":     {"alice"},
		"password":     {"secret123"},
		"pwd":          {"pass"},
		"api_key":      {"key-xyz"},
		"token":        {"tok-abc"},
		"credit_card":  {"411111111111"},
		"cvv":          {"123"},
		"search_query": {"golang"},
	}
	fields := replayFields(vals)
	for _, f := range fields {
		if isSensitiveFieldName(f.Name) {
			t.Errorf("sensitive field %q was not filtered from replay fields", f.Name)
		}
	}
	foundUser := false
	foundSearch := false
	for _, f := range fields {
		if f.Name == "username" && f.Value == "alice" {
			foundUser = true
		}
		if f.Name == "search_query" && f.Value == "golang" {
			foundSearch = true
		}
	}
	if !foundUser || !foundSearch {
		t.Errorf("benign fields missing from replay: %v", fields)
	}
}

func TestBannedOrDenyOverridesVerifiedCookie(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	rulesFile := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(rulesFile, []byte("rules:\n  - name: block_admin\n    conditions:\n      - 'path.matches(\"^/admin\")'\n    action: deny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiledRules, err := compilePolicyFile(&Config{PolicyFile: rulesFile})
	if err != nil {
		t.Fatal(err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "1")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)

	clientIP := "203.0.113.50"
	reqTemplate := httptest.NewRequest("GET", "http://example.com/normal", nil)
	reqTemplate.RemoteAddr = clientIP + ":1234"
	reqTemplate.Header.Set("User-Agent", "TestAgent")
	binding := cookieBinding(reqTemplate, cfg)
	cookieVal := signCookie(cfg.CookieSecret, time.Now().Add(time.Hour), cookieScopeFull, "", binding)

	makeReq := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = clientIP + ":1234"
		req.Header.Set("User-Agent", "TestAgent")
		req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: cookieVal})
		w := httptest.NewRecorder()
		w.Header().Set("X-Test-Decision", handleRequest(w, req, cfg, compiledRules, true, nil, nil, nil, store, nil, proxy))
		return w
	}

	w1 := makeReq("/normal")
	if dec := w1.Header().Get("X-Test-Decision"); dec != "verified" {
		t.Fatalf("normal path decision = %q, want verified", dec)
	}

	w2 := makeReq("/admin")
	if dec := w2.Header().Get("X-Test-Decision"); dec != "deny" {
		t.Fatalf("denied path decision = %q, want deny", dec)
	}

	store.Block(clientIP, time.Hour)
	w3 := makeReq("/normal")
	if dec := w3.Header().Get("X-Test-Decision"); dec != "banned" {
		t.Fatalf("banned IP decision = %q, want banned", dec)
	}
}

func timedPost(cfg *Config, store Store, ip, provider string, form url.Values) *httptest.ResponseRecorder {
	if form.Get("wait") != "" && form.Get("trouble") == "" && form.Get("captcha_id") == "" {
		form.Set("trouble", agedTroubleToken(cfg, ip))
	}
	return rawWaitPost(cfg, store, ip, provider, form)
}

func agedTroubleToken(cfg *Config, ip string) string {
	req := httptest.NewRequest("POST", "/__verify", nil)
	req.RemoteAddr = ip + ":1234"
	return troubleTokenAt(req, cfg, time.Now().Add(-2*troubleDelay))
}

func rawWaitPost(cfg *Config, store Store, ip, provider string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/__verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = ip + ":1234"
	req.AddCookie(&http.Cookie{Name: "cp_provider", Value: provider})
	w := httptest.NewRecorder()
	handleVerify(w, req, cfg, store)
	return w
}

func hasVerifiedCookie(cfg *Config, w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == cfg.CookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func timedChallengeID(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="captcha_id" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, `id="timed-form"`) {
		t.Fatal("wait page was not served")
	}
	return m[1]
}

func ageTimedChallenge(cfg *Config, id string) {
	cfg.sliderChallenges.mu.Lock()
	defer cfg.sliderChallenges.mu.Unlock()
	c := cfg.sliderChallenges.challenges[id]
	c.issued = time.Now().Add(-timedWait - time.Second)
	cfg.sliderChallenges.challenges[id] = c
}

func TestWaitIsAnEscapeHatchNotAProvider(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	ip := "203.0.113.88"

	req := httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = ip + ":1234"
	body := serve(req, true).Body.String()
	if !strings.Contains(body, "<summary>Having trouble?</summary>") {
		t.Fatal("challenge page must offer the wait through Having trouble")
	}
	if strings.Contains(body, "provider=timed") {
		t.Fatal("wait must not be listed as a captcha")
	}
	for _, p := range availableProviders(cfg) {
		if p == "timed" {
			t.Fatal("wait must not be an available provider")
		}
	}

	req = httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = ip + ":1234"
	req.AddCookie(&http.Cookie{Name: "cp_provider", Value: "timed"})
	if strings.Contains(serve(req, true).Body.String(), `id="timed-form"`) {
		t.Fatal("a provider cookie must not select the wait")
	}

	start := timedPost(cfg, store, ip, "slider", url.Values{"wait": {"1"}, "return_to": {"/page"}})
	if hasVerifiedCookie(cfg, start) {
		t.Fatal("starting a wait must not verify")
	}
	id := timedChallengeID(t, start.Body.String())
	form := url.Values{"wait": {"1"}, "captcha_id": {id}, "return_to": {"/page"}}

	early := timedPost(cfg, store, ip, "slider", form)
	if hasVerifiedCookie(cfg, early) {
		t.Fatal("pressing Continue early must not verify")
	}
	if got := timedChallengeID(t, early.Body.String()); got != id {
		t.Fatal("pressing Continue early must keep the running wait")
	}
	if n := store.IncrWalkaway(ip, time.Hour); n != 3 {
		t.Fatalf("waiting added a strike: walk-aways = %d, want 3", n)
	}

	ageTimedChallenge(cfg, id)
	if w := timedPost(cfg, store, ip, "slider", form); !hasVerifiedCookie(cfg, w) {
		t.Fatalf("expected a finished wait to verify, got status %d", w.Code)
	}
	if w := timedPost(cfg, store, ip, "slider", form); hasVerifiedCookie(cfg, w) {
		t.Fatal("a finished wait must not be reusable")
	}
}

func waitGet(cfg *Config, store Store, ip, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	handleWait(w, req, cfg, store)
	return w
}

func TestWaitMetaRefreshCompletesWithoutInput(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	ip := "203.0.113.93"
	page := timedPost(cfg, store, ip, "slider", url.Values{"wait": {"1"}, "return_to": {"/page?a=1"}}).Body.String()
	id := timedChallengeID(t, page)
	m := regexp.MustCompile(`<meta http-equiv="refresh" content="15;url=([^"]+)">`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("wait page has no meta refresh:\n%s", page)
	}
	target := html.UnescapeString(m[1])

	early := waitGet(cfg, store, ip, target)
	if hasVerifiedCookie(cfg, early) {
		t.Fatal("a refresh before the wait ends must not verify")
	}
	if got := timedChallengeID(t, early.Body.String()); got != id {
		t.Fatal("an early refresh must keep the running wait")
	}

	ageTimedChallenge(cfg, id)
	done := waitGet(cfg, store, ip, target)
	if !hasVerifiedCookie(cfg, done) || done.Code != http.StatusFound || done.Header().Get("Location") != "/page?a=1" {
		t.Fatalf("finished wait: status %d location %q", done.Code, done.Header().Get("Location"))
	}
	if w := waitGet(cfg, store, ip, target); hasVerifiedCookie(cfg, w) {
		t.Fatal("a finished wait must not be reusable")
	}
	if w := waitGet(cfg, store, ip, "/__wait?captcha_id=nope&return_to=/"); hasVerifiedCookie(cfg, w) {
		t.Fatal("an unknown wait must not verify")
	}
}

func TestWaitRejectsPostAndMetaSkipsPendingForms(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	req := httptest.NewRequest("POST", "/__wait", nil)
	req.RemoteAddr = "203.0.113.94:1234"
	w := httptest.NewRecorder()
	handleWait(w, req, cfg, store)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /__wait = %d, want 405", w.Code)
	}

	form := url.Values{"wait": {"1"}, "return_to": {"/search"}, "__replay_q": {"golang"}, "trouble": {agedTroubleToken(cfg, "203.0.113.92")}}
	post := httptest.NewRequest("POST", "/__verify", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Sec-Fetch-Site", "same-origin")
	post.RemoteAddr = "203.0.113.94:1234"
	w = httptest.NewRecorder()
	handleVerify(w, post, cfg, store)
	if strings.Contains(w.Body.String(), `http-equiv="refresh"`) {
		t.Error("a refresh would lose the pending form fields")
	}
	if !strings.Contains(w.Body.String(), `getElementById('timed-form').submit()`) {
		t.Error("a pending form must auto-submit when scripts run")
	}
}

func TestUpstreamFormFieldNamedWaitIsIgnored(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	page := serve(formPost("/search", url.Values{"wait": {"1"}}, "same-origin"), true).Body.String()
	if strings.Contains(page, `id="timed-form"`) {
		t.Fatal("a site form field named wait must not start a wait")
	}
}

func TestWaitWorksWithoutTheSlider(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	cfg.Slider.Enabled = false
	w := timedPost(cfg, store, "203.0.113.91", "cap", url.Values{"wait": {"1"}, "return_to": {"/"}})
	id := timedChallengeID(t, w.Body.String())
	ageTimedChallenge(cfg, id)
	w = timedPost(cfg, store, "203.0.113.91", "cap", url.Values{"wait": {"1"}, "captcha_id": {id}, "return_to": {"/"}})
	if !hasVerifiedCookie(cfg, w) {
		t.Fatalf("expected a finished wait to verify without the slider, got status %d", w.Code)
	}
}

func TestWaitKeepsPendingFormSubmission(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	form := url.Values{"wait": {"1"}, "return_to": {"/search"}, "__replay_q": {"golang"}, "trouble": {agedTroubleToken(cfg, "203.0.113.94")}}
	req := httptest.NewRequest("POST", "/__verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.RemoteAddr = "203.0.113.92:1234"
	w := httptest.NewRecorder()
	handleVerify(w, req, cfg, store)
	timedChallengeID(t, w.Body.String())
	if !strings.Contains(w.Body.String(), `name="__replay_q" value="golang"`) {
		t.Fatal("the wait page must keep the pending form fields")
	}
}

func TestTimedAndSliderChallengesAreSeparate(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	cfg.Slider.MinSolveTime = Duration{}

	timedID, err := cfg.sliderChallenges.issueTimed()
	if err != nil {
		t.Fatal(err)
	}
	w := timedPost(cfg, store, "203.0.113.89", "slider", url.Values{"captcha_id": {timedID}, "answer": {"0"}, "return_to": {"/"}})
	if hasVerifiedCookie(cfg, w) {
		t.Fatal("a wait challenge must not pass as a slider answer")
	}

	sliderID, err := cfg.sliderChallenges.issue(0)
	if err != nil {
		t.Fatal(err)
	}
	cfg.sliderChallenges.mu.Lock()
	c := cfg.sliderChallenges.challenges[sliderID]
	c.issued = time.Now().Add(-time.Hour)
	c.expires = time.Now().Add(time.Hour)
	cfg.sliderChallenges.challenges[sliderID] = c
	cfg.sliderChallenges.mu.Unlock()
	w = timedPost(cfg, store, "203.0.113.90", "slider", url.Values{"wait": {"1"}, "captcha_id": {sliderID}, "return_to": {"/"}})
	if hasVerifiedCookie(cfg, w) {
		t.Fatal("a slider challenge must not pass as a finished wait")
	}
}

func sliderPage(t *testing.T, serve func(*http.Request, bool) *httptest.ResponseRecorder, ip string) (string, string) {
	t.Helper()
	req := httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = ip + ":1234"
	body := serve(req, true).Body.String()
	m := regexp.MustCompile(`name="captcha_id" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("slider page was not served")
	}
	return m[1], body
}

func sliderImage(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`class="verifyngo-slider-img" src="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no puzzle image")
	}
	return m[1]
}

func TestSliderCheckKeepsPuzzleWithoutPenalty(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.Slider.MinSolveTime = Duration{}
	ip := "203.0.113.95"
	id, first := sliderPage(t, serve, ip)
	cfg.sliderChallenges.mu.Lock()
	answer := cfg.sliderChallenges.challenges[id].answer
	cfg.sliderChallenges.mu.Unlock()
	wrong := answer + 40
	if wrong > 1500 || answer < 60 {
		wrong = answer - 40
	}
	if wrong < 0 {
		wrong = answer + 40
	}

	miss := timedPost(cfg, store, ip, "slider", url.Values{"captcha_id": {id}, "answer": {strconv.Itoa(wrong)}, "check": {"1"}, "return_to": {"/"}})
	page := miss.Body.String()
	if hasVerifiedCookie(cfg, miss) {
		t.Fatal("a check must not verify")
	}
	if !strings.Contains(page, "Try again.") || !strings.Contains(html.UnescapeString(page), soundWrong) {
		t.Fatalf("missing miss feedback:\n%s", page)
	}
	if !strings.Contains(page, `name="captcha_id" value="`+id+`"`) || sliderImage(t, page) != sliderImage(t, first) {
		t.Fatal("a check must keep the same puzzle")
	}
	if !strings.Contains(page, `value="`+strconv.Itoa(wrong)+`"`) {
		t.Fatal("a check must keep the slider position")
	}
	if n := store.IncrWalkaway("fail:"+ip, time.Hour); n != 1 {
		t.Fatalf("a check counted as a failed attempt: %d", n)
	}

	hit := timedPost(cfg, store, ip, "slider", url.Values{"captcha_id": {id}, "answer": {strconv.Itoa(answer)}, "check": {"1"}, "return_to": {"/"}})
	page = hit.Body.String()
	if hasVerifiedCookie(cfg, hit) {
		t.Fatal("a check must not verify even when in place")
	}
	if !strings.Contains(page, "That&#39;s correct.") || !strings.Contains(html.UnescapeString(page), soundCorrect) {
		t.Fatalf("missing in-place feedback:\n%s", page)
	}

	w := timedPost(cfg, store, ip, "slider", url.Values{"captcha_id": {id}, "answer": {strconv.Itoa(answer)}, "return_to": {"/"}})
	if !hasVerifiedCookie(cfg, w) {
		t.Fatalf("Verify after a check must pass, got status %d", w.Code)
	}
}

func TestSliderCheckLimitHidesTheAnswer(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	id, _ := sliderPage(t, serve, "203.0.113.96")
	cfg.sliderChallenges.mu.Lock()
	answer := cfg.sliderChallenges.challenges[id].answer
	cfg.sliderChallenges.mu.Unlock()
	for i := 0; i < sliderCheckLimit; i++ {
		cfg.sliderChallenges.check(id, answer+1000, 0)
	}
	w := timedPost(cfg, store, "203.0.113.96", "slider", url.Values{"captcha_id": {id}, "answer": {strconv.Itoa(answer)}, "check": {"1"}, "return_to": {"/"}})
	page := w.Body.String()
	if strings.Contains(page, "correct") || strings.Contains(html.UnescapeString(page), soundCorrect) {
		t.Fatal("a check past the limit must not reveal the answer")
	}
	if strings.Contains(page, `name="check"`) {
		t.Fatal("the check button must go away at the limit")
	}
}

func TestSliderCheckRejectsWaitChallenge(t *testing.T) {
	cfg, _, _ := testServer(t, testConfig)
	id, err := cfg.sliderChallenges.issueTimed()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sliderChallenges.check(id, 0, 8) != nil {
		t.Fatal("a wait challenge must not answer slider checks")
	}
}

func TestSliderSeedRebuildsSamePuzzle(t *testing.T) {
	cfg, _, _ := testServer(t, testConfig)
	a, err := buildSliderChallenge(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildSliderFromSeed(cfg, a.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if a.BgDataURI != b.BgDataURI || a.PieceDataURI != b.PieceDataURI || a.Answer != b.Answer {
		t.Fatal("the same seed must draw the same puzzle")
	}
}

func TestTrapIsHiddenWithoutInlineStyles(t *testing.T) {
	_, _, serve := testServer(t, testConfig)
	req := httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = "203.0.113.97:1234"
	body := serve(req, true).Body.String()
	if !strings.Contains(body, `<div hidden aria-hidden="true"><a href="/__cp_trap"`) {
		t.Fatal("the trap must use the hidden attribute, which a CSP cannot block")
	}
	if strings.Contains(body, `style="display:none`) {
		t.Fatal("inline styles are blocked by the challenge CSP")
	}
}

func TestTrapDoesNotBanBrowsers(t *testing.T) {
	_, store, serve := testServer(t, testConfig)
	for _, site := range []string{"none", "same-origin", "same-site", "cross-site"} {
		req := httptest.NewRequest("GET", "/__cp_trap", nil)
		req.RemoteAddr = "198.51.100.98:5555"
		req.Header.Set("Sec-Fetch-Site", site)
		if w := serve(req, true); w.Code != http.StatusNotFound {
			t.Errorf("Sec-Fetch-Site %s: status %d, want 404", site, w.Code)
		}
		if store.IsBlocked("198.51.100.98") {
			t.Fatalf("Sec-Fetch-Site %s: a browser must not be banned", site)
		}
	}
}

func TestSwitchingOptionsDoesNotBan(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	ip := "203.0.113.98"
	load := func(switched bool) string {
		req := httptest.NewRequest("GET", "/page", nil)
		req.RemoteAddr = ip + ":1234"
		if switched {
			req.AddCookie(&http.Cookie{Name: switchCookie, Value: "1"})
		}
		return serve(req, true).Header().Get("X-Test-Decision")
	}
	for i := 0; i < switchAllowance; i++ {
		if d := load(true); d != "challenge" {
			t.Fatalf("switch %d: decision %q", i, d)
		}
	}
	if store.IsBlocked(ip) {
		t.Fatal("switching options must not ban")
	}
	if n := store.IncrWalkaway(ip, time.Hour); n != 1 {
		t.Fatalf("switching added %d walk-aways", n-1)
	}
	for i := 0; i < cfg.Walkaway.Threshold+1; i++ {
		load(true)
	}
	if !store.IsBlocked(ip) {
		t.Fatal("the allowance must run out so the cookie cannot dodge walk-aways forever")
	}
}

func jigsawPage(t *testing.T, cfg *Config, serve func(*http.Request, bool) *httptest.ResponseRecorder, ip string) (string, string, int, int) {
	t.Helper()
	req := httptest.NewRequest("GET", "/page", nil)
	req.RemoteAddr = ip + ":1234"
	req.AddCookie(&http.Cookie{Name: "cp_provider", Value: "jigsaw"})
	body := serve(req, true).Body.String()
	if !strings.Contains(body, `id="jigsaw-form"`) {
		t.Fatal("tile puzzle was not served")
	}
	id := regexp.MustCompile(`name="captcha_id" value="([0-9a-f]+)"`).FindStringSubmatch(body)[1]
	cfg.sliderChallenges.mu.Lock()
	answer := cfg.sliderChallenges.challenges[id].answer
	cfg.sliderChallenges.mu.Unlock()
	return id, body, answer / 9, answer % 9
}

func TestJigsawPageAndAnswer(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	cfg.Slider.MinSolveTime = Duration{}
	ip := "203.0.113.101"
	id, body, a, b := jigsawPage(t, cfg, serve, ip)
	if strings.Count(body, `name="tile"`) != 9 || !strings.Contains(body, "Row 3, column 3") {
		t.Fatal("expected nine labeled tiles")
	}
	if strings.Contains(html.UnescapeString(body), soundCorrect) || strings.Contains(html.UnescapeString(body), soundWrong) {
		t.Fatal("a fresh puzzle must not play a sound")
	}
	w := timedPost(cfg, store, ip, "jigsaw", url.Values{"captcha_id": {id}, "tile": {strconv.Itoa(b), strconv.Itoa(a)}, "return_to": {"/"}})
	if !hasVerifiedCookie(cfg, w) {
		t.Fatalf("the right tiles in either order must verify, got status %d", w.Code)
	}
	w = timedPost(cfg, store, ip, "jigsaw", url.Values{"captcha_id": {id}, "tile": {strconv.Itoa(a), strconv.Itoa(b)}, "return_to": {"/"}})
	if hasVerifiedCookie(cfg, w) {
		t.Fatal("a solved puzzle must not be reusable")
	}
}

func TestJigsawWrongAnswerPlaysSoundAndCounts(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	cfg.Slider.MinSolveTime = Duration{}
	ip := "203.0.113.102"
	id, _, a, b := jigsawPage(t, cfg, serve, ip)
	wrong := 0
	for wrong == a || wrong == b {
		wrong++
	}
	w := timedPost(cfg, store, ip, "jigsaw", url.Values{"captcha_id": {id}, "tile": {strconv.Itoa(a), strconv.Itoa(wrong)}, "return_to": {"/"}})
	page := w.Body.String()
	if hasVerifiedCookie(cfg, w) || !strings.Contains(page, "Try again.") || !strings.Contains(html.UnescapeString(page), soundWrong) {
		t.Fatal("a wrong pair must fail with feedback and the wrong sound")
	}
	if strings.Contains(page, `value="`+id+`"`) {
		t.Fatal("a wrong pair must get a new puzzle")
	}
	if n := store.IncrWalkaway("fail:"+ip, time.Hour); n != 2 {
		t.Fatalf("failed attempts = %d, want 2", n)
	}
}

func TestJigsawNeedsTwoTilesWithoutPenalty(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	ip := "203.0.113.103"
	id, first, _, _ := jigsawPage(t, cfg, serve, ip)
	image := regexp.MustCompile(`<img src="(data:image/png[^"]+)" alt="Picture cut`)
	w := timedPost(cfg, store, ip, "jigsaw", url.Values{"captcha_id": {id}, "tile": {"4"}, "return_to": {"/"}})
	page := w.Body.String()
	if !strings.Contains(page, "Select two tiles.") || !strings.Contains(page, `value="`+id+`"`) {
		t.Fatal("one tile must keep the puzzle and explain")
	}
	if image.FindStringSubmatch(page)[1] != image.FindStringSubmatch(first)[1] {
		t.Fatal("one tile must keep the same picture")
	}
	if !strings.Contains(page, `value="4" checked`) {
		t.Fatal("one tile must keep the selection")
	}
	if strings.Contains(html.UnescapeString(page), soundWrong) {
		t.Fatal("a missing selection is not a wrong answer")
	}
	if n := store.IncrWalkaway("fail:"+ip, time.Hour); n != 1 {
		t.Fatalf("a missing selection counted as a failure: %d", n)
	}
	for _, tiles := range [][]string{{"4", "4"}, {"4", "9"}, {"-1", "4"}, {"x", "4"}, {"1", "2", "3"}} {
		w := timedPost(cfg, store, ip, "jigsaw", url.Values{"captcha_id": {id}, "tile": tiles, "return_to": {"/"}})
		if hasVerifiedCookie(cfg, w) || !strings.Contains(w.Body.String(), "Select two tiles.") {
			t.Errorf("tiles %v must be rejected", tiles)
		}
	}
}

func TestChallengeKindsAreSeparate(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	cfg.Slider.Enabled = true
	cfg.Slider.MinSolveTime = Duration{}
	jigsawID, _ := cfg.sliderChallenges.issueJigsaw(0, 1, 7)
	if w := timedPost(cfg, store, "203.0.113.104", "slider", url.Values{"captcha_id": {jigsawID}, "answer": {"1"}, "return_to": {"/"}}); hasVerifiedCookie(cfg, w) {
		t.Fatal("a tile puzzle must not pass as a slider answer")
	}
	jigsawID, _ = cfg.sliderChallenges.issueJigsaw(0, 1, 7)
	if cfg.sliderChallenges.check(jigsawID, 1, 8) != nil {
		t.Fatal("a tile puzzle must not answer slider checks")
	}
	if w := timedPost(cfg, store, "203.0.113.105", "slider", url.Values{"wait": {"1"}, "captcha_id": {jigsawID}, "return_to": {"/"}}); hasVerifiedCookie(cfg, w) {
		t.Fatal("a tile puzzle must not pass as a wait")
	}
	for name, id := range map[string]func() (string, error){
		"slider": func() (string, error) { return cfg.sliderChallenges.issue(1) },
		"wait":   cfg.sliderChallenges.issueTimed,
	} {
		got, _ := id()
		if w := timedPost(cfg, store, "203.0.113.106", "jigsaw", url.Values{"captcha_id": {got}, "tile": {"0", "1"}, "return_to": {"/"}}); hasVerifiedCookie(cfg, w) {
			t.Fatalf("a %s challenge must not pass as a tile puzzle", name)
		}
	}
}

func TestJigsawSeedAndSwap(t *testing.T) {
	a, err := buildJigsawChallenge()
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildJigsawFromSeed(a.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if a.ImageURI != b.ImageURI || a.A != b.A || a.B != b.B {
		t.Fatal("the same seed must draw the same puzzle")
	}
	if a.A == a.B || a.A < 0 || a.B > 8 || a.A > 8 || a.B < 0 {
		t.Fatalf("bad swap %d, %d", a.A, a.B)
	}
}

func TestTroubleWaitsForAMinuteOrAttempts(t *testing.T) {
	cfg, store, serve := testServer(t, testConfig)
	ip := "203.0.113.110"
	load := func() string {
		req := httptest.NewRequest("GET", "/page", nil)
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		return serve(req, true).Body.String()
	}
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/favicon.ico", nil)
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("Accept", "image/avif,image/webp,*/*")
		serve(req, true)
	}
	for i := 1; i < troubleAttempts; i++ {
		if body := load(); !strings.Contains(body, "verifyngo-trouble-delayed\"") {
			t.Fatalf("load %d: trouble section must wait", i)
		}
	}
	if body := load(); strings.Contains(body, "verifyngo-trouble-delayed\"") || !strings.Contains(body, "Having trouble?") {
		t.Fatal("repeated attempts must show the trouble section right away")
	}
	req := httptest.NewRequest("GET", "/page", nil)
	resetWalkaways(store, req, cfg, net.ParseIP(ip))
	if n := troubleAttemptCount(store, net.ParseIP(ip)); n != 0 {
		t.Fatalf("solving must clear the attempts, got %d", n)
	}
}

func TestWaitIsDeniedUntilEligible(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	ip := "203.0.113.111"
	req := httptest.NewRequest("POST", "/__verify", nil)
	req.RemoteAddr = ip + ":1234"
	expired := troubleTokenAt(req, cfg, time.Now().Add(-troubleTokenMaxAge-time.Minute))
	young := troubleTokenAt(req, cfg, time.Now().Add(-troubleDelay/2))
	other := httptest.NewRequest("POST", "/__verify", nil)
	other.RemoteAddr = ip + ":1234"
	other.Header.Set("User-Agent", "other")
	for name, form := range map[string]url.Values{
		"no token":    {"wait": {"1"}, "return_to": {"/"}},
		"too young":   {"wait": {"1"}, "trouble": {young}, "return_to": {"/"}},
		"too old":     {"wait": {"1"}, "trouble": {expired}, "return_to": {"/"}},
		"forged":      {"wait": {"1"}, "trouble": {"1.deadbeef"}, "return_to": {"/"}},
		"other agent": {"wait": {"1"}, "trouble": {troubleTokenAt(other, cfg, time.Now().Add(-2*troubleDelay))}, "return_to": {"/"}},
		"unknown id":  {"wait": {"1"}, "captcha_id": {"nope"}, "return_to": {"/"}},
	} {
		page := rawWaitPost(cfg, store, ip, "slider", form).Body.String()
		if strings.Contains(page, `id="timed-form"`) {
			t.Errorf("%s: must not start a wait", name)
		}
		if !strings.Contains(page, "Try this check first.") {
			t.Errorf("%s: must explain", name)
		}
	}
	if n := len(cfg.sliderChallenges.challenges); n == 0 {
		t.Fatal("expected the normal puzzle to be issued")
	}
	cfg.sliderChallenges.mu.Lock()
	for id, c := range cfg.sliderChallenges.challenges {
		if c.timed {
			t.Errorf("denied requests issued a wait challenge %s", id)
		}
	}
	cfg.sliderChallenges.mu.Unlock()

	page := rawWaitPost(cfg, store, ip, "slider", url.Values{"wait": {"1"}, "trouble": {agedTroubleToken(cfg, ip)}, "return_to": {"/"}}).Body.String()
	if !strings.Contains(page, `id="timed-form"`) {
		t.Fatal("a token older than the delay must start the wait")
	}
}

func TestWaitAllowedAfterAttempts(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	ip := "203.0.113.112"
	for i := 0; i < troubleAttempts; i++ {
		store.IncrWalkaway("fail:"+ip, time.Hour)
	}
	page := rawWaitPost(cfg, store, ip, "slider", url.Values{"wait": {"1"}, "return_to": {"/"}}).Body.String()
	if !strings.Contains(page, `id="timed-form"`) {
		t.Fatal("repeated failures must allow the wait without the minute")
	}
}

func TestWaitThrottleDoesNotIssueAWait(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	ip := "203.0.113.113"
	for i := 0; i < sliderVerifyMaxPerMin+3; i++ {
		rawWaitPost(cfg, store, ip, "slider", url.Values{"wait": {"1"}, "return_to": {"/"}})
	}
	cfg.sliderChallenges.mu.Lock()
	defer cfg.sliderChallenges.mu.Unlock()
	for id, c := range cfg.sliderChallenges.challenges {
		if c.timed {
			t.Fatalf("a throttled request issued a wait challenge %s", id)
		}
	}
}

func TestWaitGetWithoutValidChallengeRedirects(t *testing.T) {
	cfg, store, _ := testServer(t, testConfig)
	for _, target := range []string{"/__wait?return_to=/page", "/__wait?captcha_id=nope&return_to=/page"} {
		w := waitGet(cfg, store, "203.0.113.114", target)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/page" {
			t.Errorf("%s: status %d location %q", target, w.Code, w.Header().Get("Location"))
		}
	}
	if store.IsBlocked("203.0.113.114") {
		t.Fatal("must not ban")
	}
}

func TestCSSWafTrapBansScraper(t *testing.T) {
	_, store, serve := testServer(t, testConfig)
	scraperIP := "198.51.100.99"
	req := httptest.NewRequest("GET", "/__cp_trap", nil)
	req.RemoteAddr = scraperIP + ":5555"

	w := serve(req, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected /__cp_trap to return 403, got %d", w.Code)
	}
	if !store.IsBlocked(scraperIP) {
		t.Fatalf("expected scraper IP %s to be blocked after hitting trap", scraperIP)
	}
}

func TestSliderAccessibleMarkupAndAlert(t *testing.T) {
	cfg := &Config{Provider: "slider"}
	cfg.Slider.Enabled = true
	cfg.Slider.Width = 320
	cfg.Slider.Height = 120
	cfg.sliderChallenges = newSliderChallengeStore(time.Minute, 100)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	serveChallenge(w, req, cfg, "", "203.0.113.1", "/test", "Incorrect answer, please try again.", false)
	body := w.Body.String()

	if !strings.Contains(body, `role="alert"`) || !strings.Contains(body, "Incorrect answer, please try again.") {
		t.Error("challenge page missing role='alert' error message")
	}
	if !strings.Contains(body, `aria-label="Puzzle piece position"`) {
		t.Error("slider input missing aria-label")
	}
	if !strings.Contains(body, `aria-describedby="slider-desc"`) {
		t.Error("slider input missing aria-describedby")
	}
	if !strings.Contains(body, `id="slider-desc"`) {
		t.Error("slider instructions missing id for aria-describedby")
	}
	idxDesc := strings.Index(body, `id="slider-desc"`)
	idxInput := strings.Index(body, `id="slider-input"`)
	if idxDesc < 0 || idxInput < 0 || idxDesc > idxInput {
		t.Error("slider description must precede slider input in DOM order")
	}
}
