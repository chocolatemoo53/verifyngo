package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
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
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	store := newMemoryStore("", 0)
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
