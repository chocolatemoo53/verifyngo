package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func watchRulesSource(cfg *Config, box *atomic.Value) {
	source := cfg.PolicyFile
	if source == "" {
		source = cfg.RulesFile
	}
	if source == "" {
		return
	}

	var lastMod time.Time
	if fi, err := os.Stat(source); err == nil {
		lastMod = fi.ModTime()
	}
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		fi, err := os.Stat(source)
		if err != nil {
			log.Printf("rules watch: %v", err)
			continue
		}
		if !fi.ModTime().After(lastMod) {
			continue
		}
		compiled, err := loadCompiledRules(cfg)
		if err != nil {
			log.Printf("rules watch: not reloading, parse/compile error: %v", err)
			continue
		}
		box.Store(compiled)
		lastMod = fi.ModTime()
		log.Printf("reloaded policy/rules from %s", source)
	}
}

// clientIP returns the client IP and whether it was resolved from an
// X-Forwarded-For header (true) or fell back to the connecting IP (false).
// When trust_real_ip is enabled and the connecting IP is a trusted proxy but
// no XFF header is present (e.g. Tor hidden service), resolved is false — the
// caller should skip walkaway/ban tracking for such requests since the real
// client IP is unknown.
func clientIP(r *http.Request, cfg *Config) (net.IP, bool) {
	connectingIP := func() net.IP {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return net.ParseIP(r.RemoteAddr)
		}
		return net.ParseIP(host)
	}()

	if !cfg.TrustRealIP {
		return connectingIP, true
	}

	if !cfg.compiledTrustedProxies.contains(connectingIP) {
		return connectingIP, true
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			parsed := net.ParseIP(strings.TrimSpace(parts[i]))
			if parsed == nil {
				continue
			}
			if i > 0 && cfg.compiledTrustedProxies.contains(parsed) {
				continue
			}
			return parsed, true
		}
	}
	// Trusted proxy but no XFF — real IP unknown (e.g. Tor hidden service).
	return connectingIP, false
}

func stripQuery(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

func sanitizeForLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func anonymizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.Mask(net.CIDRMask(24, 32))
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil
	}
	return ip16.Mask(net.CIDRMask(48, 128))
}

func logIP(cfg *Config, ip net.IP) string {
	if ip == nil {
		return "<nil>"
	}
	if cfg.Anonymize() {
		return anonymizeIP(ip).String()
	}
	return ip.String()
}

func logIPString(cfg *Config, s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return sanitizeForLog(s)
	}
	return logIP(cfg, ip)
}

func compileRegexList(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, re)
	}
	return out, nil
}

func pathMatchesAny(path string, patterns []*regexp.Regexp) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

var defaultBypassPaths = []string{
	`^/favicon\.ico$`,
	`^/robots\.txt$`,
	`^/sitemap\.xml$`,
	`^/\.well-known/`,
	`^/(?:manifest\.json|site\.webmanifest|manifest\.webmanifest)$`,
	`\.webmanifest$`,
	`^/browserconfig\.xml$`,
	`^/apple-touch-icon(?:-precomposed)?(?:-\d+x\d+)?\.png$`,
	`\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|wasm|mp4|webm)$`,
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	compiled, err := loadCompiledRules(cfg)
	if err != nil {
		log.Fatalf("rules: %v", err)
	}
	rulesBox := &atomic.Value{}
	rulesBox.Store(compiled)

	if cfg.RulesFile != "" || cfg.PolicyFile != "" {
		go watchRulesSource(cfg, rulesBox)
	}
	store := newStore(cfg)

	cfg.sliderChallenges = newSliderChallengeStore(cfg.Slider.TTL.Duration, cfg.Slider.MaxChallenges)

	var blacklistBox *atomic.Value
	if cfg.AbuseIPDB.Blacklist.Enabled {
		if cfg.AbuseIPDB.APIKey == "" {
			log.Fatal("abuseipdb.blacklist is enabled but abuseipdb.api_key is empty")
		}
		blacklistBox = &atomic.Value{}
		go startBlacklistFetcher(cfg, blacklistBox)
	}

	passivePaths, err := compileRegexList(cfg.Progressive.PassivePaths)
	if err != nil {
		log.Fatalf("progressive.passive_paths: %v", err)
	}

	bypassPaths, err := compileRegexList(cfg.BypassPaths)
	if err != nil {
		log.Fatalf("bypass_paths: %v", err)
	}

	alwaysPassPaths, err := compileRegexList(cfg.AlwaysPassPaths)
	if err != nil {
		log.Fatalf("always_pass_paths: %v", err)
	}

	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("upstream_url: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("X-Content-Type-Options", "nosniff")
		resp.Header.Set("X-Frame-Options", "DENY")
		resp.Header.Set("Referrer-Policy", "no-referrer")
		if cfg.ResponseCSP != "" && resp.Header.Get("Content-Security-Policy") == "" {
			resp.Header.Set("Content-Security-Policy", cfg.ResponseCSP)
		}
		return nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/__verify", func(w http.ResponseWriter, r *http.Request) {
		handleVerify(w, r, cfg, store)
	})

	mux.HandleFunc("/__set_provider", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p := q.Get("provider")
		returnTo := sanitizeReturnPath(q.Get("return_to"))
		valid := false
		for _, a := range availableProviders(cfg) {
			if a == p {
				valid = true
				break
			}
		}
		if !valid {
			http.Redirect(w, r, returnTo, http.StatusFound)
			return
		}
		expiry := time.Now().Add(30 * 24 * time.Hour)

		http.SetCookie(w, newCookie(
			r,
			cfg,
			"cp_provider",
			p,
			expiry,
		))
		http.Redirect(w, r, returnTo, http.StatusFound)
	})

	if cfg.StaticDir != "" {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(cfg.StaticDir))))
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleRequest(w, r, cfg, rulesBox.Load().([]compiledRule), passivePaths, bypassPaths, alwaysPassPaths, store, blacklistBox, proxy)
	})

	log.Printf("listening on %s, proxying to %s (provider=%s)", cfg.ListenAddr, cfg.UpstreamURL, cfg.Provider)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *Config, rules []compiledRule, passivePaths []*regexp.Regexp, bypassPaths []*regexp.Regexp, alwaysPassPaths []*regexp.Regexp, store Store, blacklist *atomic.Value, proxy *httputil.ReverseProxy) {
	ip, resolved := clientIP(r, cfg)
	if ip == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ipStr := ip.String()

	if ipAllowlisted(cfg, ip) {
		proxy.ServeHTTP(w, r)
		return
	}

	if pathMatchesAny(r.URL.Path, alwaysPassPaths) {
		proxy.ServeHTTP(w, r)
		return
	}

	if hasValidCookie(r, cfg) {
		proxy.ServeHTTP(w, r)
		return
	}

	if pathMatchesAny(r.URL.Path, bypassPaths) {
		proxy.ServeHTTP(w, r)
		return
	}

	if store.IsBlocked(ipStr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if blacklist != nil {
		if trie, ok := blacklist.Load().(*ipTrie); ok && trie != nil && trie.Contains(ip) {
			log.Printf("denied %s: on AbuseIPDB blacklist", logIP(cfg, ip))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	action := evaluate(rules, cfg.DefaultAction, r, ip)
	switch action {
	case "allow":
		proxy.ServeHTTP(w, r)
		return
	case "deny":
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	case "tarpit":
		serveTarpit(w, r, cfg)
		return
	}

	if cfg.Progressive.Enabled {
		if pathMatchesAny(r.URL.Path, passivePaths) {
			if pc, err := r.Cookie(cfg.CookieName + "_passive"); err == nil && pc.Value != "" {
				passiveCount := store.IncrPassiveCount(pc.Value, cfg.Progressive.RequestWindow.Duration)
				if passiveCount > cfg.Progressive.MaxRequests {
					cookiePrefix := pc.Value
					if len(cookiePrefix) > 8 {
						cookiePrefix = cookiePrefix[:8]
					}
					log.Printf("passive rate limit hit cookie=%s... count=%d max=%d", sanitizeForLog(cookiePrefix), passiveCount, cfg.Progressive.MaxRequests)
				} else {
					proxy.ServeHTTP(w, r)
					return
				}
			} else {
				setPassiveCookie(w, r, cfg)
				proxy.ServeHTTP(w, r)
				return
			}
		}
	}

	// When the connecting IP is a trusted proxy but no X-Forwarded-For was
	// present (e.g. Tor hidden service), the real client IP is unknown.
	// Skip walkaway/ban tracking to avoid banning the proxy IP and blocking
	// all traffic through that proxy.  The challenge is still served so the
	// user must solve the captcha and receive a cookie.
	if !resolved {
		requestURI := r.URL.RequestURI()
		log.Printf("unresolved proxy %s: serving challenge without walkaway tracking (%s)", logIP(cfg, ip), sanitizeForLog(stripQuery(requestURI)))
		serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), stripQuery(requestURI), true)
		return
	}

	requestURI := r.URL.RequestURI()
	count := store.IncrWalkaway(ipStr, cfg.Walkaway.TTL.Duration)
	store.LogPath(ipStr, stripQuery(requestURI))
	if count >= cfg.Walkaway.Threshold {
		store.Block(ipStr, cfg.Ban.Duration.Duration)
		banCount := store.IncrBanCount(ipStr)
		paths := store.RecentPaths(ipStr)
		log.Printf("banned %s after %d walk-aways (ban #%d); recent paths: %v", logIP(cfg, ip), count, banCount, sanitizeForLog(fmt.Sprint(paths)))
		if banCount >= cfg.AbuseIPDB.ReportAfterBans && store.ShouldReport(ipStr, 15*time.Minute) {
			reportIP(cfg, ipStr, count, banCount, paths)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), stripQuery(requestURI), count == 1)
}

func handleVerify(w http.ResponseWriter, r *http.Request, cfg *Config, store Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	ip, _ := clientIP(r, cfg)
	ipStr := ip.String()
	returnTo := sanitizeReturnPath(r.FormValue("return_to"))

	provider := providerForRequest(cfg, r)

	log.Printf("verify start ip=%s provider=%s return_to=%s token_len=%d", logIP(cfg, ip), provider, sanitizeForLog(returnTo), len(token))

	if provider == "slider" {
		handleSliderVerify(w, r, cfg, store, ipStr, returnTo)
		return
	}

	verifier := buildVerifierForProvider(cfg, provider)

	ok, err := verifier.Verify(token, ipStr)
	if err != nil {
		log.Printf("verify error ip=%s provider=%s err=%v", logIP(cfg, ip), provider, err)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	if !ok {
		log.Printf("verify failed ip=%s provider=%s", logIP(cfg, ip), provider)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	log.Printf("verify success ip=%s provider=%s: issuing verified cookie (cookie_name=%s secure=%v)", logIP(cfg, ip), provider, cfg.CookieName, isSecureRequest(r, cfg))

	store.ResetWalkaway(ipStr)
	setVerifiedCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	log.Printf("redirecting ip=%s to %s", logIP(cfg, ip), sanitizeForLog(returnTo))
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func handleSliderVerify(w http.ResponseWriter, r *http.Request, cfg *Config, store Store, ip, returnTo string) {
	captchaID := r.FormValue("captcha_id")
	answerStr := r.FormValue("answer")
	answer, err := strconv.Atoi(answerStr)
	if err != nil || answer < 0 || answer > 1500 {
		log.Printf("slider verify failed ip=%s id=%v answer=%q", logIPString(cfg, ip), captchaID, sanitizeForLog(answerStr))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	if !cfg.sliderChallenges.allowAttempt(ip, sliderVerifyWindow, sliderVerifyMaxPerMin) {
		log.Printf("slider verify throttled ip=%s", logIPString(cfg, ip))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	res := cfg.sliderChallenges.consume(captchaID, answer, cfg.Slider.Tolerance, cfg.Slider.MinSolveTime.Duration)
	lowVariance := cfg.sliderChallenges.recordAnswer(ip, answer, sliderAnswerSamples, cfg.Slider.Tolerance, sliderAnswerWindow)

	if res.tooFast {
		store.IncrWalkaway(ip, cfg.Walkaway.TTL.Duration)
		log.Printf("slider verify too fast ip=%s", logIPString(cfg, ip))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	if !res.ok {
		log.Printf("slider verify failed ip=%s id=%v answer=%d", logIPString(cfg, ip), captchaID, answer)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	if lowVariance {
		store.IncrWalkaway(ip, cfg.Walkaway.TTL.Duration)
		log.Printf("slider verify suspicious (repeated answers) ip=%s", logIPString(cfg, ip))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	log.Printf("verify success ip=%s provider=slider: issuing verified cookie (cookie_name=%s secure=%v)", logIPString(cfg, ip), cfg.CookieName, isSecureRequest(r, cfg))
	store.ResetWalkaway(ip)
	setVerifiedCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	log.Printf("redirecting ip=%s to %s", logIPString(cfg, ip), sanitizeForLog(returnTo))
	http.Redirect(w, r, returnTo, http.StatusFound)
}
