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
			metricRuleReloads.WithLabelValues("error").Inc()
			log.Printf("rules watch: not reloading, parse/compile error: %v", err)
			continue
		}
		metricRuleReloads.WithLabelValues("ok").Inc()
		box.Store(compiled)
		lastMod = fi.ModTime()
		log.Printf("reloaded policy/rules from %s", source)
	}
}

func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

func clientIP(r *http.Request, cfg *Config) (net.IP, bool) {
	connectingIP := peerIP(r)

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
	return connectingIP, false
}

var tlsFingerprintRe = regexp.MustCompile(`^[tqd][0-9a-zA-Z]{9}_[0-9a-f]{12}_[0-9a-f]{12}(_([0-9a-f]{12})?)?$`)

func clientFingerprint(r *http.Request, cfg *Config) (string, bool) {
	if !cfg.TrustFingerprintHeaders || !cfg.compiledTrustedProxies.contains(peerIP(r)) {
		return "", false
	}
	if fp := r.Header.Get("X-TLSFP"); tlsFingerprintRe.MatchString(fp) {
		return "tlsfp:" + fp, true
	}
	if fp := r.Header.Get("X-JA4"); tlsFingerprintRe.MatchString(fp) {
		return "ja4:" + fp, true
	}
	return "", false
}

func fingerprintKey(r *http.Request, cfg *Config, ip net.IP) (string, string, bool) {
	fp, ok := clientFingerprint(r, cfg)
	if !ok {
		return "", "", false
	}
	return "fp:" + fp + "|" + clientNetwork(ip), fp, true
}

const (
	failedAttemptFactor = 3
	torAttemptFactor    = 5
)

func resetWalkaways(store Store, r *http.Request, cfg *Config, ip net.IP) {
	store.ResetWalkaway(ip.String())
	store.ResetWalkaway("fail:" + ip.String())
	if key, _, ok := fingerprintKey(r, cfg, ip); ok {
		store.ResetWalkaway(key)
	}
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
	rulesBox := &atomic.Value{}
	go func() {
		compiled, err := loadCompiledRules(cfg)
		if err != nil {
			metricRuleReloads.WithLabelValues("error").Inc()
			log.Printf("rules: %v; applying default_action until the rules are fixed", err)
		} else {
			metricRuleReloads.WithLabelValues("ok").Inc()
		}
		rulesBox.Store(compiled)
		metricRulesLoaded.Set(1)
		log.Printf("rules loaded, checks active")
		if cfg.RulesFile != "" || cfg.PolicyFile != "" {
			watchRulesSource(cfg, rulesBox)
		}
	}()
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

	upstreamURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("upstream_url: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		metricUpstream.WithLabelValues(strconv.Itoa(resp.StatusCode/100) + "xx").Inc()
		resp.Header.Set("X-Content-Type-Options", "nosniff")
		resp.Header.Set("X-Frame-Options", "DENY")
		resp.Header.Set("Referrer-Policy", "no-referrer")
		if cfg.ResponseCSP != "" && resp.Header.Get("Content-Security-Policy") == "" {
			resp.Header.Set("Content-Security-Policy", cfg.ResponseCSP)
		}
		return nil
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		metricUpstream.WithLabelValues("error").Inc()
		log.Printf("upstream error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
	}

	upstream := withoutDeadlines(proxy)

	if cfg.MetricsAddr != "" {
		go serveMetrics(cfg.MetricsAddr)
	}
	if cfg.Tor.ExitList {
		go startTorExitFetcher(cfg)
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
		mux.Handle("/__static/", http.StripPrefix("/__static/", http.FileServer(http.Dir(cfg.StaticDir))))
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rules, loaded := rulesBox.Load().([]compiledRule)
		metricDecisions.WithLabelValues(handleRequest(w, r, cfg, rules, loaded, passivePaths, bypassPaths, alwaysPassPaths, store, blacklistBox, upstream)).Inc()
	})

	log.Printf("listening on %s, proxying to %s (provider=%s)", cfg.ListenAddr, cfg.UpstreamURL, cfg.Provider)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func withoutDeadlines(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Time{})
		rc.SetWriteDeadline(time.Time{})
		next.ServeHTTP(w, r)
	})
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *Config, rules []compiledRule, loaded bool, passivePaths []*regexp.Regexp, bypassPaths []*regexp.Regexp, alwaysPassPaths []*regexp.Regexp, store Store, blacklist *atomic.Value, proxy http.Handler) string {
	ip, resolved := clientIP(r, cfg)
	if ip == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return "bad_request"
	}
	ipStr := ip.String()
	tor := torKind(r, cfg, ip)
	shared := sharedTorIP(tor, ip)
	if tor != "" {
		metricTor.WithLabelValues(tor).Inc()
	}

	if ipAllowlisted(cfg, ip) {
		proxy.ServeHTTP(w, r)
		return "allowlisted"
	}

	if pathMatchesAny(r.URL.Path, alwaysPassPaths) {
		proxy.ServeHTTP(w, r)
		return "always_pass"
	}

	if hasValidCookie(r, cfg) {
		proxy.ServeHTTP(w, r)
		return "verified"
	}

	if pathMatchesAny(r.URL.Path, bypassPaths) {
		proxy.ServeHTTP(w, r)
		return "bypass"
	}

	if !shared && store.IsBlocked(ipStr) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return "banned"
	}

	if blacklist != nil && tor == "" {
		if trie, ok := blacklist.Load().(*ipTrie); ok && trie != nil && trie.Contains(ip) {
			log.Printf("denied %s: on AbuseIPDB blacklist", logIP(cfg, ip))
			http.Error(w, "forbidden", http.StatusForbidden)
			return "blocklist"
		}
	}

	if !loaded {
		proxy.ServeHTTP(w, r)
		return "rules_loading"
	}
	action, rule := evaluate(rules, cfg.DefaultAction, r, ip)
	metricRuleHits.WithLabelValues(rule, action).Inc()
	switch action {
	case "allow":
		proxy.ServeHTTP(w, r)
		return "allow"
	case "deny":
		http.Error(w, "forbidden", http.StatusForbidden)
		return "deny"
	case "tarpit":
		serveTarpit(w, r, cfg)
		return "tarpit"
	}

	if cfg.Progressive.Enabled && tor == "" && pathMatchesAny(r.URL.Path, passivePaths) {
		pc, err := r.Cookie(cfg.CookieName + "_passive")
		mismatch := browserMismatch(r, cfg)
		switch {
		case mismatch != "":
			metricBrowserMismatch.WithLabelValues(mismatch).Inc()
			metricPassive.WithLabelValues("mismatch").Inc()
			log.Printf("browser mismatch ip=%s kind=%s: no passive pass", logIP(cfg, ip), mismatch)
		case err == nil && validCookieValue(r, cfg, pc.Value, cookieScopePassive):
			passiveCount := store.IncrPassiveCount(pc.Value, cfg.Progressive.RequestWindow.Duration)
			if passiveCount <= cfg.Progressive.MaxRequests {
				metricPassive.WithLabelValues("pass").Inc()
				proxy.ServeHTTP(w, r)
				return "passive"
			}
			metricPassive.WithLabelValues("budget_exhausted").Inc()
			cookiePrefix := pc.Value
			if len(cookiePrefix) > 8 {
				cookiePrefix = cookiePrefix[:8]
			}
			log.Printf("passive rate limit hit cookie=%s... count=%d max=%d", sanitizeForLog(cookiePrefix), passiveCount, cfg.Progressive.MaxRequests)
		case store.IncrPassiveCount("net:"+clientNetwork(ip), cfg.Progressive.RequestWindow.Duration) <= cfg.Progressive.MaxRequests:
			metricPassive.WithLabelValues("new").Inc()
			setPassiveCookie(w, r, cfg)
			proxy.ServeHTTP(w, r)
			return "passive"
		default:
			metricPassive.WithLabelValues("network_limit").Inc()
			log.Printf("passive cookie limit hit ip=%s: too many new passive cookies from this network", logIP(cfg, ip))
		}
	}

	if !resolved {
		requestURI := r.URL.RequestURI()
		log.Printf("unresolved proxy %s: serving challenge without walkaway tracking (%s)", logIP(cfg, ip), sanitizeForLog(stripQuery(requestURI)))
		serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), requestURI, true)
		return "challenge"
	}

	requestURI := r.URL.RequestURI()
	if shared {
		serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), requestURI, false)
		return "challenge"
	}
	if fpKey, fp, ok := fingerprintKey(r, cfg, ip); ok {
		if store.IsBlocked(fpKey) {
			log.Printf("denied %s: fingerprint %s is blocked", logIP(cfg, ip), sanitizeForLog(fp))
			http.Error(w, "forbidden", http.StatusForbidden)
			return "banned"
		}
		fpCount := store.IncrWalkaway(fpKey, cfg.Walkaway.TTL.Duration)
		if fpCount >= cfg.Walkaway.Threshold {
			store.Block(fpKey, cfg.Ban.Duration.Duration)
			metricBans.WithLabelValues("fingerprint").Inc()
			log.Printf("banned fingerprint %s after %d walk-aways (ip=%s)", sanitizeForLog(fp), fpCount, logIP(cfg, ip))
			http.Error(w, "forbidden", http.StatusForbidden)
			return "banned"
		}
	}

	count := store.IncrWalkaway(ipStr, cfg.Walkaway.TTL.Duration)
	store.LogPath(ipStr, stripQuery(requestURI))
	if count >= cfg.Walkaway.Threshold {
		banClient(cfg, store, ip, count, "walk-aways")
		http.Error(w, "forbidden", http.StatusForbidden)
		return "banned"
	}
	serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), requestURI, count == 1)
	return "challenge"
}

func banClient(cfg *Config, store Store, ip net.IP, count int, reason string) {
	ipStr := ip.String()
	store.Block(ipStr, cfg.Ban.Duration.Duration)
	metricBans.WithLabelValues(reason).Inc()
	banCount := store.IncrBanCount(ipStr)
	paths := store.RecentPaths(ipStr)
	log.Printf("banned %s after %d %s (ban #%d); recent paths: %v", logIP(cfg, ip), count, reason, banCount, sanitizeForLog(fmt.Sprint(paths)))
	if banCount >= cfg.AbuseIPDB.ReportAfterBans && store.ShouldReport(ipStr, 15*time.Minute) {
		reportIP(cfg, ipStr, count, banCount, paths)
	}
}

const (
	penaltyNone     = ""
	penaltyFailed   = "failed attempts"
	penaltyWalkaway = "walk-aways"
)

func retryChallenge(w http.ResponseWriter, r *http.Request, cfg *Config, store Store, ip net.IP, returnTo, penalty string) {
	if sharedTorIP(torKind(r, cfg, ip), ip) {
		penalty = penaltyNone
	}
	key, limit := ip.String(), cfg.Walkaway.Threshold
	if penalty == penaltyFailed {
		key, limit = "fail:"+key, failedAttemptFactor*limit
	}
	if penalty != penaltyNone {
		if n := store.IncrWalkaway(key, cfg.Walkaway.TTL.Duration); n >= limit {
			banClient(cfg, store, ip, n, penalty)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	serveChallenge(w, r, cfg, cfg.Cap.APIURL, logIP(cfg, ip), returnTo, false)
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
	if ip == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ipStr := ip.String()
	returnTo := sanitizeReturnPath(r.FormValue("return_to"))

	provider := providerForRequest(cfg, r)

	log.Printf("verify start ip=%s provider=%s return_to=%s token_len=%d", logIP(cfg, ip), provider, sanitizeForLog(returnTo), len(token))

	if provider == "slider" {
		handleSliderVerify(w, r, cfg, store, ip, returnTo)
		return
	}

	verifier := buildVerifierForProvider(cfg, provider)

	ok, err := verifier.Verify(token, ipStr)
	if err != nil {
		metricChallenges.WithLabelValues(provider, "error").Inc()
		log.Printf("verify error ip=%s provider=%s err=%v", logIP(cfg, ip), provider, err)
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyNone)
		return
	}
	if !ok {
		metricChallenges.WithLabelValues(provider, "failed").Inc()
		log.Printf("verify failed ip=%s provider=%s", logIP(cfg, ip), provider)
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyFailed)
		return
	}

	metricChallenges.WithLabelValues(provider, "passed").Inc()
	log.Printf("verify success ip=%s provider=%s: issuing verified cookie (cookie_name=%s secure=%v)", logIP(cfg, ip), provider, cfg.CookieName, isSecureRequest(r, cfg))

	resetWalkaways(store, r, cfg, ip)
	setVerifiedCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	log.Printf("redirecting ip=%s to %s", logIP(cfg, ip), sanitizeForLog(returnTo))
	finishVerify(w, r, returnTo)
}

func handleSliderVerify(w http.ResponseWriter, r *http.Request, cfg *Config, store Store, ip net.IP, returnTo string) {
	ipStr := ip.String()
	captchaID := r.FormValue("captcha_id")
	answerStr := r.FormValue("answer")
	answer, err := strconv.Atoi(answerStr)
	if err != nil || answer < 0 || answer > 1500 {
		metricChallenges.WithLabelValues("slider", "failed").Inc()
		log.Printf("slider verify failed ip=%s id=%v answer=%q", logIP(cfg, ip), captchaID, sanitizeForLog(answerStr))
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyFailed)
		return
	}

	maxAttempts := sliderVerifyMaxPerMin
	if sharedTorIP(torKind(r, cfg, ip), ip) {
		maxAttempts *= torAttemptFactor
	}
	if !cfg.sliderChallenges.allowAttempt(ipStr, sliderVerifyWindow, maxAttempts) {
		metricChallenges.WithLabelValues("slider", "throttled").Inc()
		log.Printf("slider verify throttled ip=%s", logIP(cfg, ip))
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyNone)
		return
	}

	res := cfg.sliderChallenges.consume(captchaID, answer, cfg.Slider.Tolerance, cfg.Slider.MinSolveTime.Duration)
	lowVariance := cfg.sliderChallenges.recordAnswer(ipStr, answer, sliderAnswerSamples, cfg.Slider.Tolerance, sliderAnswerWindow)

	if res.tooFast {
		metricChallenges.WithLabelValues("slider", "automated").Inc()
		log.Printf("slider verify too fast ip=%s", logIP(cfg, ip))
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyWalkaway)
		return
	}
	if !res.ok {
		metricChallenges.WithLabelValues("slider", "failed").Inc()
		log.Printf("slider verify failed ip=%s id=%v answer=%d", logIP(cfg, ip), captchaID, answer)
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyFailed)
		return
	}
	if lowVariance {
		metricChallenges.WithLabelValues("slider", "automated").Inc()
		log.Printf("slider verify suspicious (repeated answers) ip=%s", logIP(cfg, ip))
		retryChallenge(w, r, cfg, store, ip, returnTo, penaltyWalkaway)
		return
	}

	metricChallenges.WithLabelValues("slider", "passed").Inc()
	log.Printf("verify success ip=%s provider=slider: issuing verified cookie (cookie_name=%s secure=%v)", logIP(cfg, ip), cfg.CookieName, isSecureRequest(r, cfg))
	resetWalkaways(store, r, cfg, ip)
	setVerifiedCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	log.Printf("redirecting ip=%s to %s", logIP(cfg, ip), sanitizeForLog(returnTo))
	finishVerify(w, r, returnTo)
}
