package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
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

func clientIP(r *http.Request, cfg *Config) net.IP {
	connectingIP := func() net.IP {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return net.ParseIP(r.RemoteAddr)
		}
		return net.ParseIP(host)
	}()

	if !cfg.TrustRealIP {
		return connectingIP
	}

	trust := cfg.compiledTrustedProxies.contains(connectingIP)
	if !trust && len(cfg.TrustedProxies) == 0 && connectingIP != nil {
		trust = connectingIP.IsLoopback() || connectingIP.IsPrivate()
	}

	if !trust {
		return connectingIP
	}

		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for _, ip := range strings.Split(xff, ",") {
				trimmed := strings.TrimSpace(ip)
				parsed := net.ParseIP(trimmed)
				if parsed != nil {
					return parsed
				}
			}
		}
		return connectingIP
	}

	return connectingIP
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
		return nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/__verify", func(w http.ResponseWriter, r *http.Request) {
		handleVerify(w, r, cfg, store)
	})

	mux.HandleFunc("/__set_provider", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p := q.Get("provider")
		returnTo := q.Get("return_to")
		if returnTo == "" {
			returnTo = "/"
		}
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
		handleRequest(w, r, cfg, rulesBox.Load().([]compiledRule), passivePaths, bypassPaths, alwaysPassPaths, store, proxy)
	})

	log.Printf("listening on %s, proxying to %s (provider=%s)", cfg.ListenAddr, cfg.UpstreamURL, cfg.Provider)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}

func handleRequest(w http.ResponseWriter, r *http.Request, cfg *Config, rules []compiledRule, passivePaths []*regexp.Regexp, bypassPaths []*regexp.Regexp, alwaysPassPaths []*regexp.Regexp, store Store, proxy *httputil.ReverseProxy) {
	ip := clientIP(r, cfg)
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

	action := evaluate(rules, cfg.DefaultAction, r, ip)
	switch action {
	case "allow":
		proxy.ServeHTTP(w, r)
		return
	case "deny":
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if cfg.Progressive.Enabled {
		if pathMatchesAny(r.URL.Path, passivePaths) {
			if pc, err := r.Cookie(cfg.CookieName + "_passive"); err == nil && pc.Value != "" {
				passiveCount := store.IncrPassiveCount(pc.Value, cfg.Progressive.RequestWindow.Duration)
				if passiveCount > cfg.Progressive.MaxRequests {
					log.Printf("passive rate limit hit cookie=%s... count=%d max=%d", pc.Value[:8], passiveCount, cfg.Progressive.MaxRequests)
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

	requestURI := r.URL.RequestURI()
	count := store.IncrWalkaway(ipStr, cfg.Walkaway.TTL.Duration)
	store.LogPath(ipStr, requestURI)
	if count >= cfg.Walkaway.Threshold {
		store.Block(ipStr, cfg.Ban.Duration.Duration)
		banCount := store.IncrBanCount(ipStr)
		paths := store.RecentPaths(ipStr)
		log.Printf("banned %s after %d walk-aways (ban #%d); recent paths: %v", ipStr, count, banCount, paths)
		if banCount >= cfg.AbuseIPDB.ReportAfterBans && store.ShouldReport(ipStr, 15*time.Minute) {
			reportIP(cfg, ipStr, count, banCount, paths)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveChallenge(w, r, cfg, cfg.Cap.APIURL, ipStr, requestURI, count == 1)
}

func handleVerify(w http.ResponseWriter, r *http.Request, cfg *Config, store Store) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	ip := clientIP(r, cfg).String()
	returnTo := sanitizeReturnPath(r.FormValue("return_to"))

	provider := providerForRequest(cfg, r)
	verifier := buildVerifierForProvider(cfg, provider)

	log.Printf("verify start ip=%s provider=%s return_to=%s token_len=%d", ip, provider, returnTo, len(token))

	ok, err := verifier.Verify(token)
	if err != nil {
		log.Printf("verify error ip=%s provider=%s err=%v", ip, provider, err)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	if !ok {
		log.Printf("verify failed ip=%s provider=%s", ip, provider)
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}

	log.Printf("verify success ip=%s provider=%s: issuing verified cookie (cookie_name=%s secure=%v)", ip, provider, cfg.CookieName, isSecureRequest(r, cfg))

	store.ResetWalkaway(ip)
	setVerifiedCookie(w, r, cfg)
	clearPassiveCookie(w, r, cfg)
	log.Printf("redirecting ip=%s to %s", ip, returnTo)
	http.Redirect(w, r, returnTo, http.StatusFound)
}
