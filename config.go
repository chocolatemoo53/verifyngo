package main

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type Rule struct {
	Match struct {
		Path string   `json:"path"`
		UA   string   `json:"ua"`
		CIDR []string `json:"cidr"`
	} `json:"match"`
	Action string `json:"action"`
}

type Config struct {
	ListenAddr   string   `json:"listen_addr"`
	UpstreamURL  string   `json:"upstream_url"`
	CookieSecret string   `json:"cookie_secret"`
	CookieName   string   `json:"cookie_name"`
	CookieTTL    Duration `json:"cookie_ttl"`

	ResponseCSP string `json:"response_csp"`

	Provider string `json:"provider"`
	Cap      struct {
		APIURL          string `json:"api_url"`
		VerifyURL       string `json:"verify_url"`
		SiteKey         string `json:"site_key"`
		SecretKey       string `json:"secret_key"`
		WidgetScriptURL string `json:"widget_script_url"`
		UseNonce        bool   `json:"use_nonce"`
		CSP             string `json:"csp"`
	} `json:"cap"`
	Turnstile struct {
		SiteKey   string `json:"site_key"`
		SecretKey string `json:"secret_key"`
	} `json:"turnstile"`
	HCaptcha struct {
		SiteKey   string `json:"site_key"`
		SecretKey string `json:"secret_key"`
	} `json:"hcaptcha"`

	Whitelist     []string `json:"whitelist"`
	Rules         []Rule   `json:"rules"`
	DefaultAction string   `json:"default_action"`

	Walkaway struct {
		Threshold int      `json:"threshold"`
		TTL       Duration `json:"ttl"`
	} `json:"walkaway"`

	Ban struct {
		Duration Duration `json:"duration"`
	} `json:"ban"`

	AbuseIPDB struct {
		Enabled         bool   `json:"enabled"`
		APIKey          string `json:"api_key"`
		Categories      string `json:"categories"`
		Comment         string `json:"comment"`
		ReportAfterBans int    `json:"report_after_bans"`

		Blacklist struct {
			Enabled bool     `json:"enabled"`
			Refresh Duration `json:"refresh"`
		} `json:"blacklist"`
	} `json:"abuseipdb"`

	TrustRealIP    bool     `json:"trust_real_ip"`
	TrustedProxies []string `json:"trusted_proxies"`

	StaticDir  string `json:"static_dir"`
	RulesFile  string `json:"rules_file"`
	PolicyFile string `json:"policy_file"`

	ASN struct {
		GeoIPDBPath  string   `json:"geoip_db_path"`
		WhoisEnabled bool     `json:"whois_enabled"`
		WhoisAddr    string   `json:"whois_addr"`
		WhoisTimeout Duration `json:"whois_timeout"`
		WhoisStrict  bool     `json:"whois_strict"`
	} `json:"asn"`

	compiledWhitelist      compiledWhitelist
	compiledTrustedProxies compiledWhitelist

	Store struct {
		Backend string `json:"backend"`

		File struct {
			Path         string   `json:"path"`
			SaveInterval Duration `json:"save_interval"`
		} `json:"file"`

		Redis struct {
			Addr      string `json:"addr"`
			Password  string `json:"password"`
			DB        int    `json:"db"`
			KeyPrefix string `json:"key_prefix"`
		} `json:"redis"`
	} `json:"store"`

	Progressive struct {
		Enabled       bool     `json:"enabled"`
		PassivePaths  []string `json:"passive_paths"`
		PassiveTTL    Duration `json:"passive_ttl"`
		MaxRequests   int      `json:"max_requests"`
		RequestWindow Duration `json:"request_window"`
	} `json:"progressive"`

	BypassPaths     []string `json:"bypass_paths"`
	AlwaysPassPaths []string `json:"always_pass_paths"`

	Branding struct {
		LogoURL string `json:"logo_url"`
		CSSURL  string `json:"css_url"`

		AccentColor     string `json:"accent_color"`
		BackgroundColor string `json:"background_color"`
		TextColor       string `json:"text_color"`
		FontFamily      string `json:"font_family"`
		FontURL         string `json:"font_url"`

		Title       string `json:"title"`
		DetailsText string `json:"details_text"`
		ContactURL  string `json:"contact_url"`
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		CookieName:    "cp_verified",
		CookieTTL:     Duration{7 * 24 * time.Hour},
		DefaultAction: "challenge",
	}
	cfg.ASN.WhoisEnabled = true
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if cfg.BypassPaths == nil {
		cfg.BypassPaths = defaultBypassPaths
	}
	if cfg.Walkaway.Threshold == 0 {
		cfg.Walkaway.Threshold = 10
	}
	if cfg.Walkaway.TTL.Duration == 0 {
		cfg.Walkaway.TTL = Duration{2 * time.Hour}
	}
	if cfg.Ban.Duration.Duration == 0 {
		cfg.Ban.Duration = Duration{24 * time.Hour}
	}
	if cfg.Store.Backend == "" {
		cfg.Store.Backend = "memory"
	}
	if cfg.Store.File.SaveInterval.Duration == 0 {
		cfg.Store.File.SaveInterval = Duration{30 * time.Second}
	}
	if cfg.Store.Redis.Addr == "" {
		cfg.Store.Redis.Addr = "127.0.0.1:6379"
	}
	if cfg.Store.Redis.KeyPrefix == "" {
		cfg.Store.Redis.KeyPrefix = "verifyngo"
	}
	if cfg.Progressive.PassiveTTL.Duration == 0 {
		cfg.Progressive.PassiveTTL = Duration{30 * time.Minute}
	}
	if cfg.Progressive.MaxRequests == 0 {
		cfg.Progressive.MaxRequests = 50
	}
	if cfg.Progressive.RequestWindow.Duration == 0 {
		cfg.Progressive.RequestWindow = Duration{10 * time.Minute}
	}
	if cfg.ASN.WhoisAddr == "" {
		cfg.ASN.WhoisAddr = "whois.radb.net:43"
	}
	if cfg.ASN.WhoisTimeout.Duration == 0 {
		cfg.ASN.WhoisTimeout = Duration{30 * time.Second}
	}
	if cfg.AbuseIPDB.ReportAfterBans == 0 {
		cfg.AbuseIPDB.ReportAfterBans = 3
	}
	if cfg.AbuseIPDB.Blacklist.Enabled && cfg.AbuseIPDB.Blacklist.Refresh.Duration == 0 {
		cfg.AbuseIPDB.Blacklist.Refresh = Duration{6 * time.Hour}
	}
	if cfg.Branding.AccentColor == "" {
		cfg.Branding.AccentColor = "#4A90D9"
	}
	if cfg.Branding.BackgroundColor == "" {
		cfg.Branding.BackgroundColor = "#000000"
	}
	if cfg.Branding.TextColor == "" {
		cfg.Branding.TextColor = "#f2f2f2"
	}
	if cfg.Branding.FontFamily == "" {
		cfg.Branding.FontFamily = "sans-serif"
	}
	if cfg.Branding.DetailsText == "" {
		cfg.Branding.DetailsText = "This page runs a quick, one-time check to confirm you're a real visitor and not an automated bot. It only takes a moment, and once you've solved it you won't see this again for a while."
	}
	cfg.compiledWhitelist = compileWhitelist(cfg.Whitelist)
	cfg.compiledTrustedProxies = compileWhitelist(cfg.TrustedProxies)

	if cfg.TrustRealIP && len(cfg.TrustedProxies) == 0 {
		log.Println("NOTE: trust_real_ip is enabled without trusted_proxies — auto-trusting X-Forwarded-For from loopback/private IPs only")
		log.Println("NOTE: set trusted_proxies explicitly if your reverse proxy connects from a non-private address")
	}

	return cfg, nil
}
