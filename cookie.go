package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	cookieScopeFull    = "full"
	cookieScopePassive = "passive"
)

func isSecureRequest(r *http.Request, cfg *Config) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Scheme"), "https") {
		return true
	}
	return false
}

func cookieBinding(r *http.Request) string {
	return r.UserAgent() + "\n" + r.Header.Get("Accept-Language")
}

func cookieMAC(secret, payload, binding string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload + "\n" + binding))
	return mac.Sum(nil)
}

func signCookie(secret string, expiry time.Time, scope, tls, binding string) string {
	payload := strconv.FormatInt(expiry.Unix(), 10) + "." + scope + "." + tls
	return payload + "." + hex.EncodeToString(cookieMAC(secret, payload, binding))
}

func verifyCookie(secret, value, expectedScope, tls, binding string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[1] != expectedScope {
		return false
	}
	if parts[2] != "" && tls != "" && parts[2] != tls {
		return false
	}

	sig, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	if !hmac.Equal(cookieMAC(secret, strings.Join(parts[:3], "."), binding), sig) {
		return false
	}

	expUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Before(time.Unix(expUnix, 0))
}

func tlsCipherHash(r *http.Request, cfg *Config) string {
	fp, ok := clientFingerprint(r, cfg)
	if !ok {
		return ""
	}
	return strings.Split(fp, "_")[1]
}

func issueCookieValue(r *http.Request, cfg *Config, expiry time.Time, scope string) string {
	return signCookie(cfg.CookieSecret, expiry, scope, tlsCipherHash(r, cfg), cookieBinding(r))
}

func validCookieValue(r *http.Request, cfg *Config, value, scope string) bool {
	return verifyCookie(cfg.CookieSecret, value, scope, tlsCipherHash(r, cfg), cookieBinding(r))
}

func browserMismatch(r *http.Request, cfg *Config) string {
	ua := r.UserAgent()
	hints := r.Header.Get("Sec-CH-UA") != ""
	chromium := strings.Contains(ua, "Chrome/")
	if hints && (strings.Contains(ua, "Firefox/") || (strings.Contains(ua, "Safari/") && !chromium)) {
		return "fake"
	}
	if chromium && !hints && isSecureRequest(r, cfg) {
		return "no-hints"
	}
	return ""
}

func newCookie(r *http.Request, cfg *Config, name, value string, expiry time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   isSecureRequest(r, cfg),
		SameSite: http.SameSiteLaxMode,
	}

	if !expiry.IsZero() {
		c.MaxAge = int(time.Until(expiry).Seconds())
	}

	return c
}

func setVerifiedCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	expiry := time.Now().Add(cfg.CookieTTL.Duration)

	http.SetCookie(w, newCookie(
		r,
		cfg,
		cfg.CookieName,
		issueCookieValue(r, cfg, expiry, cookieScopeFull),
		expiry,
	))
}

func setPassiveCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	expiry := time.Now().Add(cfg.Progressive.PassiveTTL.Duration)

	http.SetCookie(w, newCookie(
		r,
		cfg,
		cfg.CookieName+"_passive",
		issueCookieValue(r, cfg, expiry, cookieScopePassive),
		expiry,
	))
}

func clearPassiveCookie(w http.ResponseWriter, r *http.Request, cfg *Config) {
	c := newCookie(
		r,
		cfg,
		cfg.CookieName+"_passive",
		"",
		time.Unix(0, 0),
	)

	c.MaxAge = -1

	http.SetCookie(w, c)
}

func hasValidCookie(r *http.Request, cfg *Config) bool {
	c, err := r.Cookie(cfg.CookieName)
	if err != nil {
		return false
	}

	return validCookieValue(r, cfg, c.Value, cookieScopeFull)
}
